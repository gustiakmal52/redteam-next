"""
Reconnaissance Pipeline Orchestrator.
Orchestrates subfinder, httpx, gau, katana, ffuf, and arjun with async real-time
stdout streaming to TaskManager SSE logs with explicit tool-failure records.
"""

import asyncio
import os
import re
import json
import urllib.parse
import tempfile
from typing import List, Dict, Any, Set, Optional
from redteam_agent.core.config import TOOL_PATHS, SENSITIVE_PATHS
from redteam_agent.core.task_manager import ScanTask
from redteam_agent.core.http_verifier import HTTPVerifier
from redteam_agent.core.scope_manager import normalize_url, URLPolicyError

class ReconPipeline:
    def __init__(self, task: ScanTask):
        self.task = task
        self.domain = self._extract_root_domain(task.target)
        self.scope = task.scope_manager
        self.traffic = task.traffic_controller
        self.verifier = HTTPVerifier(timeout=self.traffic.config["timeout"], traffic_controller=self.traffic,
                                     scope_manager=self.scope, module="recon")

    def _extract_root_domain(self, target: str) -> str:
        """Extracts domain or hostname from URL or raw domain input."""
        cleaned = target.strip()
        if "://" in cleaned:
            parsed = urllib.parse.urlparse(cleaned)
            cleaned = parsed.netloc
        if ":" in cleaned:
            cleaned = cleaned.split(":")[0]
        return cleaned

    async def _run_async_command(self, cmd: List[str], tool_label: str) -> List[str]:
        """Runs a CLI command asynchronously, streaming lines in real time to SSE log."""
        output_lines = []
        proc = None
        try:
            await self.task.emit_log("INFO", f"[{tool_label}] Executing: {' '.join(cmd)}")
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            self.task.register_process(proc)

            while True:
                line = await proc.stdout.readline()
                if not line:
                    break
                decoded = line.decode('utf-8', errors='ignore').strip()
                if decoded:
                    output_lines.append(decoded)
                    # Stream interesting output
                    if not decoded.startswith("{") and len(decoded) < 120:
                        await self.task.emit_log("INFO", f"[{tool_label}] {decoded}")

            return_code = await proc.wait()
            stderr = (await proc.stderr.read()).decode("utf-8", errors="replace").strip()
            run_status = "failed" if return_code else ("success" if output_lines else "no_output")
            self.task.results["tool_runs"].append({"tool": tool_label,
                "status": run_status, "return_code": return_code,
                "reason": stderr[:500] if return_code else ("completed" if output_lines else "command produced no output"), "output_count": len(output_lines),
                "verified": return_code == 0 and bool(output_lines)})
        except Exception as e:
            self.task.results["tool_runs"].append({"tool": tool_label, "status": "failed", "reason": str(e), "verified": False})
            await self.task.emit_log("WARN", f"[{tool_label}] Command failed ({e}); no results fabricated.")
        finally:
            if proc is not None:
                self.task.unregister_process(proc)
        return output_lines

    async def run_subdomain_discovery(self) -> List[str]:
        """Run subfinder; wordlist guesses remain unobserved candidate records."""
        await self.task.emit_log("INFO", f"Starting Subdomain Enumeration on: {self.domain}", "Subdomain Discovery", 10)
        subdomains: Set[str] = {self.domain}
        records = [{"value": self.domain, "source": "configured_target", "observed": False, "live": None}]

        subfinder_bin = TOOL_PATHS.get("subfinder")
        if subfinder_bin and os.path.exists(subfinder_bin):
            cmd = [subfinder_bin, "-d", self.domain, "-silent", "-rl", str(int(self.traffic.config["global_rps"])),
                   "-t", str(self.traffic.config["global_concurrency"])]
            lines = await self._run_async_command(cmd, "subfinder")
            for line in lines:
                sub = line.strip().lower()
                candidate_url = f"https://{sub}"
                if self.scope.check_url(candidate_url, active=True).get("allowed"):
                    subdomains.add(sub)
                    records.append({"value": sub, "source": "subfinder", "observed": True, "live": None})
        else:
            self.task.results["tool_runs"].append({"tool": "subfinder", "status": "failed", "reason": "tool missing", "verified": False})

        # Wordlist guesses remain explicitly generated candidates, never discoveries.
        if len(subdomains) <= 1:
            for sub_prefix in ["api", "app", "dev", "staging", "admin", "auth", "backend"]:
                records.append({"value": f"{sub_prefix}.{self.domain}", "source": "generated_candidate",
                                "observed": False, "live": False})

        discovered = sorted(list(subdomains))
        self.task.results["subdomains"] = discovered
        self.task.results["subdomain_records"] = records
        self.task.results["stats"]["subdomains"] = len(discovered)
        await self.task.emit_log("SUCCESS", f"Recorded {len(discovered)} observed/configured domains; generated guesses remain candidates", progress=20)
        return discovered

    async def run_http_probing(self, subdomains: List[str]) -> List[Dict[str, Any]]:
        """Runs httpx to probe live HTTP/HTTPS services and detect technology stacks."""
        await self.task.emit_log("INFO", f"Probing {len(subdomains)} hosts via HTTPX...", "HTTP Probing & Tech Fingerprint", 25)
        live_hosts: List[Dict[str, Any]] = []

        httpx_bin = TOOL_PATHS.get("httpx")
        # Format target input
        input_targets = "\n".join(subdomains[:30])  # limit top 30 to stay fast

        if httpx_bin and os.path.exists(httpx_bin):
            proc = None
            try:
                proc = await asyncio.create_subprocess_exec(
                    httpx_bin, "-silent", "-title", "-tech-detect", "-status-code", "-content-length", "-json",
                    "-rl", str(int(self.traffic.config["global_rps"])),
                    "-threads", str(self.traffic.config["global_concurrency"]),
                    "-timeout", str(int(self.traffic.config["timeout"])),
                    "-retries", str(self.traffic.config["retry_limit"]),
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                self.task.register_process(proc)
                stdout, stderr = await proc.communicate(input=input_targets.encode('utf-8'))
                for line in stdout.decode('utf-8', errors='ignore').splitlines():
                    if line.strip().startswith("{"):
                        try:
                            data = json.loads(line.strip())
                            live_hosts.append({
                                "url": data.get("url"),
                                "host": data.get("host"),
                                "status_code": data.get("status_code", 0),
                                "title": data.get("title", ""),
                                "tech": data.get("tech", []),
                                "webserver": data.get("webserver", ""),
                                "content_length": data.get("content_length", 0)
                                ,"source": "httpx", "observed": True
                            })
                        except Exception:
                            pass
                httpx_status = "failed" if proc.returncode else ("success" if live_hosts else "no_output")
                self.task.results["tool_runs"].append({"tool": "httpx", "status": httpx_status,
                    "return_code": proc.returncode, "reason": stderr.decode("utf-8", errors="replace")[:500],
                    "output_count": len(live_hosts), "verified": bool(live_hosts)})
            except Exception as e:
                self.task.results["tool_runs"].append({"tool": "httpx", "status": "failed", "reason": str(e), "verified": False})
                await self.task.emit_log("WARN", f"[httpx] Execution error: {e}")
            finally:
                if proc is not None:
                    self.task.unregister_process(proc)
        else:
            self.task.results["tool_runs"].append({"tool": "httpx", "status": "failed", "reason": "tool missing", "verified": False})

        # Empty or failed output is an explicit failure, never a synthetic live host.
        if not live_hosts:
            await self.task.emit_log("WARN", "[httpx] No observed live hosts; status and technologies remain unknown")

        self.task.results["live_hosts"] = live_hosts
        self.task.results["stats"]["live_hosts"] = len(live_hosts)
        level = "SUCCESS" if live_hosts else "WARN"
        await self.task.emit_log(level, f"Identified {len(live_hosts)} observed live HTTP services", progress=35)
        return live_hosts

    async def run_crawlers(self, live_hosts: List[Dict[str, Any]]) -> List[str]:
        """Runs gau and katana to crawl endpoints and historical archives."""
        await self.task.emit_log("INFO", f"Crawling endpoints with Katana & GAU...", "URL & Endpoint Crawling", 40)
        seed = self.task.target if self.task.target.startswith("http") else f"https://{self.task.target}"
        endpoint_sources: Dict[str, Set[str]] = {}
        def record(url: str, source: str):
            try:
                normalized = normalize_url(url)
            except URLPolicyError:
                return
            endpoint_sources.setdefault(normalized, set()).add(source)
        record(seed, "configured_target")

        # Seed endpoints from live hosts
        for host in live_hosts:
            if host.get("url"):
                record(host["url"], "httpx")

        # Run GAU for historical URLs
        gau_bin = TOOL_PATHS.get("gau")
        if gau_bin and os.path.exists(gau_bin):
            cmd = [gau_bin, self.domain, "--blacklist", "png,jpg,jpeg,gif,svg,woff,woff2,ttf,css", "--subs"]
            gau_lines = await self._run_async_command(cmd, "gau")
            for line in gau_lines[:50]:
                u = line.strip()
                if u.startswith("http"):
                    decision = self.scope.check_url(u, active=False)
                    record(u, "gau")
                    if not decision.get("in_scope"):
                        self.task.results["external_discoveries"].append({"value": u, "source": "gau", "observed": True,
                            "active_verification_skipped": "outside_scope"})

        # Run Katana active crawl on top target
        katana_bin = TOOL_PATHS.get("katana")
        if katana_bin and os.path.exists(katana_bin) and live_hosts:
            target_url = live_hosts[0]["url"]
            cmd = [katana_bin, "-u", target_url, "-d", "2", "-silent", "-jc",
                   "-c", str(self.traffic.config["global_concurrency"]), "-rl", str(int(self.traffic.config["global_rps"])),
                   "-hrl", str(int(self.traffic.config["per_host_rps"])),
                   "-timeout", str(int(self.traffic.config["timeout"])), "-retry", str(self.traffic.config["retry_limit"])]
            katana_lines = await self._run_async_command(cmd, "katana")
            for line in katana_lines[:50]:
                u = line.strip()
                if u.startswith("http"):
                    decision = self.scope.check_url(u, active=False)
                    record(u, "katana")
                    if not decision.get("in_scope"):
                        self.task.results["external_discoveries"].append({"value": u, "source": "katana", "observed": True,
                            "active_verification_skipped": "outside_scope"})

        discovered = sorted(endpoint_sources)
        self.task.results["endpoint_records"] = [{"url": url, "sources": sorted(sources),
            "observed": any(source != "configured_target" for source in sources),
            "in_scope": self.scope.check_url(url, active=False).get("in_scope", False)} for url, sources in endpoint_sources.items()]
        self.task.results["endpoints"] = discovered
        self.task.results["stats"]["endpoints"] = len(discovered)
        await self.task.emit_log("SUCCESS", f"Harvested {len(discovered)} unique endpoints and paths", progress=50)
        return discovered

    async def run_sensitive_path_fuzzing(self, base_url: str) -> List[Dict[str, Any]]:
        """Runs fast sensitive path probing (e.g. .git, .env, swagger, graphql)."""
        await self.task.emit_log("INFO", f"Fuzzing sensitive routes & configuration leaks on {base_url}...", "Directory & Config Fuzzing", 70)
        exposed_findings = []
        
        for path in SENSITIVE_PATHS[:12]:
            test_url = urllib.parse.urljoin(base_url, path)
            response = await asyncio.to_thread(self.verifier.send_http_request, test_url, priority="normal")
            if response.get("status_code") == 200:
                body_preview = response.get("body", "")[:200]
                if "404" not in body_preview.lower() and len(body_preview) > 5:
                    await self.task.emit_log("INFO", f"[RECON] Observed candidate endpoint: {test_url} (HTTP 200)")
                    exposed_findings.append({"path": path, "url": test_url, "status": 200,
                        "preview": body_preview[:80], "finding_status": "DISCOVERED", "observed": True,
                        "source": "direct_sensitive_probe"})

        return exposed_findings

    async def run_param_miner(self, base_url: str) -> List[str]:
        """Run the configured Arjun binary with traffic-aware threads/timeouts."""
        binary = TOOL_PATHS.get("arjun")
        if not binary or not os.path.exists(binary):
            self.task.results["tool_runs"].append({"tool": "arjun", "status": "failed", "reason": "tool missing", "verified": False})
            return []
        output_path = None
        try:
            with tempfile.NamedTemporaryFile("w", delete=False, prefix="redteam_arjun_", suffix=".json") as handle:
                output_path = handle.name
            await self._run_async_command([binary, "-u", base_url, "-t", str(self.traffic.config["per_host_concurrency"]),
                "--stable", "-oJ", output_path], "arjun")
            try:
                with open(output_path, "r", encoding="utf-8") as handle:
                    data = json.load(handle)
            except (OSError, ValueError):
                return []
            params: Set[str] = set()
            values = data.values() if isinstance(data, dict) else []
            for value in values:
                if isinstance(value, list):
                    params.update(item for item in value if isinstance(item, str))
                elif isinstance(value, dict):
                    for nested in value.values():
                        if isinstance(nested, list):
                            params.update(item for item in nested if isinstance(item, str))
            return sorted(params)
        finally:
            if output_path:
                try:
                    os.unlink(output_path)
                except OSError:
                    pass

    async def run_ffuf(self, base_url: str) -> List[Dict[str, Any]]:
        """Use ffuf when installed; generated paths are promoted only from real output."""
        binary = TOOL_PATHS.get("ffuf")
        if not binary or not os.path.exists(binary):
            self.task.results["tool_runs"].append({"tool": "ffuf", "status": "failed", "reason": "tool missing", "verified": False})
            return []
        wordlist = None
        try:
            with tempfile.NamedTemporaryFile("w", delete=False, prefix="redteam_ffuf_", suffix=".txt") as handle:
                handle.write("\n".join(path.lstrip("/") for path in SENSITIVE_PATHS))
                wordlist = handle.name
            target = base_url.rstrip("/") + "/FUZZ"
            lines = await self._run_async_command([binary, "-u", target, "-w", wordlist, "-json", "-s",
                "-rate", str(int(self.traffic.config["per_host_rps"])), "-t", str(self.traffic.config["per_host_concurrency"]),
                "-timeout", str(int(self.traffic.config["timeout"]))], "ffuf")
            results = []
            for line in lines:
                try:
                    item = json.loads(line)
                except ValueError:
                    continue
                if item.get("url"):
                    results.append({"url": item["url"], "status": item.get("status"), "source": "ffuf", "observed": True})
            return results
        finally:
            if wordlist:
                try:
                    os.unlink(wordlist)
                except OSError:
                    pass
