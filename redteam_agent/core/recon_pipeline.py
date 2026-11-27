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
        stderr_task = None
        try:
            await self.task.emit_log("INFO", f"[{tool_label}] Executing: {' '.join(cmd)}")
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            self.task.register_process(proc)
            # Drain stderr concurrently.  Reading it only after stdout can
            # deadlock a verbose recon tool once the OS pipe buffer fills.
            stderr_task = asyncio.create_task(proc.stderr.read())

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
            stderr = (await stderr_task).decode("utf-8", errors="replace").strip()
            run_status = "failed" if return_code else ("success" if output_lines else "no_output")
            self.task.results["tool_runs"].append({"tool": tool_label,
                "status": run_status, "return_code": return_code,
                "reason": stderr[:500] if return_code else ("completed" if output_lines else "command produced no output"), "output_count": len(output_lines),
                "verified": return_code == 0 and bool(output_lines)})
        except Exception as e:
            self.task.results["tool_runs"].append({"tool": tool_label, "status": "failed", "reason": str(e), "verified": False})
            await self.task.emit_log("WARN", f"[{tool_label}] Command failed ({e}); no results fabricated.")
        finally:
            if stderr_task is not None and not stderr_task.done():
                stderr_task.cancel()
                await asyncio.gather(stderr_task, return_exceptions=True)
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
            cmd = [subfinder_bin, "-d", self.domain, "-all", "-oJ", "-cs", "-duc",
                   "-rl", str(int(self.traffic.config["global_rps"])),
                   "-t", str(self.traffic.config["global_concurrency"])]
            lines = await self._run_async_command(cmd, "subfinder")
            for line in lines:
                sources = ["subfinder"]
                try:
                    item = json.loads(line)
                except (TypeError, ValueError):
                    item = None
                if isinstance(item, dict):
                    sub = str(item.get("host") or item.get("input") or "").strip().lower()
                    reported_sources = item.get("sources") or ([item.get("source")] if item.get("source") else [])
                    if isinstance(reported_sources, str):
                        reported_sources = [reported_sources]
                    sources = sorted({str(source) for source in reported_sources if source}) or sources
                else:
                    sub = line.strip().lower()
                if not sub:
                    continue
                candidate_url = f"https://{sub}"
                if self.scope.check_url(candidate_url, active=True).get("allowed"):
                    subdomains.add(sub)
                    records.append({"value": sub, "source": "subfinder", "sources": sources,
                                    "observed": True, "live": None})
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
        # httpx owns pacing/concurrency for this subprocess.  Do not silently
        # discard every host after the first 30; the configured scan budget is
        # the coverage ceiling.
        remaining = self.traffic.stats().get("requests_remaining")
        candidates = list(dict.fromkeys(subdomains))
        if remaining is not None:
            candidates = candidates[:max(0, int(remaining) - int(self.traffic.verification_reserve))]
        input_targets = "\n".join(candidates)

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
                seen_urls: Set[str] = set()
                for line in stdout.decode('utf-8', errors='ignore').splitlines():
                    if line.strip().startswith("{"):
                        try:
                            data = json.loads(line.strip())
                            url = data.get("url")
                            if not url or not self.scope.check_url(url, active=True).get("allowed"):
                                continue
                            normalized = normalize_url(url)
                            if normalized in seen_urls:
                                continue
                            seen_urls.add(normalized)
                            live_hosts.append({
                                "url": normalized,
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
        endpoint_records: Dict[str, Dict[str, Any]] = {}
        external_seen = {
            (str(item.get("value") or ""), str(item.get("source") or ""))
            for item in self.task.results.get("external_discoveries", []) if isinstance(item, dict)
        }

        def record(url: str, source: str, *, method: str = "GET",
                   body_fields: Optional[List[str]] = None,
                   content_type: Optional[str] = None,
                   status_code: Optional[int] = None,
                   technologies: Optional[List[str]] = None):
            try:
                normalized = normalize_url(url)
            except URLPolicyError:
                return
            if not self.scope.check_url(normalized, active=False).get("in_scope"):
                return
            entry = endpoint_records.setdefault(normalized, {
                "url": normalized, "sources": set(), "methods": set(),
                "body_fields": set(), "content_types": set(), "status_codes": set(),
                "technologies": set(),
            })
            entry["sources"].add(source)
            entry["methods"].add(str(method or "GET").upper())
            fields = body_fields if isinstance(body_fields, list) else ([body_fields] if body_fields else [])
            entry["body_fields"].update(str(item) for item in fields if str(item))
            if content_type:
                entry["content_types"].add(str(content_type))
            if status_code is not None:
                entry["status_codes"].add(int(status_code))
            tech_values = technologies if isinstance(technologies, list) else ([technologies] if technologies else [])
            entry["technologies"].update(str(item) for item in tech_values if str(item))

        def record_external(url: str, source: str):
            key = (url, source)
            if key in external_seen:
                return
            external_seen.add(key)
            self.task.results["external_discoveries"].append({
                "value": url, "source": source, "observed": True,
                "active_verification_skipped": "outside_scope",
            })

        def priority(entry: Dict[str, Any]) -> tuple[int, List[str]]:
            parsed = urllib.parse.urlsplit(entry["url"])
            fields = {key.lower() for key, _ in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)}
            fields.update(str(item).lower() for item in entry["body_fields"])
            path = parsed.path.lower()
            reasons: List[str] = []
            if entry["methods"] - {"GET", "HEAD", "OPTIONS"}:
                reasons.append("state_changing_method")
            if fields:
                reasons.append("user_controlled_fields")
            if fields & {"cmd", "command", "exec", "shell", "query", "search", "filter", "where",
                         "url", "uri", "host", "domain", "callback", "webhook", "redirect", "next",
                         "file", "path", "template", "id", "user_id", "account_id"}:
                reasons.append("high_value_input")
            if any(token in path for token in ("/api/", "/graphql", "/rpc", "/admin", "/internal",
                                               "/debug", "/upload", "/import", "/webhook", "/proxy",
                                               "/fetch", "/render", "/execute", "/search")):
                reasons.append("high_value_route")
            return len(reasons), reasons

        record(seed, "configured_target")

        # Seed endpoints from live hosts
        for host in live_hosts:
            if host.get("url"):
                record(host["url"], "httpx")

        # Run GAU for historical URLs
        gau_bin = TOOL_PATHS.get("gau")
        if gau_bin and os.path.exists(gau_bin):
            cmd = [gau_bin, self.domain, "--blacklist", "png,jpg,jpeg,gif,svg,woff,woff2,ttf,css", "--subs",
                   "--threads", str(self.traffic.config["global_concurrency"]),
                   "--timeout", str(int(self.traffic.config["timeout"])),
                   "--retries", str(self.traffic.config["retry_limit"])]
            gau_lines = await self._run_async_command(cmd, "gau")
            for line in gau_lines:
                u = line.strip()
                if u.startswith("http"):
                    decision = self.scope.check_url(u, active=False)
                    record(u, "gau")
                    if not decision.get("in_scope"):
                        record_external(u, "gau")
        else:
            self.task.results["tool_runs"].append({
                "tool": "gau", "status": "failed", "reason": "tool missing", "verified": False,
            })

        # One Katana process crawls every observed in-scope live host.  JSONL
        # preserves request methods, form fields, status, and technologies for
        # target-specific prioritization.
        katana_bin = TOOL_PATHS.get("katana")
        if katana_bin and os.path.exists(katana_bin) and live_hosts:
            katana_seeds = []
            seen_seeds = set()
            for host in live_hosts:
                url = host.get("url")
                if not url or not self.scope.check_url(url, active=True).get("allowed"):
                    continue
                try:
                    normalized = normalize_url(url)
                except URLPolicyError:
                    continue
                if normalized in seen_seeds:
                    continue
                seen_seeds.add(normalized)
                katana_seeds.append(normalized)
            remaining = self.traffic.stats().get("requests_remaining")
            if remaining is not None:
                katana_seeds = katana_seeds[:max(0, int(remaining) - int(self.traffic.verification_reserve))]
            seed_file = None
            try:
                with tempfile.NamedTemporaryFile("w", delete=False, prefix="redteam_katana_", suffix=".txt") as handle:
                    handle.write("\n".join(katana_seeds))
                    seed_file = handle.name
                if katana_seeds:
                    cmd = [katana_bin, "-list", seed_file, "-d", "3", "-silent", "-jc", "-kf", "all",
                           "-fx", "-td", "-j", "-or", "-ob", "-s", "breadth-first", "-pc", "-fsu",
                           "-c", str(self.traffic.config["global_concurrency"]),
                           "-p", str(min(len(katana_seeds), self.traffic.config["global_concurrency"])),
                           "-rl", str(int(self.traffic.config["global_rps"])),
                           "-hrl", str(int(self.traffic.config["per_host_rps"])),
                           "-timeout", str(int(self.traffic.config["timeout"])),
                           "-retry", str(self.traffic.config["retry_limit"])]
                    katana_lines = await self._run_async_command(cmd, "katana")
                    for line in katana_lines:
                        try:
                            item = json.loads(line)
                        except (TypeError, ValueError):
                            item = None
                        if isinstance(item, dict):
                            request = item.get("request") or {}
                            response = item.get("response") or {}
                            u = str(request.get("endpoint") or item.get("url") or "").strip()
                            if u.startswith("http"):
                                decision = self.scope.check_url(u, active=False)
                                record(u, "katana", method=request.get("method") or item.get("method") or "GET",
                                       status_code=response.get("status_code"),
                                       technologies=response.get("technologies") or [])
                                if not decision.get("in_scope"):
                                    record_external(u, "katana")
                            for form in response.get("forms") or []:
                                if not isinstance(form, dict):
                                    continue
                                action = str(form.get("action") or "").strip()
                                if action.startswith("http"):
                                    decision = self.scope.check_url(action, active=False)
                                    record(action, "katana_form", method=form.get("method") or "GET",
                                           body_fields=form.get("parameters") or [], content_type=form.get("enctype"))
                                    if not decision.get("in_scope"):
                                        record_external(action, "katana_form")
                        else:
                            u = line.strip()
                            if u.startswith("http"):
                                decision = self.scope.check_url(u, active=False)
                                record(u, "katana")
                                if not decision.get("in_scope"):
                                    record_external(u, "katana")
            finally:
                if seed_file:
                    try:
                        os.unlink(seed_file)
                    except OSError:
                        pass
        elif not katana_bin or not os.path.exists(katana_bin):
            self.task.results["tool_runs"].append({
                "tool": "katana", "status": "failed", "reason": "tool missing", "verified": False,
            })
        else:
            self.task.results["tool_runs"].append({
                "tool": "katana", "status": "no_output", "reason": "no observed live hosts to crawl",
                "verified": False,
            })

        public_records = []
        for entry in endpoint_records.values():
            score, reasons = priority(entry)
            methods = sorted(entry["methods"])
            public_records.append({
                "url": entry["url"], "sources": sorted(entry["sources"]),
                "observed": any(source != "configured_target" for source in entry["sources"]),
                "in_scope": self.scope.check_url(entry["url"], active=False).get("in_scope", False),
                "method": methods[0] if len(methods) == 1 else "MULTIPLE", "methods": methods,
                "body_fields": sorted(entry["body_fields"]), "content_types": sorted(entry["content_types"]),
                "status_codes": sorted(entry["status_codes"]), "technologies": sorted(entry["technologies"]),
                "priority_score": score, "priority_reasons": reasons,
            })
        public_records.sort(key=lambda item: (-item["priority_score"], item["url"]))
        discovered = [item["url"] for item in public_records]
        self.task.results["endpoint_records"] = public_records
        self.task.results["endpoints"] = discovered
        self.task.results["stats"]["endpoints"] = len(discovered)
        await self.task.emit_log("SUCCESS", f"Harvested {len(discovered)} unique endpoints and paths", progress=50)
        return discovered

    async def run_sensitive_path_fuzzing(self, base_url: str) -> List[Dict[str, Any]]:
        """Runs fast sensitive path probing (e.g. .git, .env, swagger, graphql)."""
        await self.task.emit_log("INFO", f"Fuzzing sensitive routes & configuration leaks on {base_url}...", "Directory & Config Fuzzing", 70)
        exposed_findings = []
        
        for path in SENSITIVE_PATHS:
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
