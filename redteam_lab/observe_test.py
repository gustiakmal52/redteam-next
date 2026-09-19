#!/usr/bin/env python3
"""
Observation test: run redteam_agent against the hardened local lab and prove
the results are honest.

How it works
------------
1. Start `lab_server.py` (hardened target) on 127.0.0.1 with a JSONL access log.
2. Self-audit the lab quickly (headers, uniform 404, no CORS) so the control
   is verified before the scan runs.
3. Run the agent (CLI, --preset lab_hardened --allow-private) as a subprocess.
4. Stop the lab and cross-check:
     * scan summary (findings / verified / quarantined / DB results)
     * every *evidence claim* the scan made (finding URLs, download URLs,
       admin panel URLs, connection-string sources) must appear in the lab's
       own access log — anything else would be a hallucinated request.

Expected outcome against this hardened target: zero VERIFIED vulnerabilities
and zero unbacked claims. Non-empty quarantine of low-confidence candidates
is honest behavior, not a failure.

Usage
-----
    python3 redteam_lab/observe_test.py                # full run
    python3 redteam_lab/observe_test.py --preset full  # broader (uses more modules)
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LAB_SERVER = os.path.join(ROOT, "redteam_lab", "lab_server.py")
DEFAULT_OUT = os.path.join(ROOT, "redteam_lab", "output")


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------

def pick_free_port(host: str = "127.0.0.1") -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return sock.getsockname()[1]


def http_get(url: str, timeout: float = 3.0) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "lab-observer/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            # Header names are normalized to lowercase so checks are case-proof.
            headers = {str(key).lower(): value for key, value in resp.headers.items()}
            return {"status": resp.status, "headers": headers,
                    "body": resp.read(2000).decode("utf-8", "replace")}
    except urllib.error.HTTPError as exc:
        headers = {str(key).lower(): value for key, value in exc.headers.items()}
        return {"status": exc.code, "headers": headers,
                "body": exc.read(2000).decode("utf-8", "replace")}
    except Exception as exc:  # noqa: BLE001
        return {"status": 0, "error": str(exc)}


def walk_strings(value, sink: list[str]) -> None:
    """Collect every string in a nested JSON structure."""
    if isinstance(value, dict):
        for item in value.values():
            walk_strings(item, sink)
    elif isinstance(value, list):
        for item in value:
            walk_strings(item, sink)
    elif isinstance(value, str):
        sink.append(value)


def claim_urls(scan: dict, port: int) -> list[str]:
    """URLs the scan points at the lab target (its own claims, not ours)."""
    strings: list[str] = []
    walk_strings(scan, strings)
    claims: list[str] = []
    for text in strings:
        for token in text.split():
            if token.startswith("http://127.0.0.1:"):
                claims.append(token.strip("'\",)]}"))
    return claims


def audit_request_claims(scan: dict, observed: list[dict], target: str) -> dict:
    """Compare structured HTTP claims only; a URL mention is not a request.

    Matching method, path and exact query establishes request presence only.
    The lab log cannot establish request body or response-content equality.
    """
    origin = urllib.parse.urlsplit(target)
    claims = set()

    def visit(value):
        if isinstance(value, dict):
            method = value.get("method")
            url = value.get("url") or value.get("endpoint") or value.get("target_url")
            if isinstance(method, str) and method.strip() and isinstance(url, str):
                try:
                    parsed = urllib.parse.urlsplit(url)
                    if (parsed.scheme, parsed.hostname, parsed.port) == (origin.scheme, origin.hostname, origin.port):
                        claims.add((method.upper(), parsed.path or "/", parsed.query))
                except ValueError:
                    pass
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(scan)
    received = {(str(row.get("method", "")).upper(), row.get("path", "/"), row.get("query", ""))
                for row in observed}
    return {"claim_count": len(claims), "missing": sorted(claims - received)}


# --------------------------------------------------------------------------
# lab lifecycle
# --------------------------------------------------------------------------

class Lab:
    def __init__(self, port: int, log_path: str, extra_args: list[str] | None = None):
        self.port = port
        self.log_path = log_path
        self.extra_args = list(extra_args or [])
        self.proc: subprocess.Popen | None = None

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self) -> None:
        self.proc = subprocess.Popen(
            [sys.executable, LAB_SERVER, "--port", str(self.port), "--log", self.log_path] + self.extra_args,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        deadline = time.time() + 10
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError("lab server exited during startup")
            if http_get(f"{self.base_url}/api/v1/health")["status"] == 200:
                return
            time.sleep(0.15)
        raise RuntimeError("lab server did not become healthy in time")

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)

    def observed_requests(self) -> list[dict]:
        if not os.path.exists(self.log_path):
            return []
        rows = []
        with open(self.log_path, encoding="utf-8") as handle:
            for line in handle:
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return rows


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="Observation test for redteam_agent on the hardened lab")
    parser.add_argument("--preset", default="lab_hardened",
                        help="Scan preset (default: lab_hardened = offline & fully attributable)")
    parser.add_argument("--traffic", default="FAST", choices=["STEALTH", "NORMAL", "FAST"])
    parser.add_argument("--max-requests", type=int, default=800)
    parser.add_argument("--port", type=int, default=0, help="Lab port (0 = pick free)")
    parser.add_argument("--outdir", default=DEFAULT_OUT)
    parser.add_argument("--demo", action="store_true",
                        help="Start the lab with the deliberately leaky /api/v1/parse endpoint "
                             "and expect probe_error_disclosure to VERIFY it.")
    parser.add_argument("--offensive-fixture", action="store_true",
                        help="Start the isolated positive offensive fixture and expect real VERIFIED findings.")
    args = parser.parse_args()

    port = args.port or pick_free_port()
    run_id = time.strftime("run-%Y%m%d-%H%M%S") + f"-{time.time_ns() % 1_000_000_000:09d}"
    out_dir = os.path.join(args.outdir, run_id)
    os.makedirs(out_dir, exist_ok=True)
    log_path = os.path.join(out_dir, "lab_access.jsonl")
    scan_path = os.path.join(out_dir, "scan_results.json")
    summary_path = os.path.join(out_dir, "summary.txt")

    target = f"http://127.0.0.1:{port}"
    fixture_args = []
    if args.demo:
        fixture_args.append("--demo")
    if args.offensive_fixture:
        fixture_args.append("--offensive-fixture")
    lab = Lab(port, log_path, extra_args=fixture_args)

    lines: list[str] = []

    def note(text: str = "") -> None:
        lines.append(text)
        print(text)

    try:
        # 1) start lab
        if args.offensive_fixture:
            lab_label = "OFFENSIVE POSITIVE FIXTURE"
        elif args.demo:
            lab_label = "DEMO (leaky parse endpoint)"
        else:
            lab_label = "hardened"
        note(f"🛡  Starting {lab_label} lab at {target}  (log: {log_path})")
        lab.start()

        # 2) self-audit the control target before scanning
        note("\n--- Lab control self-audit (must all pass) ---")
        checks = []
        root = http_get(target + "/")
        checks.append(("landing page returns 200 HTML", root["status"] == 200
                       and "text/html" in root["headers"].get("content-type", "")))
        checks.append(("CSP present", "content-security-policy" in root["headers"]))
        checks.append(("X-Frame-Options DENY", root["headers"].get("x-frame-options", "").upper() == "DENY"))
        checks.append(("nosniff present", root["headers"].get("x-content-type-options", "").lower() == "nosniff"))
        checks.append(("no CORS header (no ACAO)", "access-control-allow-origin" not in root["headers"]))
        for probe in ["/.env", "/.git/HEAD", "/db.sql", "/phpmyadmin/", "/graphql",
                      "/api/v1/admin/users", "/backup/database.sql.gz"]:
            resp = http_get(target + probe)
            checks.append((f"uniform 404 on {probe}", resp["status"] == 404))
        if args.demo:
            parse = http_get(target + "/api/v1/parse")
            checks.append(("demo /api/v1/parse exists (GET 200)", parse["status"] == 200))
            req = urllib.request.Request(target + "/api/v1/parse",
                                         data=b'{"q":',
                                         headers={"Content-Type": "application/json"}, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=3) as resp:
                    leak_body = resp.read(3000).decode("utf-8", "replace")
                    leak_status = resp.status
            except urllib.error.HTTPError as exc:
                leak_body = exc.read(3000).decode("utf-8", "replace")
                leak_status = exc.code
            checks.append(("demo parse leaks stack trace (500 + Traceback marker)",
                           leak_status == 500 and "Traceback (most recent call last)" in leak_body))
        for label, passed in checks:
            note(f"   [{'PASS' if passed else 'FAIL'}] {label}")
        control_ok = all(passed for _, passed in checks)
        if not control_ok:
            note("   Lab control failed — aborting before scan.")

        # 3) run the scan
        if control_ok:
            note("\n--- Running redteam_agent scan (lab_hardened, allow-private) ---")
            cmd = [sys.executable, "-m", "redteam_agent.cli",
                   "--url", target, "--preset", args.preset, "--allow-private",
                   "--traffic", args.traffic, "--max-requests", str(args.max_requests), "--json"]
            if args.offensive_fixture:
                cmd.append("--offensive")
                # Engagement record is generated per-run into the ignored output
                # dir; the committed repo keeps tools only, no engagement data.
                lab_engagement = os.path.join(out_dir, "engagement_lab.json")
                with open(lab_engagement, "w", encoding="utf-8") as fh:
                    json.dump({
                        "engagement_id": "LAB-2026-001",
                        "authorization_reference": "LOCAL-LAB-ROE-2026-001",
                        "allowed_targets": ["127.0.0.1", "localhost"],
                        "expires_at": "2026-12-31T23:59:59+08:00",
                        "prohibited_techniques": ["denial-of-service", "social-engineering", "destructive-write"],
                        "allowed_techniques": ["idor", "bola", "sqli", "xss", "ssrf", "auth-bypass",
                                               "authorization", "ssti", "open-redirect", "graphql",
                                               "cloud-baas", "command-injection", "cache-poisoning", "dom-xss"],
                        "objective": "Prove unauthorized confidentiality or integrity impact with non-destructive "
                                     "evidence on the local hardened lab and its deliberately vulnerable fixtures.",
                        "emergency_contact": "Local lab operator; no personal contact data stored.",
                        "notes": ["Local loopback lab only. Stop immediately on service instability."],
                    }, fh, indent=2)
                cmd += ["--engagement-file", lab_engagement]
                cmd += ["--vuln-class", "xss", "--vuln-class", "ssti", "--vuln-class", "graphql",
                        "--vuln-class", "open-redirect", "--vuln-class", "sqli"]
            try:
                proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=900)
            except subprocess.TimeoutExpired:
                note("   Scan subprocess timed out (900s). Aborting.")
                lab.stop()
                return 2
            if proc.returncode != 0:
                note(f"   CLI exited rc={proc.returncode}")
                note((proc.stderr or "")[-1500:])
                lab.stop()
                return 2
            scan = json.loads(proc.stdout)
            with open(scan_path, "w", encoding="utf-8") as handle:
                json.dump(scan, handle, indent=2, default=str)
            note(f"   Scan finished. Full JSON saved to {scan_path}")

        # 4) stop lab and analyze
        lab.stop()

        if control_ok:
            stats = scan.get("stats", {})
            db = scan.get("db_hunter", {}) or {}
            fp = scan.get("fp_kill_summary", {}) or {}
            quarantined = scan.get("quarantined_findings", []) or []
            vrt = scan.get("vrt_summary", {}) or {}

            expectation = "positive VERIFIED primitives expected" if args.offensive_fixture else "all zero except totals"
            note(f"\n--- Scan summary (honest expectation: {expectation}) ---")
            note(f"   candidates (findings):   {len(scan.get('findings', []))}")
            note(f"   VERIFIED vulnerabilities: {len(scan.get('vulnerabilities', []))}")
            note(f"   quarantined (FP kill):   {len(quarantined)}")
            note(f"   vrt triage:              {vrt}")
            note(f"   db connection strings:   {db.get('total_connection_strings', 0)}")
            note(f"   db exposed ports:        {db.get('total_exposed_ports', 0)}")
            note(f"   db admin panels:         {db.get('total_admin_panels', 0)}")
            note(f"   db backup files:         {db.get('total_backup_files', 0)}")
            note(f"   hidden db strings:       {db.get('total_hidden_db_strings', 0)}")
            note(f"   js secrets:              {stats.get('secrets_found', 0)}")
            note(f"   js grep matches:         {stats.get('js_grep_matches', 0)}")
            note(f"   waf bypass proven:       {len(scan.get('waf_bypass_findings', []))}")
            note(f"   tool runs (external):    {[(t.get('tool'), t.get('status')) for t in scan.get('tool_runs', [])]}")
            coverage = scan.get("exploit_coverage", []) or []
            if coverage:
                gated = [c for c in coverage if c.get("kind") == "auth_gated"]
                json_api = [c for c in coverage if c.get("post_json_api")]
                note(f"   exploit coverage:        {len(coverage)} endpoint(s) preflighted "
                     f"| {len(gated)} auth-gated | {len(json_api)} JSON-body injected")
                for c in gated:
                    note(f"      AUTH-GATED (deep probes skipped, needs creds): {c.get('endpoint')} "
                         f"(GET {c.get('get_status')})")
                for c in json_api:
                    note(f"      JSON-body probes ran: {c.get('endpoint')} -> {', '.join(c.get('probes', []))}")
            if quarantined:
                note("   Quarantined items (honest, non-submission):")
                for q in quarantined[:5]:
                    note(f"      - {q.get('type')} {q.get('endpoint', '')} -> {q.get('fp_kill', {}).get('reasons', [])}")

            # 5) integrity cross-check: every evidence claim must exist in the lab log
            note("\n--- Integrity cross-check (claims vs lab access log) ---")
            observed = lab.observed_requests()
            observed_paths = {row["method"]: Counter() for row in observed}
            get_paths: Counter[str] = Counter()
            for row in observed:
                get_paths[row["path"]] += 1
                observed_paths.setdefault(row["method"], Counter())[row["path"]] += 1
            note(f"   total HTTP requests the lab received: {len(observed)}")
            note(f"   unique paths requested:              {len(get_paths)}")

            audit = audit_request_claims(scan, observed, target)
            missing = audit["missing"]
            if missing:
                note("   ⚠  CLAIMED BUT NEVER REQUESTED (method/path/query mismatch):")
                for method, path, query in missing:
                    note(f"      - {method} {path}{'?' + query if query else ''}")
            elif not audit["claim_count"]:
                note("   Unknown — no structured local HTTP request claims were recorded.")
            else:
                note("   ✅ structured local HTTP claims match method/path/query in the log")
            note("   URL mentions alone are not request claims; body/response equality is not checked.")

            # verdict
            verified_vulns = scan.get("vulnerabilities", []) or []
            no_verified = (len(verified_vulns) == 0
                           and not any(f.get("status") == "VERIFIED" for f in scan.get("findings", [])))
            no_findings = len(scan.get("findings", [])) == 0
            clean = control_ok and no_verified and not missing
            if args.offensive_fixture:
                # Positive fixture expectation: at least one target-specific
                # primitive must survive the FP gate, and every structured
                # request claim must still be backed by the access log.
                verified = [f for f in verified_vulns if f.get("status") == "VERIFIED"]
                types = {str(f.get("type") or "").lower() for f in verified}
                expected = {
                    "context-specific reflected xss": any("xss" in item for item in types),
                    "ssti": any("template injection" in item or "ssti" in item for item in types),
                    "graphql": any("graphql" in item for item in types),
                    "open redirect": any("redirect" in item for item in types),
                }
                deep = scan.get("deep_exploit", {}) or {}
                primitives = deep.get("primitives", []) or []
                passed = bool(verified) and bool(primitives) and not missing
                note("\n--- Offensive fixture assertion ---")
                note(f"   verified findings retained: {len(verified)}")
                note(f"   verified primitive records:  {len(primitives)}")
                note(f"   target-specific hypotheses:  {len(deep.get('plan', []) or [])}")
                note(f"   category coverage:            {expected}")
                if passed:
                    note("\n✅ VERDICT: DETECTED (offensive fixture) — real target-specific findings survived FP-KILL and matched the lab access log:")
                    for finding in verified:
                        note(f"   • {finding.get('type')} @ {finding.get('endpoint')}")
                else:
                    note("\n⚠  VERDICT: FAIL (offensive fixture) — the deliberately vulnerable local surfaces did not produce a backed VERIFIED finding.")
            elif args.demo:
                # Expectation: the deliberate stack-trace leak is DETECTED and
                # VERIFIED by probe_error_disclosure — proven by a real request.
                detected = [f for f in verified_vulns
                            if "stack-trace" in (f.get("type") or "").lower()
                            or "disclosure" in (f.get("type") or "").lower()]
                success = bool(detected) and not missing
                if success:
                    note("\n✅ VERDICT: DETECTED (demo) — probe_error_disclosure benar-benar "
                         "VERIFIED stack-trace leak di endpoint demo:")
                    for f in detected:
                        note(f"   • {f.get('type')} @ {f.get('endpoint')} (CVSS {f.get('cvss_score')})")
                    note("   Structured request claims checked against access log; response content not validated here.")
                else:
                    note("\n⚠  VERDICT: FAIL (demo) — leak yang disengaja TIDAK terdeteksi "
                         "atau klaimnya tidak terbukti. Lihat summary.txt.")
            elif clean and no_findings:
                note("\n✅ VERDICT: CLEAN — no findings at all on the hardened target, "
                     "and no structured request mismatches detected.")
            elif clean:
                note("\n✅ VERDICT: CLEAN — zero VERIFIED vulnerabilities; non-verified "
                     "candidates were not escalated; no structured request mismatches detected.")
            else:
                note("\n⚠  VERDICT: INVESTIGATE — see findings/quarantine above.")
            if not args.demo and coverage and any(c.get("kind") == "auth_gated" for c in coverage):
                note("\n📌 Coverage note: endpoint(s) di balik auth (401/403) tidak dites dalam — "
                     "0 finding berlaku untuk permukaan publik saja. Sediakan kredensial "
                     "untuk cakupan penuh (lihat summary.txt).")
            note(f"\nArtifacts: {out_dir}")
            if args.offensive_fixture:
                return 0 if passed else 1
            return 0 if (success if args.demo else clean) else 1
        else:
            note("\nControl self-audit failed; no scan ran. The lab is not behaving as hardened.")
            return 1
        return 0
    finally:
        try:
            lab.stop()
        finally:
            with open(summary_path, "w", encoding="utf-8") as handle:
                handle.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
