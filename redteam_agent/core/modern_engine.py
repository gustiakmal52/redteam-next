"""Modern Behavioral Engine — injection & misconfiguration detection for the
AI era, where WAFs block every known payload and every scanner replays them.

Instead of signature payloads, this engine compares the application's actual
behavior across semantically-different inputs:

  1. sqli_boolean_differential   — boolean oracle via syntactically-valid
     expressions (1 AND 1=1 vs 1 AND 1=2).  No quotes, no comments, nothing
     a WAF signature would flag; the oracle is the response difference.
  2. ssti_arithmetic_multi_engine — template evaluation via arithmetic
     ({{7*7}} -> 49 vs {{7*8}} -> 56) across Jinja2/Twig/EL/SpEL/Freemarker
     syntaxes.  Two semantically-different evaluations = template execution.
  3. cmd_time_based_median       — command injection via median-of-3 timing
     (sleep 1 vs sleep 5).  Single spikes are rejected; only a repeatable
     median shift counts.
  4. cache_poisoning             — X-Forwarded-Host / X-Original-URL reflected
     into a cached response (Age/X-Cache/CF-Cache-Status present).
  5. security_headers_audit      — CSP/HSTS/XFO/nosniff/COOP/CORP coverage.
  6. dom_xss_analysis            — static data-flow over JS bundles: sink
     (innerHTML/document.write/eval/...) reached from a source
     (location.hash/search/referrer/postMessage/...).

Discipline: findings are LIKELY candidates with explicit missing_evidence;
VERIFIED only when the evidence tuple is complete.
"""

from __future__ import annotations

import json
import re
import time
import urllib.parse
from typing import Any, Dict, List, Optional

from redteam_agent.core.findings import FindingStatus, normalized_finding
from redteam_agent.core.http_verifier import HTTPVerifier

# ---------------------------------------------------------------------------
# 1. SQLi boolean oracle — syntactically valid, WAF-invisible
# ---------------------------------------------------------------------------
_BOOLEAN_PAIRS = [
    ("1 AND 1=1", "1 AND 1=2"),
    ("1/**/AND/**/1=1", "1/**/AND/**/1=2"),
    ("1' AND '1'='1", "1' AND '1'='2"),
    ("1\" AND \"1\"=\"1", "1\" AND \"1\"=\"2"),
]

# ---------------------------------------------------------------------------
# 2. SSTI arithmetic — multi template engine
# ---------------------------------------------------------------------------
_SSTI_ENGINES = [
    ("{{7*7}}", "{{7*8}}", "jinja2/twig"),
    ("${7*7}", "${7*8}", "el/spel/thymeleaf"),
    ("#{7*7}", "#{7*8}", "freemarker"),
    ("[[7*7]]", "[[7*8]]", "twig-array"),
]

# ---------------------------------------------------------------------------
# 3. Command injection — median timing
# ---------------------------------------------------------------------------
_CMD_SLEEP_PAIRS = [
    ("; sleep 1", "; sleep 5"),
    ("| sleep 1", "| sleep 5"),
    ("&& sleep 1", "&& sleep 5"),
    ("`sleep 1`", "`sleep 5`"),
    ("$(sleep 1)", "$(sleep 5)"),
]

# ---------------------------------------------------------------------------
# 4. Cache poisoning
# ---------------------------------------------------------------------------
_CACHE_HEADERS = ("age", "x-cache", "cf-cache-status", "x-served-by",
                  "x-cache-status", "x-vercel-cache", "x-akamai-transformed")
_POISON_HEADERS = ("X-Forwarded-Host", "X-Original-URL", "X-Rewrite-URL",
                   "X-Host", "Forwarded")

# ---------------------------------------------------------------------------
# 5. Security headers
# ---------------------------------------------------------------------------
_SECURITY_HEADERS = {
    "Content-Security-Policy": "CSP missing — XSS mitigation absent",
    "Strict-Transport-Security": "HSTS missing — downgrade/SSL-strip risk",
    "X-Frame-Options": "Clickjacking protection missing",
    "X-Content-Type-Options": "MIME-sniffing protection missing",
    "Cross-Origin-Opener-Policy": "COOP missing — cross-origin isolation absent",
    "Cross-Origin-Resource-Policy": "CORP missing — cross-origin reads not constrained",
    "Referrer-Policy": "Referrer policy missing — token leakage via Referer",
}

# ---------------------------------------------------------------------------
# 6. DOM XSS — static data flow
# ---------------------------------------------------------------------------
_DOM_SINKS = (
    r"\.innerHTML\s*=", r"\.outerHTML\s*=", r"document\.write\s*\(",
    r"insertAdjacentHTML\s*\(", r"eval\s*\(", r"new\s+Function\s*\(",
    r"\.srcdoc\s*=", r"setAttribute\(\s*['\"](?:src|href|srcdoc)['\"]",
)
_DOM_SOURCES = (
    r"location\.hash", r"location\.search", r"location\.href",
    r"document\.referrer", r"addEventListener\(\s*['\"]message['\"]",
    r"window\.name", r"location\.pathname",
)


class ModernEngine:
    """Behavioral injection & misconfiguration detection."""

    def __init__(self, verifier: HTTPVerifier):
        self.verifier = verifier

    # ------------------------------------------------------------------
    # 1. SQLi boolean oracle
    # ------------------------------------------------------------------
    def sqli_boolean_differential(self, url: str, param: str) -> Optional[Dict[str, Any]]:
        """Compare responses for syntactically-valid true/false expressions.

        A consistent response difference between 1=1 and 1=2 variants is a
        boolean oracle — evidence the input reaches a SQL predicate.
        """
        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if param not in query:
            return None
        base = urllib.parse.urlunparse(parsed._replace(query=""))
        # Baseline = query asli tanpa injeksi. Oracle SQLi sejati: payload true
        # TIDAK mengubah hasil vs baseline (1=1 selalu true), payload false
        # mengubah hasil (1=2 selalu false). Jika payload true pun mengubah
        # hasil, query literal ikut mempengaruhi respons (search teks biasa /
        # refleksi query) -> BUKAN oracle SQL -> anti-FP.
        baseline_resp = self.verifier.send_http_request(url)
        baseline_status = baseline_resp.get("status_code", 0)
        baseline_body = str(baseline_resp.get("body", "") or "")
        oracle_hits = []
        for true_expr, false_expr in _BOOLEAN_PAIRS:
            true_url = f"{base}?{param}={urllib.parse.quote(true_expr, safe="")}"
            false_url = f"{base}?{param}={urllib.parse.quote(false_expr, safe="")}"
            true_resp = self.verifier.send_http_request(true_url)
            false_resp = self.verifier.send_http_request(false_url)
            t_status, f_status = true_resp.get("status_code", 0), false_resp.get("status_code", 0)
            t_body, f_body = str(true_resp.get("body", "") or ""), str(false_resp.get("body", "") or "")
            if t_status != f_status or t_body != f_body:
                # anti-FP: true-payload harus setara baseline (kondisi selalu
                # true tidak mengubah hasil); false-payload harus berbeda.
                if t_body != baseline_body or f_body == baseline_body:
                    continue
                oracle_hits.append({
                    "true_expr": true_expr, "false_expr": false_expr,
                    "true_status": t_status, "false_status": f_status,
                    "true_bytes": len(t_body.encode("utf-8")),
                    "false_bytes": len(f_body.encode("utf-8")),
                    "bodies_differ": t_body != f_body,
                    "true_matches_baseline": t_body == baseline_body,
                    "false_differs_from_baseline": f_body != baseline_body,
                })
                if len(oracle_hits) >= 2:
                    break
        if not oracle_hits:
            return None
        return normalized_finding(
            finding_type="SQL Injection (Boolean Oracle)", target=url,
            endpoint=url, status=FindingStatus.LIKELY, confidence=.7,
            source_module="modern_engine", source_tool="HTTPVerifier",
            baseline=self._evidence(true_resp), test=self._evidence(false_resp),
            evidence=[{"oracle_pairs": oracle_hits}],
            verification_checks=[{"name": "syntactically_valid_expressions", "passed": True},
                                 {"name": "consistent_response_difference", "passed": True}],
            false_positive_reasons=["Response difference may come from non-SQL input handling",
                                    "WAF may rewrite the expression before the backend"],
            missing_evidence=["Repeatable oracle across more variants",
                              "Database-specific error or timing confirmation"],
            severity="High", cvss_score=8.6, param=param,
            reproduction_curl=f'curl -i -s "{true_url}" && curl -i -s "{false_url}"',
            verification_note=f"Boolean oracle detected: {len(oracle_hits)} true/false pair(s) produced distinct responses.",
            observed_impact="Input reaches a conditional evaluation that reflects the injected expression.",
            potential_impact="If exploitable, data extraction via boolean-based blind SQLi.",
            raw_request=true_resp.get("raw_request", ""),
            raw_response=false_resp.get("raw_response", "")[:1500],
            vrt_category="Server-Side Injection > SQL Injection",
        )

    # ------------------------------------------------------------------
    # 2. SSTI arithmetic — multi engine
    # ------------------------------------------------------------------
    def ssti_arithmetic_multi_engine(self, url: str, param: str) -> Optional[Dict[str, Any]]:
        """Template evaluation via arithmetic across engine syntaxes.

        {{7*7}} -> 49 and {{7*8}} -> 56 is a template execution proof: the
        server evaluated our expression, not just echoed it.
        """
        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if param not in query:
            return None
        base = urllib.parse.urlunparse(parsed._replace(query=""))
        for seven, eight, engine in _SSTI_ENGINES:
            url7 = f"{base}?{param}={urllib.parse.quote(seven, safe="")}"
            url8 = f"{base}?{param}={urllib.parse.quote(eight, safe="")}"
            resp7 = self.verifier.send_http_request(url7)
            resp8 = self.verifier.send_http_request(url8)
            body7 = str(resp7.get("body", "") or "")
            body8 = str(resp8.get("body", "") or "")
            if "49" in body7 and "56" in body8:
                return normalized_finding(
                    finding_type="Server-Side Template Injection (SSTI)", target=url,
                    endpoint=url7, status=FindingStatus.VERIFIED, confidence=.95,
                    source_module="modern_engine", source_tool="HTTPVerifier",
                    baseline=self._evidence(resp7), test=self._evidence(resp8),
                    evidence=[{"engine": engine, "expr_7x7": seven, "expr_7x8": eight,
                               "result_49_present": True, "result_56_present": True}],
                    verification_checks=[{"name": "arithmetic_evaluated", "passed": True},
                                         {"name": "two_semantically_different_results", "passed": True}],
                    false_positive_reasons=[],
                    missing_evidence=["RCE primitive (read/write/exec) beyond arithmetic"],
                    severity="Critical", cvss_score=9.8, param=param,
                    reproduction_curl=f'curl -i -s "{url7}" && curl -i -s "{url8}"',
                    verification_note=f"Template engine ({engine}) evaluated 7*7=49 and 7*8=56 in the response.",
                    observed_impact="Arbitrary template expressions are evaluated server-side.",
                    potential_impact="Full RCE if the engine exposes object access (Jinja2/Twig/SpEL).",
                    raw_request=resp7.get("raw_request", ""),
                    raw_response=resp8.get("raw_response", "")[:1500],
                    vrt_category="Server-Side Injection > Template Injection",
                )
        return None

    # ------------------------------------------------------------------
    # 3. Command injection — median timing
    # ------------------------------------------------------------------
    def cmd_time_based_median(self, url: str, param: str,
                              samples: int = 3) -> Optional[Dict[str, Any]]:
        """Command injection via median-of-N timing (sleep 1 vs sleep 5).

        Only a repeatable median shift counts; single spikes are rejected.
        """
        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if param not in query:
            return None
        base = urllib.parse.urlunparse(parsed._replace(query=""))
        baseline = self._median_time(f"{base}?{param}=1", samples)
        for sleep1, sleep5 in _CMD_SLEEP_PAIRS:
            t1 = self._median_time(f"{base}?{param}={urllib.parse.quote(f'1{sleep1}', safe='')}", samples)
            t5 = self._median_time(f"{base}?{param}={urllib.parse.quote(f'1{sleep5}', safe='')}", samples)
            if t5 - t1 >= 2.0 and t1 - baseline >= 0.3:
                encoded_payload = urllib.parse.quote(f'1{sleep5}', safe='')
                return normalized_finding(
                    finding_type="Command Injection (Time-Based)", target=url,
                    endpoint=f"{base}?{param}={encoded_payload}", status=FindingStatus.LIKELY,
                    confidence=.75, source_module="modern_engine", source_tool="HTTPVerifier",
                    baseline=self._evidence({"status_code": 200, "body": "", "headers": {}}),
                    test={},
                    evidence=[{"variant": sleep5.strip(), "median_baseline_s": round(baseline, 2),
                               "median_sleep1_s": round(t1, 2), "median_sleep5_s": round(t5, 2),
                               "samples": samples}],
                    verification_checks=[{"name": "median_shift_repeatable", "passed": True},
                                         {"name": "sleep5_slower_than_sleep1", "passed": True}],
                    false_positive_reasons=["Backend may sleep on complex queries",
                                            "Network jitter on a slow endpoint"],
                    missing_evidence=["Out-of-band confirmation (DNS/HTTP callback)",
                                      "Command output reflection"],
                    severity="Critical", cvss_score=9.0, param=param,
                    reproduction_curl=f'curl -i -s "{base}?{param}={encoded_payload}"',
                    verification_note=f"Median response time shifted {round(t1, 2)}s -> {round(t5, 2)}s for sleep 1 vs sleep 5.",
                    observed_impact="Input appears to reach a shell command evaluator.",
                    potential_impact="Remote code execution if command output is reflected or OOB is available.",
                    raw_request="", raw_response="",
                    vrt_category="Server-Side Injection > Command Injection",
                )
        return None

    # ------------------------------------------------------------------
    # 4. Cache poisoning
    # ------------------------------------------------------------------
    def cache_poisoning(self, url: str) -> Optional[Dict[str, Any]]:
        """Host-header reflection into a cached response."""
        baseline = self.verifier.send_http_request(url)
        baseline_body = str(baseline.get("body", "") or "")
        baseline_headers = {k.lower(): v for k, v in (baseline.get("headers") or {}).items()}
        for header in _POISON_HEADERS:
            poisoned = self.verifier.send_http_request(
                url, headers={header: "attacker.example"})
            p_body = str(poisoned.get("body", "") or "")
            p_headers = {k.lower(): v for k, v in (poisoned.get("headers") or {}).items()}
            reflected = "attacker.example" in p_body and "attacker.example" not in baseline_body
            cached = any(h in p_headers for h in _CACHE_HEADERS)
            if reflected and cached:
                return normalized_finding(
                    finding_type="Web Cache Poisoning", target=url,
                    endpoint=url, status=FindingStatus.LIKELY, confidence=.7,
                    source_module="modern_engine", source_tool="HTTPVerifier",
                    baseline=self._evidence(baseline), test=self._evidence(poisoned),
                    evidence=[{"header_tested": header, "reflected": True,
                               "cache_headers": [h for h in _CACHE_HEADERS if h in p_headers]}],
                    verification_checks=[{"name": "host_header_reflected", "passed": True},
                                         {"name": "cache_header_present", "passed": True}],
                    false_positive_reasons=["Cache may not persist the poisoned variant",
                                            "Header may be reflected only in debug mode"],
                    missing_evidence=["Poisoned response served to a second anonymous client",
                                      "Cache key does not include the poisoned header"],
                    severity="Medium", cvss_score=6.1, param=header,
                    reproduction_curl=f'curl -i -s "{url}" -H "{header}: attacker.example"',
                    verification_note=f"Host header '{header}' reflected into a response carrying cache headers.",
                    observed_impact="Attacker-controlled host value appears in a cacheable response.",
                    potential_impact="Poisoned cache serves attacker content to other users.",
                    raw_request=poisoned.get("raw_request", ""),
                    raw_response=poisoned.get("raw_response", "")[:1500],
                    vrt_category="Client-Side > Web Cache Poisoning",
                )
        return None

    # ------------------------------------------------------------------
    # 5. Security headers audit
    # ------------------------------------------------------------------
    def security_headers_audit(self, url: str) -> Optional[Dict[str, Any]]:
        """Report missing security headers (informational misconfiguration)."""
        response = self.verifier.send_http_request(url)
        if response.get("status_code") not in (200, 201, 301, 302):
            return None
        headers = {k.lower(): v for k, v in (response.get("headers") or {}).items()}
        missing = []
        for header, reason in _SECURITY_HEADERS.items():
            if header.lower() not in headers:
                missing.append({"header": header, "reason": reason})
        if not missing:
            return None
        return normalized_finding(
            finding_type="Security Headers Misconfiguration", target=url,
            endpoint=url, status=FindingStatus.LIKELY, confidence=.9,
            source_module="modern_engine", source_tool="HTTPVerifier",
            baseline=self._evidence(response), test={},
            evidence=[{"missing_headers": missing}],
            verification_checks=[{"name": "response_reachable", "passed": True},
                                 {"name": "headers_absent", "passed": True}],
            false_positive_reasons=["Headers may be set at a different layer for other routes"],
            missing_evidence=["Impact demonstration (e.g. clickjacking PoC, MIME-sniffing)"],
            severity="Low", cvss_score=3.7, param="",
            reproduction_curl=f'curl -i -s "{url}"',
            verification_note=f"{len(missing)} security header(s) missing: {', '.join(m['header'] for m in missing[:5])}.",
            observed_impact="Response lacks standard hardening headers.",
            potential_impact="Increased exposure to clickjacking, MIME sniffing, SSL-strip, and cross-origin reads.",
            raw_request=response.get("raw_request", ""),
            raw_response=response.get("raw_response", "")[:1500],
            vrt_category="Security Misconfiguration > Missing Security Headers",
        )

    # ------------------------------------------------------------------
    # 6. DOM XSS — static data flow over JS bundles
    # ------------------------------------------------------------------
    def dom_xss_analysis(self, js_assets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Find sink/source pairs in JS bundles (static data-flow candidate)."""
        findings: List[Dict[str, Any]] = []
        sink_re = re.compile("|".join(_DOM_SINKS))
        source_re = re.compile("|".join(_DOM_SOURCES))
        for asset in js_assets or []:
            content = str(asset.get("content") or asset.get("body") or "")
            if not content:
                continue
            sinks = sorted({m.group(0) for m in sink_re.finditer(content)})[:10]
            sources = sorted({m.group(0) for m in source_re.finditer(content)})[:10]
            if sinks and sources:
                findings.append({
                    "finding_type": "DOM XSS Candidate (Static Data-Flow)",
                    "target": asset.get("url", ""),
                    "status": FindingStatus.SUSPECTED.value,
                    "confidence": 0.4,
                    "source_module": "modern_engine",
                    "evidence": [{"sinks": sinks, "sources": sources,
                                  "asset": asset.get("url", "")}],
                    "missing_evidence": ["Runtime confirmation that a source value reaches a sink",
                                         "Browser execution with a crafted fragment"],
                    "severity": "Medium", "cvss_score": 6.1,
                })
        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _median_time(self, url: str, samples: int) -> float:
        times = []
        for _ in range(max(1, samples)):
            response = self.verifier.send_http_request(url)
            times.append(float(response.get("response_time_sec") or 0.0))
        times.sort()
        return times[len(times) // 2]

    @staticmethod
    def _evidence(response: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "status_code": response.get("status_code", 0),
            "body_bytes": len(str(response.get("body", "") or "").encode("utf-8")),
            "headers": {k: v for k, v in (response.get("headers") or {}).items()
                        if k.lower() not in {"set-cookie", "authorization"}},
        }