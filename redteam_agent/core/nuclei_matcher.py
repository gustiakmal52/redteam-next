"""Nuclei CVE template matcher — turns DISCOVERED tech matches into VERIFIED
exploit attempts using the bundled nuclei-templates reference.

Discipline (anti-halu):
- Templates are reference exploit signatures; running them against a target
  is an offensive action gated by engagement + scope + explicit flag.
- Matcher evaluation is deterministic (status / word / regex) — no guessing.
- Session auth is replayed only to the same netloc via the shared verifier.
- Templates requiring external interaction (interactsh callbacks) are skipped
  and reported as NOT_PROVEN, never as verified.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from redteam_agent.core.http_verifier import HTTPVerifier

DEFAULT_TEMPLATE_ROOT = os.environ.get(
    "REDTEAM_NUCLEI_TEMPLATES",
    "/home/utopia/.local/share/opencode/repos/github.com/projectdiscovery/nuclei-templates",
)

# Template variables that require external interaction or are unsafe to
# substitute locally; such templates are skipped honestly.
_EXTERNAL_MARKERS = ("interactsh", "{{callback}}", "{{oast}}", "{{url}}", "{{file}}")


class NucleiTemplate:
    """Parsed representation of a nuclei CVE template (http.raw subset)."""

    def __init__(self, raw: Dict[str, Any], source: str):
        self.source = source
        self.template_id = str(raw.get("id") or "")
        info = raw.get("info") or {}
        self.name = str(info.get("name") or self.template_id)
        self.severity = str(info.get("severity") or "unknown")
        classification = info.get("classification") or {}
        self.cve_id = str(classification.get("cve-id") or "").strip()
        self.cwe_id = str(classification.get("cwe-id") or "").strip()
        self.cvss_score = classification.get("cvss-score")
        self.epss_score = classification.get("epss-score")
        self.cpe = str(classification.get("cpe") or "")
        self.tags = str(info.get("tags") or "")
        self.variables = {str(k): str(v) for k, v in (raw.get("variables") or {}).items()}
        http = raw.get("http") or []
        self.requests: List[Dict[str, Any]] = []
        for block in http:
            if not isinstance(block, dict):
                continue
            raw_requests = block.get("raw") or []
            if not raw_requests:
                continue
            self.requests.append({
                "raw": [str(r) for r in raw_requests],
                "stop_at_first_match": bool(block.get("stop-at-first-match", False)),
                "matchers_condition": str(block.get("matchers-condition") or "or"),
                "matchers": block.get("matchers") or [],
            })

    @property
    def usable(self) -> bool:
        """True when the template has raw requests and no external markers."""
        if not self.requests:
            return False
        for block in self.requests:
            for raw in block["raw"]:
                if any(marker in raw for marker in _EXTERNAL_MARKERS):
                    return False
        return True

    def safe(self) -> Dict[str, Any]:
        return {
            "template_id": self.template_id, "name": self.name,
            "severity": self.severity, "cve_id": self.cve_id,
            "cwe_id": self.cwe_id, "cvss_score": self.cvss_score,
            "epss_score": self.epss_score, "cpe": self.cpe,
            "source": self.source, "usable": self.usable,
        }


def _parse_raw_request(raw: str, hostname: str, base_url: str,
                       variables: Dict[str, str]) -> Optional[Dict[str, Any]]:
    """Parse a nuclei raw HTTP request into method/path/headers/body.

    Placeholders substituted: {{Hostname}} -> netloc, {{BaseURL}} -> scheme://netloc,
    {{RootURL}} -> scheme://netloc, plus template variables (e.g. {{cmd}}).
    Returns None when the request cannot be parsed safely.
    """
    text = raw.replace("{{Hostname}}", hostname)
    text = text.replace("{{BaseURL}}", base_url)
    text = text.replace("{{RootURL}}", base_url)
    for key, value in variables.items():
        text = text.replace("{{" + key + "}}", value)
    lines = text.splitlines()
    if not lines:
        return None
    first = lines[0].strip()
    parts = first.split(" ")
    if len(parts) < 2:
        return None
    method, target = parts[0].upper(), parts[1]
    headers: Dict[str, str] = {}
    body_lines: List[str] = []
    in_body = False
    for line in lines[1:]:
        if in_body:
            body_lines.append(line)
            continue
        if line.strip() == "":
            in_body = True
            continue
        if ":" in line:
            key, _, value = line.partition(":")
            headers[key.strip()] = value.strip()
    body = "\n".join(body_lines).strip() or None
    return {"method": method, "target": target, "headers": headers, "body": body}


def _evaluate_matchers(matchers: List[Dict[str, Any]], condition: str,
                       body: str, status_code: int) -> bool:
    """Deterministic matcher evaluation (status / word / regex)."""
    if not matchers:
        return False
    results: List[bool] = []
    for matcher in matchers:
        mtype = str(matcher.get("type") or "")
        if mtype == "status":
            codes = [int(c) for c in (matcher.get("status") or []) if str(c).isdigit()]
            results.append(status_code in codes)
        elif mtype == "word":
            words = [str(w) for w in (matcher.get("words") or [])]
            if not words:
                results.append(False)
                continue
            if str(matcher.get("condition") or "or").lower() == "and":
                results.append(all(w in body for w in words))
            else:
                results.append(any(w in body for w in words))
        elif mtype == "regex":
            patterns = [str(p) for p in (matcher.get("regex") or [])]
            if not patterns:
                results.append(False)
                continue
            try:
                if str(matcher.get("condition") or "or").lower() == "and":
                    results.append(all(re.search(p, body) for p in patterns))
                else:
                    results.append(any(re.search(p, body) for p in patterns))
            except re.error:
                results.append(False)
        else:
            results.append(False)
    if str(condition).lower() == "and":
        return all(results)
    return any(results)


class NucleiTemplateMatcher:
    """Loads nuclei CVE templates and runs them through a scoped verifier."""

    def __init__(self, template_root: Optional[str] = None):
        self.template_root = Path(template_root or DEFAULT_TEMPLATE_ROOT)
        self.templates: List[NucleiTemplate] = []
        self._by_cve: Dict[str, List[NucleiTemplate]] = {}
        self.load_error: Optional[str] = None

    def load_templates(self) -> int:
        """Scan <root>/http/cves/**/*.yaml and parse usable templates."""
        cves_dir = self.template_root / "http" / "cves"
        if not cves_dir.is_dir():
            self.load_error = f"nuclei cves directory not found: {cves_dir}"
            return 0
        count = 0
        for path in sorted(cves_dir.rglob("*.yaml")):
            try:
                with path.open("r", encoding="utf-8") as handle:
                    data = yaml.safe_load(handle)
            except (OSError, yaml.YAMLError):
                continue
            if not isinstance(data, dict):
                continue
            template = NucleiTemplate(data, str(path))
            if not template.template_id:
                continue
            self.templates.append(template)
            if template.cve_id:
                self._by_cve.setdefault(template.cve_id.upper(), []).append(template)
            count += 1
        return count

    def find_by_cve(self, cve_id: str) -> List[NucleiTemplate]:
        return self._by_cve.get(str(cve_id or "").upper(), [])

    def find_by_keywords(self, keywords: List[str]) -> List[NucleiTemplate]:
        """Match templates by CVE id, tags, or CPE product keywords."""
        needles = [str(k).lower() for k in keywords if str(k).strip()]
        hits: List[NucleiTemplate] = []
        for template in self.templates:
            haystack = f"{template.cve_id} {template.tags} {template.cpe}".lower()
            if any(n in haystack for n in needles):
                hits.append(template)
        return hits

    def run_template(self, template: NucleiTemplate, base_url: str,
                     verifier: HTTPVerifier) -> Dict[str, Any]:
        """Execute a template's raw requests through the scoped verifier.

        Session auth is injected by the verifier itself (same-netloc only).
        Returns a deterministic verdict: VERIFIED only when a matcher passes.
        """
        parsed = _parse_url(base_url)
        if parsed is None:
            return {"template_id": template.template_id, "status": "REJECTED",
                    "reason": "invalid base URL"}
        hostname, scheme = parsed
        attempts: List[Dict[str, Any]] = []
        verified = False
        verified_matcher: Optional[Dict[str, Any]] = None
        for block in template.requests:
            for raw in block["raw"]:
                request = _parse_raw_request(raw, hostname, base_url,
                                             template.variables)
                if request is None:
                    attempts.append({"request": raw[:120], "status": "SKIPPED",
                                     "reason": "unparseable raw request"})
                    continue
                url = f"{scheme}://{hostname}{request['target']}"
                response = verifier.send_http_request(
                    url, method=request["method"], headers=request["headers"],
                    body=request["body"], priority="verification")
                status_code = response.get("status_code", 0)
                body = str(response.get("body", "") or "")
                attempts.append({
                    "method": request["method"], "target": request["target"],
                    "status_code": status_code,
                    "body_bytes": len(body.encode("utf-8")),
                    "matcher_pass": False,
                })
                if _evaluate_matchers(block["matchers"], block["matchers_condition"],
                                      body, status_code):
                    verified = True
                    verified_matcher = {
                        "condition": block["matchers_condition"],
                        "matchers": [m.get("type") for m in block["matchers"]],
                    }
                    attempts[-1]["matcher_pass"] = True
                    if block["stop_at_first_match"]:
                        break
            if verified and block["stop_at_first_match"]:
                break
        return {
            "template_id": template.template_id,
            "cve_id": template.cve_id,
            "name": template.name,
            "severity": template.severity,
            "cvss_score": template.cvss_score,
            "epss_score": template.epss_score,
            "status": "VERIFIED" if verified else "NOT_PROVEN",
            "verified_matcher": verified_matcher,
            "attempts": attempts,
            "source": template.source,
        }


def _parse_url(base_url: str) -> Optional[tuple]:
    import urllib.parse
    parsed = urllib.parse.urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return parsed.netloc, parsed.scheme