"""Read-only official reference clients for hypothesis selection.

These clients retrieve metadata only. They do not download exploit code, run
PoCs, or send reference payloads to a target. The caller supplies a shared
HTTPVerifier so all reference requests inherit the task traffic controller,
TLS policy, and an allowlisted reference scope.
"""

from __future__ import annotations

import json
import urllib.parse
from typing import Any, Dict, Iterable, Optional

from redteam_agent.core.http_verifier import HTTPVerifier
from redteam_agent.core.scope_manager import ScopeManager


REFERENCE_HOSTS = [
    "services.nvd.nist.gov", "nvd.nist.gov", "www.cisa.gov", "api.github.com",
    "github.com", "portswigger.net", "bughunters.google.com", "www.hackerone.com",
    "www.bugcrowd.com",
]


class ReferenceIntelClient:
    """Fetch structured advisory metadata from explicitly allowlisted sources."""

    def __init__(self, verifier: Optional[HTTPVerifier] = None):
        self.verifier = verifier or HTTPVerifier(
            timeout=8.0,
            scope_manager=ScopeManager(REFERENCE_HOSTS, resolve_dns=True),
            module="reference_intel",
        )

    @staticmethod
    def _json(response: Dict[str, Any]) -> Any:
        try:
            return json.loads(str(response.get("body", "") or ""))
        except (TypeError, ValueError, json.JSONDecodeError):
            return None

    @staticmethod
    def _failure(response: Dict[str, Any], source: str, url: str) -> Dict[str, Any]:
        return {"source": source, "url": url, "status": "NOT_FETCHED",
                "http_status": response.get("status_code", 0),
                "reason": str(response.get("error") or response.get("failure") or "reference request failed")[:300],
                "read_only": True, "automatic_exploit_execution": False}

    def nvd_keyword(self, keyword: str, *, limit: int = 10) -> Dict[str, Any]:
        query = str(keyword or "").strip()
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode({
            "keywordSearch": query, "resultsPerPage": max(1, min(20, int(limit))),
        })
        response = self.verifier.send_http_request(url, headers={"Accept": "application/json"},
                                                   priority="normal")
        data = self._json(response)
        if not isinstance(data, dict):
            return self._failure(response, "NVD", url)
        records = []
        for item in (data.get("vulnerabilities") or [])[:max(0, int(limit))]:
            cve = item.get("cve") if isinstance(item, dict) else {}
            if not isinstance(cve, dict):
                continue
            descriptions = cve.get("descriptions") or []
            description = next((row.get("value") for row in descriptions
                                if isinstance(row, dict) and row.get("lang") == "en"), "")
            records.append({
                "source": "NVD", "cve_id": cve.get("id"),
                "published": cve.get("published"), "last_modified": cve.get("lastModified"),
                "description": str(description)[:1000],
                "references": [row.get("url") for row in (cve.get("references") or [])
                               if isinstance(row, dict) and row.get("url")][:10],
                "read_only": True, "hypothesis_only": True,
                "automatic_exploit_execution": False,
            })
        return {"source": "NVD", "status": "FETCHED", "query": query,
                "total_results": data.get("totalResults", len(records)), "records": records,
                "read_only": True, "automatic_exploit_execution": False}

    def cisa_kev(self, keyword: str = "", *, limit: int = 20) -> Dict[str, Any]:
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        response = self.verifier.send_http_request(url, headers={"Accept": "application/json"},
                                                   priority="normal")
        data = self._json(response)
        if not isinstance(data, dict):
            return self._failure(response, "CISA KEV", url)
        needle = str(keyword or "").lower().strip()
        records = []
        for item in data.get("vulnerabilities", []) or []:
            if not isinstance(item, dict):
                continue
            haystack = json.dumps(item, default=str).lower()
            if needle and needle not in haystack:
                continue
            records.append({
                "source": "CISA KEV", "cve_id": item.get("cveID"),
                "vendor_project": item.get("vendorProject"), "product": item.get("product"),
                "vulnerability_name": item.get("vulnerabilityName"),
                "date_added": item.get("dateAdded"), "due_date": item.get("dueDate"),
                "short_description": item.get("shortDescription"),
                "required_action": item.get("requiredAction"),
                "known_ransomware_use": item.get("knownRansomwareCampaignUse"),
                "read_only": True, "hypothesis_only": True,
                "automatic_exploit_execution": False,
            })
            if len(records) >= max(0, int(limit)):
                break
        return {"source": "CISA KEV", "status": "FETCHED", "query": keyword,
                "records": records, "catalog_version": data.get("catalogVersion"),
                "read_only": True, "automatic_exploit_execution": False}

    def github_advisory(self, ghsa_or_cve: str) -> Dict[str, Any]:
        identifier = str(ghsa_or_cve or "").strip()
        if not identifier or not (identifier.upper().startswith("GHSA-") or identifier.upper().startswith("CVE-")):
            return {"source": "GitHub Advisory Database", "status": "REJECTED",
                    "reason": "identifier must be GHSA-* or CVE-*", "read_only": True}
        url = "https://api.github.com/advisories/" + urllib.parse.quote(identifier, safe="-")
        response = self.verifier.send_http_request(url, headers={"Accept": "application/vnd.github+json"},
                                                   priority="normal")
        data = self._json(response)
        if not isinstance(data, dict):
            return self._failure(response, "GitHub Advisory Database", url)
        return {
            "source": "GitHub Advisory Database", "status": "FETCHED", "url": url,
            "ghsa_id": data.get("ghsa_id"), "cve_id": data.get("cve_id"),
            "summary": data.get("summary"), "description": str(data.get("description") or "")[:1200],
            "severity": data.get("severity"), "published_at": data.get("published_at"),
            "updated_at": data.get("updated_at"), "withdrawn_at": data.get("withdrawn_at"),
            "cvss": data.get("cvss"), "cwes": data.get("cwes"),
            "vulnerabilities": data.get("vulnerabilities", []),
            "references": data.get("references", []),
            "read_only": True, "hypothesis_only": True,
            "automatic_exploit_execution": False,
        }

    def enrich(self, component: str, vulnerability_class: str = "", *, limit: int = 10) -> Dict[str, Any]:
        """Fetch NVD/CISA metadata for an explicit operator-selected component."""
        query = " ".join(item for item in (str(component).strip(), str(vulnerability_class).strip()) if item)
        return {"component": component, "vulnerability_class": vulnerability_class,
                "nvd": self.nvd_keyword(query, limit=limit),
                "cisa_kev": self.cisa_kev(component, limit=limit),
                "read_only": True, "hypothesis_only": True,
                "automatic_exploit_execution": False}


__all__ = ["REFERENCE_HOSTS", "ReferenceIntelClient"]
