"""
CISA KEV & CVE/EPSS Live Threat Intelligence Engine.
Maps detected target tech stack, servers, and components to the official
CISA Known Exploited Vulnerabilities (KEV) Catalog and EPSS scoring system.
"""

import json
import os
from typing import List, Dict, Any, Optional
from redteam_agent.core.http_verifier import HTTPVerifier
from redteam_agent.core.scope_manager import ScopeManager

# Bundled offline high-priority CISA KEV & Web CVE dataset for instant matching
OFFLINE_CISA_KEV = [
    {
        "cve_id": "CVE-2023-46604",
        "vendor": "Apache",
        "product": "ActiveMQ",
        "vuln_name": "Apache ActiveMQ OpenWire Remote Code Execution",
        "date_added": "2023-11-02",
        "required_action": "Apply vendor mitigations",
        "epss_score": None,
        "cvss": 9.8,
        "keywords": ["activemq", "openwire"]
    },
    {
        "cve_id": "CVE-2024-3400",
        "vendor": "Palo Alto Networks",
        "product": "PAN-OS",
        "vuln_name": "PAN-OS GlobalProtect Command Injection Vulnerability",
        "date_added": "2024-04-12",
        "required_action": "Apply hotfix per vendor instructions",
        "epss_score": None,
        "cvss": 10.0,
        "keywords": ["globalprotect", "pan-os"]
    },
    {
        "cve_id": "CVE-2023-22515",
        "vendor": "Atlassian",
        "product": "Confluence Data Center and Server",
        "vuln_name": "Atlassian Confluence Broken Access Control Vulnerability",
        "date_added": "2023-10-05",
        "required_action": "Upgrade affected instances immediately",
        "epss_score": None,
        "cvss": 9.8,
        "keywords": ["confluence", "atlassian"]
    },
    {
        "cve_id": "CVE-2021-44228",
        "vendor": "Apache",
        "product": "Log4j",
        "vuln_name": "Apache Log4j2 JNDI Remote Code Execution (Log4Shell)",
        "date_added": "2021-12-10",
        "required_action": "Apply Log4j patch",
        "epss_score": None,
        "cvss": 10.0,
        "keywords": ["log4j", "log4shell"]
    },
    {
        "cve_id": "CVE-2022-22965",
        "vendor": "Spring",
        "product": "Spring Framework",
        "vuln_name": "Spring Framework Remote Code Execution (Spring4Shell)",
        "date_added": "2022-04-04",
        "required_action": "Upgrade Spring Framework",
        "epss_score": None,
        "cvss": 9.8,
        "keywords": ["spring", "spring-boot", "actuator"]
    },
    {
        "cve_id": "CVE-2023-49103",
        "vendor": "ownCloud",
        "product": "graphapi",
        "vuln_name": "ownCloud Information Disclosure Vulnerability (Environment Leak)",
        "date_added": "2023-11-28",
        "required_action": "Apply security updates",
        "epss_score": None,
        "cvss": 10.0,
        "keywords": ["owncloud", "graphapi"]
    },
    {
        "cve_id": "CVE-2024-27198",
        "vendor": "JetBrains",
        "product": "TeamCity",
        "vuln_name": "JetBrains TeamCity Authentication Bypass Vulnerability",
        "date_added": "2024-03-04",
        "required_action": "Upgrade TeamCity to 2023.11.4+",
        "epss_score": None,
        "cvss": 9.8,
        "keywords": ["teamcity", "jetbrains"]
    },
    {
        "cve_id": "CVE-2023-34362",
        "vendor": "Progress",
        "product": "MOVEit Transfer",
        "vuln_name": "MOVEit Transfer SQL Injection Vulnerability",
        "date_added": "2023-06-02",
        "required_action": "Apply security patch",
        "epss_score": None,
        "cvss": 9.8,
        "keywords": ["moveit"]
    },
    {
        "cve_id": "CVE-2023-48788",
        "vendor": "Fortinet",
        "product": "FortiClientEMS",
        "vuln_name": "Fortinet FortiClientEMS SQL Injection Vulnerability",
        "date_added": "2024-03-12",
        "required_action": "Apply security patch",
        "epss_score": None,
        "cvss": 9.8,
        "keywords": ["fortinet", "forticlient"]
    }
]

class ThreatIntelEngine:
    def __init__(self, verifier: Optional[HTTPVerifier] = None):
        self.cisa_catalog = OFFLINE_CISA_KEV.copy()
        self.verifier = verifier or HTTPVerifier(scope_manager=ScopeManager(["www.cisa.gov"]), module="threat_intel")
        self.last_fetch = {"status": "not_attempted", "verified": False}

    def fetch_live_cisa_kev(self) -> int:
        """Attempts to fetch the latest CISA KEV JSON catalog from cisa.gov."""
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        try:
            response = self.verifier.send_http_request(url, headers={"User-Agent": "Gustiakmal-RedTeam-ThreatIntel/2.1"}, priority="normal")
            if response.get("status_code") == 200:
                data = json.loads(response.get("body", ""))
                vulnerabilities = data.get("vulnerabilities", [])
                for v in vulnerabilities[:100]:  # Cache top entries
                    self.cisa_catalog.append({
                        "cve_id": v.get("cveID"),
                        "vendor": v.get("vendorProject"),
                        "product": v.get("product"),
                        "vuln_name": v.get("vulnerabilityName"),
                        "date_added": v.get("dateAdded"),
                        "required_action": v.get("requiredAction"),
                        "epss_score": None,
                        "cvss": None,
                        "source": "CISA_KEV_LIVE",
                        "keywords": [v.get("product", "").lower(), v.get("vendorProject", "").lower()]
                    })
                self.last_fetch = {"status": "success", "source": "CISA_KEV_LIVE", "verified": True,
                                   "records": len(vulnerabilities)}
                return len(self.cisa_catalog)
            self.last_fetch = response.get("failure") or {"status": "failed", "reason": f"HTTP {response.get('status_code')}", "verified": False}
        except Exception as exc:
            self.last_fetch = {"status": "failed", "reason": str(exc), "verified": False}
            return len(self.cisa_catalog)
        return len(self.cisa_catalog)

    def match_technologies(self, tech_list: List[str], server_banner: str = "") -> List[Dict[str, Any]]:
        """
        Matches detected technologies, libraries, and server headers against CISA KEV.
        """
        matches = []
        search_terms = [t.lower() for t in tech_list]
        if server_banner:
            search_terms.append(server_banner.lower())

        seen_cves = set()
        for item in self.cisa_catalog:
            if item["cve_id"] in seen_cves:
                continue
            for kw in item["keywords"]:
                if any(kw in term for term in search_terms):
                    seen_cves.add(item["cve_id"])
                    match = dict(item)
                    match["match_status"] = "DISCOVERED"
                    match["match_type"] = "TECHNOLOGY_KEYWORD_MATCH"
                    match["verified_affected_version"] = False
                    match.setdefault("source", "bundled_reference")
                    matches.append(match)
                    break
        return matches

    def get_cisa_threat_card(self, cve_id: str) -> Optional[Dict[str, Any]]:
        for item in self.cisa_catalog:
            if item["cve_id"].upper() == cve_id.upper():
                return item
        return None

    def verify_matches_with_nuclei(self, matches: List[Dict[str, Any]],
                                   base_url: str, verifier: HTTPVerifier,
                                   matcher=None) -> List[Dict[str, Any]]:
        """Upgrade DISCOVERED tech matches to VERIFIED via nuclei templates.

        For every match that has a usable nuclei template, the template is run
        through the shared (auth-capable) verifier.  A deterministic matcher
        pass promotes the match to VERIFIED with exploit evidence; otherwise
        the match stays DISCOVERED with an honest NOT_PROVEN note.
        """
        if matcher is None:
            from redteam_agent.core.nuclei_matcher import NucleiTemplateMatcher
            matcher = NucleiTemplateMatcher()
            if not matcher.templates:
                matcher.load_templates()
        if not matcher.templates:
            for match in matches:
                match["nuclei_verify"] = {"status": "NOT_RUN",
                                          "reason": "no nuclei templates loaded"}
            return matches
        for match in matches:
            cve_id = str(match.get("cve_id") or "").strip()
            templates = matcher.find_by_cve(cve_id) if cve_id else []
            if not templates:
                match["nuclei_verify"] = {"status": "NOT_RUN",
                                          "reason": "no template for this CVE"}
                continue
            usable = [t for t in templates if t.usable]
            if not usable:
                match["nuclei_verify"] = {"status": "NOT_RUN",
                                          "reason": "templates require external interaction"}
                continue
            result = matcher.run_template(usable[0], base_url, verifier)
            match["nuclei_verify"] = {
                "status": result["status"], "template_id": result["template_id"],
                "severity": result["severity"], "cvss_score": result["cvss_score"],
                "epss_score": result["epss_score"],
                "verified_matcher": result.get("verified_matcher"),
                "attempts": result.get("attempts", []),
            }
            if result["status"] == "VERIFIED":
                match["match_status"] = "VERIFIED"
                match["verified_affected_version"] = True
                match["match_type"] = "NUCLEI_EXPLOIT_VERIFIED"
                match["evidence"] = {
                    "template": result["template_id"],
                    "cve_id": cve_id,
                    "matcher": result.get("verified_matcher"),
                    "attempts": result.get("attempts", []),
                }
        return matches
