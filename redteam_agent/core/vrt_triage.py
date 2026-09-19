"""
VRT Triage Engine (Anti-N/A Engine)
Filters out out-of-scope, low-impact, and non-exploitable bug reports based on HackerOne & Bugcrowd VRT standards.
"""

from typing import Dict, Any, Tuple

# Blacklist keywords and triggers for low-impact / N/A findings
NA_PATTERNS = {
    "missing_headers": {
        "title": "Missing Security Headers (HSTS, X-Frame-Options, CSP, etc.)",
        "reason": "Missing HTTP security headers without a demonstrated active exploit vector are classified as N/A / Informational by Bugcrowd and HackerOne VRT.",
        "keywords": ["hsts", "x-frame-options", "content-security-policy", "x-content-type-options", "referrer-policy", "missing header"]
    },
    "self_xss": {
        "title": "Self-XSS / Non-Impactful XSS",
        "reason": "Cross-Site Scripting that only executes in the victim's own browser session without cross-user impact or privilege escalation is N/A.",
        "keywords": ["self-xss", "self xss", "console xss"]
    },
    "dmarc_spf": {
        "title": "Missing SPF / DMARC / DKIM Email Records",
        "reason": "Email spoofing configuration weaknesses without direct exploitation chain on the target application are out-of-scope / Informational.",
        "keywords": ["dmarc", "spf", "dkim", "email spoofing"]
    },
    "csrf_low": {
        "title": "CSRF on Logout / Login / Search / Non-Sensitive Forms",
        "reason": "Cross-Site Request Forgery on non-state-changing or low-impact endpoints (e.g., logout, search query) is classified as N/A.",
        "keywords": ["csrf logout", "csrf search", "csrf login", "logout csrf"]
    },
    "rate_limit_generic": {
        "title": "Generic Rate Limiting Missing",
        "reason": "Missing rate limit on login/forgot-password is N/A unless accompanied by a verified Account Takeover (ATO) proof.",
        "keywords": ["missing rate limit", "rate-limiting", "brute force login", "no rate limit"]
    },
    "open_redirect_low": {
        "title": "Generic Open Redirect without OAuth/Session Leakage",
        "reason": "Open redirects without credential theft, token exfiltration, or OAuth state bypass are generally Low/Informational or N/A.",
        "keywords": ["open redirect", "arbitrary redirect"]
    },
    "banner_disclosure": {
        "title": "Software Version Disclosure / Server Banner",
        "reason": "Information disclosure of generic version strings (e.g. Apache/2.4.41, PHP/7.4) without CVE exploit chain is Informational / N/A.",
        "keywords": ["version disclosure", "server header", "banner grabbing", "x-powered-by"]
    },
    "username_enum": {
        "title": "Username / Email Enumeration via Standard Error Messages",
        "reason": "Different login error messages (e.g., 'User not found' vs 'Invalid password') are classified as Informational / N/A on most programs.",
        "keywords": ["username enumeration", "user enumeration", "email enumeration"]
    },
    "csv_injection_low": {
        "title": "CSV / Formula Injection without RCE",
        "reason": "CSV injection requiring local spreadsheet execution without remote code execution proof is classified as N/A.",
        "keywords": ["csv injection", "formula injection", "excel injection"]
    }
}

INFO_ONLY_PATTERNS = {
    "graphql_introspection_only": {
        "title": "GraphQL Introspection Without Sensitive-Field Impact",
        "reason": "Schema introspection is an enumeration primitive. It is useful for targeted GraphQL authorization testing but is not submission-ready without sensitive field access or another concrete impact.",
        "keywords": ["graphql introspection", "graphql schema disclosure", "graphql schema introspection"],
    }
}

VALID_VRT_CATEGORIES = {
    "RCE": {"name": "Remote Code Execution", "severity": "Critical", "cvss": 9.8},
    "SQLi": {"name": "SQL Injection", "severity": "Critical", "cvss": 9.3},
    "ATO": {"name": "Account Takeover", "severity": "Critical", "cvss": 9.0},
    "SSRF": {"name": "Server-Side Request Forgery", "severity": "High", "cvss": 8.6},
    "IDOR": {"name": "Broken Object Level Authorization (IDOR)", "severity": "High", "cvss": 8.1},
    "XSS": {"name": "Cross-Site Scripting (Reflected/Stored)", "severity": "Medium", "cvss": 6.1},
    "AUTH_BYPASS": {"name": "Authentication Bypass", "severity": "High", "cvss": 8.8},
    "BUSINESS_LOGIC": {"name": "Business Logic Vulnerability", "severity": "High", "cvss": 7.5}
}

class VRTTriageEngine:
    def __init__(self):
        self.na_rules = NA_PATTERNS
        self.valid_vrt = VALID_VRT_CATEGORIES

    def evaluate_finding(self, title: str, description: str, poc_verified: bool, possesses_active_exploit: bool = False) -> Dict[str, Any]:
        """
        Evaluates a potential finding against N/A rules and VRT standards.
        Returns evaluation dict with approval status.
        """
        combined_text = f"{title} {description}".lower()

        # Keep this as an explicit informational disposition rather than
        # treating schema discovery as a failed exploit.  The offensive
        # GraphQL planner can still consume the recorded schema evidence.
        for rule_key, rule in INFO_ONLY_PATTERNS.items():
            if any(keyword in combined_text for keyword in rule["keywords"]):
                return {
                    "is_approved": False,
                    "status": "INFO_ONLY",
                    "reason": rule["reason"],
                    "rule_triggered": rule["title"],
                    "vrt_category": "Informational > GraphQL Schema Exposure",
                    "severity": "Informational",
                    "cvss_score": 0.0,
                    "recommended_action": "Retain as an enumeration primitive and test field-level authorization separately.",
                }

        # Check against N/A patterns
        for rule_key, rule in self.na_rules.items():
            for kw in rule["keywords"]:
                if kw in combined_text:
                    # Exception: If active exploit with real business impact is proven
                    if possesses_active_exploit and poc_verified:
                        continue
                    return {
                        "is_approved": False,
                        "status": "REJECTED (ANTI-N/A)",
                        "reason": rule["reason"],
                        "rule_triggered": rule["title"],
                        "vrt_category": "N/A / Out of Scope",
                        "recommended_action": "Discard report to protect program reputation."
                    }

        if not poc_verified:
            return {
                "is_approved": False,
                "status": "REJECTED (ANTI-HALU)",
                "reason": "The finding lacks live HTTP PoC verification. Unverified claims are rejected.",
                "rule_triggered": "Missing Executable HTTP Proof",
                "vrt_category": "Unverified",
                "recommended_action": "Execute HTTP PoC request to verify response payload."
            }

        # Classify valid VRT category
        matched_cat = "BUSINESS_LOGIC"
        for cat_code, cat_info in self.valid_vrt.items():
            if cat_code.lower() in combined_text or cat_info["name"].lower() in combined_text:
                matched_cat = cat_code
                break

        cat_data = self.valid_vrt[matched_cat]
        return {
            "is_approved": True,
            "status": "APPROVED",
            "reason": "Finding meets high-impact VRT standards and passed live PoC verification.",
            "rule_triggered": None,
            "vrt_category": cat_data["name"],
            "severity": cat_data["severity"],
            "cvss_score": cat_data["cvss"]
        }
