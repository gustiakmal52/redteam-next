"""
Configuration settings, tool paths, regex patterns, and wordlists
for the Red Team Bug Bounty Recon & Deep Exploitation Platform.
"""

import os
import shutil
from copy import deepcopy

# Tool binary paths - prioritize projectdiscovery binaries to avoid python httpx collision
def _pick_tool(name: str, preferred: str) -> str:
    if os.path.exists(preferred) and os.access(preferred, os.X_OK):
        return preferred
    found = shutil.which(name)
    # shutil.which may return venv python-httpx — reject it for httpx
    if name == "httpx" and found and found.endswith(".venv/bin/httpx"):
        for alt in ["/home/utopia/go/bin/httpx", "/home/utopia/.local/bin/httpx"]:
            if os.path.exists(alt):
                return alt
    return found or preferred

TOOL_PATHS = {
    "subfinder": _pick_tool("subfinder", "/home/utopia/go/bin/subfinder"),
    "httpx": _pick_tool("httpx", "/home/utopia/go/bin/httpx"),
    "gau": _pick_tool("gau", "/home/utopia/go/bin/gau"),
    "katana": _pick_tool("katana", "/home/utopia/go/bin/katana"),
    "ffuf": _pick_tool("ffuf", "/home/utopia/.local/bin/ffuf"),
    "arjun": _pick_tool("arjun", "/home/utopia/.local/bin/arjun"),
    "naabu": _pick_tool("naabu", "/home/utopia/go/bin/naabu"),
    "curl": shutil.which("curl") or "/usr/bin/curl",
    "grep": shutil.which("grep") or "/usr/bin/grep",
    "jq": shutil.which("jq") or "/usr/bin/jq",
    "python3": shutil.which("python3") or "/usr/bin/python3"
}

# Regex patterns for detecting secrets in modern JS bundles, HTML, and responses
SECRET_PATTERNS = {
    "supabase_anon_key": r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.ey[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+",
    "supabase_url": r"https://[a-zA-Z0-9\-]+\.supabase\.co",
    "firebase_url": r"https://[a-zA-Z0-9\-]+\.firebaseio\.com",
    "firebase_api_key": r"AIza[0-9A-Za-z\-_]{34,36}",
    "jwt_token": r"ey[A-Za-z0-9-_=]+\.ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*",
    "aws_access_key": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
    "google_api_key": r"AIza[0-9A-Za-z\-_]{34,36}",
    "stripe_secret_key": r"(?:sk_live|rk_live)_[0-9a-zA-Z]{24,34}",
    "stripe_publishable": r"pk_live_[0-9a-zA-Z]{24,34}",
    "github_token": r"(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,255}",
    "slack_token": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9]*",
    "sendgrid_key": r"SG\.[a-zA-Z0-9_\-\.]{66}",
    "bearer_auth_header": r"[Bb]earer\s+([a-zA-Z0-9_\-\.]{20,})"
}

# Extended regex grep patterns applied to every JS bundle, inline script, and
# sourcemap source. Every match is recorded with its source label and context.
GREP_PATTERNS = {
    "api_endpoint": r'["\'](/api/[a-zA-Z0-9_\-/.{}:]+)["\']',
    "graphql_endpoint": r'["\'](/graphql[a-zA-Z0-9_\-/]*(?:\?[^"\']*)?)["\']',
    "internal_url": r'["\'](https?://(?:localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})[^"\']*)["\']',
    "internal_domain": r'["\'](https?://(?:[a-z0-9\-]+\.)*(?:internal|local|corp|lan|home|dev|stage|docker)[^"\']*)["\']',
    "email_address": r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
    "ip_address": r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d{2,5})?\b',
    "aws_s3_bucket": r'["\']((?:https?://)?[a-zA-Z0-9.\-]+\.s3[.-][a-z0-9.\-]*(?:/[^"\']*)?)["\']',
    "auth_header_key": r'["\'](authorization|api[_-]?key|x-api-key|x-auth-token|token|secret|session[_-]?id)["\']\s*:\s*["\']',
    "rpc_endpoint": r'["\'](/rpc/[a-zA-Z0-9_\-/]+)["\']',
    "websocket_url": r'["\'](wss?://[^"\']+)["\']',
}

# Call-site patterns for tracing API usage inside JS (fetch/axios/XHR/WebSocket).
API_CALL_PATTERNS = [
    ("fetch", r'fetch\s*\(\s*[`"\']([^`"\']+)[`"\']'),
    ("axios", r'axios\.(?:get|post|put|patch|delete|options|head|request)\s*\(\s*[`"\']([^`"\']+)[`"\']'),
    ("axios_alias", r'\.(?:get|post|put|patch|delete)\s*\(\s*[`"\']([^`"\']+)[`"\']'),
    ("xhr", r'XMLHttpRequest\.prototype\.open\s*\(\s*["\']([A-Z]+)["\'],\s*[`"\']([^`"\']+)[`"\']'),
    ("xhr_short", r'\.open\s*\(\s*["\']([A-Z]+)["\'],\s*[`"\']([^`"\']+)[`"\']'),
    ("websocket", r'new\s+WebSocket\s*\(\s*[`"\']([^`"\']+)[`"\']'),
]

# Regex patterns for discovering API routes in JS bundles & sourcemaps
ROUTE_PATTERNS = [
    r'["\'](/api/v[0-9]+/[a-zA-Z0-9_\-/]+)["\']',
    r'["\'](/api/[a-zA-Z0-9_\-/]+)["\']',
    r'["\'](/v[0-9]+/[a-zA-Z0-9_\-/]+)["\']',
    r'["\'](/graphql[a-zA-Z0-9_\-/]*)["\']',
    r'["\'](/_next/data/[a-zA-Z0-9_\-/]+\.json)["\']',
    r'["\'](/rest/v[0-9]+/[a-zA-Z0-9_\-/]+)["\']',
    r'["\'](/internal/[a-zA-Z0-9_\-/]+)["\']',
    r'["\'](/admin/[a-zA-Z0-9_\-/]+)["\']',
    r'["\'](/auth/[a-zA-Z0-9_\-/]+)["\']',
    r'["\'](/users?/[a-zA-Z0-9_\-/]+)["\']',
    r'["\'](/webhook[s]?/[a-zA-Z0-9_\-/]+)["\']'
]

# Sensitive paths for rapid fuzzing (FFUF / Direct Probing)
SENSITIVE_PATHS = [
    "/.env",
    "/.git/HEAD",
    "/.git/config",
    "/api/v1",
    "/api/v2",
    "/swagger/v1/swagger.json",
    "/api-docs",
    "/openapi.json",
    "/actuator/health",
    "/actuator/env",
    "/actuator/heapdump",
    "/graphql",
    "/graphql/playground",
    "/debug/pprof",
    "/server-status",
    "/metrics",
    "/.well-known/security.txt",
    "/config.json",
    "/settings.json",
    "/_next/static/development/_buildManifest.js",
    "/package.json"
]

# Exploit modes.  SAFE remains available for compatibility, but the deep
# exploit presets can run the target-specific OFFENSIVE planner.  OFFENSIVE
# does not mean blind spraying: it means the engine is allowed to execute
# hypotheses derived from observed method/body/header/route relationships and
# supplied researcher-owned identities.
EXPLOIT_MODES = {
    "SAFE": {
        "label": "Baseline / bounded verification",
        "aggressive_payloads": False,
        "ssrf_probing": False,
        "target_specific_planner": False,
    },
    "AGGRESSIVE": {
        "label": "Aggressive compatibility mode",
        "aggressive_payloads": True,
        "ssrf_probing": True,
        "target_specific_planner": True,
    },
    "OFFENSIVE": {
        "label": "Deep offensive target-specific exploit mode",
        "aggressive_payloads": True,
        "ssrf_probing": True,
        "target_specific_planner": True,
    },
}

DEFAULT_EXPLOIT_MODE = "SAFE"

# Deep bypass is deliberately a sub-budget, separate from the global traffic
# Bypass budget: requests untuk adaptive WAF bypass, chained payload mutation,
# normalization evasion, authorization test, adaptive retry, confirmation.
# Dinaikkan 2x lipat untuk bug bounty deep exploitation.
DEFAULT_BYPASS_REQUEST_BUDGET = 160
MAX_BYPASS_DEPTH = 3

# Very common, weak HMAC secrets tried against discovered JWTs. This is done
# strictly offline (local computation), never sent back to the target.
JWT_WEAK_SECRETS = [
    "secret", "password", "123456", "123456789", "qwerty", "supersecret",
    "changeme", "secret123", "secret_key", "jwt_secret", "jwt-secret",
    "token", "test", "testing", "key", "null", "default", "admin",
    "your-secret-key", "s3cr3t", "letmein", "welcome", "abc123",
]

# Common URL/redirect parameters that accept attacker-controlled destinations.
REDIRECT_PARAMS = [
    "url", "next", "redirect", "redirect_uri", "return", "returnTo",
    "return_url", "rurl", "dest", "destination", "continue", "out",
    "view", "login_url", "image_url", "go", "target", "callback",
]

# Database connection string patterns detected in JS bundles, sourcemaps,
# and HTML. Used by core/db_hunter.py (Supabase/Firebase/Postgres/MySQL/...).
DB_URL_PATTERNS = {
    "postgres": r"(?:postgres|postgresql|psql)://(?:[^@\s]*@)?[^/\s]+",
    "mysql": r"mysql://(?:[^@\s]*@)?[^/\s]+",
    "mariadb": r"mariadb://(?:[^@\s]*@)?[^/\s]+",
    "mongodb": r"mongodb(?:\+srv)?://(?:[^@\s]*@)?[^/\s]+",
    "redis": r"redis(?:\+tls)?://(?:[^@\s]*@)?[^/\s]+",
    "cockroachdb": r"cockroachdb://(?:[^@\s]*@)?[^/\s]+",
    "sqlserver": r"(?:sqlserver|mssql)://(?:[^@\s]*@)?[^/\s]+",
    "oracle": r"oracle://(?:[^@\s]*@)?[^/\s]+",
    "sqlite": r"sqlite:///[^\s]+",
    "dynamodb": r"arn:aws:dynamodb:[a-z0-9\-]+:\d+:table/[A-Za-z0-9_\-]+",
}

DB_PORT_SERVICES = {
    5432: "postgres", 5433: "postgres", 5434: "postgres", 6432: "postgres", 6543: "postgres",
    3306: "mysql", 3307: "mysql", 13306: "mysql", 13307: "mysql",
    27017: "mongodb", 27018: "mongodb", 27019: "mongodb",
    6379: "redis", 6380: "redis", 16379: "redis", 26379: "redis",
    1433: "sqlserver", 1434: "sqlserver", 1521: "oracle", 2483: "oracle",
    9200: "elasticsearch", 9300: "elasticsearch",
    5984: "couchdb", 11211: "memcached", 9042: "cassandra", 9142: "cassandra",
}

# Well-known web database admin panels probed on discovered endpoints. Reaching
# a login page is DISCOVERED-level evidence only; login bypass is never assumed.
DB_ADMIN_PANEL_PATHS = {
    "/phpmyadmin/": "phpMyAdmin", "/phpMyAdmin/": "phpMyAdmin", "/pma/": "phpMyAdmin",
    "/adminer.php": "Adminer", "/adminer/": "Adminer", "/adminer.php/": "Adminer",
    "/pgadmin/": "pgAdmin", "/pgadmin4/": "pgAdmin",
    "/mongo-express/": "Mongo Express", "/mongoadmin/": "Mongo Express",
    "/redis-commander/": "Redis Commander", "/redis/": "Redis Commander",
}

# Page markers that identify each DB admin panel, matched case-insensitively.
DB_ADMIN_PANEL_MARKERS = {
    "phpMyAdmin": ["phpmyadmin", "pma_username", "pma_password", "name=\"token\""],
    "Adminer": ["adminer", "class=\"version\""],
    "pgAdmin": ["pgadmin", "pg-admin"],
    "Mongo Express": ["mongo express", "mongo-express", "mongodb"],
    "Redis Commander": ["redis commander", "redis-commander"],
}

# Backup/dump file paths that commonly leak a full database snapshot.
DB_BACKUP_PATHS = [
    "/db.sql", "/database.sql", "/backup.sql", "/dump.sql", "/backup/db.sql",
    "/backup/database.sql", "/backup/dump.sql", "/backups/db.sql", "/backups/database.sql",
    "/sql/dump.sql", "/db.sql.gz", "/database.sql.gz", "/backup.sql.gz", "/dump.sql.gz",
    "/backup/db.sql.gz", "/backup/database.sql.gz", "/db_backup.sql", "/data.sql",
    "/mysql.sql", "/postgres.sql", "/mongo.dump", "/backup/mongo.dump",
]

# Content markers proving a fetched file is a real SQL/database dump (VERIFIED
# only when one of these appears alongside an HTTP 200 and a dump MIME type).
SQL_DUMP_MARKERS = [
    "CREATE TABLE", "INSERT INTO", "DROP TABLE", "-- MySQL dump", "PostgreSQL database dump",
    "Dump completed", "pg_dump", "\\copy ", "dbname=", "Server version",
]

# Header profiles — the first line of defense fingerprinting.
# Modern bot management (Cloudflare Bot Management, Akamai BMP, AWS WAF Bot
# Control, DataDome, Kasada, HUMAN) scores the header *shape* and TLS client
# fingerprint before a payload is ever inspected.  A self-declaring scanner
# User-Agent combined with default-Python TLS is an instant challenge page no
# matter how good the payload mutations are.  ``browser`` is therefore the
# default transport identity; researcher transparency is preserved separately
# via program contact headers (X-Bugcrowd-Ninja, REDTEAM_EXTRA_HEADERS), which
# still ride every request and still win precedence over this profile.
HEADER_PROFILES = {
    "browser": {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language": "en-US,en;q=0.9",
        "sec-ch-ua": '"Chromium";v="131", "Not_A Brand";v="24"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"macOS"',
    },
    "scanner": {
        "User-Agent": "Gustiakmal-RedTeam-Verifier/2.1",
    },
}
DEFAULT_HEADER_PROFILE = "browser"
HEADER_PROFILE_ENV = "REDTEAM_HEADER_PROFILE"


def get_header_profile(name: str | None = None) -> dict[str, str]:
    """Resolve a header profile: explicit name > env override > default."""
    chosen = (name or os.environ.get(HEADER_PROFILE_ENV, "") or DEFAULT_HEADER_PROFILE).strip().lower()
    if chosen not in HEADER_PROFILES:
        raise ValueError(f"unknown header profile {chosen!r}; available: {', '.join(sorted(HEADER_PROFILES))}")
    return dict(HEADER_PROFILES[chosen])


# Default HTTP Request Headers — alias of the browser profile so legacy
# consumers (js_analyzer) stay fingerprint-consistent with the transport
# layer instead of overriding it with an older, hint-less header set.
DEFAULT_HEADERS = dict(HEADER_PROFILES["browser"])

# Scan Presets
SCAN_PRESETS = {
    "full": {
        "name": "Full Auto Recon & Exploit",
        "description": "Subdomain enum -> HTTP probe -> GAU/Katana -> JS/hidden asset discovery -> BaaS correlation -> Param Miner -> FFUF -> Recon depth -> Exploit verification -> adaptive bypass",
        "modules": ["subfinder", "httpx", "crawlers", "js_analyzer", "hidden_assets", "cloud_baas", "param_miner", "ffuf", "recon_depth", "exploit_verifier", "bypass_engine", "threat_intel", "db_hunter"]
    },
    "smart": {
        "name": "Smart Stealth Recon",
        "description": "Subdomain discovery, tech stack fingerprinting, JS route extraction, recon depth, and non-intrusive misconfig checks",
        "modules": ["subfinder", "httpx", "crawlers", "js_analyzer", "hidden_assets", "cloud_baas", "recon_depth", "threat_intel", "db_hunter"]
    },
    "js_hunter": {
        "name": "JS & API Bundle Hunter",
        "description": "Deep JS bundle downloading, sourcemap (.map) unpacking, API route tracing, token/secret harvesting, and DB connection string detection",
        "modules": ["js_analyzer", "hidden_assets", "cloud_baas", "db_hunter"]
    },
    "cloud_baas": {
        "name": "Cloud / BaaS / Database Hunter",
        "description": "Dedicated Supabase RLS bypass auditor, Firebase open rules tester, and database connection exposure detection",
        "modules": ["cloud_baas", "js_analyzer", "hidden_assets", "db_hunter"]
    },
    "active_exploit": {
        "name": "Deep Exploit Verification",
        "description": "Offensive target-specific verification: discovered method/body/header relationships feed active injection, parser differential, auth, GraphQL, redirect, SSRF, and bypass hypotheses. No status-only bypass claim. No RCE claimed without execution proof; SSTI is never upgraded to RCE without execution proof.",
        "modules": ["exploit_verifier", "bypass_engine", "hidden_assets", "threat_intel"]
    },
    "deep_bypass": {
        "name": "Deep Adaptive Bypass",
        "description": "Baseline -> protection detection -> target-specific attack planning -> adaptive mutation -> differential verification -> exploit-chain evidence. Uses discovered request shapes and researcher-owned identities; no generic payload spray.",
        "modules": ["exploit_verifier", "bypass_engine", "hidden_assets", "threat_intel"]
    },
    "lab_hardened": {
        "name": "Lab Hardened (Own Strict Local Target)",
        "description": "Offline audit profile for your own hardened local/private lab target. In-process HTTP modules only: JS/API route discovery, DB exposure hunt, deterministic exploit verification, and baseline protection learning. No external recon or host port scan.",
        "modules": ["js_analyzer", "hidden_assets", "cloud_baas", "db_hunter", "exploit_verifier", "bypass_engine"]
    }
}

# Central traffic policy — NORMAL is the default; FAST must be selected
# explicitly. Adaptive backoff stays active to avoid bans; starting points
# are conservative so repeated 429s throttle a host down quickly.
TRAFFIC_PRESETS = {
    "STEALTH": {
        "global_rps": 2.0, "per_host_rps": 1.0,
        "global_concurrency": 4, "per_host_concurrency": 2,
        "timeout": 12.0, "retry_limit": 2,
        "adaptive_backoff": True, "respect_retry_after": True,
    },
    "NORMAL": {
        "global_rps": 5.0, "per_host_rps": 3.0,
        "global_concurrency": 8, "per_host_concurrency": 4,
        "timeout": 12.0, "retry_limit": 2,
        "adaptive_backoff": True, "respect_retry_after": True,
    },
    "FAST": {
        "global_rps": 10.0, "per_host_rps": 6.0,
        "global_concurrency": 16, "per_host_concurrency": 8,
        "timeout": 12.0, "retry_limit": 3,
        "adaptive_backoff": True, "respect_retry_after": True,
    },
}

DEFAULT_TRAFFIC_PRESET = "NORMAL"
# Global request budget — dinaikkan untuk deep recon + exploitation
DEFAULT_REQUEST_BUDGET = 2000
DEFAULT_VERIFICATION_RESERVE = 200


def get_traffic_profile(name: str = DEFAULT_TRAFFIC_PRESET):
    """Return an isolated preset dict so runtime throttling cannot mutate constants."""
    normalized = (name or DEFAULT_TRAFFIC_PRESET).upper()
    if normalized not in TRAFFIC_PRESETS:
        raise ValueError(f"Unknown traffic preset: {name}")
    return deepcopy(TRAFFIC_PRESETS[normalized])


def cvss3_score(vector: str, fallback: float = 0.0) -> float:
    """Return a deterministic CVSS 3.1 base score for the supported vectors.

    Scores are pinned with the vectors below instead of depending on whichever
    CVSS implementation happens to be installed at runtime.  Unknown vectors
    return the caller-supplied fallback so legacy/custom findings remain
    serializable without inventing a score.
    """
    return float(CVSS_STATIC_SCORES.get(str(vector or ""), fallback))


# CVSS 3.1 vectors per finding class. Kept next to the traffic policy so
# exploit scoring is one deterministic source of truth (no per-test magic).
CVSS_VECTORS = {
    "reflected_xss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "sqli_time_based": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "ssti": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    "graphql_introspection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "open_redirect": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
    "csrf_missing_token": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
    "jwt_weak_secret": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "exposed_env": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "exposed_git": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "cors_data_exposure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
    "bola": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "jwt_alg_none": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "ssrf_timing": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N",
    "cloud_credential_read": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "db_unauth_exposed": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "db_admin_panel_exposed": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "db_dump_exposed": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "error_disclosure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
}

CVSS_STATIC_SCORES = {
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N": 8.2,
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N": 5.3,
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N": 4.3,
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N": 9.1,
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N": 7.5,
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N": 5.8,
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N": 6.5,
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N": 7.5,
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N": 5.3,
}
