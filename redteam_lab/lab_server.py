#!/usr/bin/env python3
"""
Hardened Local Web Lab ("weblocal") — a strict, production-grade style target
used to observe redteam_agent behavior honestly (zero-FP / anti-halu proof).

Design rules (this is NOT an intentionally vulnerable lab):
  * Static HTML only — nothing ever reflects a request parameter into markup.
  * JSON APIs never echo user input back (nothing to reflect, nothing to inject).
  * Unknown paths (/.env, /.git/HEAD, /db.sql, /phpmyadmin/, ...) => uniform 404.
  * No CORS headers at all, no forms (no CSRF surface), auth required on /api/v1/products.
  * Security headers on every response; no stack traces ever; no version banners.
  * Every request is written to a JSONL access log so a scan's claims can be
    cross-checked against what the lab actually received.

Run directly:  python3 redteam_lab/lab_server.py --port 8791 --log /tmp/lab.jsonl
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import hmac
import json
import os
import secrets
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

APP_NAME = "Acme Cloud API"
VERSION = "1.4.2"

# --------------------------------------------------------------------------
# Static content (kept as constants — never served from disk, so directory
# traversal or .git exposure is structurally impossible).
# --------------------------------------------------------------------------

LANDING_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="Acme Cloud API - developer platform for building reliable web services">
<title>Acme Cloud API</title>
<link rel="stylesheet" href="/assets/app.css">
</head>
<body>
<header class="topbar">
  <div class="wrap">
    <span class="brand">Acme Cloud API</span>
    <nav><a href="/#features">Features</a><a href="/#docs">Documentation</a><a href="/#status">Status</a></nav>
  </div>
</header>
<main>
  <section class="hero">
    <div class="wrap">
      <h1>Build reliable web services, faster</h1>
      <p>The Acme Cloud API gives your team a single endpoint for identity,
      search, and product data with predictable billing and a 99.95% uptime goal.</p>
      <p id="health-pill" class="pill">Checking service status...</p>
    </div>
  </section>
  <section id="features" class="wrap">
    <h2>What you get</h2>
    <div class="cards">
      <article><h3>Identity</h3><p>Token-based authentication with short-lived
      sessions and server-side validation on every protected route.</p></article>
      <article><h3>Search</h3><p>Parameterized queries against a read replica.
      Results are rendered server-side and returned as structured JSON.</p></article>
      <article><h3>Product data</h3><p>Protected catalog endpoints that require a
      valid session token obtained from the login endpoint.</p></article>
    </div>
  </section>
  <section id="docs" class="wrap">
    <h2>Quick reference</h2>
    <pre><code>GET  /api/v1/health
GET  /api/v1/search?q=term
POST /api/v1/auth/login        {"username":"...","password":"..."}
GET  /api/v1/products          (Authorization: Bearer &lt;token&gt;)</code></pre>
    <p>See the <a href="/.well-known/security.txt">security contact</a> before
    reporting anything about this service.</p>
  </section>
</main>
<footer><div class="wrap">&#169; 2026 Acme Cloud. All rights reserved.</div></footer>
<script src="/assets/app.js" defer></script>
</body>
</html>
"""

APP_JS_BASE = """(function () {
  "use strict";

  function getJson(path, init) {
    return fetch(path, init).then(function (res) {
      return res.json().then(function (body) {
        return { status: res.status, body: body };
      });
    });
  }

  function checkHealth() {
    return getJson("/api/v1/health", { headers: { Accept: "application/json" } });
  }

  function searchProducts(query) {
    return getJson("/api/v1/search?q=" + encodeURIComponent(query),
      { headers: { Accept: "application/json" } });
  }

  function signIn(username, password) {
    return getJson("/api/v1/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ username: username, password: password })
    });
  }

  function fetchProducts(token) {
    return getJson("/api/v1/products", {
      headers: { Accept: "application/json", Authorization: "Bearer " + token }
    });
  }

  function setPill(text, ok) {
    var pill = document.getElementById("health-pill");
    if (!pill) { return; }
    pill.textContent = text;
    pill.className = "pill" + (ok ? " pill-ok" : " pill-bad");
  }

  checkHealth().then(function (res) {
    if (res.status === 200 && res.body.status === "ok") {
      setPill("Service operational (v" + res.body.version + ")", true);
    } else {
      setPill("Service check failed", false);
    }
  }).catch(function () { setPill("Service check failed", false); });

  window.AcmeApi = { checkHealth: checkHealth, searchProducts: searchProducts,
                     signIn: signIn, fetchProducts: fetchProducts };
})();
"""

APP_JS = APP_JS_BASE  # replaced at startup for --demo/offensive fixture modes

# Positive fixture used only by the local offensive regression. It is kept
# separate from the hardened target so a non-zero result is real evidence from
# an intentionally vulnerable handler, not a weakened FP-control target.
OFFENSIVE_JS_EXTRA = r'''
(function () {
  "use strict";
  const runtime = fetch("/runtime-config.js");
  const searchUrl = "/api/v1/search?q=lab";
  const renderUrl = "/api/v1/render";
  const graphUrl = "/api/v1/graphql";
  const redirectUrl = "/api/v1/redirect?next=/dashboard";
  const catalogUrl = "/api/v1/catalog?id=1";
  const pingUrl = "/api/v1/ping?host=lab.local";
  const echoUrl = "/api/v1/echo";
  const publicClientId = "lab-public-client-2026";

  fetch(searchUrl, { headers: { Accept: "text/html" } });
  fetch(renderUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({ template: "welcome" })
  });
  fetch(graphUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({ query: "query Viewer { viewer { id } }" })
  });
  fetch(redirectUrl, { headers: { Accept: "text/html" } });
  fetch(catalogUrl, { headers: { Accept: "application/json" } });
  fetch(pingUrl, { headers: { Accept: "application/json" } });
  fetch(echoUrl, { headers: { Accept: "application/json" } });
  import("/assets/admin.chunk.js");
  navigator.serviceWorker.register("/sw.js");
  window.__CONFIG__ = { clientId: publicClientId, environment: "offensive-fixture" };
})();
//# sourceMappingURL=app.js.map
'''

OFFENSIVE_ADMIN_CHUNK = r'''
// Deliberate local-lab route surface. This is not shipped by hardened mode.
fetch("/api/v1/redirect?next=/dashboard", { headers: { Accept: "text/html" } });
fetch("/api/v1/graphql", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ query: "query Viewer { viewer { id } }" })
});
'''

OFFENSIVE_SERVICE_WORKER = r'''
self.addEventListener("fetch", function (event) {
  if (event.request.url.includes("/api/v1/graphql")) {
    event.respondWith(fetch("/api/v1/graphql"));
  }
});
'''

OFFENSIVE_SOURCE_MAP = json.dumps({
    "version": 3,
    "file": "app.js",
    "sourceRoot": "webpack://lab/",
    "sources": ["src/hidden-client.js"],
    "names": ["renderUrl", "template"],
    "sourcesContent": [
        'export function render(template) {\n'
        '  return fetch("/api/v1/render", {\n'
        '    method: "POST",\n'
        '    headers: { "Content-Type": "application/json" },\n'
        '    body: JSON.stringify({ template })\n'
        '  });\n'
        '}\n'
    ],
})

APP_CSS = """* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: ui-sans-serif, system-ui, sans-serif; color: #1f2937; background: #f9fafb; line-height: 1.55; }
.wrap { max-width: 960px; margin: 0 auto; padding: 0 20px; }
.topbar { background: #111827; color: #fff; }
.topbar .wrap { display: flex; justify-content: space-between; align-items: center; height: 56px; }
.brand { font-weight: 700; }
nav a { color: #d1d5db; margin-left: 18px; text-decoration: none; }
nav a:hover { color: #fff; }
.hero { background: linear-gradient(180deg, #1e3a8a, #1d4ed8); color: #fff; padding: 64px 0; }
.hero h1 { font-size: 40px; margin-bottom: 12px; }
.hero p { max-width: 640px; color: #dbeafe; }
.pill { display: inline-block; margin-top: 18px; padding: 6px 14px; border-radius: 999px; background: #374151; font-size: 14px; }
.pill-ok { background: #065f46; color: #d1fae5; }
.pill-bad { background: #7f1d1d; color: #fee2e2; }
h2 { margin: 40px 0 12px; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; }
.cards article { background: #fff; border: 1px solid #e5e7eb; border-radius: 10px; padding: 18px; }
.cards h3 { margin-bottom: 6px; font-size: 18px; }
pre { background: #0f172a; color: #e2e8f0; padding: 18px; border-radius: 10px; overflow-x: auto; font-size: 14px; }
footer { margin-top: 48px; border-top: 1px solid #e5e7eb; padding: 24px 0; color: #6b7280; }
"""

# Demo-only fragment (--demo): references the deliberately leaky /api/v1/parse
# endpoint so the scan's route discovery actually finds it. The hardened lab
# serves the base app.js without this fragment.
DEMO_JS_EXTRA = """
(function () {
  fetch("/api/v1/parse", { method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({ payload: "demo" }) }).catch(function () {});
})();
"""

ROBOTS_TXT = "User-agent: *\nDisallow: /internal/\nDisallow: /api/v1/admin/\n"

# --demo only ---------------------------------------------------------------
def demo_leak_body(reason: str) -> str:
    """Realistic unhandled-exception traceback leaked in a 500 JSON response.
    Mimics a missing global error handler in a dev-style utility endpoint."""
    if reason == "json":
        trace = ("Traceback (most recent call last):\n"
                 '  File "/opt/acme/app/api/parse.py", line 201, in parse_payload\n'
                 "    data = json.loads(raw)\n"
                 '  File "/usr/lib/python3.11/json/__init__.py", line 346, in loads\n'
                 "    return _default_decoder.decode(s)\n"
                 "json.decoder.JSONDecodeError: Expecting value: line 1 column 1 (char 0)")
    else:
        trace = ("Traceback (most recent call last):\n"
                 '  File "/opt/acme/app/api/parse.py", line 214, in parse_payload\n'
                 "    normalized = payload.strip()\n"
                 "AttributeError: 'dict' object has no attribute 'strip'")
    return json.dumps({"error": "unhandled_exception", "service": "parse", "trace": trace})


SECURITY_TXT = """Contact: mailto:security@acme-cloud.example
Expires: 2027-01-01T00:00:00Z
Preferred-Languages: en
Canonical: https://acme-cloud.example/.well-known/security.txt
"""

# --------------------------------------------------------------------------
# Request log
# --------------------------------------------------------------------------

_log_lock = threading.Lock()
_log_handle = None  # optional open JSONL file


def init_log(path: str | None) -> None:
    global _log_handle
    if path:
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        _log_handle = open(path, "a", encoding="utf-8")


def write_log(entry: dict) -> None:
    handle = _log_handle
    if handle is None:
        return
    with _log_lock:
        try:
            handle.write(json.dumps(entry) + "\n")
            handle.flush()
        except Exception:
            pass


# --------------------------------------------------------------------------
# Demo credential store (ephemeral per boot — deliberately not shipped in code)
# --------------------------------------------------------------------------

_ADMIN_USER = os.environ.get("LAB_ADMIN_USER", "acme_admin")
_ADMIN_PASS = os.environ.get("LAB_ADMIN_PASS", secrets.token_urlsafe(18))
_VALID_TOKENS: set[str] = set()

# --demo flag: deliberately leaky endpoint enabled (default lab stays strict).
DEMO_LEAK = False
# Positive fixture flag; default lab stays hardened and source-compatible.
OFFENSIVE_FIXTURE = False

SEARCH_CATALOG = [
    {"id": 101, "name": "Identity SDK", "category": "identity"},
    {"id": 102, "name": "Search Indexer", "category": "search"},
    {"id": 103, "name": "Product Catalog API", "category": "catalog"},
    {"id": 104, "name": "Usage Analytics", "category": "observability"},
    {"id": 105, "name": "Webhook Relay", "category": "integrations"},
]


def _constant_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


# --------------------------------------------------------------------------
# HTTP handler
# --------------------------------------------------------------------------

class LabHandler(BaseHTTPRequestHandler):
    server_version = "LabEdge"      # generic; no version banner leakage
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args):  # suppress default stderr noise
        return

    # -- helpers ----------------------------------------------------------

    def _respond(self, status: int, body: bytes, content_type: str,
                 cache_control: str = "no-store", security_headers: bool = True) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", cache_control)
        if security_headers:
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
            self.send_header("Cross-Origin-Opener-Policy", "same-origin")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            self.send_header("Content-Security-Policy",
                             "default-src 'none'; script-src 'self'; style-src 'self'; "
                             "img-src 'self'; connect-src 'self'; base-uri 'none'; "
                             "form-action 'self'; frame-ancestors 'none'")
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass
        self._record(status)

    def _record(self, status: int) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        write_log({
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "method": self.command,
            "path": parsed.path,
            "query": parsed.query,
            "status": status,
            "ua": self.headers.get("User-Agent", ""),
        })

    def _json(self, status: int, payload: dict) -> None:
        self._respond(status, json.dumps(payload).encode("utf-8"), "application/json")

    def _redirect(self, status: int, location: str) -> None:
        body = b"redirecting\n"
        self.send_response(status)
        self.send_header("Location", location)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass
        self._record(status)

    def _static(self, status: int, text: str, content_type: str, cache: str = "public, max-age=60") -> None:
        self._respond(status, text.encode("utf-8"), content_type, cache)

    def _not_found(self) -> None:
        # Uniform, minimal 404 for every unknown path (including /phpmyadmin/,
        # /db.sql, /.env, /.git/HEAD ...). No body content that could be read
        # as an exposure, no enumeration hints.
        if self.path.startswith("/api/"):
            self._json(404, {"error": "not_found"})
        else:
            self._static(404, "Not Found\n", "text/plain; charset=utf-8", "no-store")

    # -- routing -----------------------------------------------------------

    def _read_body(self, limit: int = 64 * 1024) -> bytes:
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            length = 0
        if length <= 0:
            return b""
        if length > limit:
            return b""
        try:
            return self.rfile.read(length)
        except Exception:
            return b""

    def _route(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        path = urllib.parse.unquote(parsed.path or "/")
        params = urllib.parse.parse_qs(parsed.query)

        # --- static / informational ---
        if path == "/" and self.command in ("GET", "HEAD"):
            return self._static(200, LANDING_HTML, "text/html; charset=utf-8")
        if path == "/assets/app.js" and self.command in ("GET", "HEAD"):
            return self._static(200, APP_JS, "application/javascript; charset=utf-8")
        if OFFENSIVE_FIXTURE and path == "/assets/admin.chunk.js" and self.command in ("GET", "HEAD"):
            return self._static(200, OFFENSIVE_ADMIN_CHUNK, "application/javascript; charset=utf-8")
        if OFFENSIVE_FIXTURE and path == "/sw.js" and self.command in ("GET", "HEAD"):
            return self._static(200, OFFENSIVE_SERVICE_WORKER, "application/javascript; charset=utf-8")
        if OFFENSIVE_FIXTURE and path == "/assets/app.js.map" and self.command in ("GET", "HEAD"):
            return self._static(200, OFFENSIVE_SOURCE_MAP, "application/json; charset=utf-8")
        if OFFENSIVE_FIXTURE and path == "/runtime-config.js" and self.command in ("GET", "HEAD"):
            return self._static(200, (
                'window.__ENV__ = { "PUBLIC_API_ORIGIN": "http://127.0.0.1:%s", '
                '"PUBLIC_CLIENT_ID": "lab-public-client-2026" };\n' % self.server.server_address[1]
            ), "application/javascript; charset=utf-8")
        if path == "/assets/app.css" and self.command in ("GET", "HEAD"):
            return self._static(200, APP_CSS, "text/css; charset=utf-8")
        if path == "/robots.txt" and self.command in ("GET", "HEAD"):
            return self._static(200, ROBOTS_TXT, "text/plain; charset=utf-8")
        if path == "/.well-known/security.txt" and self.command in ("GET", "HEAD"):
            return self._static(200, SECURITY_TXT, "text/plain; charset=utf-8")

        # --- public API ---
        if path == "/api/v1/health":
            if self.command in ("GET", "HEAD"):
                return self._json(200, {"status": "ok", "service": APP_NAME, "version": VERSION})
            return self._json(405, {"error": "method_not_allowed"})

        if path == "/api/v1/search":
            if self.command not in ("GET", "HEAD"):
                return self._json(405, {"error": "method_not_allowed"})
            values = params.get("q") or [""]
            query = (values[0] or "").strip()
            if not query:
                return self._json(400, {"error": "missing_required_parameter", "param": "q"})
            if len(query) > 200:
                return self._json(400, {"error": "parameter_too_long", "param": "q"})
            if OFFENSIVE_FIXTURE:
                # Deliberate reflected-XSS surface for the local positive lab.
                # Security headers are omitted only on this fixture response so
                # a browser execution canary is meaningful.
                html_body = ("<!doctype html><html><body><h1>Search results</h1>"
                             "<div class=\"result\">" + query + "</div></body></html>").encode("utf-8")
                return self._respond(200, html_body, "text/html; charset=utf-8", security_headers=False)
            # Results are a fixed catalog; the query term is intentionally NOT
            # echoed back, so there is no reflection surface by design.
            return self._json(200, {"results": SEARCH_CATALOG, "total": len(SEARCH_CATALOG)})

        if OFFENSIVE_FIXTURE and path == "/api/v1/render":
            if self.command != "POST":
                return self._json(405, {"error": "method_not_allowed"})
            raw = self._read_body()
            try:
                payload = json.loads(raw.decode("utf-8") or "{}")
            except (json.JSONDecodeError, UnicodeDecodeError):
                return self._json(400, {"error": "invalid_json_body"})
            template = payload.get("template") if isinstance(payload, dict) else None
            if not isinstance(template, str):
                return self._json(400, {"error": "invalid_template"})
            rendered = {"{{7*77}}": "539", "{{8*83}}": "664"}.get(template, template)
            return self._json(200, {"rendered": rendered, "engine": "lab-template"})

        if OFFENSIVE_FIXTURE and path == "/api/v1/graphql":
            if self.command != "POST":
                return self._json(405, {"error": "method_not_allowed"})
            raw = self._read_body()
            try:
                payload = json.loads(raw.decode("utf-8") or "{}")
            except (json.JSONDecodeError, UnicodeDecodeError):
                return self._json(400, {"errors": [{"message": "invalid json"}]})
            query = payload.get("query", "") if isinstance(payload, dict) else ""
            if "__schema" in str(query):
                return self._json(200, {"data": {"__schema": {"types": [
                    {"name": "Query"}, {"name": "Viewer"}, {"name": "User"}
                ]}}})
            return self._json(200, {"data": {"viewer": {"id": "lab-viewer"}}})

        if OFFENSIVE_FIXTURE and path == "/api/v1/redirect":
            if self.command not in ("GET", "HEAD"):
                return self._json(405, {"error": "method_not_allowed"})
            destination = (params.get("next") or [""])[0]
            if not destination:
                return self._json(400, {"error": "missing_next"})
            # The fixture only redirects to the researcher canary or a local
            # path; it never contacts an arbitrary external host.
            if destination.startswith(("https://redirect-canary.invalid", "/")):
                return self._redirect(302, destination)
            return self._json(400, {"error": "destination_not_allowed"})

        if OFFENSIVE_FIXTURE and path == "/api/v1/catalog":
            if self.command not in ("GET", "HEAD"):
                return self._json(405, {"error": "method_not_allowed"})
            value = (params.get("id") or [""])[0]
            # Deliberate boolean differential fixture, realistic semantics:
            # WHERE id=1 (baseline) and WHERE id=1 AND 1=1 (always-true) both
            # return the row; WHERE id=1 AND 1=2 (always-false) returns none.
            # The agent must require stable true/false response evidence
            # (true == baseline, false != baseline) before escalating.
            if "1=2" in value:
                return self._json(200, {"rows": []})
            if "1=1" in value or "OR 1" in value.upper():
                return self._json(200, {"rows": [{"id": 1, "name": "fixture-row"}]})
            return self._json(200, {"rows": [{"id": 1, "name": "fixture-row"}]})

        if OFFENSIVE_FIXTURE and path == "/api/v1/ping":
            if self.command not in ("GET", "HEAD"):
                return self._json(405, {"error": "method_not_allowed"})
            host = (params.get("host") or [""])[0]
            # Deliberate time-based command-injection fixture. The focused RCE
            # verifier must observe three delays in each of two shell syntax
            # families while an inert string containing the same sleep text
            # stays fast. The older 1s/5s behavior remains for compatibility.
            if ";sleep 2" in host or "$(sleep 2)" in host:
                time.sleep(2.0)
                return self._json(200, {"host": host, "latency_ms": 2000})
            if "sleep 5" in host:
                time.sleep(2.5)
                return self._json(200, {"host": host, "latency_ms": 2500})
            if "sleep 1" in host:
                time.sleep(0.5)
                return self._json(200, {"host": host, "latency_ms": 500})
            return self._json(200, {"host": host, "latency_ms": 5})

        if OFFENSIVE_FIXTURE and path == "/api/v1/echo":
            if self.command not in ("GET", "HEAD"):
                return self._json(405, {"error": "method_not_allowed"})
            # Deliberate cache-poisoning fixture: reflects the X-Forwarded-Host
            # header into the body and marks the response as cached (Age + X-Cache).
            forwarded = self.headers.get("X-Forwarded-Host", "")
            body = json.dumps({"host": forwarded or "lab.local", "path": path}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "public, max-age=300")
            self.send_header("Age", "12")
            self.send_header("X-Cache", "HIT")
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass
            self._record(200)

        if path == "/api/v1/auth/login":
            if self.command != "POST":
                return self._json(405, {"error": "method_not_allowed"})
            body = self._read_body()
            try:
                payload = json.loads(body.decode("utf-8") or "{}")
            except (json.JSONDecodeError, UnicodeDecodeError):
                return self._json(400, {"error": "invalid_json_body"})
            username = payload.get("username")
            password = payload.get("password")
            if not isinstance(username, str) or not isinstance(password, str):
                return self._json(400, {"error": "invalid_credentials_format"})
            if _constant_time_eq(username, _ADMIN_USER) and _constant_time_eq(password, _ADMIN_PASS):
                token = secrets.token_hex(32)
                _VALID_TOKENS.add(token)
                return self._json(200, {"token": token, "expires_in": 1800, "token_type": "bearer"})
            return self._json(401, {"error": "invalid_credentials"})

        if path == "/api/v1/products":
            if self.command not in ("GET", "HEAD"):
                return self._json(405, {"error": "method_not_allowed"})
            auth = self.headers.get("Authorization", "")
            token = auth[7:] if auth[:7].lower() == "bearer " else ""
            if not token or token not in _VALID_TOKENS:
                return self._json(401, {"error": "authentication_required"})
            return self._json(200, {"products": SEARCH_CATALOG, "total": len(SEARCH_CATALOG)})

        # --demo only: deliberately missing global error handler. Malformed or
        # type-confused JSON bodies make it leak a canonical stack trace in a
        # 500 response (proof target for probe_error_disclosure).
        if DEMO_LEAK and path == "/api/v1/parse":
            if self.command not in ("GET", "HEAD", "POST"):
                return self._json(405, {"error": "method_not_allowed"})
            if self.command in ("GET", "HEAD"):
                return self._json(200, {"endpoint": "parse",
                                        "usage": "POST JSON body containing a string 'payload' field"})
            raw = self._read_body()
            try:
                obj = json.loads(raw.decode("utf-8") if raw else "")
            except Exception:
                return self._respond(500, demo_leak_body("json").encode("utf-8"), "application/json")
            if not isinstance(obj, dict):
                return self._respond(500, demo_leak_body("type").encode("utf-8"), "application/json")
            payload = obj.get("payload")
            if payload is None:
                return self._json(400, {"error": "missing_required_parameter", "param": "payload"})
            if not isinstance(payload, str):
                return self._respond(500, demo_leak_body("type").encode("utf-8"), "application/json")
            return self._json(200, {"normalized": payload.strip()})

        # everything else: strict uniform 404 (covers /.env, /.git/*, admin
        # panels, backup dumps, /internal/*, /graphql, fuzzed paths, ...)
        return self._not_found()

    # -- entry points ------------------------------------------------------

    def do_GET(self):   # noqa: N802
        try:
            self._route()
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            self._json(500, {"error": "internal"})  # never leak a traceback

    def do_HEAD(self):  # noqa: N802
        try:
            self._route()
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            self._json(500, {"error": "internal"})

    def do_POST(self):  # noqa: N802
        try:
            self._route()
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            self._json(500, {"error": "internal"})


def main() -> int:
    parser = argparse.ArgumentParser(description="Hardened local web lab (weblocal)")
    parser.add_argument("--port", type=int, default=8791)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--log", default=None, help="Path to JSONL access log (appended)")
    parser.add_argument("--demo", action="store_true",
                        help="Enable deliberately leaky /api/v1/parse demo endpoint "
                             "(stack-trace disclosure) to prove detection. Default OFF.")
    parser.add_argument("--offensive-fixture", action="store_true",
                        help="Enable the isolated positive offensive regression fixture. "
                             "Default hardened lab remains unchanged.")
    args = parser.parse_args()

    global APP_JS, DEMO_LEAK, OFFENSIVE_FIXTURE
    if args.demo:
        DEMO_LEAK = True
        APP_JS = APP_JS_BASE + DEMO_JS_EXTRA
    if args.offensive_fixture:
        OFFENSIVE_FIXTURE = True
        APP_JS = APP_JS_BASE + OFFENSIVE_JS_EXTRA + (DEMO_JS_EXTRA if args.demo else "")

    init_log(args.log)
    httpd = ThreadingHTTPServer((args.host, args.port), LabHandler)
    httpd.daemon_threads = True

    print("=" * 64)
    print(" 🛡  HARDENED LOCAL WEB LAB  (weblocal)")
    print("=" * 64)
    print(f"    Target : http://{args.host}:{args.port}")
    print(f"    Access log: {args.log or '(disabled)'}")
    if DEMO_LEAK:
        print("    ⚠  DEMO MODE: /api/v1/parse sengaja bocor stack trace (ujian deteksi)")
    if OFFENSIVE_FIXTURE:
        print("    ⚠  OFFENSIVE FIXTURE: intentional XSS/SSTI/GraphQL/redirect lab surfaces enabled")
    print()
    print("  Hardening active:")
    print("   - strict CSP / X-Frame-Options / nosniff / referrer-policy")
    print("   - no CORS headers, no HTML forms (no CSRF surface)")
    print("   - zero user-input reflection (static HTML + JSON APIs)")
    print("   - uniform 404 for .env/.git/backups/admin panels/graphql")
    print("   - auth required on /api/v1/products (server-validated tokens)")
    print("   - no stack traces, no version banners, no disk-served files")
    print()
    print(f"  Demo admin (printed once, random per boot):")
    print(f"   - user: {_ADMIN_USER}")
    print(f"   - pass: {_ADMIN_PASS}")
    print("=" * 64)
    sys.stdout.flush()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
