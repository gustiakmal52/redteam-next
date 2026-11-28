"""Regression tests for the modern primitive sweep (XBOW-grade coverage).

Each primitive is validated against a deterministic local fixture that either
exposes the vulnerability exactly or is clean, so both the positive proof and
the anti-false-positive behavior are covered:

- Web Cache Deception: cache marks HIT and replays the personalized body to a
  session-less client; a cache that never serves HITs must stay unverified.
- Host Header Poisoning: generated link embeds the attacker host; text echo
  without a generated URL must not verify.
- CRLF Injection: injected header materializes in response headers.
- XXE: differential between a defined-entity document and an undefined-entity
  control document is required evidence.
"""

import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from redteam_agent.core.exploit_engine import ExploitEngine
from redteam_agent.core.findings import FindingStatus
from redteam_agent.core.http_verifier import HTTPVerifier
from redteam_agent.core.scope_manager import ScopeManager
from redteam_agent.core.traffic_controller import TrafficController

CANARY = "poison-canary.invalid"


class _VulnHandler(BaseHTTPRequestHandler):
    """Fixture: cacheable personalized profile, poisoned reset link, CRLF echo."""

    def _send(self, body: bytes, status: int = 200, headers: dict | None = None):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):  # noqa: N802 - stdlib handler API
        parsed = urllib.parse.urlparse(self.path)
        path, query = parsed.path, urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        profile_body = json.dumps({"user": "victim@example.test", "role": "member"}).encode()

        # Web cache deception: /profile.css and /profile.js serve the profile
        # body and are cacheable (HIT on second view of the same path).
        if path in ("/profile", "/profile.css", "/profile.js", "/profile/nonexistent.css"):
            self._send(profile_body, headers={"X-Cache": "HIT" if path != "/profile" else "MISS"})
            return

        # Host header poisoning: the "reset" page generates a link from
        # X-Forwarded-Host (a realistic front-end pattern).
        if path == "/reset":
            forwarded = self.headers.get("X-Forwarded-Host") or self.headers.get("Host") or "app.test"
            host = forwarded.split(",")[0].strip()
            if host != "app.test" and not host.endswith("app.test"):
                # Only generate the link for genuinely injected hosts; the
                # direct-Host variant is absorbed by the virtual host config.
                if self.headers.get("X-Forwarded-Host"):
                    self._send(f'<html><body>Reset link: https://{host}/reset?token=abc123</body></html>'.encode())
                    return
            self._send(b"<html><body>https://app.test/reset?token=abc123</body></html>")
            return

        # CRLF: the reflect endpoint passes the parameter through a raw status
        # line injection simulation by emitting a genuine injected header.
        if path == "/reflect":
            raw = query.get("q", [""])[0]
            if "\r\n" in raw:
                injected = raw.split("\r\n", 1)[1]
                name, _, value = injected.partition(":")
                if name.strip().lower() == "x-injected-canary":
                    self._send(b"<html><body>ok</body></html>", headers={"X-Injected-Canary": value.strip()})
                    return
            self._send(f"<html><body>{raw}</body></html>".encode())
            return

        # XXE: /api/xml parses DOCTYPE docs. A defined file:// entity resolves
        # into the body; the undefined-entity control doc errors differently.
        if path == "/api/xml":
            length = int(self.headers.get("Content-Length", 0))
            doc = self.rfile.read(length).decode("utf-8", errors="replace")
            if "undefined_entity_ref" in doc:
                self._send(b'{"error": "undefined entity undefined_entity_ref"}', status=400)
            elif "xxe_canary" in doc and "file://" in doc:
                self._send(b'{"result": "fixture-hostname-01"}')
            else:
                self._send(b'{"error": "bad xml"}', status=400)
            return

        self._send(b"<html><body>static index</body></html>")

    def do_POST(self):  # noqa: N802 - stdlib handler API
        parsed = urllib.parse.urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0))
        doc = self.rfile.read(length).decode("utf-8", errors="replace")
        if parsed.path == "/api/xml":
            if "undefined_entity_ref" in doc:
                self._send(b'{"error": "undefined entity undefined_entity_ref"}', status=400)
            elif "xxe_canary" in doc and "file://" in doc:
                self._send(b'{"result": "fixture-hostname-01"}')
            else:
                self._send(b'{"error": "bad xml"}', status=400)
            return
        self._send(b'{"error": "bad xml"}', status=400)

    def log_message(self, *_args):
        return


class _CleanHandler(_VulnHandler):
    """Same app, no cache headers, no host poisoning, strict CRLF handling."""

    def do_GET(self):  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        path, query = parsed.path, urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if path == "/profile":
            self._send(json.dumps({"user": "victim@example.test"}).encode())
            return
        if path == "/profile.css":
            self._send(b"body{color:#111}", headers={"X-Cache": "HIT"})
            return
        if path == "/reset":
            self._send(b"<html><body>https://app.test/reset?token=abc123</body></html>")
            return
        if path == "/reflect":
            raw = query.get("q", [""])[0]
            self._send(f"<html><body>{raw}</body></html>".encode())
            return
        self._send(b"<html><body>static index</body></html>")

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        self._send(b'{"error": "bad xml"}', status=400)


@pytest.fixture(scope="module")
def servers():
    vuln = ThreadingHTTPServer(("127.0.0.1", 0), _VulnHandler)
    clean = ThreadingHTTPServer(("127.0.0.1", 0), _CleanHandler)
    for server in (vuln, clean):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    yield (f"http://127.0.0.1:{vuln.server_port}", f"http://127.0.0.1:{clean.server_port}")
    for server in (vuln, clean):
        server.shutdown()
        server.server_close()


def _engine() -> ExploitEngine:
    scope = ScopeManager(["127.0.0.1"], allow_private=True, resolve_dns=False)
    traffic = TrafficController("FAST", max_requests=512, verification_reserve=8)
    verifier = HTTPVerifier(scope_manager=scope, traffic_controller=traffic, module="primitive_test")
    return ExploitEngine(verifier)


# -- Web Cache Deception ------------------------------------------------------

def test_cache_deception_verified_on_vulnerable_fixture(servers):
    engine = _engine()
    finding = engine.test_cache_deception(f"{servers[0]}/profile")
    assert finding is not None
    assert finding["status"] == FindingStatus.VERIFIED.value
    assert any(check["name"] == "anonymous_replay_serves_personalized_body" and check["passed"]
               for check in finding["verification_checks"])
    assert finding["evidence"][0]["cache_hit_marker"]


def test_cache_deception_stays_away_on_clean_fixture(servers):
    engine = _engine()
    # /profile.css is a real static asset (different body from /profile), and
    # the clean app never serves the profile on decorated paths.
    assert engine.test_cache_deception(f"{servers[1]}/profile") is None


# -- Host Header Poisoning ----------------------------------------------------

def test_host_header_poisoning_verified_via_forwarded_host(servers):
    engine = _engine()
    finding = engine.test_host_header_poisoning(f"{servers[0]}/reset")
    assert finding is not None
    assert finding["status"] == FindingStatus.VERIFIED.value
    assert CANARY in json.dumps(finding["evidence"])


def test_host_header_poisoning_rejects_clean_fixture(servers):
    engine = _engine()
    assert engine.test_host_header_poisoning(f"{servers[1]}/reset") is None


# -- CRLF Injection -----------------------------------------------------------

def test_crlf_injection_verified_when_header_materializes(servers):
    engine = _engine()
    finding = engine.test_crlf_injection(f"{servers[0]}/reflect?q=x")
    assert finding is not None
    assert finding["status"] == FindingStatus.VERIFIED.value
    assert finding["evidence"][0]["injected_header"].lower() == "x-injected-canary"


def test_crlf_body_echo_alone_never_verifies(servers):
    engine = _engine()
    # Clean handler body-echoes the payload but no header appears.
    assert engine.test_crlf_injection(f"{servers[1]}/reflect?q=x") is None


# -- XXE ----------------------------------------------------------------------

def test_xxe_differential_resolves_on_vulnerable_fixture(servers):
    engine = _engine()
    finding = engine.test_xxe_file_read(f"{servers[0]}/api/xml")
    assert finding is not None
    assert finding["status"] == FindingStatus.VERIFIED.value
    assert finding["evidence"][0]["differential_vs_undefined_entity"] is True


def test_xxe_uniform_parser_error_stays_likely(servers):
    engine = _engine()
    # Clean fixture rejects both documents identically (same 400 body shape),
    # but the error signature still classifies the finding honestly as LIKELY.
    finding = engine.test_xxe_file_read(f"{servers[1]}/api/xml")
    if finding is not None:
        assert finding["status"] != FindingStatus.VERIFIED.value
        assert finding["missing_evidence"]


# -- Raw request evidence ------------------------------------------------------

def test_findings_carry_reproduction_evidence(servers):
    engine = _engine()
    finding = engine.test_crlf_injection(f"{servers[0]}/reflect?q=x")
    assert finding is not None
    assert finding.get("reproduction_curl", "").startswith("curl")
    assert finding.get("raw_request") or finding.get("raw_response")


# -- Deep-engine planner integration -----------------------------------------

def test_planner_creates_modern_primitive_hypotheses(servers):
    from redteam_agent.core.deep_exploit_engine import DeepExploitEngine

    engine = DeepExploitEngine(HTTPVerifier(
        scope_manager=ScopeManager(["127.0.0.1"], allow_private=True, resolve_dns=False),
        traffic_controller=TrafficController("FAST", max_requests=128),
        module="planner_test"), exploit_mode="OFFENSIVE")
    records = [
        {"url": f"{servers[0]}/profile", "method": "GET", "request_type": "REST",
         "source_file": "app.js", "auth_required": False},
        {"url": f"{servers[0]}/reflect?q=x", "method": "GET", "request_type": "REST",
         "source_file": "app.js", "auth_required": False},
        {"url": f"{servers[0]}/api/xml", "method": "POST", "request_type": "REST",
         "source_file": "app.js", "auth_required": False},
    ]
    techniques = {h.technique for h in engine.build_attack_plan(records)}
    assert "cache_deception" in techniques
    assert "host_header_poisoning" in techniques
    assert "crlf_injection" in techniques
    assert "xxe_file_read" in techniques


def test_focus_routing_reaches_modern_primitives(servers):
    """--vuln-class crlf must route the plan to the CRLF primitive and verify
    against the vulnerable fixture through the full planner pipeline."""
    from redteam_agent.core.deep_exploit_engine import DeepExploitEngine

    engine = DeepExploitEngine(HTTPVerifier(
        scope_manager=ScopeManager(["127.0.0.1"], allow_private=True, resolve_dns=False),
        traffic_controller=TrafficController("FAST", max_requests=128),
        module="planner_test"), exploit_mode="OFFENSIVE")
    records = [{"url": f"{servers[0]}/reflect?q=x", "method": "GET", "request_type": "REST",
                "source_file": "app.js", "auth_required": False}]
    report = engine.run_discovered(records, techniques=["crlf"], request_budget=64)
    verified = [f for f in report.get("findings", []) if f.get("status") == "VERIFIED"]
    assert any(f.get("type", "").startswith("CRLF") for f in verified)
