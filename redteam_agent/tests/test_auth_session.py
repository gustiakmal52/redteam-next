"""Session authentication support — login_session, set_session_auth, netloc
scoping, sensitive-header redaction, and auth-gated re-preflight.

Discipline: tokens are never returned from login_session; auth headers are
replayed only to the exact netloc they were obtained from; explicit caller
headers always take precedence; raw_request evidence redacts sensitive
headers.
"""
import json

import pytest

from redteam_agent.core.exploit_engine import ExploitEngine
from redteam_agent.core.http_verifier import HTTPVerifier
from redteam_agent.core.scope_manager import ScopeManager


def _verifier():
    return HTTPVerifier(scope_manager=ScopeManager(["example.com"], resolve_dns=False))


def _resp(status=200, body="", headers=None):
    return {
        "success": 200 <= status < 400, "status_code": status,
        "headers": headers or {}, "body": body,
        "response_time_sec": 0.02, "raw_request": "", "raw_response": "",
        "redirects": [],
    }


def test_has_session_auth_false_by_default():
    verifier = _verifier()
    assert verifier.has_session_auth() is False


def test_login_session_json_token():
    verifier = _verifier()
    verifier.send_http_request = lambda *a, **k: _resp(
        200, json.dumps({"token": "abc123"}), {"Content-Type": "application/json"})
    result = verifier.login_session("https://example.com/api/login", "alice", "pw")
    assert result["success"] is True
    assert result["token_source"] == "json:token"
    assert result["auth_netloc"] == "example.com"
    assert "Authorization" in result["auth_headers"]
    assert "abc123" not in json.dumps(result)
    assert verifier.has_session_auth() is True


def test_login_session_nested_json_token():
    verifier = _verifier()
    verifier.send_http_request = lambda *a, **k: _resp(
        200, json.dumps({"data": {"accessToken": "nested-tok"}}),
        {"Content-Type": "application/json"})
    result = verifier.login_session("https://example.com/api/login", "alice", "pw")
    assert result["success"] is True
    assert result["token_source"] == "json:data.accessToken"


def test_login_session_header_token():
    verifier = _verifier()
    verifier.send_http_request = lambda *a, **k: _resp(
        200, "ok", {"Authorization": "Bearer header-tok"})
    result = verifier.login_session("https://example.com/api/login", "alice", "pw")
    assert result["success"] is True
    assert result["token_source"] == "header:authorization"
    assert "Authorization" in result["auth_headers"]


def test_login_session_cookie():
    verifier = _verifier()
    verifier.send_http_request = lambda *a, **k: _resp(
        200, "ok", {"Set-Cookie": "session=abc123; Path=/; HttpOnly"})
    result = verifier.login_session("https://example.com/api/login", "alice", "pw")
    assert result["success"] is True
    assert result["token_source"] == "cookie"
    assert "Cookie" in result["auth_headers"]


def test_login_session_no_token_fails():
    verifier = _verifier()
    verifier.send_http_request = lambda *a, **k: _resp(200, "ok")
    result = verifier.login_session("https://example.com/api/login", "alice", "pw")
    assert result["success"] is False
    assert "no token found" in result["error"]
    assert verifier.has_session_auth() is False


def test_login_session_http_error():
    verifier = _verifier()
    verifier.send_http_request = lambda *a, **k: _resp(401, json.dumps({"error": "bad"}))
    result = verifier.login_session("https://example.com/api/login", "alice", "pw")
    assert result["success"] is False
    assert result["status_code"] == 401
    assert verifier.has_session_auth() is False


def test_auth_replay_same_netloc_only():
    verifier = HTTPVerifier(scope_manager=ScopeManager(["example.com", "evil.example.com"], resolve_dns=False))
    verifier.set_session_auth({"Authorization": "Bearer tok"}, netloc="example.com")
    seen = {}

    class FakeResp:
        status = 200
        headers = {"Content-Type": "text/html"}

        def read(self):
            return b"ok"

    def fake_open(req, timeout=None):
        seen[req.full_url] = dict(req.headers)
        return FakeResp()

    verifier._opener.open = fake_open
    verifier.send_http_request("https://example.com/api/me")
    verifier.send_http_request("https://evil.example.com/api/me")
    assert seen["https://example.com/api/me"].get("Authorization") == "Bearer tok"
    assert "Authorization" not in seen["https://evil.example.com/api/me"]


def test_auth_does_not_override_explicit_header():
    verifier = _verifier()
    verifier.set_session_auth({"Authorization": "Bearer session-tok"}, netloc="example.com")
    seen = {}

    class FakeResp:
        status = 200
        headers = {"Content-Type": "text/html"}

        def read(self):
            return b"ok"

    def fake_open(req, timeout=None):
        seen[req.full_url] = dict(req.headers)
        return FakeResp()

    verifier._opener.open = fake_open
    verifier.send_http_request("https://example.com/api/me",
                               headers={"Authorization": "Bearer identity-a"})
    assert seen["https://example.com/api/me"]["Authorization"] == "Bearer identity-a"


def test_raw_request_redacts_sensitive_headers():
    raw = HTTPVerifier._format_raw_request(
        "GET", "https://example.com/api/me",
        {"Authorization": "Bearer secret", "Cookie": "session=secret",
         "X-Api-Key": "k123", "User-Agent": "test"}, None)
    assert "[REDACTED]" in raw
    assert "Bearer secret" not in raw
    assert "session=secret" not in raw
    assert "k123" not in raw
    assert "User-Agent: test" in raw


def test_repreflight_auth_gated_after_login():
    """An endpoint that was 401 during preflight must be re-preflighted once a
    session token exists; the coverage ledger is updated honestly and the
    endpoint leaves the auth_gated list."""
    verifier = _verifier()
    verifier.set_session_auth({"Authorization": "Bearer tok"}, netloc="example.com")
    calls = {"products": 0}

    def gate(url, method="GET", **k):
        if "/api/v1/products" in url:
            calls["products"] += 1
            if calls["products"] <= 2:  # preflight GET + POST
                return _resp(401, json.dumps({"error": "auth_required"}),
                             {"Content-Type": "application/json"})
            return _resp(200, "<html>ok</html>", {"Content-Type": "text/html"})
        return _resp(200, "<html>ok</html>", {"Content-Type": "text/html"})

    verifier.send_http_request = gate
    exploit = ExploitEngine(verifier=verifier, exploit_mode="SAFE")
    audit = exploit.run_deep_exploit_audit(["https://example.com/api/v1/products"])
    by_endpoint = {c["endpoint"]: c for c in audit["coverage"]}
    products = by_endpoint["https://example.com/api/v1/products"]
    assert products["kind"] == "tested_after_login"
    assert products["get_status"] == 200
    assert "xss_get" in products["probes"]
    assert "https://example.com/api/v1/products" not in audit["auth_gated"]


def test_repreflight_stays_auth_gated_when_still_401():
    verifier = _verifier()
    verifier.set_session_auth({"Authorization": "Bearer tok"}, netloc="example.com")
    verifier.send_http_request = lambda *a, **k: _resp(
        401, json.dumps({"error": "auth_required"}), {"Content-Type": "application/json"})
    exploit = ExploitEngine(verifier=verifier, exploit_mode="SAFE")
    audit = exploit.run_deep_exploit_audit(["https://example.com/api/v1/products"])
    by_endpoint = {c["endpoint"]: c for c in audit["coverage"]}
    products = by_endpoint["https://example.com/api/v1/products"]
    assert products["kind"] == "auth_gated"
    assert "https://example.com/api/v1/products" in audit["auth_gated"]