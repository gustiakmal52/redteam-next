"""Regression tests for the transport header/TLS profile layer.

Modern bot management scores header shape and TLS fingerprints before payload
inspection, so the profile layer must be deterministic: browser profile is the
default identity, caller headers win over the profile, program identification
headers win over callers, and the TLS context is hardened without disabling
certificate verification.
"""

import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import pytest

from redteam_agent.core.config import (
    DEFAULT_HEADER_PROFILE,
    HEADER_PROFILE_ENV,
    get_header_profile,
)
from redteam_agent.core.http_verifier import HTTPVerifier
from redteam_agent.core.scope_manager import ScopeManager
from redteam_agent.core.traffic_controller import TrafficController


class EchoHandler(BaseHTTPRequestHandler):
    """Echoes the received User-Agent and sec-ch-ua back as JSON."""

    def do_GET(self):  # noqa: N802 - stdlib handler API
        payload = json.dumps({
            "ua": self.headers.get("User-Agent", ""),
            "sec_ch_ua": self.headers.get("sec-ch-ua", ""),
            "sec_ch_ua_platform": self.headers.get("sec-ch-ua-platform", ""),
            "accept_language": self.headers.get("Accept-Language", ""),
            "request_purpose": self.headers.get("X-Request-Purpose", ""),
            "custom_caller": self.headers.get("X-Caller-Custom", ""),
        }).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_args):
        return


@pytest.fixture()
def echo_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), EchoHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()


def _make_verifier(**kwargs) -> HTTPVerifier:
    scope = kwargs.pop("scope", None) or ScopeManager(["127.0.0.1"], allow_private=True, resolve_dns=False)
    traffic = TrafficController("FAST", max_requests=64, verification_reserve=4)
    return HTTPVerifier(scope_manager=scope, traffic_controller=traffic, module="profile_test", **kwargs)


def test_default_profile_is_browser():
    profile = get_header_profile()
    assert DEFAULT_HEADER_PROFILE == "browser"
    assert "Chrome/" in profile["User-Agent"]
    assert profile["sec-ch-ua"]
    assert profile["sec-ch-ua-mobile"] == "?0"


def test_scanner_profile_is_explicitly_selectable():
    profile = get_header_profile("scanner")
    assert profile["User-Agent"] == "Gustiakmal-RedTeam-Verifier/2.1"


def test_unknown_profile_raises():
    with pytest.raises(ValueError):
        get_header_profile("does_not_exist")


def test_env_override_selects_profile(monkeypatch):
    monkeypatch.setenv(HEADER_PROFILE_ENV, "scanner")
    assert get_header_profile()["User-Agent"] == "Gustiakmal-RedTeam-Verifier/2.1"
    monkeypatch.delenv(HEADER_PROFILE_ENV)
    assert "Chrome/" in get_header_profile()["User-Agent"]


def test_verifier_default_uses_browser_profile():
    verifier = _make_verifier()
    assert verifier.header_profile_name == "browser"
    assert "sec-ch-ua" in verifier.header_profile
    assert "Gustiakmal-RedTeam" not in verifier.header_profile.get("User-Agent", "")


def test_verifier_respects_profile_argument():
    verifier = _make_verifier(header_profile="scanner")
    assert verifier.header_profile_name == "scanner"
    assert verifier.header_profile["User-Agent"] == "Gustiakmal-RedTeam-Verifier/2.1"


def test_caller_headers_override_profile(echo_server):
    verifier = _make_verifier()
    response = verifier.send_http_request(f"{echo_server}/", headers={"X-Caller-Custom": "custom-value"})
    body = json.loads(response.get("body", "{}"))
    assert body["custom_caller"] == "custom-value"
    # Profile UA still applies when the caller did not set one.
    assert "Chrome/" in body["ua"]


def test_caller_user_agent_wins_over_profile(echo_server):
    verifier = _make_verifier()
    response = verifier.send_http_request(f"{echo_server}/", headers={"User-Agent": "CallerOwned/9.9"})
    body = json.loads(response.get("body", "{}"))
    assert body["ua"] == "CallerOwned/9.9"


def test_program_headers_win_over_profile(echo_server, monkeypatch):
    monkeypatch.setenv("REDTEAM_REQUEST_PURPOSE", "BugcrowdResearch")
    try:
        verifier = _make_verifier()
        response = verifier.send_http_request(f"{echo_server}/")
        body = json.loads(response.get("body", "{}"))
        assert body["request_purpose"] == "BugcrowdResearch"
        assert "Chrome/" in body["ua"]
    finally:
        monkeypatch.delenv("REDTEAM_REQUEST_PURPOSE")


def test_tls_context_is_hardened_but_verifying():
    verifier = _make_verifier()
    context = verifier.ssl_context
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2
    assert verifier._tls_alpn == ["http/1.1"]
    # TLS-level compression stays off (CRIME mitigation).
    assert bool(context.options & ssl.OP_NO_COMPRESSION)


def test_explicit_ssl_context_is_preserved():
    custom = ssl.create_default_context()
    verifier = _make_verifier(ssl_context=custom)
    assert verifier.ssl_context is custom


def test_raw_request_evidence_reflects_profile(echo_server):
    verifier = _make_verifier()
    response = verifier.send_http_request(f"{echo_server}/")
    raw = response.get("raw_request", "")
    assert "Chrome/" in raw
    assert "Gustiakmal-RedTeam-Verifier" not in raw


def test_scanner_profile_available_for_differential_work(echo_server):
    """The scanner identity stays reachable so researchers can run explicit
    differential tests between transport identities when a program requires
    researcher identification via the User-Agent itself."""
    verifier = _make_verifier(header_profile="scanner")
    response = verifier.send_http_request(f"{echo_server}/")
    body = json.loads(response.get("body", "{}"))
    assert body["ua"] == "Gustiakmal-RedTeam-Verifier/2.1"
