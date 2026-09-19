"""Post-Auth Behavioral Hunter tests — differential auth, BOLA with session,
excessive data exposure, and mass assignment.

Discipline: findings are LIKELY candidates with explicit missing_evidence;
nothing is VERIFIED without the full tuple
PRODUCT-CONTROL -> STATE-CHANGE -> POST-CHANGE-CALL -> EFFECT.
"""
import json

from redteam_agent.core.http_verifier import HTTPVerifier
from redteam_agent.core.post_auth_hunter import PostAuthHunter
from redteam_agent.core.scope_manager import ScopeManager


def _verifier():
    verifier = HTTPVerifier(scope_manager=ScopeManager(["example.com"], resolve_dns=False))
    verifier.set_session_auth({"Authorization": "Bearer tok"}, netloc="example.com")
    return verifier


def _resp(status=200, body="", headers=None):
    return {
        "success": 200 <= status < 400, "status_code": status,
        "headers": headers or {}, "body": body,
        "response_time_sec": 0.02, "raw_request": "", "raw_response": "",
        "redirects": [],
    }


def _hunter(authed_resp, anon_resp):
    verifier = _verifier()
    verifier.send_http_request = lambda *a, **k: authed_resp
    hunter = PostAuthHunter(verifier)
    hunter.anonymous_verifier.send_http_request = lambda *a, **k: anon_resp
    return hunter


def test_differential_auth_detects_unauthenticated_access():
    # Anonymous path returns the same data the authenticated path returns —
    # but the authenticated path is the control proving the endpoint exists
    # for logged-in users; anonymous reaching it with data is the finding.
    anon_body = json.dumps({"records": [{"id": 1, "name": "x"}] * 20})
    authed_body = json.dumps({"records": [{"id": 1, "name": "x", "owner": "me"}] * 20})
    hunter = _hunter(_resp(200, authed_body), _resp(200, anon_body))
    finding = hunter.differential_auth("https://example.com/api/v1/records")
    assert finding is not None
    assert finding["status"] == "LIKELY"
    assert "Unauthenticated Access" in finding["type"]
    assert finding["evidence"][0]["anonymous_status"] == 200
    assert finding["missing_evidence"]


def test_differential_auth_control_401_returns_none():
    hunter = _hunter(
        _resp(200, json.dumps({"records": []})),
        _resp(401, json.dumps({"error": "auth_required"})),
    )
    assert hunter.differential_auth("https://example.com/api/v1/records") is None


def test_differential_auth_identical_public_endpoint_returns_none():
    body = json.dumps({"public": "info"})
    hunter = _hunter(_resp(200, body), _resp(200, body))
    assert hunter.differential_auth("https://example.com/api/v1/records") is None


def test_differential_auth_empty_anonymous_body_returns_none():
    hunter = _hunter(
        _resp(200, json.dumps({"records": [{"id": 1}]})),
        _resp(200, " "),
    )
    assert hunter.differential_auth("https://example.com/api/v1/records") is None


def test_bola_sequential_auth_detects_foreign_objects():
    verifier = _verifier()
    bodies = {
        "https://example.com/api/v1/orders/100": json.dumps({"order": "mine", "items": ["a"] * 5}),
        "https://example.com/api/v1/orders/101": json.dumps({"order": "other-1", "items": ["b"] * 50}),
        "https://example.com/api/v1/orders/102": json.dumps({"order": "other-2", "items": ["c"] * 50}),
        "https://example.com/api/v1/orders/103": json.dumps({"order": "other-3", "items": ["d"] * 50}),
    }
    verifier.send_http_request = lambda url, *a, **k: _resp(200, bodies.get(url, "{}"))
    hunter = PostAuthHunter(verifier)
    finding = hunter.bola_sequential_auth("https://example.com/api/v1/orders/100")
    assert finding is not None
    assert finding["status"] == "LIKELY"
    assert "BOLA" in finding["type"]
    assert finding["evidence"][0]["object_ids_tested"] == ["100", "101", "102", "103"]


def test_bola_sequential_auth_no_id_returns_none():
    hunter = _hunter(_resp(200, "ok"), _resp(200, "ok"))
    assert hunter.bola_sequential_auth("https://example.com/api/v1/orders") is None


def test_bola_sequential_auth_401_on_foreign_returns_none():
    verifier = _verifier()
    verifier.send_http_request = lambda url, *a, **k: (
        _resp(200, json.dumps({"order": "mine"})) if url.endswith("/100")
        else _resp(401, json.dumps({"error": "forbidden"})))
    hunter = PostAuthHunter(verifier)
    assert hunter.bola_sequential_auth("https://example.com/api/v1/orders/100") is None


def test_excessive_data_exposure_detects_sensitive_keys():
    hunter = _hunter(
        _resp(200, json.dumps({"user": {"email": "a@b.c", "phone": "123", "api_key": "k"}})),
        _resp(401, "{}"),
    )
    finding = hunter.excessive_data_exposure("https://example.com/api/v1/me")
    assert finding is not None
    assert "Excessive Data Exposure" in finding["type"]
    keys = finding["evidence"][0]["sensitive_keys"]
    assert "email" in keys and "api_key" in keys


def test_excessive_data_exposure_clean_json_returns_none():
    hunter = _hunter(
        _resp(200, json.dumps({"user": {"name": "alice", "id": 1}})),
        _resp(401, "{}"),
    )
    assert hunter.excessive_data_exposure("https://example.com/api/v1/me") is None


def test_mass_assignment_acceptance_detected():
    verifier = _verifier()
    verifier.send_http_request = lambda *a, **k: _resp(200, json.dumps({"ok": True}))
    hunter = PostAuthHunter(verifier)
    finding = hunter.mass_assignment("https://example.com/api/v1/users")
    assert finding is not None
    assert "Mass Assignment" in finding["type"]
    assert finding["evidence"][0]["field_tested"] in ("role", "is_admin", "admin")


def test_mass_assignment_rejected_returns_none():
    verifier = _verifier()
    verifier.send_http_request = lambda *a, **k: _resp(400, json.dumps({"error": "bad"}))
    hunter = PostAuthHunter(verifier)
    assert hunter.mass_assignment("https://example.com/api/v1/users") is None