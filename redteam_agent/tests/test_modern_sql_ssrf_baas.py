from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from redteam_agent.core.cloud_baas_hunter import CloudBaaSHunter
from redteam_agent.core.browser_verifier import BrowserVerifier
from redteam_agent.core.deep_exploit_engine import DeepExploitEngine, OffensiveHypothesis
from redteam_agent.core.http_verifier import HTTPVerifier
from redteam_agent.core.reference_clients import ReferenceIntelClient
from redteam_agent.core.scope_manager import ScopeManager
from redteam_agent.core.sql_strategies import strategy_for
from redteam_agent.core.ssrf_verifier import callback_proof, callback_variants
from redteam_agent.core.traffic_controller import TrafficController


def _response(body: str = "ok", *, elapsed: float = .02, status: int = 200) -> dict:
    return {
        "success": 200 <= status < 400, "status_code": status,
        "headers": {"Content-Type": "application/json"}, "body": body,
        "response_time_sec": elapsed, "raw_request": "", "raw_response": body,
    }


def test_firebase_evidence_has_structure_not_raw_credential_values():
    class FakeVerifier:
        def send_http_request(self, url, **kwargs):
            if "shallow=true" in url:
                return _response('{"users":{"u1":"present"}}')
            return _response(json.dumps({
                "users": {"u1": {"email": "owner@example.test",
                                   "password": "RAW_PASSWORD_SHOULD_NOT_LEAK",
                                   "token": "RAW_TOKEN_SHOULD_NOT_LEAK"}}}
            ))

    result = CloudBaaSHunter(verifier=FakeVerifier()).audit_firebase(
        "https://fixture.firebaseio.com")
    serialized = json.dumps(result)
    assert "RAW_PASSWORD_SHOULD_NOT_LEAK" not in serialized
    assert "RAW_TOKEN_SHOULD_NOT_LEAK" not in serialized
    response = result["findings"][0]["test"]["response"]
    assert response["raw_body_stored"] is False
    assert response["raw_excerpt_stored"] is False
    assert "users.u1.password" in response["sensitive_field_paths"]
    assert "users.u1.token" in response["sensitive_field_paths"]
    assert response["body_sha256"]


def test_sql_strategy_renders_dialect_specific_modern_probes():
    assert "SLEEP(4)" in strategy_for("mysql").render("time_true", delay_sec=4)
    assert "pg_sleep(4)" in strategy_for("postgres").render("time_true", delay_sec=4)
    assert "WAITFOR DELAY" in strategy_for("mssql").render("time_true", delay_sec=4)
    assert "DBMS_PIPE.RECEIVE_MESSAGE" in strategy_for("oracle").render("time_true", delay_sec=4)
    assert strategy_for("sqlite").render("time_true", delay_sec=4) == ""


def test_adaptive_sqli_uses_observed_json_field_and_repeatable_boolean_differential():
    verifier = HTTPVerifier(scope_manager=ScopeManager(["example.test"], resolve_dns=False))

    def fake(url, method="GET", headers=None, body=None, **kwargs):
        body = body or ""
        if "1=2" in body:
            return _response('{"rows":[]}', status=200)
        if "1=1" in body:
            return _response('{"rows":[{"id":1}]}', status=200)
        return _response('{"rows":[{"id":1}]}', status=200)

    verifier.send_http_request = fake
    result = verifier.verify_sqli_adaptive(
        "https://example.test/api/search", "filter", method="POST",
        input_location="json", body='{"filter":"x","limit":1}',
        dialect="postgres", request_budget=10)
    assert result["verified"] is True
    assert result["proof_mode"] == "boolean_differential"
    assert result["dialect"] == "postgres"
    assert all(item["request"]["method"] == "POST" for item in result["attempts"])
    assert all('"filter"' in (item["request"]["body"] or "") for item in result["attempts"])


def test_ssrf_callback_proof_requires_token_bound_interaction():
    variants = callback_variants("https://oast.researcher.test/hit/{token}", token="rt-123")
    assert variants
    assert any(item["label"] == "percent_encoded" for item in variants)
    assert callback_proof({"observed": True, "request_id": "i-1",
                           "request_url": "https://oast.researcher.test/hit/rt-123"},
                          token="rt-123")["verified"] is True
    assert callback_proof({"observed": True, "request_id": "i-1",
                           "request_url": "https://oast.researcher.test/hit/other"},
                          token="rt-123")["verified"] is False


def test_scope_explicit_scheme_and_port_are_hard_boundaries():
    scope = ScopeManager(["https://app.test:8443"], resolve_dns=False)
    assert scope.check_url("https://app.test:8443/api", active=True)["allowed"] is True
    assert scope.check_url("https://app.test:443/api", active=True)["allowed"] is False
    assert scope.check_url("http://app.test:8443/api", active=True)["allowed"] is False


def test_reference_client_returns_metadata_only_and_marks_hypotheses():
    class FakeReferenceVerifier:
        def send_http_request(self, url, **kwargs):
            if "nvd.nist.gov" in url:
                return _response(json.dumps({"totalResults": 1, "vulnerabilities": [{
                    "cve": {"id": "CVE-2099-0001", "published": "2099-01-01",
                             "lastModified": "2099-01-01", "descriptions": [{"lang": "en", "value": "test"}],
                             "references": []}
                }]}))
            if "cisa.gov" in url:
                return _response(json.dumps({"catalogVersion": "1.0", "vulnerabilities": [{
                    "cveID": "CVE-2099-0001", "vendorProject": "Fixture", "product": "Fixture Web",
                    "vulnerabilityName": "Fixture SSRF", "shortDescription": "controlled fixture"
                }]}))
            return _response(json.dumps({"ghsa_id": "GHSA-aaaa-bbbb-cccc", "cve_id": "CVE-2099-0001",
                                         "summary": "fixture", "description": "metadata only"}))

    client = ReferenceIntelClient(FakeReferenceVerifier())
    nvd = client.nvd_keyword("Fixture SSRF")
    kev = client.cisa_kev("Fixture")
    ghsa = client.github_advisory("GHSA-aaaa-bbbb-cccc")
    assert nvd["records"][0]["cve_id"] == "CVE-2099-0001"
    assert kev["records"][0]["source"] == "CISA KEV"
    assert ghsa["hypothesis_only"] is True
    assert ghsa["automatic_exploit_execution"] is False


def test_deep_ssrf_keeps_parser_variants_but_only_verifies_oast_proof(monkeypatch):
    class FixedUUID:
        hex = "cafebabecafebabecafebabecafebabe"

    monkeypatch.setattr("redteam_agent.core.deep_exploit_engine.uuid.uuid4", lambda: FixedUUID())

    class FakeVerifier:
        def send_http_request(self, url, method="GET", headers=None, body=None, **kwargs):
            return _response('{"result":"accepted"}')

    hypothesis = OffensiveHypothesis(
        technique="ssrf_callback", endpoint="https://app.test/api/fetch", method="POST",
        field="callback_url", input_location="json", body='{"callback_url":""}',
        context={"controlled_callback_url": "https://oast.researcher.test/hit/{token}"},
    )
    engine = DeepExploitEngine(FakeVerifier(), exploit_mode="OFFENSIVE", request_budget=8)
    evidence = {"observed": True, "request_id": "interaction-1",
                "request_url": "https://oast.researcher.test/hit/rt-cafebabecafe"}
    result = engine._direct_ssrf(hypothesis, {
        "controlled_callback_url": "https://oast.researcher.test/hit/{token}",
        "controlled_callback_evidence": evidence,
    }, 8)
    assert result["verified"] is True
    assert result["finding"]["status"] == "VERIFIED"
    assert any(item["label"] == "percent_encoded" for item in result["observations"])


def test_browser_verifier_executes_canary_in_fresh_context():
    """Prove the adapter is a real execution check, not reflection metadata."""
    if not BrowserVerifier.runtime_available():
        pytest.skip("Playwright Chromium runtime is not installed")
    class ReflectHandler(BaseHTTPRequestHandler):
        def do_OPTIONS(self):  # noqa: N802 - stdlib handler API
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", self.headers.get("Origin", ""))
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
            self.send_header("Access-Control-Allow-Private-Network", "true")
            self.end_headers()

        def do_GET(self):  # noqa: N802 - stdlib handler API
            if urlsplit(self.path).path == "/cors":
                body = b'{"profile":"CORS_CONTROLLED_MARKER"}'
            else:
                value = parse_qs(urlsplit(self.path).query).get("q", [""])[0]
                body = f"<!doctype html><html><body>{value}</body></html>".encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json" if urlsplit(self.path).path == "/cors"
                             else "text/html; charset=utf-8")
            if urlsplit(self.path).path == "/cors":
                self.send_header("Access-Control-Allow-Origin", self.headers.get("Origin", ""))
                self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), ReflectHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        scope = ScopeManager(["127.0.0.1"], allow_private=True, resolve_dns=False)
        traffic = TrafficController("FAST", max_requests=12, verification_reserve=2)
        browser = BrowserVerifier(scope_manager=scope, traffic_controller=traffic, timeout_ms=6000)
        proof = browser.verify_reflected_xss(
            f"http://127.0.0.1:{server.server_port}/reflect", "q",
            "<script>window.__AGY_XSS_CANARY__=true</script>",
            canary="AGY_BROWSER_TEST",
        )
        browser.stop()
        assert proof["available"] is True
        assert proof["verified"] is True
        assert proof["browser_execution"] is True
        assert traffic.stats()["requests_by_module"].get("browser_verify", 0) >= 1

        cors_browser = BrowserVerifier(scope_manager=scope, traffic_controller=traffic, timeout_ms=6000)
        cors_proof = cors_browser.verify_cors_read(
            f"http://127.0.0.1:{server.server_port}/cors",
            researcher_origin=f"http://127.0.0.1:{server.server_port + 1}",
            expected_marker="CORS_CONTROLLED_MARKER",
        )
        cors_browser.stop()
        assert cors_proof["verified"] is True, cors_proof
        assert cors_proof["read_authenticated_response"] is True
        assert cors_proof["marker_found"] is True
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
