"""Regression coverage for the P0/P1 integrity and control-plane fixes."""

import asyncio
import json
import pathlib
import ssl
import sys

from fastapi.testclient import TestClient

from redteam_agent.core.config import DEFAULT_REQUEST_BUDGET, CVSS_VECTORS, cvss3_score
from redteam_agent.core.findings import FindingStatus, normalized_finding
from redteam_agent.core.fp_killer import kill_pass
from redteam_agent.core.http_verifier import HTTPVerifier
from redteam_agent.core.task_manager import ProcessRegistry, task_manager
from redteam_agent.core.traffic_controller import TrafficController
from redteam_agent.core.engagement import EngagementProfile
from redteam_agent.core.scope_manager import ScopeManager
from redteam_agent.discovery.request_corpus import endpoint_records_from_corpus


def test_reflection_only_xss_is_likely_at_shared_gate():
    finding = normalized_finding(
        finding_type="Cross-Site Scripting (Reflected)", target="https://example.test",
        endpoint="https://example.test/search?q=x", status=FindingStatus.VERIFIED,
        confidence=.95, verification_checks=[
            {"name": "unescaped_html_reflection", "passed": True},
            {"name": "browser_execution", "passed": False},
        ], vrt_triage={"is_approved": True},
    )
    result = kill_pass([finding])
    assert result["submission_ready"] == []
    assert finding["status"] == FindingStatus.LIKELY.value
    assert finding["disposition"] == "LIKELY_REFLECTION_ONLY"
    assert "Browser execution canary in the reflected context" in finding["missing_evidence"]


def test_graphql_introspection_is_info_only_at_shared_gate():
    finding = normalized_finding(
        finding_type="GraphQL Introspection Enabled", target="https://example.test",
        endpoint="https://example.test/graphql", status=FindingStatus.VERIFIED,
        confidence=.95, verification_checks=[{"name": "schema_types_in_response", "passed": True}],
        vrt_triage={"is_approved": True},
    )
    result = kill_pass([finding])
    assert result["submission_ready"] == []
    assert finding["status"] == FindingStatus.DISCOVERED.value
    assert finding["disposition"] == "INFO_ONLY"
    assert finding["severity"] == "Informational"
    assert finding["cvss_score"] == 0.0


def test_validate_poc_cannot_promote_graphql_introspection(monkeypatch):
    from redteam_agent import app as app_module

    app_module.configure_web_auth("127.0.0.1")  # loopback: no token required
    task_manager.tasks.clear()
    engagement = EngagementProfile.from_mapping({
        "engagement_id": "TEST-POC", "authorization_reference": "TEST-ROE",
        "allowed_targets": ["example.com"], "expires_at": "2099-01-01T00:00:00Z",
        "prohibited_techniques": ["denial-of-service"], "allowed_techniques": ["graphql"],
        "objective": "Validate a deterministic GraphQL observation",
    })
    task = task_manager.create_task(
        "example.com", offensive=True, engagement=engagement,
        hunt_focus={"vulnerability_classes": ["graphql"]},
    )
    finding = normalized_finding(
        finding_type="GraphQL Introspection Enabled", target="example.com",
        endpoint="https://example.com/graphql", status=FindingStatus.SUSPECTED,
    )
    task.results["findings"] = [finding]

    class FakeVerifier:
        def send_http_request(self, *args, **kwargs):
            return {"status_code": 200, "body": json.dumps({"data": {"__schema": {"types": [{"name": "Query"}]}}}),
                    "headers": {}, "raw_request": "", "raw_response": ""}

    monkeypatch.setattr(app_module, "HTTPVerifier", lambda *args, **kwargs: FakeVerifier())
    response = TestClient(app_module.app).post(
        f"/api/findings/{task.task_id}/{finding['id']}/validate-poc"
    )
    assert response.status_code == 200
    data = response.json()
    assert data["validation"]["passed"] is True
    assert data["disposition"] == "INFO_ONLY"
    assert data["submission_ready"] is False
    assert task.results["vulnerabilities"] == []


def test_tls_verification_and_global_default_budget_are_on():
    verifier = HTTPVerifier()
    assert verifier.verify_tls is True
    assert verifier.ssl_context.verify_mode == ssl.CERT_REQUIRED
    assert verifier.ssl_context.check_hostname is True
    assert DEFAULT_REQUEST_BUDGET > 0
    assert TrafficController().stats()["max_requests"] == DEFAULT_REQUEST_BUDGET


def test_bugcrowd_session_headers_are_forced_from_environment(monkeypatch):
    monkeypatch.setenv("REDTEAM_REQUEST_PURPOSE", "BugcrowdResearch")
    monkeypatch.setenv("REDTEAM_BUGCROWD_NINJA", "researcher")
    verifier = HTTPVerifier()
    assert verifier.required_headers == {
        "X-Request-Purpose": "BugcrowdResearch",
        "X-Bugcrowd-Ninja": "researcher",
    }


def test_mathworks_auth_header_is_recognized_without_retaining_value():
    records, summary = endpoint_records_from_corpus({"requests": [{
        "url": "https://matlab.mathworks.com/service/core/authnz",
        "method": "POST",
        "headers": [{"name": "x-mw-authentication", "value": "secret-token"}],
    }]}, scope_manager=ScopeManager(["matlab.mathworks.com"], resolve_dns=False))
    assert summary["credentials_retained"] is False
    assert records[0].auth_required is True
    assert records[0].headers == {"x-mw-authentication": "captured-present"}
    assert "secret-token" not in json.dumps(records[0].to_dict())


def test_cvss_scores_are_deterministic_for_supported_vectors():
    first = {key: cvss3_score(vector) for key, vector in CVSS_VECTORS.items()}
    second = {key: cvss3_score(vector) for key, vector in CVSS_VECTORS.items()}
    assert first == second
    assert first["graphql_introspection"] == 5.3


def test_dashboard_requires_token_when_bound_beyond_loopback():
    from redteam_agent import app as app_module

    token = app_module.configure_web_auth("192.0.2.10", "unit-test-token")
    try:
        client = TestClient(app_module.app)
        assert client.get("/api/scan/list").status_code == 401
        login = client.post("/api/auth/login", json={"token": token})
        assert login.status_code == 200
        assert client.get("/api/scan/list").status_code == 200
    finally:
        app_module.configure_web_auth("127.0.0.1")


def test_process_registry_terminates_owned_child():
    async def scenario():
        registry = ProcessRegistry()
        process = await asyncio.create_subprocess_exec(
            sys.executable, "-c", "import time; time.sleep(60)"
        )
        registry.register_process(process)
        await registry.cancel_all()
        return process.returncode

    assert asyncio.run(scenario()) is not None


def test_dashboard_source_has_no_unsafe_inner_html_or_inline_handlers():
    app_js = pathlib.Path(__file__).parents[1] / "web" / "app.js"
    source = app_js.read_text(encoding="utf-8")
    assert "innerHTML" not in source
    assert "onclick=" not in source
