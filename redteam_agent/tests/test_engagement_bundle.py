"""Authorization gating and portable evidence-bundle regressions."""

import datetime as dt
import hashlib
import io
import json
import subprocess
import sys
import zipfile

import pytest
from fastapi.testclient import TestClient

from redteam_agent.core.engagement import EngagementError, EngagementProfile
from redteam_agent.core.evidence_bundle import EvidenceBundleBuilder
from redteam_agent.core.task_manager import ScanTask, task_manager
from redteam_agent.core.scope_manager import ScopeManager
from redteam_agent.discovery.request_corpus import endpoint_records_from_corpus
from redteam_agent.core.deep_exploit_engine import DeepExploitEngine


def profile(**overrides):
    value = {
        "engagement_id": "BB-42",
        "authorization_reference": "ROE-42",
        "allowed_targets": ["example.com", "*.example.com"],
        "expires_at": "2099-12-31T23:59:59+08:00",
        "prohibited_techniques": ["denial-of-service", "destructive-write"],
        "allowed_techniques": ["idor", "bola"],
        "objective": "Prove a cross-tenant authorization failure",
    }
    value.update(overrides)
    return EngagementProfile.from_mapping(value)


def test_offensive_task_without_engagement_stays_on_exact_target():
    task = ScanTask("t", "example.com", offensive=True,
                    hunt_focus={"vulnerability_classes": ["xss"]})
    assert task.scope_manager.include == ["example.com"]
    assert task.auth_context == {}
    assert task.results["engagement"]["authorization_validated"] is False
    assert not task.scope_manager.check_url("https://api.example.com", active=True)["allowed"]
    with pytest.raises(EngagementError, match="additional offensive scope"):
        ScanTask("wide", "example.com", offensive=True, scope_in=["*.example.com"],
                 hunt_focus={"vulnerability_classes": ["xss"]})


def test_offensive_task_rejects_unfocused_generic_session():
    with pytest.raises(EngagementError, match="selected vulnerability classes"):
        ScanTask("t", "example.com", offensive=True, engagement=profile())


def test_idor_focus_can_discover_without_identities_but_cannot_prove_cross_account_access():
    task = ScanTask("t", "example.com", offensive=True, engagement=profile(),
                    hunt_focus={"vulnerability_classes": ["idor"]})
    report = DeepExploitEngine(request_budget=0).run_discovered([{
        "url": "https://example.com/api/invoices/1", "method": "GET",
        "auth_required": True, "headers": {"Authorization": "captured-present"},
    }], techniques=["idor"], auth_context=task.auth_context, request_budget=0)
    assert task.scope_manager.include == ["example.com", "*.example.com"]
    assert not any(item["technique"] == "authorization_cross_identity" for item in report["plan"])


def test_cli_identity_list_is_merged_into_focused_auth_context():
    task = ScanTask(
        "t", "example.com", offensive=True, engagement=profile(),
        hunt_focus={"vulnerability_classes": ["idor"]},
        authorization_identities=[
            {"name": "user_a", "headers": {"Authorization": "Bearer A"}, "owner_marker": "owner-A"},
            {"name": "user_b", "headers": {"Authorization": "Bearer B"}},
        ],
    )
    assert len(task.auth_context["identities"]) == 2
    assert task.results["discovery_policy"]["auth_identities"] == ["user_a", "user_b"]
    assert task.results["engagement"]["authorization_validated"] is True


def test_engagement_validates_expiry_scope_and_techniques():
    active = profile()
    active.validate_session(
        "https://app.example.com/api/invoices",
        requested_scope=["*.example.com"], techniques=["idor"],
        now=dt.datetime(2027, 1, 1, tzinfo=dt.timezone.utc),
    )
    with pytest.raises(EngagementError, match="outside engagement"):
        active.validate_session("https://outside.test")
    with pytest.raises(EngagementError, match="prohibited"):
        active.validate_session("example.com", techniques=["denial-of-service"])
    with pytest.raises(EngagementError, match="expired"):
        profile(expires_at="2020-01-01T00:00:00Z").validate_session("example.com")
    ongoing = profile(expires_at=None, allowed_techniques=[])
    ongoing.validate_session("api.example.com", techniques=["ssrf"])
    with pytest.raises(EngagementError, match="prohibited"):
        ongoing.validate_session("api.example.com", techniques=["denial-of-service"])
    bounty = EngagementProfile.from_mapping({
        "engagement_id": "public-program", "authorization_reference": "https://policy.example.test/program",
        "allowed_targets": ["*.example.com"],
    })
    task = ScanTask("bounty", "api.example.com", offensive=True, engagement=bounty,
                    hunt_focus={"vulnerability_classes": ["ssrf"]})
    assert task.scope_manager.include == ["*.example.com"]


def test_engagement_fails_closed_for_incomplete_records_and_scope_expansion():
    for record in ({}, {"engagement_id": "BB-42"}):
        with pytest.raises(EngagementError, match="engagement requires"):
            EngagementProfile.from_mapping(record).validate_session("example.com")
    for expiry in ("invalid", "2099-01-01T00:00:00"):
        with pytest.raises(EngagementError, match="expiry must"):
            profile(expires_at=expiry).validate_session("example.com")
    with pytest.raises(EngagementError, match="allowed techniques"):
        profile().validate_session("example.com", techniques=["ssrf"])
    exact_host = profile(allowed_targets=["example.com"])
    with pytest.raises(EngagementError, match="outside engagement scope"):
        exact_host.validate_session("example.com", requested_scope=["*.example.com"])
    with pytest.raises(EngagementError, match="outside engagement scope"):
        ScanTask("t", "example.com", offensive=True, engagement=exact_host,
                 scope_in=["outside.test"], hunt_focus={"vulnerability_classes": ["xss"]})
    task = ScanTask("t", "example.com", offensive=True, engagement=exact_host,
                    hunt_focus={"vulnerability_classes": ["idor"]},
                    authorization_identities=[{"owner_marker": "a"}, {"name": "b"}])
    assert task.scope_manager.include == ["example.com"]


def test_engagement_public_summary_does_not_export_contact_value():
    active = profile(emergency_contact="private-person@example.test +62-000")
    summary = active.public_summary()
    assert summary["emergency_contact_recorded"] is True
    assert summary["authorization_validated"] is False
    assert "not independently verified" in summary["authorization_basis"]
    assert "emergency_contact" not in summary
    assert "private-person" not in json.dumps(summary)


def test_offensive_task_rejects_unimplemented_generic_focus_class():
    unrestricted = profile(allowed_techniques=["business-logic"])
    with pytest.raises(EngagementError, match="target-specific planner"):
        ScanTask(
            "task-unsupported", "example.com", offensive=True,
            engagement=unrestricted,
            hunt_focus={"vulnerability_classes": ["business-logic"]},
        )


def test_evidence_bundle_is_redacted_and_hashes_match():
    token = "Bearer eyJabcdefgh.abcdefgh.abcdefghijklmnop"
    raw_sentinel = "local-raw-value-not-matched-by-token-regex"
    results = {
        "target": "https://example.com/",
        "status": "completed",
        "engagement": profile().public_summary(),
        "hunt_focus": {"objective": "IDOR", "vulnerability_classes": ["idor"]},
        "scope": {"include": ["example.com"]},
        "findings": [{"type": "Synthetic", "status": "SUSPECTED", "raw_request": token,
                      "_raw_value": raw_sentinel, "context": f"prefix {raw_sentinel} suffix"}],
        "stats": {},
    }
    payload = EvidenceBundleBuilder().build_zip(results)
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        assert set(archive.namelist()) == {"manifest.json", "results.json", "report.md"}
        manifest = json.loads(archive.read("manifest.json"))
        for name in ("results.json", "report.md"):
            content = archive.read(name)
            assert manifest["files"][name]["sha256"] == hashlib.sha256(content).hexdigest()
            assert manifest["files"][name]["bytes"] == len(content)
        assert token.encode() not in archive.read("results.json")
        safe_results = json.loads(archive.read("results.json"))
        assert safe_results["findings"][0]["_raw_value"] == "[REDACTED]"
        assert raw_sentinel.encode() not in archive.read("results.json")
        assert manifest["engagement"]["authorization_reference"] == "ROE-42"


def test_evidence_directory_is_published_once_with_matching_manifest(tmp_path):
    destination = tmp_path / "audit-1"
    builder = EvidenceBundleBuilder()
    builder.write_directory({"target": "example.com", "status": "completed", "stats": {}}, destination)
    manifest = json.loads((destination / "manifest.json").read_text())
    for name, entry in manifest["files"].items():
        assert hashlib.sha256((destination / name).read_bytes()).hexdigest() == entry["sha256"]
    with pytest.raises(FileExistsError):
        builder.write_directory({"target": "different.test", "status": "completed", "stats": {}}, destination)
    assert json.loads((destination / "manifest.json").read_text()) == manifest


def test_cli_rejects_existing_bundle_directory_before_scan(tmp_path):
    result = subprocess.run(
        [sys.executable, "-m", "redteam_agent.cli", "--url", "https://example.invalid",
         "--output-dir", str(tmp_path)], capture_output=True, text=True,
    )
    assert result.returncode == 2
    assert "--output-dir must be a new directory" in result.stderr


def test_bundle_report_includes_reproduction_for_verified_finding():
    report = EvidenceBundleBuilder().files({
        "target": "https://example.com", "status": "completed", "stats": {},
        "findings": [{"type": "Synthetic control", "status": "VERIFIED",
                      "reproduction_curl": "curl -i https://example.com/control",
                      "verification_checks": [{"name": "control", "passed": True}]}],
    })["report.md"].decode()
    assert "## Reproduction" in report
    assert "curl -i https://example.com/control" in report
    assert "## Verification Checks" in report
    assert "## Remediation" in report


def test_web_offensive_scan_starts_without_engagement_or_target_auth(monkeypatch):
    from redteam_agent import app as app_module

    async def no_scan(task):
        return None

    app_module.configure_web_auth("127.0.0.1")  # loopback: no token required
    monkeypatch.setattr(app_module.engine, "run_full_scan_pipeline", no_scan)
    response = TestClient(app_module.app).post(
        "/api/scan/start",
        json={"target": "example.com", "preset": "deep_bypass", "offensive": True,
              "vulnerability_classes": ["xss"]},
    )
    assert response.status_code == 200
    task = task_manager.get_task(response.json()["task_id"])
    assert task.scope_manager.include == ["example.com"]
    assert task.auth_context == {}


def test_web_offensive_scan_rejects_empty_engagement_before_launch():
    from redteam_agent import app as app_module

    app_module.configure_web_auth("127.0.0.1")
    response = TestClient(app_module.app).post("/api/scan/start", json={
        "target": "example.com", "offensive": True,
        "vulnerability_classes": ["xss"], "engagement": {},
    })
    assert response.status_code == 400


def test_web_offensive_scan_accepts_ongoing_bounty_policy_scope(monkeypatch):
    from redteam_agent import app as app_module

    async def no_scan(task):
        return None

    app_module.configure_web_auth("127.0.0.1")
    monkeypatch.setattr(app_module.engine, "run_full_scan_pipeline", no_scan)
    response = TestClient(app_module.app).post("/api/scan/start", json={
        "target": "api.example.com", "offensive": True,
        "vulnerability_classes": ["xss"],
        "engagement": {"engagement_id": "public-program",
                       "authorization_reference": "https://policy.example.test/program",
                       "allowed_targets": ["*.example.com"]},
    })
    assert response.status_code == 200
    task = task_manager.get_task(response.json()["task_id"])
    assert task.scope_manager.include == ["*.example.com"]


def test_direct_sandbox_and_cloud_audit_allow_no_engagement(monkeypatch):
    from redteam_agent import app as app_module

    app_module.configure_web_auth("127.0.0.1")  # loopback: no token required
    monkeypatch.setattr(app_module.HTTPVerifier, "send_http_request",
                        lambda self, *args, **kwargs: {"status_code": 200, "scope": {"in_scope": True}})
    monkeypatch.setattr(app_module.CloudBaaSHunter, "audit_firebase",
                        lambda self, url: {"target": url, "status": "synthetic"})
    client = TestClient(app_module.app)
    sandbox = client.post("/api/exploit/test", json={
        "url": "https://example.com/api/object/1",
        "technique": "idor",
        "payload": "2",
    })
    assert sandbox.status_code == 200
    cloud = client.post("/api/cloud/audit", json={
        "platform": "firebase", "url": "https://example.com",
    })
    assert cloud.status_code == 200
    prohibited = client.post("/api/exploit/test", json={
        "url": "https://example.com", "technique": "denial-of-service",
    })
    assert prohibited.status_code == 400
    assert "prohibited" in prohibited.json()["detail"]
    for endpoint, payload in (
        ("/api/exploit/test", {"url": "https://example.com/api/object/1", "technique": "idor", "payload": "2"}),
        ("/api/cloud/audit", {"platform": "firebase", "url": "https://example.com"}),
    ):
        response = client.post(endpoint, json={**payload, "engagement": {}})
        assert response.status_code == 400
        assert "engagement requires" in response.json()["detail"]


def test_web_bundle_download_contains_manifest():
    from redteam_agent import app as app_module

    app_module.configure_web_auth("127.0.0.1")  # loopback: no token required
    task_manager.tasks.clear()
    task = task_manager.create_task("example.com")
    task.results["status"] = "completed"
    response = TestClient(app_module.app).get(f"/api/report/bundle/{task.task_id}")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/zip"
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        assert "manifest.json" in archive.namelist()


def test_web_polling_redacts_in_progress_raw_value_and_sibling_context():
    from redteam_agent import app as app_module

    app_module.configure_web_auth("127.0.0.1")  # loopback: no token required
    raw = "postgresql://admin:poll-secret@example.com/app"
    task_manager.tasks.clear()
    task = task_manager.create_task("example.com")
    task.status = "running"
    task.results["js_grep"] = [{"_raw_value": raw, "context": f"const db = '{raw}'"}]

    response = TestClient(app_module.app).get(f"/api/scan/results/{task.task_id}")
    assert response.status_code == 200
    assert raw not in response.text
    assert response.json()["js_grep"][0]["_raw_value"] == "[REDACTED]"


def test_har_corpus_keeps_target_shape_but_not_secret_values():
    har = {"log": {"entries": [{"request": {
        "url": "https://api.example.com/v2/invoices/42?expand=owner",
        "method": "GET",
        "headers": [
            {"name": "Authorization", "value": "Bearer secret-user-a"},
            {"name": "Accept", "value": "application/json"},
        ],
    }}, {"request": {
        "url": "https://outside.test/api/users/9", "method": "GET", "headers": [],
    }}]}}
    records, summary = endpoint_records_from_corpus(
        har, scope_manager=ScopeManager(["example.com", "*.example.com"], resolve_dns=False),
        source_name="burp-export.har",
    )
    assert len(records) == 1
    record = records[0].to_dict()
    assert record["method"] == "GET"
    assert record["auth_required"] is True
    assert record["headers"]["Authorization"] == "captured-present"
    assert "secret-user-a" not in json.dumps(record)
    assert summary["in_scope_unique_requests"] == 1
    assert summary["rejected"][0]["reason"] == "outside active engagement scope"


def test_offensive_plan_is_filtered_to_selected_target_specific_class():
    engine = DeepExploitEngine(request_budget=0)
    records = [{
        "url": "https://example.com/api/search?q=invoice",
        "method": "GET",
        "body_shape": {"fields": []},
        "headers": {},
        "auth_required": False,
        "source_file": "capture.har",
    }]
    report = engine.run_discovered(
        records,
        techniques=["idor"],
        auth_context={"identities": {
            "user_a": {"headers": {"Authorization": "Bearer A"}, "owner_marker": "owner-A"},
            "user_b": {"headers": {"Authorization": "Bearer B"}},
        }},
        request_budget=0,
    )
    assert all(item["technique"] == "authorization_cross_identity" for item in report["plan"])
    assert report["focus"]["generic_payload_spray"] is False
    assert report["focus"]["hypotheses_filtered_out"] >= 1
