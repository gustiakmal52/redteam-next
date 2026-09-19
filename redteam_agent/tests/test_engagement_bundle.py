"""Authorization gating and portable evidence-bundle regressions."""

import datetime as dt
import hashlib
import io
import json
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


def test_offensive_task_requires_engagement_record():
    with pytest.raises(EngagementError, match="requires --engagement-file"):
        ScanTask("t", "example.com", offensive=True)


def test_offensive_task_rejects_unfocused_generic_session():
    with pytest.raises(EngagementError, match="selected vulnerability classes"):
        ScanTask("t", "example.com", offensive=True, engagement=profile())


def test_idor_focus_requires_two_identities_and_owner_marker():
    with pytest.raises(EngagementError, match="two researcher-owned identities"):
        ScanTask(
            "t", "example.com", offensive=True, engagement=profile(),
            hunt_focus={"vulnerability_classes": ["idor"]},
        )
    with pytest.raises(EngagementError, match="owner-controlled response marker"):
        ScanTask(
            "t", "example.com", offensive=True, engagement=profile(),
            hunt_focus={"vulnerability_classes": ["idor"]},
            auth_context={"identities": {
                "a": {"headers": {"Authorization": "Bearer A"}},
                "b": {"headers": {"Authorization": "Bearer B"}},
            }},
        )


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


def test_engagement_public_summary_does_not_export_contact_value():
    active = profile(emergency_contact="private-person@example.test +62-000")
    summary = active.public_summary()
    assert summary["emergency_contact_recorded"] is True
    assert "emergency_contact" not in summary
    assert "private-person" not in json.dumps(summary)


def test_offensive_task_rejects_unimplemented_generic_focus_class():
    unrestricted = profile(allowed_techniques=[])
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


def test_web_offensive_scan_rejects_missing_engagement_before_launch():
    from redteam_agent import app as app_module

    app_module.configure_web_auth("127.0.0.1")  # loopback: no token required
    response = TestClient(app_module.app).post(
        "/api/scan/start",
        json={"target": "example.com", "preset": "deep_bypass", "offensive": True},
    )
    assert response.status_code == 400
    assert "requires --engagement-file" in response.json()["detail"]


def test_direct_sandbox_and_cloud_audit_require_engagement_before_network():
    from redteam_agent import app as app_module

    app_module.configure_web_auth("127.0.0.1")  # loopback: no token required
    client = TestClient(app_module.app)
    sandbox = client.post("/api/exploit/test", json={
        "url": "https://example.com/api/object/1",
        "technique": "idor",
        "payload": "2",
    })
    assert sandbox.status_code == 400
    assert "requires --engagement-file" in sandbox.json()["detail"]
    cloud = client.post("/api/cloud/audit", json={
        "platform": "firebase", "url": "https://example.com",
    })
    assert cloud.status_code == 400
    assert "requires --engagement-file" in cloud.json()["detail"]


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
