"""Offline regression coverage for report claims and imported finding data."""

import copy

import pytest

from redteam_agent.core.report_builder import ReportBuilder


def test_human_verification_is_not_reported_as_deterministic():
    finding = {
        "status": "VERIFIED", "type": "Example finding", "confidence": .8,
        "human_review": {"action": "MARK_VERIFIED", "reason": "Evidence reviewed"},
    }
    before = copy.deepcopy(finding)
    builder = ReportBuilder()
    for report in (builder.generate_markdown_report(finding),
                   builder.generate_full_audit_report({"findings": [finding]})):
        assert "Human review recorded" in report
        assert "Deterministically verified" not in report
    assert finding == before


def test_scanner_status_is_attributed_without_independent_validation_claim():
    report = ReportBuilder().generate_markdown_report({"status": "VERIFIED"})
    assert "Scanner-reported VERIFIED" in report
    assert "independent validation not established" in report
    assert "during authorized testing" not in report
    assert "Authorization is not established" in report
    assert "an empty list does not establish completeness" in report
    assert "Unknown — endpoint was not recorded" in report
    assert "Unknown — target was not recorded" in report


def test_rejected_findings_are_separate_from_pending_candidates():
    rejected = {"type": "Dismissed item", "status": "REJECTED",
                "human_review": {"reason": "Expected behavior"}}
    report = ReportBuilder().generate_full_audit_report({"findings": [
        rejected, {"type": "Pending item", "status": "SUSPECTED"},
    ]})
    assert "**Candidates requiring review**: `1`" in report
    assert "**Rejected findings**: `1`" in report
    pending = report.split("## Candidates (Not Verified)")[1].split("## Rejected Findings")[0]
    assert "Pending item" in pending and "Dismissed item" not in pending
    assert "Dismissed item** — Expected behavior" in report
    assert "Rejected; excluded from active candidates" in ReportBuilder().generate_markdown_report(rejected)


@pytest.mark.parametrize("confidence", [None, "bad", float("nan"), float("inf"), -1, 2, True, {}])
def test_invalid_imported_confidence_does_not_crash_or_mislead(confidence):
    finding = {"status": "VERIFIED", "confidence": confidence}
    builder = ReportBuilder()
    assert "Unknown —" in builder.generate_markdown_report(finding).split("**Confidence**:")[1].splitlines()[0]
    assert "Unknown —" in builder.generate_full_audit_report({"findings": [finding]}).split("**Confidence**:")[1].splitlines()[0]


@pytest.mark.parametrize("confidence, expected", [(0, "0.00"), (.85, "0.85"), (1, "1.00"), ("0.4", "0.40")])
def test_valid_confidence_remains_readable(confidence, expected):
    assert f"**Confidence**: `{expected}`" in ReportBuilder().generate_markdown_report({"confidence": confidence})


def test_hidden_discovery_report_keeps_public_provider_ids_and_masks_secret_material():
    raw_secret = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.signature123"
    report = ReportBuilder().generate_full_audit_report({
        "target": "https://app.test",
        "hidden_assets": {
            "stats": {"assets": 2, "endpoints": 1, "credentials": 1, "baas_projects": 1,
                       "source_maps": 0, "auth_flows": 0, "relationships": 2},
            "assets": [{"url": "https://app.test/app.js"}],
            "endpoints": [{"method": "GET", "url": "https://app.test/api/me", "headers": {"Authorization": {}},
                           "body_shape": {}, "source_file": "app.js", "source_line": 12}],
            "credentials": [{"credential_type": "POTENTIAL_SECRET", "provider": "Supabase", "status": "VERIFIED",
                             "public": False, "masked_value": "eyJhbG...1234", "sha256": "f" * 64,
                             "source_file": "app.js", "source_line": 3, "variable_name": "SERVICE_KEY",
                             "linked_endpoints": ["https://runtime-a.supabase.co/rest/v1/"],
                             "verification": {"status": "VERIFIED"}, "reason": "linked project accepted it"}],
            "baas_projects": [{"provider": "AWS Cognito", "project_ref": "us-east-1_pool123",
                               "url": "https://cognito-idp.us-east-1.amazonaws.com",
                               "key_type": "public-config", "public_identifiers": {
                                   "userPoolId": "us-east-1_pool123", "identityPoolId": "us-east-1:identity",
                                   "clientId": "client-public-123", "tenantId": "tenant-public"
                               }, "services": ["Authentication"], "verification": {"status": "NOT_RUN"}}],
            "source_maps": [], "runtime_configs": [], "auth_flows": [],
            "relationships": [{"relationship_type": "credential_to_endpoint",
                               "from_node": "credential:POTENTIAL_SECRET:" + "f" * 64,
                               "to_node": "endpoint:GET https://app.test/api/me"}],
        },
        "findings": [], "stats": {},
    })
    assert "userPoolId=us-east-1_pool123" in report
    assert "identityPoolId=us-east-1:identity" in report
    assert "clientId=client-public-123" in report
    assert "tenantId=tenant-public" in report
    assert raw_secret not in report
    assert "eyJhbG...1234" in report
