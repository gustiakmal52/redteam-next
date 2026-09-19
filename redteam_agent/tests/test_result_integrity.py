"""Offline regression tests for result evaluation; all scan execution is mocked."""
import pytest

from redteam_agent.core.fp_killer import kill_pass
from redteam_lab.observe_test import audit_request_claims
from redteam_lab.diagnostics.check_result_integrity import run_observer

BASE = "http://127.0.0.1:12345"


def record(**kwargs):
    return {"status": "VERIFIED", "type": "Synthetic item", "confidence": .9,
            "vrt_triage": {"is_approved": True}, **kwargs}


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -1, 2, "invalid", None, True, {}])
def test_invalid_confidence_preserves_record_and_does_not_abort_batch(value):
    bad, good = record(confidence=value), record()
    result = kill_pass([bad, good])
    assert result["submission_ready"] == [good]
    assert result["quarantined"] == [bad]
    assert bad["confidence"] is value
    assert "INVALID_CONFIDENCE" in bad["fp_kill"]["reasons"]
    assert bad["status"] == "VERIFIED"


@pytest.mark.parametrize("status, reason", [("REJECTED", "Reviewed"), ("VERIFIED", "   "), ("VERIFIED", 123)])
def test_inconsistent_or_empty_review_cannot_override(status, reason):
    finding = record(status=status, confidence=.1,
                     human_review={"action": "MARK_VERIFIED", "reason": reason})
    assert kill_pass([finding])["quarantined"] == [finding]


def test_explicit_valid_human_review_still_overrides():
    finding = record(confidence="invalid", missing_evidence=["Scanner could not decide"],
                     human_review={"action": "MARK_VERIFIED", "reason": "Evidence reviewed manually"})
    assert kill_pass([finding])["submission_ready"] == [finding]


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -.1, 2, True, None, "bad"])
def test_invalid_threshold_is_rejected(value):
    with pytest.raises(ValueError):
        kill_pass([], min_confidence=value)


def test_method_query_and_origin_are_distinguished():
    rows = [{"method": "GET", "path": "/", "query": "a=1&b=2"}]
    scan = {"records": [{"method": "POST", "url": BASE + "/?a=1&b=2"},
                        {"method": "GET", "url": BASE + "/?b=2&a=1"},
                        {"method": "GET", "url": BASE + "/?a=1&b=2"},
                        {"method": "GET", "url": "http://127.0.0.1:123456/"}]}
    result = audit_request_claims(scan, rows, BASE)
    assert result["claim_count"] == 3
    assert len(result["missing"]) == 2


def test_url_mentions_do_not_become_request_claims():
    assert audit_request_claims({"target": BASE + "/not-requested"}, [], BASE) == {"claim_count": 0, "missing": []}


@pytest.mark.parametrize("scan", [
    {"findings": [], "request": {"method": "GET", "url": BASE + "/missing"}},
    {"findings": [], "vulnerabilities": [record(endpoint=BASE + "/")]},
    {"findings": [record(endpoint=BASE + "/")], "vulnerabilities": []},
    {"findings": [record(status="SUSPECTED", method="POST", endpoint=BASE + "/?q=1")]},
])
def test_observer_returns_failure_and_writes_summary_for_inconsistent_results(scan):
    result = run_observer(scan)
    assert result["exit_code"] == 1
    assert "INVESTIGATE" in result["verdict"]
    assert result["summary_written"]


def test_consistent_candidate_remains_clean_without_rejection():
    scan = {"findings": [record(status="SUSPECTED", method="GET", endpoint=BASE + "/")], "vulnerabilities": []}
    result = run_observer(scan)
    assert result["exit_code"] == 0
    assert "CLEAN" in result["verdict"]
    assert result["summary_written"]
    assert scan["findings"][0]["status"] == "SUSPECTED"
