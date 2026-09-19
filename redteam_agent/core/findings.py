"""Normalized finding lifecycle plus AI and human review contracts."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


class FindingStatus(str, Enum):
    DISCOVERED = "DISCOVERED"
    SUSPECTED = "SUSPECTED"
    LIKELY = "LIKELY"
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"


# These are evidence classes, not scanner modules.  Keeping the invariant in
# the shared finding model prevents a new UI action, adapter, or API endpoint
# from accidentally promoting an observation that cannot carry the claimed
# impact on its own.
GRAPHQL_INFO_MARKERS = (
    "graphql introspection",
    "graphql schema disclosure",
    "graphql schema introspection",
)
XSS_MARKERS = ("cross-site scripting", "reflected xss", "stored xss", "xss")
BROWSER_EXECUTION_CHECKS = {
    "browser_execution",
    "browser_canary_executed",
    "dom_xss_canary",
    "script_canary_executed",
}


class AIReviewInput(BaseModel):
    finding_type: str
    scanner_status: FindingStatus
    confidence: float = Field(ge=0, le=1)
    baseline_request: dict[str, Any] = Field(default_factory=dict)
    baseline_response: dict[str, Any] = Field(default_factory=dict)
    test_request: dict[str, Any] = Field(default_factory=dict)
    test_response: dict[str, Any] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    timings: dict[str, Any] = Field(default_factory=dict)
    payload: str = ""
    expected_behavior: str = ""
    actual_behavior: str = ""
    technology_context: list[str] = Field(default_factory=list)
    response_diff: dict[str, Any] = Field(default_factory=dict)
    scanner_reasoning: str = ""
    verification_checks: list[dict[str, Any]] = Field(default_factory=list)
    false_positive_reasons: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)


class AIReviewOutput(BaseModel):
    verdict: Literal["likely_valid", "uncertain", "likely_false_positive"]
    confidence: float = Field(ge=0, le=1)
    reasoning_summary: str
    missing_evidence: list[str] = Field(default_factory=list)
    recommended_safe_validation: list[str] = Field(default_factory=list)


def normalized_finding(*, finding_type: str, target: str, endpoint: str, status: FindingStatus = FindingStatus.SUSPECTED,
                       confidence: float = 0.3, method: str = "GET", payload: str = "", baseline: Optional[dict] = None,
                       test: Optional[dict] = None, evidence: Optional[list] = None, verification_checks: Optional[list] = None,
                       false_positive_reasons: Optional[list] = None, missing_evidence: Optional[list] = None,
                       source_module: str = "", source_tool: str = "", **legacy: Any) -> dict[str, Any]:
    finding = {
        "id": legacy.pop("id", f"finding_{uuid.uuid4().hex[:12]}"),
        "type": finding_type, "status": status.value if isinstance(status, FindingStatus) else str(status),
        "confidence": max(0.0, min(1.0, float(confidence))), "target": target, "endpoint": endpoint,
        "method": method.upper(), "payload": payload, "baseline": baseline or {"request": {}, "response": {}},
        "test": test or {"request": {}, "response": {}}, "evidence": evidence or [],
        "verification_checks": verification_checks or [], "false_positive_reasons": false_positive_reasons or [],
        "missing_evidence": missing_evidence or [], "source_module": source_module, "source_tool": source_tool,
        "observed_at": datetime.now(timezone.utc).isoformat(), "ai_review": None, "human_review": None,
        # ``disposition`` is intentionally separate from scanner status.  A
        # primitive can be observed without being submission-ready.
        "disposition": "UNTRIAGED", "submission_eligible": False,
    }
    finding.update(legacy)
    finding.setdefault("vuln_type", finding_type)
    finding.setdefault("target_url", endpoint)
    return finding


def has_browser_execution_proof(finding: dict[str, Any]) -> bool:
    """Return true only for an explicit browser/DOM execution canary.

    A reflected ``<script>`` string is not browser execution.  The check is
    deliberately narrow so a future browser adapter has to publish a named,
    passed verification check rather than merely setting ``verified``.
    """
    check_sets = [finding.get("verification_checks") or []]
    validation = finding.get("poc_validation") or {}
    check_sets.append(validation.get("checks") or [])
    for checks in check_sets:
        for item in checks:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "").strip().lower()
            if name in BROWSER_EXECUTION_CHECKS and item.get("passed") is True:
                return True
    for evidence in finding.get("evidence") or []:
        if not isinstance(evidence, dict):
            continue
        if any(evidence.get(key) is True for key in (
            "browser_execution", "browser_executed", "dom_execution", "canary_executed"
        )):
            return True
    return False


def _is_graphql_introspection(type_label: str) -> bool:
    lowered = (type_label or "").lower()
    return any(marker in lowered for marker in GRAPHQL_INFO_MARKERS)


def _is_xss(type_label: str) -> bool:
    lowered = (type_label or "").lower()
    return any(marker in lowered for marker in XSS_MARKERS)


def enforce_disposition_invariants(finding: dict[str, Any]) -> dict[str, Any]:
    """Apply non-bypassable status invariants to one finding.

    This is the central disposition boundary used by the FP kill gate and by
    live PoC validation.  It does not remove an offensive attempt or its raw
    evidence; it prevents an observation from being mislabeled as a verified
    impact.
    """
    status = str(finding.get("status") or FindingStatus.SUSPECTED.value)
    type_label = str(finding.get("type") or finding.get("vuln_type") or "")

    if status == FindingStatus.REJECTED.value:
        finding["submission_eligible"] = False
        finding["disposition"] = "REJECTED"
        return finding

    if _is_graphql_introspection(type_label):
        # Introspection proves schema exposure only.  It is useful input for
        # the offensive GraphQL planner, but not a standalone submission.
        finding["status"] = FindingStatus.DISCOVERED.value
        finding["disposition"] = "INFO_ONLY"
        finding["submission_eligible"] = False
        finding["severity"] = "Informational"
        finding["cvss_score"] = 0.0
        finding["observed_impact"] = finding.get("observed_impact") or (
            "GraphQL schema introspection was returned; field authorization impact was not established."
        )
        missing = list(finding.get("missing_evidence") or [])
        required = "Sensitive field access or authorization impact beyond schema introspection"
        if required not in missing:
            missing.append(required)
        finding["missing_evidence"] = missing
        return finding

    if _is_xss(type_label) and not has_browser_execution_proof(finding):
        # Reflection is retained as a useful likely primitive for the
        # offensive workflow, but cannot claim execution without a browser or
        # equivalent DOM canary.
        if status != FindingStatus.REJECTED.value:
            finding["status"] = FindingStatus.LIKELY.value
        finding["disposition"] = "LIKELY_REFLECTION_ONLY"
        finding["submission_eligible"] = False
        finding["cvss_score"] = 0.0
        missing = list(finding.get("missing_evidence") or [])
        required = "Browser execution canary in the reflected context"
        if required not in missing:
            missing.append(required)
        finding["missing_evidence"] = missing
        return finding

    if status == FindingStatus.VERIFIED.value:
        finding["disposition"] = "VERIFIED"
        finding["submission_eligible"] = True
    else:
        finding["disposition"] = status
        finding["submission_eligible"] = False
    return finding


def apply_validation_result(finding: dict[str, Any], validation: dict[str, Any]) -> dict[str, Any]:
    """Merge a live PoC without giving the validation route a status bypass."""
    finding["poc_validation"] = validation
    if validation.get("passed"):
        # A positive HTTP observation is sufficient for ordinary deterministic
        # PoCs, but the two special evidence classes still go through the
        # invariant gate below.
        finding["status"] = FindingStatus.VERIFIED.value
        finding["missing_evidence"] = []
        try:
            current_confidence = float(finding.get("confidence", 0.0))
        except (TypeError, ValueError, OverflowError):
            current_confidence = 0.0
        finding["confidence"] = max(0.0, min(1.0, max(current_confidence, 0.9)))
    else:
        finding["status"] = FindingStatus.SUSPECTED.value
        if validation.get("reason"):
            finding["missing_evidence"] = sorted(set(
                (finding.get("missing_evidence") or []) + [validation["reason"]]
            ))
    return enforce_disposition_invariants(finding)


def apply_ai_review(finding: dict, review: AIReviewOutput | dict) -> dict:
    parsed = review if isinstance(review, AIReviewOutput) else AIReviewOutput.model_validate(review)
    finding["ai_review"] = parsed.model_dump()
    # Deliberately never promotes to VERIFIED. AI is advisory and may lower
    # confidence or surface missing evidence, but deterministic HTTP evidence wins.
    finding["missing_evidence"] = sorted(set(finding.get("missing_evidence", []) + parsed.missing_evidence))
    return finding


def apply_human_review(finding: dict, action: str, reviewer: str = "local_operator", reason: str = "") -> dict:
    normalized = action.upper().replace(" ", "_")
    if normalized == "MARK_VERIFIED":
        finding["status"] = FindingStatus.VERIFIED.value
    elif normalized == "REJECT":
        finding["status"] = FindingStatus.REJECTED.value
    elif normalized == "NEEDS_MORE_VALIDATION":
        finding["status"] = FindingStatus.SUSPECTED.value
    else:
        raise ValueError("Unknown human review action")
    finding["human_review"] = {
        "action": normalized, "reviewer": reviewer, "reason": reason,
        "reviewed_at": datetime.now(timezone.utc).isoformat(),
    }
    return finding
