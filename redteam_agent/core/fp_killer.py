"""False-Positive Kill Gate.

Deterministic, evidence-first final filter run at the end of the pipeline.
Only findings that pass every gate are treated as submission-ready; the rest
are quarantined with an explicit reason so they never reach the triage desk
as noise. A human "MARK VERIFIED" review with a reason overrides the gate
(you are allowed to accept what the machine rejects).

Kill rules (all deterministic, no AI involved):
  1. NOT_VERIFIED      — candidates are never auto-submitted.
  2. MISSING_EVIDENCE  — finding claims VERIFIED but still lists missing evidence.
  3. UNRESOLVED_FP     — scanner itself flagged possible false-positive reasons.
  4. LOW_CONFIDENCE    — confidence below the submission threshold.
  5. VRT_REJECTED      — the VRT triage engine did not approve the finding.
  6. KNOWN_NA_CLASS    — finding type matches a class triage desks commonly reject.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional

from redteam_agent.core.findings import FindingStatus, enforce_disposition_invariants


# Finding-type substrings that are notorious for being rejected as N/A or
# low-impact by bug bounty triage unless a real impact chain is proven.
KNOWN_NA_CLASS_MARKERS = (
    "open redirect", "self-xss", "missing security header", "hsts", "x-frame-options",
    "content-security-policy", "csrf on logout", "dmarc", "spf", "dkim", "rate limit",
    "username enumeration", "email enumeration", "server banner", "version disclosure",
    "csv injection", "cors_credentials_risk", "cors_configuration_issue",
)

DEFAULT_MIN_CONFIDENCE = 0.5


def _na_class(type_label: str) -> bool:
    lowered = (type_label or "").lower()
    return any(marker in lowered for marker in KNOWN_NA_CLASS_MARKERS)


def _verified_researcher_redirect(finding: Dict[str, Any]) -> bool:
    """Allow a redirect only when the active proof is materially present.

    Generic open-redirect candidates remain quarantined for compatibility with
    the existing triage policy. The offensive planner's exact canary proof is
    different: it records a 3xx response, the researcher-controlled host, and
    the resulting Location. That evidence is sufficient to retain the
    primitive for triage without pretending it is an OAuth/session leak.
    """
    if finding.get("status") != FindingStatus.VERIFIED.value:
        return False
    checks = finding.get("verification_checks") or []
    has_location_check = any(
        isinstance(item, dict)
        and item.get("name") == "researcher_controlled_location"
        and item.get("passed") is True
        for item in checks
    )
    for item in finding.get("evidence") or []:
        if not isinstance(item, dict):
            continue
        domain = str(item.get("researcher_controlled_domain") or "").strip().lower()
        location = str(item.get("location") or item.get("redirect_target") or "").lower()
        if domain and location and domain in location and has_location_check:
            return True
    return False


def _human_approved(finding: Dict[str, Any]) -> bool:
    review = finding.get("human_review") or {}
    reason = review.get("reason")
    return (finding.get("status") == FindingStatus.VERIFIED.value
            and review.get("action") == "MARK_VERIFIED"
            and isinstance(reason, str) and bool(reason.strip()))


def kill_pass(findings: List[Dict[str, Any]], min_confidence: float = DEFAULT_MIN_CONFIDENCE,
              vrt_check: bool = True) -> Dict[str, Any]:
    """Runs every finding through the gate.

    Returns a report with submission_ready (in order) and quarantined items.
    Each finding gets an ``fp_kill`` annotation describing its disposition.
    """
    try:
        threshold = float(min_confidence)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("min_confidence must be a finite number between 0 and 1") from exc
    if isinstance(min_confidence, bool) or not math.isfinite(threshold) or not 0 <= threshold <= 1:
        raise ValueError("min_confidence must be a finite number between 0 and 1")
    min_confidence = threshold
    submission: List[Dict[str, Any]] = []
    quarantined: List[Dict[str, Any]] = []
    summary = {"submission_ready": 0, "quarantined": 0, "reasons": {}}

    for finding in findings:
        # This is the single disposition boundary.  Every caller—including
        # human review and live PoC validation—comes through this gate before
        # a finding can enter ``submission_ready``.
        enforce_disposition_invariants(finding)
        status = str(finding.get("status", FindingStatus.SUSPECTED.value))
        type_label = str(finding.get("type") or finding.get("vuln_type") or "")
        reasons: List[str] = []

        if _human_approved(finding):
            reasons.clear()  # human explicitly accepted with a reason: override all
            disposition = "SUBMISSION_READY"
            finding["fp_kill"] = {"status": disposition, "reasons": [],
                                  "note": "Human MARK_VERIFIED override with reason."}
            submission.append(finding)
            summary["submission_ready"] += 1
            continue

        raw_confidence = finding.get("confidence", 0.0)
        try:
            confidence = float(raw_confidence)
            valid_confidence = (not isinstance(raw_confidence, bool)
                                and math.isfinite(confidence) and 0 <= confidence <= 1)
        except (TypeError, ValueError, OverflowError):
            confidence, valid_confidence = 0.0, False
        if not valid_confidence:
            reasons.append("INVALID_CONFIDENCE")
        if status != FindingStatus.VERIFIED.value:
            reasons.append("NOT_VERIFIED")
        if finding.get("missing_evidence"):
            reasons.append("MISSING_EVIDENCE")
        if finding.get("false_positive_reasons"):
            reasons.append("UNRESOLVED_FP")
        if valid_confidence and confidence < min_confidence:
            reasons.append("LOW_CONFIDENCE")
        if vrt_check and not (finding.get("vrt_triage") or {}).get("is_approved"):
            reasons.append("VRT_REJECTED")
        if _na_class(type_label) and not (
                "open redirect" in type_label.lower()
                and _verified_researcher_redirect(finding)):
            reasons.append("KNOWN_NA_CLASS")

        if reasons:
            disposition = "QUARANTINED"
            finding["fp_kill"] = {"status": disposition, "reasons": reasons,
                                  "note": "Blocked by deterministic FP kill gate."}
            quarantined.append(finding)
            summary["quarantined"] += 1
            for reason in reasons:
                summary["reasons"][reason] = summary["reasons"].get(reason, 0) + 1
        else:
            disposition = "SUBMISSION_READY"
            finding["fp_kill"] = {"status": disposition, "reasons": [],
                                  "note": "Passed deterministic FP kill gate."}
            submission.append(finding)
            summary["submission_ready"] += 1

    return {
        "submission_ready": submission,
        "quarantined": quarantined,
        "summary": summary,
    }
