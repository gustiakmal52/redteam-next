"""Export + Exploit Analysis Engine — analyzes exported scan results with exploit proof."""

from __future__ import annotations

import json
import math
from typing import Any, Dict, List

from redteam_agent.core.findings import enforce_disposition_invariants, has_browser_execution_proof
from redteam_agent.core.fp_killer import kill_pass
from redteam_agent.core.vrt_triage import VRTTriageEngine
from redteam_agent.core.config import CVSS_VECTORS, cvss3_score


REMEDIATION_MAP = {
    "sqli": "Gunakan parameterized queries / prepared statements, validasi input strict, least-privilege DB user, WAF rule SQLi sebagai defense-in-depth saja.",
    "sql": "Gunakan parameterized queries / prepared statements, validasi input strict, least-privilege DB user.",
    "xss": "Encode output sesuai konteks, CSP strict, sanitasi input, validasi reflected context dengan browser canary sebelum klaim execution.",
    "ssti": "Jangan render template dari input user, sandbox engine, allowlist template, validasi strict.",
    "ssrf": "Allowlist destination, blok private/metadata IP, validasi URL server-side, network segmentation.",
    "idor": "Enforce authorization per-object, cek ownership di server, jangan andalkan ID sequential, audit BOLA.",
    "bola": "Enforce authorization per-object, cek ownership di server, jangan andalkan ID sequential.",
    "authorization": "Perbaiki access control matrix, test cross-identity dengan marker unik, enforce di backend.",
    "open redirect": "Allowlist redirect target, validasi absolute URL, jangan pakai user input langsung untuk Location.",
    "graphql": "Disable introspection di prod, enforce field-level auth, rate limit, depth limit.",
    "cors": "Jangan reflect Origin sembarang, allowlist origin spesifik, jangan pakai wildcard + credentials.",
    "jwt": "Validasi alg, jangan pakai none, pakai secret kuat, rotasi key, cek exp/aud/iss.",
    "exposed": "Hapus file dari public, rotasi credential, audit git history, blok akses .env/.git.",
    "firebase": "Perbaiki Realtime DB rules, require auth, validasi per-node, audit open read/write.",
    "supabase": "Perbaiki RLS policy, test dengan anon key, deny by default, audit bypass.",
    "default": "Perbaiki root cause spesifik, re-run deterministic PoC yang sama untuk konfirmasi patch, jangan andalkan penghapusan header/generic fix.",
}

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "informational": 0}


def _remediation_for(finding_type: str) -> str:
    lowered = (finding_type or "").lower()
    for key, value in REMEDIATION_MAP.items():
        if key != "default" and key in lowered:
            return value
    return REMEDIATION_MAP["default"]


def _severity_rank(sev: str) -> int:
    return SEVERITY_ORDER.get((sev or "").lower().strip(), 0)


def _safe_float(value: Any, fallback: float = 0.0) -> float:
    try:
        num = float(value)
        if isinstance(value, bool) or not math.isfinite(num):
            return fallback
        return num
    except Exception:
        return fallback


def analyze_export(results: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze an exported scan result dict (redacted results.json content)."""
    if not isinstance(results, dict):
        raise ValueError("export must be a JSON object")

    findings_raw: List[Dict[str, Any]] = list(results.get("findings") or results.get("vulnerabilities") or [])
    # Enforce disposition invariants like pipeline does
    for finding in findings_raw:
        enforce_disposition_invariants(finding)

    # FP kill gate
    kill_report = kill_pass(findings_raw)
    submission_ready = kill_report["submission_ready"]
    quarantined = kill_report["quarantined"]
    kill_summary = kill_report["summary"]

    # VRT breakdown (ensure each finding has vrt_triage)
    vrt_engine = VRTTriageEngine()
    for finding in findings_raw:
        if "vrt_triage" not in finding or not isinstance(finding["vrt_triage"], dict):
            title = str(finding.get("type") or finding.get("vuln_type") or "")
            desc = str(finding.get("observed_impact") or finding.get("verification_note") or "")
            poc_verified = str(finding.get("status") or "") == "VERIFIED"
            finding["vrt_triage"] = vrt_engine.evaluate_finding(title, desc, poc_verified=poc_verified, possesses_active_exploit=poc_verified)

    total = len(findings_raw)
    verified = len([f for f in findings_raw if str(f.get("status")) == "VERIFIED"])
    discovered = len([f for f in findings_raw if str(f.get("status")) == "DISCOVERED"])
    likely = len([f for f in findings_raw if str(f.get("status")) == "LIKELY"])
    rejected = len([f for f in findings_raw if str(f.get("status")) == "REJECTED"])

    # Severity breakdown
    severity_breakdown: Dict[str, int] = {}
    type_breakdown: Dict[str, int] = {}
    for finding in findings_raw:
        sev = str(finding.get("severity") or "info").lower()
        severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1
        typ = str(finding.get("type") or finding.get("vuln_type") or "unknown").lower()
        type_breakdown[typ] = type_breakdown.get(typ, 0) + 1

    # Per-finding deep analysis
    findings_analysis: List[Dict[str, Any]] = []
    for finding in findings_raw:
        ftype = str(finding.get("type") or finding.get("vuln_type") or "unknown")
        status = str(finding.get("status") or "SUSPECTED")
        confidence = _safe_float(finding.get("confidence"), 0.0)
        vrt = finding.get("vrt_triage") or {}
        fp = finding.get("fp_kill") or {}
        disposition = str(finding.get("disposition") or status)
        submission_eligible = bool(finding.get("submission_eligible"))

        # CVSS
        cvss_vector = None
        cvss_score_val = _safe_float(finding.get("cvss_score"), 0.0)
        # Try to infer vector from type
        lowered = ftype.lower()
        for key, vec in CVSS_VECTORS.items():
            if key.replace("_", " ") in lowered or key in lowered:
                cvss_vector = vec
                cvss_score_val = cvss3_score(vec, fallback=cvss_score_val)
                break

        # Proof quality
        has_proof = status == "VERIFIED" and not finding.get("missing_evidence")
        has_browser_proof = has_browser_execution_proof(finding)
        checks = finding.get("verification_checks") or []
        poc_validation = finding.get("poc_validation") or {}

        # Risk prioritization score: cvss + confidence + submission boost
        risk_score = cvss_score_val * 0.7 + confidence * 3.0
        if submission_eligible:
            risk_score += 2.0
        if has_proof:
            risk_score += 1.0

        findings_analysis.append({
            "id": finding.get("id"),
            "type": ftype,
            "endpoint": finding.get("endpoint") or finding.get("target_url") or "",
            "method": finding.get("method") or "GET",
            "param": finding.get("param") or "",
            "status": status,
            "disposition": disposition,
            "severity": finding.get("severity") or vrt.get("severity") or "Info",
            "confidence": confidence,
            "cvss_vector": cvss_vector,
            "cvss_score": cvss_score_val,
            "vrt_category": vrt.get("vrt_category"),
            "vrt_status": vrt.get("status"),
            "vrt_approved": bool(vrt.get("is_approved")),
            "fp_kill_status": fp.get("status"),
            "fp_reasons": fp.get("reasons") or [],
            "submission_eligible": submission_eligible,
            "submission_ready": finding in submission_ready,
            "quarantined": finding in quarantined,
            "has_proof": has_proof,
            "has_browser_execution_proof": has_browser_proof,
            "checks_passed": len([c for c in checks if isinstance(c, dict) and c.get("passed")]),
            "checks_total": len(checks),
            "missing_evidence": finding.get("missing_evidence") or [],
            "poc_validation": poc_validation,
            "reproduction_curl": finding.get("reproduction_curl") or "",
            "observed_impact": finding.get("observed_impact") or finding.get("verification_note") or "",
            "remediation": _remediation_for(ftype),
            "risk_score": round(risk_score, 2),
        })

    # Prioritized: sort by risk_score desc, then cvss desc
    prioritized = sorted(findings_analysis, key=lambda x: (x["risk_score"], x["cvss_score"], x["confidence"]), reverse=True)

    # Global risk
    max_cvss = max([_safe_float(f.get("cvss_score"), 0) for f in findings_analysis], default=0.0)
    avg_conf = sum(_safe_float(f.get("confidence"), 0) for f in findings_analysis) / total if total else 0.0
    # Hidden discovery summary if present
    hidden = results.get("hidden_assets") or {}
    deep_exploit = results.get("deep_exploit") or {}
    recon_depth = results.get("recon_depth") or {}

    summary = {
        "target": results.get("target"),
        "preset": results.get("preset"),
        "status": results.get("status"),
        "total_findings": total,
        "verified": verified,
        "likely": likely,
        "discovered": discovered,
        "rejected": rejected,
        "submission_ready": len(submission_ready),
        "quarantined": len(quarantined),
        "severity_breakdown": severity_breakdown,
        "type_breakdown": type_breakdown,
        "fp_kill_summary": kill_summary,
        "max_cvss": max_cvss,
        "avg_confidence": round(avg_conf, 3),
        "hidden_assets_count": (hidden.get("stats") or {}).get("assets") if isinstance(hidden, dict) else 0,
        "deep_exploit_hypotheses": len(deep_exploit.get("plan") or []) if isinstance(deep_exploit, dict) else 0,
        "deep_exploit_primitives": len(deep_exploit.get("primitives") or []) if isinstance(deep_exploit, dict) else 0,
    }

    # Recommendations (top 3)
    recommendations: List[str] = []
    for item in prioritized[:3]:
        if item["submission_ready"]:
            recommendations.append(f"Prioritaskan {item['type']} di {item['endpoint']} — {item['severity']} CVSS {item['cvss_score']} — remediation: {item['remediation']}")
        elif item["quarantined"]:
            reason = ", ".join(item["fp_reasons"]) or item["vrt_status"] or "needs triage"
            recommendations.append(f"Triage {item['type']} di {item['endpoint']} — quarantine reason: {reason} — lengkapi: {', '.join(item['missing_evidence'][:2]) or 'bukti tambahan'}")
    if not recommendations and total == 0:
        recommendations.append("Tidak ada finding — lakukan scan ulang dengan preset deep_bypass + vulnerability_classes spesifik untuk probe lebih dalam.")

    # Markdown synthesis
    md_lines = [
        f"# Export Exploit Analysis — {summary['target'] or 'unknown target'}",
        "",
        f"- Preset: `{summary['preset'] or 'unknown'}` | Status: `{summary['status'] or 'unknown'}`",
        f"- Total findings: **{total}** | VERIFIED: **{verified}** | Submission-ready: **{len(submission_ready)}** | Quarantined: **{len(quarantined)}**",
        f"- Max CVSS: **{max_cvss}** | Avg confidence: **{round(avg_conf,3)}**",
        f"- Severity: `{json.dumps(severity_breakdown, ensure_ascii=False)}`",
        f"- Types: `{json.dumps(type_breakdown, ensure_ascii=False)}`",
        "",
        "## Prioritized Findings",
    ]
    for idx, item in enumerate(prioritized[:20], 1):
        md_lines.append(f"{idx}. **{item['type']}** `{item['method']} {item['endpoint']}` — {item['status']}/{item['disposition']} | {item['severity']} CVSS {item['cvss_score']} | risk {item['risk_score']} | ready={item['submission_ready']} quarantined={item['quarantined']}")
        if item["observed_impact"]:
            md_lines.append(f"   - Observed: {item['observed_impact'][:240]}")
        if item["missing_evidence"]:
            md_lines.append(f"   - Missing: {', '.join(item['missing_evidence'][:3])}")
        md_lines.append(f"   - Remediation: {item['remediation']}")
    md_lines.extend(["", "## Recommendations", ""])
    for rec in recommendations:
        md_lines.append(f"- {rec}")
    md_lines.extend(["", "## FP Kill Summary", f"```json\n{json.dumps(kill_summary, indent=2, ensure_ascii=False)}\n```"])

    markdown = "\n".join(md_lines)

    return {
        "summary": summary,
        "findings_analysis": findings_analysis,
        "prioritized": prioritized,
        "kill_report": {"submission_ready_ids": [f.get("id") for f in submission_ready], "quarantined_ids": [f.get("id") for f in quarantined], "summary": kill_summary},
        "recommendations": recommendations,
        "markdown": markdown,
        "meta": {
            "hidden_assets": hidden.get("stats") if isinstance(hidden, dict) else {},
            "deep_exploit": {"plan": len(deep_exploit.get("plan") or []), "primitives": len(deep_exploit.get("primitives") or []), "requests_used": deep_exploit.get("requests_used")} if isinstance(deep_exploit, dict) else {},
            "recon_depth": {"waf": (recon_depth.get("waf") or {}).get("detected") if isinstance(recon_depth, dict) else [], "ports": len(recon_depth.get("ports") or []) if isinstance(recon_depth, dict) else 0},
        },
    }
