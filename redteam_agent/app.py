"""
FastAPI Server & Real-time SSE Streamer for Gustiakmal RedTeam Next.
Serves the modern Cyber Command Center Web UI, manages scan tasks,
and streams live terminal outputs to the browser.
"""

import asyncio
import datetime
import hmac
import io
import ipaddress
import json
import os
import secrets
from typing import Dict, Any, Optional, List
from fastapi import FastAPI, HTTPException, Request, BackgroundTasks
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from redteam_agent.core.task_manager import task_manager
from redteam_agent.core.agent_engine import RedTeamAgentEngine
from redteam_agent.core.cloud_baas_hunter import CloudBaaSHunter
from redteam_agent.core.http_verifier import HTTPVerifier
from redteam_agent.core.report_builder import ReportBuilder
from redteam_agent.core.threat_intel import ThreatIntelEngine
from redteam_agent.core.scope_manager import ScopeManager, URLPolicyError
from redteam_agent.core.traffic_controller import TrafficController
from redteam_agent.core.findings import (
    AIReviewOutput, FindingStatus, apply_ai_review, apply_human_review,
    apply_validation_result,
)
from redteam_agent.core.config import (
    DEFAULT_BYPASS_REQUEST_BUDGET, DEFAULT_REQUEST_BUDGET, MAX_BYPASS_DEPTH, SCAN_PRESETS, TRAFFIC_PRESETS,
)
from redteam_agent.core.db_hunter import probe_db_port
from redteam_agent.core.fp_killer import kill_pass
from redteam_agent.core.vrt_triage import VRTTriageEngine
from redteam_agent.core.engagement import EngagementError, EngagementProfile, engagement_required
from redteam_agent.core.evidence_bundle import EvidenceBundleBuilder
from redteam_agent.core.export_analyzer import analyze_export


def validate_finding_poc(task, finding):
    """Re-runs a live, deterministic PoC for a finding using the task's scope &
    traffic controls. Never fabricates evidence; returns a fresh validation."""
    verifier = HTTPVerifier(
        timeout=task.traffic_controller.config.get("timeout", 10.0),
        traffic_controller=task.traffic_controller,
        scope_manager=task.scope_manager, module="poc_validation")
    ftype = f"{finding.get('type') or ''} {finding.get('vuln_type') or ''}".lower()
    endpoint = finding.get("endpoint") or finding.get("target_url") or ""
    param = finding.get("param") or "q"
    result = {"validated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "passed": False, "checks": [], "status": 0, "reason": ""}

    try:
        if "xss" in ftype and endpoint:
            r = verifier.verify_xss(endpoint, param)
            result["passed"] = r["verified"]
            result["checks"] = [{"name": "executable_html_context", "passed": r["verified"]}]
            result["status"] = r.get("request", {}).get("status_code", 0)
            result["reason"] = r["verification_note"]
        elif "sql" in ftype and endpoint:
            r = verifier.verify_sqli_time_based(endpoint, param)
            result["passed"] = r["verified"]
            result["checks"] = [{"name": "repeatable_delay", "passed": r["verified"]}]
            result["reason"] = r["verification_note"]
        elif ("ssti" in ftype or "template" in ftype) and endpoint:
            r = verifier.verify_ssti(endpoint, param)
            result["passed"] = r["verified"]
            result["checks"] = r.get("verification_checks", [])
            result["reason"] = r["verification_note"]
        elif "cors" in ftype and endpoint:
            resp = verifier.send_http_request(endpoint, headers={"Origin": "https://cors-canary.invalid"})
            h = {k.lower(): v for k, v in resp.get("headers", {}).items()}
            result["passed"] = h.get("access-control-allow-origin") == "https://cors-canary.invalid"
            result["status"] = resp.get("status_code", 0)
            result["checks"] = [{"name": "origin_reflected", "passed": result["passed"]}]
            result["reason"] = "CORS origin reflected" if result["passed"] else "CORS origin not reflected"
        elif ("git" in ftype or "environment file" in ftype) and endpoint:
            resp = verifier.send_http_request(endpoint)
            body = resp.get("body", "")
            marker = "ref: refs/" if "git" in ftype else "DB_PASSWORD="
            result["passed"] = resp.get("status_code") == 200 and marker in body
            result["status"] = resp.get("status_code", 0)
            result["checks"] = [{"name": "content_signature", "passed": result["passed"]}]
            result["reason"] = f"marker '{marker}' present" if result["passed"] else "content signature not found"
        elif "graphql" in ftype and endpoint:
            q = json.dumps({"query": "query{__schema{types{name}}}"})
            resp = verifier.send_http_request(endpoint, method="POST",
                headers={"Content-Type": "application/json"}, body=q)
            result["passed"] = resp.get("status_code") == 200 and "__schema" in resp.get("body", "")
            result["status"] = resp.get("status_code", 0)
            result["checks"] = [{"name": "schema_in_response", "passed": result["passed"]}]
            result["eligible_for_verified"] = False
            result["disposition"] = "INFO_ONLY"
            result["reason"] = "introspection schema returned" if result["passed"] else "no schema in response"
        elif any(t in ftype for t in ("redis", "postgres", "mysql", "mongodb", "sqlserver",
                                       "oracle", "cockroach", "elasticsearch", "couchdb")):
            # endpoint is host:port
            if ":" in endpoint:
                host, _, port_s = endpoint.rpartition(":")
                try:
                    port = int(port_s)
                except ValueError:
                    port = None
                if host and port:
                    probe = probe_db_port(host, port,
                                          scope_manager=task.scope_manager,
                                          traffic_controller=task.traffic_controller)
                    result["passed"] = bool(probe.get("auth_free"))
                    result["status"] = 1 if probe.get("state") == "open" else 0
                    result["checks"] = [{"name": "service_answered_unauth", "passed": result["passed"]},
                                         {"name": "port_open", "passed": probe.get("state") == "open"}]
                    result["reason"] = " ".join(probe.get("notes", [])) or ("port open" if probe.get("state") == "open" else "port unreachable")
        elif "firebase" in ftype and endpoint:
            base = endpoint.split("/.json")[0]
            resp = verifier.send_http_request(f"{base}/.json?shallow=true&limitToFirst=1")
            body = resp.get("body", "")
            result["passed"] = resp.get("status_code") == 200 and body.strip() not in {"", "null"}
            result["status"] = resp.get("status_code", 0)
            result["checks"] = [{"name": "unauthenticated_read", "passed": result["passed"]}]
            result["reason"] = "data returned" if result["passed"] else "no data returned"
        else:
            result["reason"] = "No automated re-verification available for this finding type; manual review required."
    except Exception as exc:
        result["reason"] = f"Validation error: {exc}"
    return result

app = FastAPI(title="Gustiakmal RedTeam Next", version="2.1.0")
# Fail-closed: dashboard requires auth unless explicitly configured.
# The CLI always calls configure_web_auth(); a direct `uvicorn app:app`
# run stays locked unless REDTEAM_WEB_TOKEN is set, or REDTEAM_WEB_AUTH_DISABLE=1
# opts out explicitly (never the default).
app.state.web_auth_required = os.environ.get("REDTEAM_WEB_AUTH_DISABLE") != "1"
app.state.web_auth_token = os.environ.get("REDTEAM_WEB_TOKEN") or None


def _is_loopback_bind(listen: str) -> bool:
    value = str(listen or "").strip().lower()
    if value in {"localhost", "ip6-localhost"}:
        return True
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def configure_web_auth(listen: str, token: Optional[str] = None) -> str:
    """Configure dashboard authentication for the selected bind address."""
    required = not _is_loopback_bind(listen)
    app.state.web_auth_required = required
    app.state.web_auth_token = (token or secrets.token_urlsafe(32)) if required else None
    return app.state.web_auth_token or ""


def _request_web_token(request: Request) -> str:
    authorization = request.headers.get("Authorization", "")
    bearer = authorization[7:].strip() if authorization.lower().startswith("bearer ") else ""
    return request.cookies.get("redteam_session", "") or request.headers.get("X-RedTeam-Token", "") or bearer


@app.middleware("http")
async def dashboard_auth_middleware(request: Request, call_next):
    if not app.state.web_auth_required:
        return await call_next(request)
    path = request.url.path
    public = path in {"/", "/api/auth/status", "/api/auth/login"} or path.startswith("/static/")
    if public:
        return await call_next(request)
    expected = str(app.state.web_auth_token or "")
    supplied = _request_web_token(request)
    if not expected or not supplied or not hmac.compare_digest(supplied, expected):
        return JSONResponse({"detail": "Web dashboard authentication required."}, status_code=401,
                            headers={"X-RedTeam-Auth-Required": "1"})
    return await call_next(request)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8899", "http://localhost:8899"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization", "X-RedTeam-Token"],
)

engine = RedTeamAgentEngine()
baas_hunter = CloudBaaSHunter()
verifier = HTTPVerifier()
report_builder = ReportBuilder()
threat_intel = ThreatIntelEngine()

WEB_DIR = os.path.join(os.path.dirname(__file__), "web")

# -------------------------------------------------------------
# Pydantic Request Models
# -------------------------------------------------------------
class StartScanRequest(BaseModel):
    target: str
    preset: str = "full"
    traffic_preset: str = "NORMAL"
    max_requests: Optional[int] = DEFAULT_REQUEST_BUDGET
    scope_include: Optional[List[str]] = None
    scope_exclude: Optional[List[str]] = None
    exact_urls: Optional[List[str]] = None
    allow_private: bool = False
    aggressive: bool = False
    offensive: bool = False
    bypass_budget: int = DEFAULT_BYPASS_REQUEST_BUDGET  # Default: 80
    max_depth: int = 3  # Default: 3 for full exploit chaining
    authorization_identities: Optional[List[Dict[str, Any]]] = None
    deep_assets: bool = False
    secret_discovery: bool = False
    auth_flow: bool = False
    source_maps: bool = False
    browser_verify: bool = False
    # Browser/session material is accepted only for the in-process task and is
    # never copied into result JSON. The UI normally sends identity labels and
    # the operator may explicitly provide a researcher-owned auth context.
    auth_context: Optional[Dict[str, Any]] = None
    engagement: Optional[Dict[str, Any]] = None
    objective: str = ""
    vulnerability_classes: List[str] = Field(default_factory=list)
    request_corpus: Any = None
    request_corpus_source: str = "dashboard_capture"
    # One-shot session authentication.  Credentials and the extracted token
    # stay in process memory; only a summary (success/source/netloc) is ever
    # exposed through the API.
    login: Optional[Dict[str, Any]] = None

class InteractiveExploitRequest(BaseModel):
    url: str
    param: Optional[str] = "id"
    payload: Optional[str] = ""
    method: str = "GET"
    headers: Optional[Dict[str, str]] = None
    body: Optional[str] = None
    task_id: Optional[str] = None
    allow_private: bool = False
    technique: str = ""
    engagement: Optional[Dict[str, Any]] = None

class BaasAuditRequest(BaseModel):
    platform: str  # "supabase" or "firebase"
    url: str
    anon_key: Optional[str] = ""
    allow_private: bool = False
    engagement: Optional[Dict[str, Any]] = None

class HumanReviewRequest(BaseModel):
    action: str
    reviewer: str = "local_operator"
    reason: str = ""

class AIReviewRequest(BaseModel):
    review: AIReviewOutput


class WebLoginRequest(BaseModel):
    token: str

# -------------------------------------------------------------
# REST API Endpoints
# -------------------------------------------------------------
@app.get("/api/auth/status")
async def web_auth_status(request: Request):
    expected = str(app.state.web_auth_token or "")
    supplied = _request_web_token(request)
    authenticated = not app.state.web_auth_required or bool(expected and supplied and hmac.compare_digest(supplied, expected))
    return {"required": bool(app.state.web_auth_required), "authenticated": authenticated}


@app.post("/api/auth/login")
async def web_auth_login(req: WebLoginRequest):
    if not app.state.web_auth_required:
        return {"authenticated": True, "required": False}
    expected = str(app.state.web_auth_token or "")
    if not expected or not hmac.compare_digest(req.token.strip(), expected):
        raise HTTPException(status_code=401, detail="Invalid dashboard token.")
    response = JSONResponse({"authenticated": True, "required": True})
    response.set_cookie("redteam_session", expected, httponly=True, samesite="strict", max_age=28800)
    return response


@app.post("/api/scan/start")
async def start_scan(req: StartScanRequest):
    if not req.target or not req.target.strip():
        raise HTTPException(status_code=400, detail="Target domain or URL is required.")
    if req.preset not in SCAN_PRESETS:
        raise HTTPException(status_code=400, detail="Unknown scan preset.")
    traffic_preset = req.traffic_preset.upper()
    if traffic_preset not in TRAFFIC_PRESETS:
        raise HTTPException(status_code=400, detail="Unknown traffic preset.")
    if req.max_requests is not None and req.max_requests < 1:
        raise HTTPException(status_code=400, detail="max_requests must be positive.")
    if req.bypass_budget < 0:
        raise HTTPException(status_code=400, detail="bypass_budget must be zero or positive.")
    if req.max_depth < 0 or req.max_depth > MAX_BYPASS_DEPTH:
        raise HTTPException(status_code=400, detail=f"max_depth must be between 0 and {MAX_BYPASS_DEPTH}.")
    offensive = bool(req.offensive or req.aggressive or req.preset in {"active_exploit", "deep_bypass"})
    hunt_focus = {
        "objective": (req.objective or "").strip(),
        "vulnerability_classes": list(dict.fromkeys(req.vulnerability_classes)),
    }
    engagement_profile = None
    if req.engagement:
        try:
            engagement_profile = EngagementProfile.from_mapping(req.engagement)
        except (ValueError, TypeError) as exc:
            raise HTTPException(status_code=400, detail=f"invalid engagement: {exc}") from exc
    if offensive and engagement_profile is None:
        raise HTTPException(status_code=400, detail="offensive scan requires --engagement-file")
    try:
        task = task_manager.create_task(req.target.strip(), preset=req.preset, scope_in=req.scope_include,
        scope_exclude=req.scope_exclude, exact_urls=req.exact_urls, allow_private=req.allow_private,
            traffic_preset=traffic_preset, max_requests=(req.max_requests or DEFAULT_REQUEST_BUDGET), aggressive=req.aggressive,
            offensive=offensive,
            bypass_budget=req.bypass_budget, max_depth=req.max_depth,
            authorization_identities=req.authorization_identities,
            deep_assets=req.deep_assets, secret_discovery=req.secret_discovery,
            auth_flow=req.auth_flow, source_maps=req.source_maps,
            browser_verify=req.browser_verify, auth_context=req.auth_context,
            engagement=engagement_profile, hunt_focus=hunt_focus,
            request_corpus=req.request_corpus,
            request_corpus_source=req.request_corpus_source,
            login=req.login)
    except (ValueError, URLPolicyError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    
    # Launch background async pipeline
    task.attach_pipeline_task(asyncio.create_task(engine.run_full_scan_pipeline(task)))
    
    return {
        "status": "started",
        "task_id": task.task_id,
        "target": task.target,
        "preset": task.preset
        ,"traffic_preset": task.traffic_controller.preset,
        "scope": task.scope_manager.summary(),
        "discovery_policy": task.results.get("discovery_policy", {}),
    }

@app.get("/api/scan/list")
async def list_scans():
    return {"scans": task_manager.list_tasks()}

@app.get("/api/scan/status/{task_id}")
async def get_scan_status(task_id: str):
    task = task_manager.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Scan task not found.")
    return engine.redactor.redact_json({
        "task_id": task.task_id,
        "target": task.target,
        "preset": task.preset,
        "status": task.status,
        "current_step": task.current_step,
        "progress": task.progress,
        "stats": task.results.get("stats", {}),
        "recent_logs": task.logs[-15:]
        ,"traffic": task.traffic_controller.stats(),
        "scope": task.scope_manager.summary(),
        "auth_session": task.results.get("auth_session"),
    })

@app.get("/api/scan/results/{task_id}")
async def get_scan_results(task_id: str):
    task = task_manager.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Scan task not found.")
    task.results["traffic"] = task.traffic_controller.stats()
    return engine.redactor.redact_json(task.results)

@app.post("/api/scan/stop/{task_id}")
async def stop_scan(task_id: str):
    task = task_manager.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Scan task not found.")
    await task.stop()
    await task.emit_log("WARN", "[KILL-SWITCH] no new requests will start; pipeline and owned processes stopped")
    return {"status": task.status, "task_id": task_id, "kill_switch": True}

@app.get("/api/stream/{task_id}")
async def stream_task_logs(task_id: str):
    """
    Server-Sent Events (SSE) endpoint: streams backlog and real-time live logs.
    """
    task = task_manager.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Scan task not found.")

    async def event_generator():
        # First yield all past logs in backlog
        for log in task.logs:
            yield f"data: {json.dumps(engine.redactor.redact_json(log))}\n\n"

        # If already completed or failed, close stream
        if task.status in ["completed", "failed", "stopped"]:
            yield f"data: {json.dumps({'level': 'SYSTEM', 'message': '[STREAM_END]', 'progress': task.progress})}\n\n"
            return

        queue = task.subscribe()
        try:
            while True:
                try:
                    entry = await asyncio.wait_for(queue.get(), timeout=20.0)
                    yield f"data: {json.dumps(engine.redactor.redact_json(entry))}\n\n"
                    if task.status in ["completed", "failed", "stopped"] and queue.empty():
                        yield f"data: {json.dumps({'level': 'SYSTEM', 'message': '[STREAM_END]', 'progress': task.progress})}\n\n"
                        break
                except asyncio.TimeoutError:
                    # Keep-alive heartbeat comment
                    yield ": ping\n\n"
                    if task.status in ["completed", "failed", "stopped"]:
                        yield f"data: {json.dumps({'level': 'SYSTEM', 'message': '[STREAM_END]', 'progress': task.progress})}\n\n"
                        break
        finally:
            task.unsubscribe(queue)

    return StreamingResponse(event_generator(), media_type="text/event-stream")

@app.post("/api/exploit/test")
async def test_interactive_payload(req: InteractiveExploitRequest):
    """
    Interactive payload execution & verification console.
    """
    if not req.technique.strip():
        raise HTTPException(status_code=400, detail="An exact target-specific technique is required.")
    if req.engagement is None:
        raise HTTPException(status_code=400, detail="offensive scan requires --engagement-file")
    try:
        engagement_profile = EngagementProfile.from_mapping(req.engagement)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=400, detail=f"invalid engagement: {exc}") from exc
    engagement_profile.assert_active()
    engagement_profile.assert_scope(req.url)
    engagement_profile.assert_techniques([req.technique])
    full_url = req.url
    if req.param and req.payload:
        import urllib.parse
        parsed = urllib.parse.urlparse(full_url)
        query = urllib.parse.parse_qs(parsed.query)
        query[req.param] = [req.payload]
        new_query = urllib.parse.urlencode(query, doseq=True)
        full_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

    if req.task_id:
        task = task_manager.get_task(req.task_id)
        if not task:
            raise HTTPException(status_code=404, detail="Scan task not found.")
        scope, traffic = task.scope_manager, task.traffic_controller
    else:
        try:
            scope = ScopeManager.from_target(req.url, allow_private=req.allow_private)
        except (ValueError, URLPolicyError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        traffic = TrafficController("NORMAL")
    sandbox_verifier = HTTPVerifier(traffic_controller=traffic, scope_manager=scope, module="exploit_sandbox")
    res = await asyncio.to_thread(sandbox_verifier.send_http_request, full_url, req.method, req.headers, req.body)
    res["verification_state"] = "EXECUTED" if res.get("status_code") else "REJECTED"
    res["in_scope"] = bool(res.get("scope", {}).get("in_scope"))
    res["traffic"] = traffic.stats()
    return res

@app.post("/api/cloud/audit")
async def audit_cloud_target(req: BaasAuditRequest):
    """Directly tests Supabase RLS or Firebase open rules."""
    if req.engagement is None:
        raise HTTPException(status_code=400, detail="offensive scan requires --engagement-file")
    try:
        engagement_profile = EngagementProfile.from_mapping(req.engagement)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=400, detail=f"invalid engagement: {exc}") from exc
    engagement_profile.assert_active()
    engagement_profile.assert_scope(req.url)
    engagement_profile.assert_techniques(["cloud-baas"])
    try:
        direct_scope = ScopeManager.from_target(req.url, allow_private=req.allow_private)
    except (ValueError, URLPolicyError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if req.platform.lower() == "supabase":
        if not req.anon_key:
            raise HTTPException(status_code=400, detail="Supabase anon_key is required.")
        direct = CloudBaaSHunter(scope_manager=direct_scope)
        report = await asyncio.to_thread(direct.audit_supabase, req.url, req.anon_key)
        return report
    elif req.platform.lower() == "firebase":
        direct = CloudBaaSHunter(scope_manager=direct_scope)
        report = await asyncio.to_thread(direct.audit_firebase, req.url)
        return report
    else:
        raise HTTPException(status_code=400, detail="Invalid platform. Choose 'supabase' or 'firebase'.")

@app.post("/api/findings/{task_id}/{finding_id}/human-review")
async def human_review(task_id: str, finding_id: str, req: HumanReviewRequest):
    task = task_manager.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Scan task not found.")
    finding = next((item for item in task.results.get("findings", []) if item.get("id") == finding_id), None)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found.")
    try:
        apply_human_review(finding, req.action, req.reviewer, req.reason)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    # Re-run the FP kill gate so a MARK_VERIFIED override with reason moves the
    # finding into the submission list, while REJECT keeps it out.
    kill_report = kill_pass(task.results.get("findings", []))
    task.results["quarantined_findings"] = kill_report["quarantined"]
    task.results["fp_kill_summary"] = kill_report["summary"]
    task.results["vulnerabilities"] = kill_report["submission_ready"]
    task.results["stats"]["vulnerabilities"] = len(kill_report["submission_ready"])
    task.results["stats"]["quarantined"] = len(kill_report["quarantined"])
    return engine.redactor.redact_json(finding)

@app.post("/api/findings/{task_id}/{finding_id}/validate-poc")
async def validate_poc(task_id: str, finding_id: str):
    """Re-run a deterministic PoC, then recompute the shared disposition.

    A passing PoC can promote an ordinary finding only when its evidence class
    supports VERIFIED. Reflection-only XSS and GraphQL introspection retain
    their observed primitive but remain LIKELY/INFO_ONLY respectively.
    """
    task = task_manager.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Scan task not found.")
    finding = next((item for item in task.results.get("findings", []) if item.get("id") == finding_id), None)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found.")
    validation = await asyncio.to_thread(validate_finding_poc, task, finding)
    if "vrt_triage" not in finding:
        finding["vrt_triage"] = VRTTriageEngine().evaluate_finding(
            str(finding.get("type") or finding.get("vuln_type") or ""),
            str(finding.get("observed_impact") or finding.get("verification_note") or ""),
            poc_verified=bool(validation.get("passed")),
            possesses_active_exploit=bool(validation.get("passed")),
        )
    apply_validation_result(finding, validation)
    # Recompute the complete disposition, including VRT/FP gates.  This is
    # intentionally the same path used at pipeline completion; validate-poc
    # cannot manufacture a submission-ready record by itself.
    kill_report = kill_pass(task.results.get("findings", []))
    task.results["quarantined_findings"] = kill_report["quarantined"]
    task.results["fp_kill_summary"] = kill_report["summary"]
    task.results["vulnerabilities"] = kill_report["submission_ready"]
    task.results["stats"]["vulnerabilities"] = len(kill_report["submission_ready"])
    task.results["stats"]["quarantined"] = len(kill_report["quarantined"])
    return engine.redactor.redact_json({
        "validation": validation, "id": finding["id"], "status": finding["status"],
        "disposition": finding.get("disposition"), "submission_ready": finding in kill_report["submission_ready"],
    })

@app.post("/api/findings/{task_id}/{finding_id}/ai-review")
async def ai_review(task_id: str, finding_id: str, req: AIReviewRequest):
    task = task_manager.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Scan task not found.")
    finding = next((item for item in task.results.get("findings", []) if item.get("id") == finding_id), None)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found.")
    apply_ai_review(finding, req.review)
    return engine.redactor.redact_json(finding)

@app.get("/api/report/markdown/{task_id}")
async def get_markdown_report(task_id: str):
    task = task_manager.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Scan task not found.")
    md = report_builder.generate_full_audit_report(engine.redactor.redact_json(task.results))
    return PlainTextResponse(md, media_type="text/markdown")


@app.get("/api/report/bundle/{task_id}")
async def get_evidence_bundle(task_id: str):
    task = task_manager.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Scan task not found.")
    payload = EvidenceBundleBuilder().build_zip(task.results)
    filename = f"{task.task_id}-evidence.zip"
    return StreamingResponse(
        io.BytesIO(payload), media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

class ExportAnalyzeRequest(BaseModel):
    results: Optional[Dict[str, Any]] = None
    data: Optional[Dict[str, Any]] = None


@app.get("/api/report/analyze/{task_id}")
async def analyze_task_export(task_id: str):
    task = task_manager.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Scan task not found.")
    try:
        report = analyze_export(engine.redactor.redact_json(task.results))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Analyze failed: {exc}") from exc
    return JSONResponse(report)


@app.post("/api/report/analyze")
async def analyze_uploaded_export(request: Request):
    try:
        body = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {exc}") from exc
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Export must be a JSON object")
    # Support {results:{...}}, {data:{...}}, or raw results.json dict
    candidate = None
    if isinstance(body.get("results"), dict):
        candidate = body["results"]
    elif isinstance(body.get("data"), dict):
        candidate = body["data"]
    elif "target" in body or "findings" in body or "vulnerabilities" in body or "stats" in body:
        candidate = body
    else:
        # Try to find first dict value that looks like results
        for value in body.values():
            if isinstance(value, dict) and ("findings" in value or "target" in value):
                candidate = value
                break
    if candidate is None:
        candidate = body
    try:
        report = analyze_export(candidate)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Analyze failed: {exc}") from exc
    return JSONResponse(report)


@app.get("/api/intel/cisa")
async def get_cisa_intel():
    return {
        "total_catalog_count": len(threat_intel.cisa_catalog),
        "sample_entries": threat_intel.cisa_catalog[:10],
        "catalog_provenance": "bundled_reference unless an entry source is CISA_KEV_LIVE",
        "last_live_fetch": threat_intel.last_fetch,
        "affected_versions_verified": False,
    }

# -------------------------------------------------------------
# Static Frontend Serving
# -------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
async def serve_index():
    index_file = os.path.join(WEB_DIR, "index.html")
    with open(index_file, "r", encoding="utf-8") as f:
        return f.read()

app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")

def run(port: int = 8899, listen: str = "127.0.0.1", web_auth_token: Optional[str] = None):
    import uvicorn
    token = configure_web_auth(listen, web_auth_token)
    if token:
        print(f"[AUTH] Web dashboard token: {token}")
    uvicorn.run(app, host=listen, port=port, reload=False)

if __name__ == "__main__":
    run()
