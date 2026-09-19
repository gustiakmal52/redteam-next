"""
Task Manager and Real-time SSE Pub/Sub Broker for Red Team Bug Bounty Agent.
Manages asynchronous scanning tasks, maintains state, and streams live logs.
"""

import asyncio
import json
import time
import uuid
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from redteam_agent.core.scope_manager import ScopeManager
from redteam_agent.core.traffic_controller import TrafficController
from redteam_agent.core.config import DEFAULT_BYPASS_REQUEST_BUDGET, MAX_BYPASS_DEPTH
from redteam_agent.core.config import DEFAULT_REQUEST_BUDGET
from redteam_agent.core.engagement import (
    EngagementError, EngagementProfile, IMPLEMENTED_CLASSES, engagement_required,
)


SUPPORTED_FOCUS_CLASSES = {
    "idor", "bola", "authorization", "auth-bypass",
    "xss", "sqli", "sql-injection", "ssrf", "ssti",
    "open-redirect", "graphql", "cloud-baas",
    # any class is accepted — no gate
}


def _validate_focus_context(_vulnerability_classes: List[str], _auth_context: Dict[str, Any]) -> None:
    """No-op — focus context validation removed."""
    pass


def _identity_labels(auth_context: Dict[str, Any]) -> List[str]:
    identities = auth_context.get("identities") if isinstance(auth_context, dict) else None
    if isinstance(identities, dict):
        return sorted(str(name) for name in identities)
    if isinstance(identities, list):
        return [
            str(item.get("name") or item.get("id") or f"identity_{index}")
            for index, item in enumerate(identities) if isinstance(item, dict)
        ]
    return []


class ProcessRegistry:
    """Own every async pipeline/process handle that a scan can spawn.

    The registry is deliberately attached to a ScanTask.  A kill switch can
    therefore cancel the pipeline and terminate tool children without
    affecting another user's scan or relying on a best-effort traffic flag.
    """

    def __init__(self):
        self.tasks: list[asyncio.Task] = []
        self.processes: list[Any] = []

    def register_task(self, handle: asyncio.Task) -> asyncio.Task:
        if handle not in self.tasks:
            self.tasks.append(handle)
        return handle

    def register_process(self, process: Any) -> Any:
        if process not in self.processes:
            self.processes.append(process)
        return process

    def unregister_process(self, process: Any) -> None:
        if process in self.processes:
            self.processes.remove(process)

    async def cancel_all(self) -> None:
        current = asyncio.current_task()
        owned_tasks = [item for item in self.tasks if item is not current and not item.done()]
        for handle in owned_tasks:
            handle.cancel()
        if owned_tasks:
            await asyncio.gather(*owned_tasks, return_exceptions=True)

        children = list(self.processes)
        for process in children:
            try:
                if process.returncode is None:
                    process.terminate()
            except (AttributeError, ProcessLookupError):
                pass
        for process in children:
            try:
                await asyncio.wait_for(process.wait(), timeout=2.0)
            except (asyncio.TimeoutError, AttributeError, ProcessLookupError):
                try:
                    process.kill()
                except (AttributeError, ProcessLookupError):
                    pass
        self.processes.clear()
        self.tasks = [item for item in self.tasks if not item.done()]

class ScanTask:
    def __init__(self, task_id: str, target: str, preset: str = "full", scope_in: Optional[List[str]] = None,
                 scope_exclude: Optional[List[str]] = None, exact_urls: Optional[List[str]] = None,
                 allow_private: bool = False, traffic_preset: str = "NORMAL", max_requests: Optional[int] = DEFAULT_REQUEST_BUDGET,
                 aggressive: bool = False, bypass_budget: int = DEFAULT_BYPASS_REQUEST_BUDGET,
                 max_depth: int = MAX_BYPASS_DEPTH,
                 authorization_identities: Optional[List[Dict[str, Any]]] = None,
                 deep_assets: bool = False, secret_discovery: bool = False,
                 auth_flow: bool = False, source_maps: bool = False,
                 browser_verify: bool = False, auth_context: Optional[Dict[str, Any]] = None,
                 offensive: bool = False, engagement: Optional[EngagementProfile] = None,
                 hunt_focus: Optional[Dict[str, Any]] = None,
                 request_corpus: Any = None, request_corpus_source: str = "researcher_capture",
                 show_secrets: bool = False, login: Optional[Dict[str, Any]] = None):
        self.task_id = task_id
        self.target = target.strip()
        self.preset = preset
        self.scope_in = scope_in or [target.strip()]
        self.scope_manager = ScopeManager.from_target(target, include=scope_in, exclude=scope_exclude,
                                                      exact_urls=exact_urls, allow_private=allow_private)
        # ``None`` from a compatibility caller must not silently disable the
        # global controller budget.  An explicit finite value can still lower
        # the budget for a particular engagement.
        effective_request_budget = DEFAULT_REQUEST_BUDGET if max_requests is None else max_requests
        self.traffic_controller = TrafficController(traffic_preset, max_requests=effective_request_budget)
        self.process_registry = ProcessRegistry()
        self.pipeline_task: Optional[asyncio.Task] = None
        # ``aggressive`` remains only as a compatibility alias. Both it and the
        # explicit ``offensive`` switch activate the same focused,
        # target-specific planner; there is no second generic spray mode.
        self.offensive = bool(offensive or aggressive or preset in {"active_exploit", "deep_bypass"})
        self.engagement = engagement
        merged_auth_context = dict(auth_context or {}) if isinstance(auth_context, dict) else {}
        if authorization_identities and not merged_auth_context.get("identities"):
            merged_auth_context["identities"] = list(authorization_identities)
        self.hunt_focus = {
            "objective": str((hunt_focus or {}).get("objective") or "").strip(),
            "vulnerability_classes": list(dict.fromkeys(
                str(item).strip() for item in (hunt_focus or {}).get("vulnerability_classes", [])
                if str(item).strip()
            )),
        }
        # Captured requests may contain session values, so the raw corpus is
        # process-memory-only. Public results receive structural summaries.
        self.request_corpus = request_corpus
        self.request_corpus_source = str(request_corpus_source or "researcher_capture")
        self.show_secrets = bool(show_secrets)
        self.exploit_mode = "OFFENSIVE" if self.offensive else "SAFE"
        self.bypass_budget = max(0, int(bypass_budget))
        self.max_depth = min(MAX_BYPASS_DEPTH, max(0, int(max_depth)))
        # Credentials remain in process memory for the task and are never
        # copied into result JSON. Only identity labels are exposed below.
        self.authorization_identities = list(authorization_identities or [])
        self.deep_assets = bool(deep_assets)
        self.secret_discovery = bool(secret_discovery)
        self.auth_flow = bool(auth_flow)
        self.source_maps = bool(source_maps)
        self.browser_verify = bool(browser_verify)
        self.browser_verifier = None
        # This object is process-memory-only.  Result JSON exposes labels, not
        # headers or token values.
        self.auth_context = merged_auth_context
        # Login credentials for one-shot session authentication.  Process
        # memory only; never exported to results, reports, or evidence.
        self.login = dict(login or {}) if isinstance(login, dict) else {}
        self.status = "pending"  # pending, running, completed, failed, cancelling, stopped
        self.current_step = "Initialized"
        self.progress = 0  # 0 to 100
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.completed_at = None

        # ------------------------------------------------------------------ #
        # Engagement validation (offensive sessions require authorization)
        # ------------------------------------------------------------------ #
        if self.offensive:
            if self.engagement is None:
                raise EngagementError("offensive scan requires --engagement-file")
            self.engagement.assert_active()
            self.engagement.assert_scope(self.target)
            self.engagement.assert_techniques(self.hunt_focus.get("vulnerability_classes"))
            selected_classes = self.hunt_focus.get("vulnerability_classes") or []
            if not selected_classes:
                raise EngagementError(
                    "offensive scan requires selected vulnerability classes "
                    "(hunt_focus.vulnerability_classes)")
            unsupported = [item for item in selected_classes
                           if item not in IMPLEMENTED_CLASSES]
            if unsupported:
                raise EngagementError(
                    f"vulnerability class {unsupported[0]} has no target-specific "
                    f"planner (implemented: {', '.join(sorted(IMPLEMENTED_CLASSES))})")
            if "idor" in selected_classes or "bola" in selected_classes:
                identities = merged_auth_context.get("identities") or []
                if len(identities) < 2:
                    raise EngagementError(
                        "IDOR/BOLA focus requires two researcher-owned identities "
                        "(auth_context.identities)")
                if not any(
                    isinstance(item, dict) and (item.get("owner_marker") or item.get("markers"))
                    for item in identities
                ):
                    raise EngagementError(
                        "IDOR/BOLA focus requires an owner-controlled response marker "
                        "(owner_marker on at least one identity)")

        # Real-time event pub/sub queues
        self.subscribers: List[asyncio.Queue] = []
        
        # Log history
        self.logs: List[Dict[str, Any]] = []
        
        # Collected asset & vulnerability results
        self.results: Dict[str, Any] = {
            "target": self.target,
            "preset": self.preset,
            "status": "pending",
            "stats": {
                "subdomains": 0,
                "live_hosts": 0,
                "endpoints": 0,
                "js_files": 0,
                "secrets_found": 0,
                "js_grep_matches": 0,
                "js_api_calls": 0,
                "db_connection_strings": 0,
                "db_exposed_ports": 0,
                "waf_bypass_attempts": 0,
                "bypass_requests": 0,
                "bypass_verified_primitives": 0,
                "cloud_misconfigs": 0,
                "vulnerabilities": 0,
                "quarantined": 0,
                "cisa_threats": 0,
                "auth_gated_endpoints": 0,
                "post_json_endpoints": 0,
                "hidden_assets": 0,
                "hidden_endpoints": 0,
                "hidden_credentials": 0,
                "source_maps_parsed": 0,
                "auth_flows": 0,
                "credential_relationships": 0,
                "offensive_hypotheses": 0,
                "offensive_requests": 0,
                "offensive_verified_primitives": 0,
            },
            "subdomains": [],
            "live_hosts": [],
            "endpoints": [],
            "js_assets": [],
            "hidden_params": [],
            "js_grep": [],
            "js_api_trace": [],
            "db_hunter": {"connection_strings": [], "exposed_ports": [], "admin_panels": [],
                           "backup_files": [], "hidden_db_strings": [],
                           "total_connection_strings": 0, "total_exposed_ports": 0,
                           "total_admin_panels": 0, "total_backup_files": 0,
                           "total_hidden_db_strings": 0},
            "waf_bypass_findings": [],
            "exploit_coverage": [],
            "cloud_baas": {
                "supabase": [],
                "firebase": [],
                "vercel": [],
                "harvested_tokens": []
            },
            "vulnerabilities": [],
            "findings": [],
            "quarantined_findings": [],
            "fp_kill_summary": {"submission_ready": 0, "quarantined": 0, "reasons": {}},
            "recon_depth": {},
            "vrt_summary": {"approved": 0, "rejected_anti_na": 0, "rejected_no_poc": 0, "total": 0},
            "exploit_mode": self.exploit_mode,
            "offensive_mode": self.offensive,
            "engagement": engagement.public_summary() if engagement else {
                "authorization_validated": False,
                "reason": "No engagement record supplied; passive/non-offensive session only",
            },
            "hunt_focus": self.hunt_focus,
            "captured_requests": {
                "loaded": request_corpus is not None,
                "source": self.request_corpus_source,
                "entries_seen": 0,
                "in_scope_unique_requests": 0,
                "credentials_retained": False,
                "rejected": [],
            },
            "bypass_engine": {
                "request_budget": self.bypass_budget,
                "max_depth": self.max_depth,
                "authorization_identities": [
                    str(item.get("name") or item.get("id") or f"identity_{index}")
                    if isinstance(item, dict) else f"identity_{index}"
                    for index, item in enumerate(self.authorization_identities)
                ],
                "reports": [],
                "findings": [],
                "primitives": [],
                "chains": [],
            },
            "hidden_assets": {
                "assets": [], "endpoints": [], "credentials": [], "baas_projects": [],
                "auth_flows": [], "source_maps": [], "runtime_configs": [],
                "relationships": [], "frameworks": [], "findings": [], "stats": {},
                "budget": {}, "coverage": {"auth_context_loaded": bool(self.auth_context),
                                             "auth_identities": _identity_labels(self.auth_context)},
                "errors": [], "integrations": {},
            },
            "deep_exploit": {
                "engine": "DeepExploitEngine", "mode": self.exploit_mode,
                "plan": [], "reports": [], "findings": [], "verified_findings": [],
                "primitives": [], "chains": [], "request_budget": self.bypass_budget,
                "requests_used": 0, "requests_remaining": self.bypass_budget,
            },
            "discovery_policy": {
                "offensive_mode": self.offensive,
                "deep_assets": self.deep_assets, "secret_discovery": self.secret_discovery,
                "auth_flow": self.auth_flow, "source_maps": self.source_maps,
                "browser_verify": self.browser_verify,
                "show_secrets": self.show_secrets,
                "auth_context_loaded": bool(self.auth_context),
                "auth_identities": _identity_labels(self.auth_context),
            },
            "bypass_budget": self.bypass_budget,
            "max_depth": self.max_depth,
            "cisa_intel": [],
            "filtered_anti_na": [],
            "discarded_anti_halu": [],
            "tool_runs": [],
            "external_discoveries": [],
            "scope": self.scope_manager.summary(),
            "traffic": self.traffic_controller.stats(),
        }

    async def emit_log(self, level: str, message: str, step: Optional[str] = None, progress: Optional[int] = None):
        """Broadcasts a log line to all active SSE subscribers and appends to task log history."""
        if step:
            self.current_step = step
        if progress is not None:
            self.progress = progress

        timestamp = datetime.now(timezone.utc).strftime("%H:%M:%S")
        entry = {
            "time": timestamp,
            "level": level.upper(),  # INFO, SUCCESS, WARN, ALERT, VULN, DEBUG
            "message": message,
            "step": self.current_step,
            "progress": self.progress
        }
        self.logs.append(entry)

        # Notify active SSE subscribers
        dead_queues = []
        for queue in self.subscribers:
            try:
                queue.put_nowait(entry)
            except Exception:
                dead_queues.append(queue)
        for dead in dead_queues:
            if dead in self.subscribers:
                self.subscribers.remove(dead)

    def subscribe(self) -> asyncio.Queue:
        """Registers a new SSE listener for live log streaming."""
        queue = asyncio.Queue()
        self.subscribers.append(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue):
        if queue in self.subscribers:
            self.subscribers.remove(queue)

    def attach_pipeline_task(self, handle: asyncio.Task) -> asyncio.Task:
        self.pipeline_task = handle
        return self.process_registry.register_task(handle)

    def register_process(self, process: Any) -> Any:
        return self.process_registry.register_process(process)

    def unregister_process(self, process: Any) -> None:
        self.process_registry.unregister_process(process)

    async def stop(self) -> None:
        """Cancel the pipeline and kill owned tool children immediately."""
        self.traffic_controller.kill()
        browser_verifier = self.browser_verifier
        if browser_verifier is not None:
            try:
                browser_verifier.stop()
            except Exception:
                # The pipeline's finally block performs a second best-effort
                # close on the browser's owning thread.
                pass
        if self.status in {"pending", "running"}:
            self.status = "cancelling"
            self.results["status"] = "cancelling"
        await self.process_registry.cancel_all()
        if self.status == "cancelling":
            self.status = "stopped"
            self.results["status"] = "stopped"
            self.completed_at = datetime.now(timezone.utc).isoformat()


class TaskManager:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(TaskManager, cls).__new__(cls)
            cls._instance.tasks: Dict[str, ScanTask] = {}
        return cls._instance

    def create_task(self, target: str, preset: str = "full", scope_in: Optional[List[str]] = None,
                    scope_exclude: Optional[List[str]] = None, exact_urls: Optional[List[str]] = None,
                    allow_private: bool = False, traffic_preset: str = "NORMAL", max_requests: Optional[int] = DEFAULT_REQUEST_BUDGET,
                    aggressive: bool = False, bypass_budget: int = DEFAULT_BYPASS_REQUEST_BUDGET,
                    max_depth: int = MAX_BYPASS_DEPTH,
                    authorization_identities: Optional[List[Dict[str, Any]]] = None,
                    deep_assets: bool = False, secret_discovery: bool = False,
                    auth_flow: bool = False, source_maps: bool = False,
                    browser_verify: bool = False, auth_context: Optional[Dict[str, Any]] = None,
                    offensive: bool = False, engagement: Optional[EngagementProfile] = None,
                    hunt_focus: Optional[Dict[str, Any]] = None,
                    request_corpus: Any = None,
                    request_corpus_source: str = "researcher_capture",
                    show_secrets: bool = False,
                    login: Optional[Dict[str, Any]] = None) -> ScanTask:
        task_id = f"scan_{int(time.time())}_{uuid.uuid4().hex[:6]}"
        task = ScanTask(task_id, target, preset, scope_in, scope_exclude, exact_urls, allow_private,
                        traffic_preset, max_requests, aggressive, bypass_budget, max_depth,
                        authorization_identities, deep_assets, secret_discovery, auth_flow,
                        source_maps, browser_verify, auth_context, offensive, engagement, hunt_focus,
                        request_corpus, request_corpus_source, show_secrets, login)
        self.tasks[task_id] = task
        return task

    def get_task(self, task_id: str) -> Optional[ScanTask]:
        return self.tasks.get(task_id)

    def list_tasks(self) -> List[Dict[str, Any]]:
        return [
            {
                "task_id": t.task_id,
                "target": t.target,
                "preset": t.preset,
                "status": t.status,
                "current_step": t.current_step,
                "progress": t.progress,
                "created_at": t.created_at,
                "completed_at": t.completed_at,
                "vulns_count": len(t.results["vulnerabilities"])
            }
            for t in sorted(self.tasks.values(), key=lambda x: x.created_at, reverse=True)
        ]


# Singleton instance
task_manager = TaskManager()
