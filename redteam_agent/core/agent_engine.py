"""Incremental V2.1 pipeline orchestrator: recon, active proof, skeptical triage."""

from __future__ import annotations

import asyncio
import datetime
import urllib.parse
from typing import Any, Dict, List, Optional

from redteam_agent.core.cloud_baas_hunter import CloudBaaSHunter
from redteam_agent.core.config import SCAN_PRESETS, DEFAULT_BYPASS_REQUEST_BUDGET, DEFAULT_REQUEST_BUDGET, MAX_BYPASS_DEPTH
from redteam_agent.core.bypass_engine import BypassEngine
from redteam_agent.core.browser_verifier import BrowserVerifier
from redteam_agent.core.deep_exploit_engine import DeepExploitEngine
from redteam_agent.core.db_hunter import DBHunter
from redteam_agent.core.exploit_engine import ExploitEngine
from redteam_agent.core.findings import FindingStatus
from redteam_agent.core.fp_killer import kill_pass
from redteam_agent.core.http_verifier import HTTPVerifier
from redteam_agent.core.js_analyzer import JSAnalyzer
from redteam_agent.core.recon_depth import ReconDepth
from redteam_agent.core.recon_pipeline import ReconPipeline
from redteam_agent.core.report_builder import ReportBuilder
from redteam_agent.core.scope_manager import ScopeManager
from redteam_agent.core.task_manager import ScanTask
from redteam_agent.core.threat_intel import ThreatIntelEngine
from redteam_agent.core.vrt_triage import VRTTriageEngine
from redteam_agent.discovery.hidden_assets import HiddenAssetEngine
from redteam_agent.discovery.redaction import SecretRedactor
from redteam_agent.discovery.request_corpus import endpoint_records_from_corpus


class RedTeamAgentEngine:
    def __init__(self):
        self.report_builder = ReportBuilder()
        self.threat_intel = ThreatIntelEngine()
        self.redactor = SecretRedactor()

    def _safe_secret(self, secret: dict, *, reveal: bool = False) -> dict:
        """Return an isolated result record; plaintext is CLI opt-in only."""
        safe = dict(secret)
        raw = str(safe.get("_raw_value") or safe.get("value") or "")
        if reveal:
            safe["_raw_value"] = raw
            return safe
        safe.pop("_raw_value", None)
        masked = self.redactor.mask_secret(raw)
        for key in ("value", "display_value"):
            if key in safe:
                safe[key] = masked
        return safe

    @staticmethod
    def _context_strings(value: Any) -> List[str]:
        """Collect transient auth-context strings solely for final scrubbing."""
        if isinstance(value, dict):
            output: List[str] = []
            for item in value.values():
                output.extend(RedTeamAgentEngine._context_strings(item))
            return output
        if isinstance(value, (list, tuple)):
            output: List[str] = []
            for item in value:
                output.extend(RedTeamAgentEngine._context_strings(item))
            return output
        return [value] if isinstance(value, str) and value else []

    def _redact_public_state(self, task: ScanTask, known_values: List[str], *, preserve_raw_values: bool = False) -> None:
        """Scrub the legacy result surface as well as the new discovery export.

        Raw discoveries are preserved only in the private ``_raw_value`` field
        when the local CLI explicitly opts in.  Nearby snippets, logs, auth
        context, and every default result remain sanitized.
        """
        values = [str(value) for value in known_values if value]

        def scrub(value: Any, field: str = "") -> Any:
            if isinstance(value, dict):
                return {
                    key: item if preserve_raw_values and key == "_raw_value" else scrub(item, key)
                    for key, item in value.items()
                    if preserve_raw_values or key != "_raw_value"
                }
            if isinstance(value, list):
                return [scrub(item, field) for item in value]
            if isinstance(value, str):
                return self.redactor.redact_text(value, values)
            return value

        task.results = scrub(task.results)
        task.logs = scrub(task.logs)

    async def run_full_scan_pipeline(self, task: ScanTask):
        browser_verifier = None
        try:
            task.status = "running"
            task.results["status"] = "running"
            loop = asyncio.get_running_loop()
            task.traffic_controller.event_callback = lambda message: asyncio.run_coroutine_threadsafe(
                task.emit_log("WARN", message), loop)
            modules = set(SCAN_PRESETS.get(task.preset, SCAN_PRESETS["full"])["modules"])
            await task.emit_log("INFO", f"[RECON] Launching {task.preset} pipeline on {task.target}", "Pipeline Initialization", 5)

            recon = ReconPipeline(task)
            target_url = task.target if task.target.startswith(("http://", "https://")) else f"https://{task.target}"
            decision = task.scope_manager.check_url(target_url, active=True)
            if not decision.get("allowed"):
                raise ValueError(f"Target rejected by URL/scope policy: {decision.get('reason')}")
            captured_records = []
            if task.request_corpus is not None:
                captured_records, captured_summary = endpoint_records_from_corpus(
                    task.request_corpus,
                    scope_manager=task.scope_manager,
                    source_name=task.request_corpus_source,
                )
                for rejected in captured_summary.get("rejected", []):
                    if isinstance(rejected, dict) and rejected.get("url"):
                        rejected["url"] = self.redactor.redact_url(rejected["url"])
                task.results["captured_requests"] = captured_summary
                await task.emit_log(
                    "SUCCESS",
                    f"[CAPTURE] {len(captured_records)} in-scope target-specific request shape(s) loaded; no credential values retained",
                    "Captured Request Mapping",
                    8,
                )
            verifier = HTTPVerifier(timeout=task.traffic_controller.config["timeout"], traffic_controller=task.traffic_controller,
                                    scope_manager=task.scope_manager, module="pipeline")

            def global_budget(reserve: int = 0) -> Optional[int]:
                """Live ceiling from the shared traffic controller, minus a verification reserve."""
                try:
                    stats = task.traffic_controller.stats()
                    value = stats.get("requests_remaining")
                    if value is None:
                        return None
                    return max(0, int(value) - max(0, int(reserve)))
                except (AttributeError, TypeError, ValueError):
                    return None

            startup_budget = global_budget(8)
            pipeline_bypass_budget = (task.bypass_budget if startup_budget is None
                                      else min(task.bypass_budget, startup_budget))
            if task.browser_verify:
                # The browser is lazy: importing/constructing the adapter does
                # not launch anything. It is only invoked by a discovered
                # browser-proof hypothesis, with the same scope and global
                # traffic controller as the HTTP pipeline.
                browser_verifier = BrowserVerifier(
                    scope_manager=task.scope_manager,
                    traffic_controller=task.traffic_controller,
                    timeout_ms=max(1000, int(task.traffic_controller.config["timeout"] * 1000)),
                )
                task.browser_verifier = browser_verifier
            # Reference lookups are still network activity.  Give the CISA
            # client a narrow reference scope but the same task controller so
            # it cannot bypass the scan-wide request budget.
            def engine_verifier(module_name: str, scope_manager=None) -> HTTPVerifier:
                """Share one keep-alive pool and TLS context across pipeline engines."""
                return HTTPVerifier(
                    timeout=task.traffic_controller.config["timeout"],
                    traffic_controller=task.traffic_controller,
                    scope_manager=scope_manager or task.scope_manager,
                    module=module_name,
                    pool=verifier._pool,
                    ssl_context=verifier.ssl_context,
                )

            task_threat_intel = ThreatIntelEngine(verifier=engine_verifier(
                "threat_intel", ScopeManager(["www.cisa.gov"], resolve_dns=False)))
            js_analyzer = JSAnalyzer(verifier=verifier, scope_manager=task.scope_manager)
            baas_hunter = CloudBaaSHunter(verifier=verifier, scope_manager=task.scope_manager)
            recon_depth = ReconDepth(task, verifier)
            exploit_engine = ExploitEngine(engine_verifier("exploit_verifier"),
                exploit_mode=task.exploit_mode, browser_verifier=browser_verifier)
            bypass_engine = BypassEngine(
                verifier=engine_verifier("bypass_engine"),
                exploit_mode=task.exploit_mode,
                request_budget=pipeline_bypass_budget,
                max_depth=task.max_depth,
            )
            deep_exploit_engine = DeepExploitEngine(
                verifier=engine_verifier("deep_exploit_engine"),
                exploit_mode=task.exploit_mode,
                request_budget=pipeline_bypass_budget,
                max_depth=task.max_depth,
                reference_intel=bypass_engine.reference_intel,
                browser_verifier=browser_verifier,
            )

            # One-shot session authentication: login once through the scoped
            # verifier, then replay the token to the exact netloc across every
            # pipeline verifier.  Credentials and token stay in process memory.
            if task.login:
                login_result = verifier.login_session(
                    auth_url=task.login.get("auth_url", ""),
                    username=task.login.get("username", ""),
                    password=task.login.get("password", ""),
                    username_field=task.login.get("username_field", "username"),
                    password_field=task.login.get("password_field", "password"),
                    extra_fields=task.login.get("extra_fields"),
                    token_paths=task.login.get("token_paths"),
                    token_header=task.login.get("token_header", "Authorization"),
                    token_prefix=task.login.get("token_prefix", "Bearer "),
                )
                task.results["auth_session"] = {
                    "success": login_result.get("success", False),
                    "status_code": login_result.get("status_code"),
                    "token_source": login_result.get("token_source"),
                    "auth_netloc": login_result.get("auth_netloc"),
                    "auth_headers": login_result.get("auth_headers", []),
                }
                if login_result.get("success"):
                    for other in (exploit_engine.verifier, bypass_engine.verifier,
                                  deep_exploit_engine.verifier):
                        other.set_session_auth(
                            verifier._auth_headers, netloc=verifier._auth_netloc,
                            cookies=verifier._auth_cookies, origin=verifier._auth_origin)
                    await task.emit_log(
                        "SUCCESS",
                        f"[AUTH] Session authenticated as {task.login.get('username', '')} "
                        f"(token source: {login_result.get('token_source')}); replayed only to "
                        f"{login_result.get('auth_netloc')}",
                        "Session Authentication", 10,
                    )
                else:
                    await task.emit_log(
                        "WARN",
                        f"[AUTH] Login failed (HTTP {login_result.get('status_code')}): "
                        f"{str(login_result.get('error', ''))[:120]}",
                        "Session Authentication", 10,
                    )

            subdomains = [recon.domain]
            if "subfinder" in modules:
                subdomains = await recon.run_subdomain_discovery()
            else:
                await task.emit_log("INFO", f"[RECON] subfinder skipped by preset {task.preset}")

            live_hosts: list[dict] = []
            if "httpx" in modules:
                live_hosts = await recon.run_http_probing(subdomains)
            else:
                await task.emit_log("INFO", f"[RECON] httpx skipped by preset {task.preset}; no live host synthesized")

            endpoints = [target_url]
            if "crawlers" in modules:
                endpoints = await recon.run_crawlers(live_hosts)
            else:
                task.results["endpoints"] = endpoints
                task.results["endpoint_records"] = [{"url": target_url, "sources": ["configured_target"],
                    "observed": False, "in_scope": True}]

            js_results = {"js_assets": [], "routes": [], "secrets": [], "hidden_params": [],
                          "external_discoveries": [], "probed_routes": [], "web3": {}}
            if "js_analyzer" in modules:
                await task.emit_log("INFO", "[JS] Analyzing bundles and feeding sourcemap sources back into discovery", "JS & API Analysis", 55)
                js_results = await asyncio.to_thread(js_analyzer.analyze_target, target_url)
                task.results["js_assets"] = js_results.get("js_assets", [])
                task.results["hidden_params"] = js_results.get("hidden_params", [])
                safe_js_context = self.redactor.redact_json({
                    "known": [{"_raw_value": item.get("_raw_value") or item.get("value")}
                              for item in js_results.get("secrets", []) if isinstance(item, dict)],
                    "grep": js_results.get("grep_matches", []),
                    "trace": js_results.get("api_trace", []),
                })
                task.results["js_grep"] = safe_js_context["grep"]
                task.results["js_api_trace"] = safe_js_context["trace"]
                task.results["stats"]["js_files"] = len(js_results.get("js_assets", []))
                task.results["stats"]["secrets_found"] = len(js_results.get("secrets", []))
                task.results["stats"]["js_grep_matches"] = len(task.results["js_grep"])
                task.results["stats"]["js_api_calls"] = len(task.results["js_api_trace"])
                task.results["web3_recon"] = self.redactor.redact_json(js_results.get("web3") or {})
                web3_stats = task.results["web3_recon"].get("stats") or {}
                task.results["stats"]["web3_rpc_verified"] = web3_stats.get("rpc_verified", 0)
                task.results["stats"]["web3_contracts_verified"] = web3_stats.get("contracts_verified", 0)
                task.results["stats"]["web3_proxies_verified"] = web3_stats.get("proxies_verified", 0)
                task.results["stats"]["web3_programs_verified"] = web3_stats.get("solana_programs_verified", 0)
                for rpc in task.results["web3_recon"].get("rpc_endpoints", []):
                    if rpc.get("status") == "SKIPPED_OUT_OF_SCOPE":
                        task.results["external_discoveries"].append({
                            "value": rpc.get("url"), "source": "web3_rpc_from_frontend",
                            "observed": True, "active_verification_skipped": "outside_scope",
                        })
                task.results["external_discoveries"].extend(js_results.get("external_discoveries", []))
                task.results["tool_runs"].extend(js_results.get("failures", []))
                records_by_url = {
                    record["url"]: dict(record)
                    for record in task.results.get("endpoint_records", [])
                    if isinstance(record, dict) and record.get("url")
                }
                for route in js_results.get("routes", []):
                    full = urllib.parse.urljoin(target_url, route)
                    scope = task.scope_manager.check_url(full, active=False)
                    if scope.get("in_scope"):
                        full = scope.get("url") or full
                        record = records_by_url.setdefault(full, {
                            "url": full, "sources": [], "observed": True, "in_scope": True,
                            "method": "GET", "methods": ["GET"], "body_fields": [],
                            "content_types": [], "status_codes": [], "technologies": [],
                            "priority_score": 0, "priority_reasons": [],
                        })
                        record["sources"] = sorted(set(record.get("sources", [])) | {"js_bundle_or_sourcemap"})
                        record["observed"] = True
                    else:
                        task.results["external_discoveries"].append({"value": full, "source": "js_bundle_or_sourcemap",
                            "observed": True, "active_verification_skipped": "outside_scope"})
                task.results["endpoint_records"] = sorted(
                    records_by_url.values(), key=lambda item: (-int(item.get("priority_score", 0)), item["url"]))
                endpoints = [item["url"] for item in task.results["endpoint_records"]]
                task.results["endpoints"] = endpoints
                task.results["stats"]["endpoints"] = len(endpoints)
                await task.emit_log("SUCCESS", f"[JS] {len(js_results.get('routes', []))} routes, "
                    f"{len(js_results.get('secrets', []))} classified token patterns", progress=65)
                if task.results["web3_recon"].get("detected"):
                    await task.emit_log(
                        "SUCCESS",
                        f"[WEB3] {web3_stats.get('rpc_verified', 0)} RPC verified, "
                        f"{web3_stats.get('contracts_verified', 0)} EVM contract(s), "
                        f"{web3_stats.get('proxies_verified', 0)} EIP-1967 proxy(s), "
                        f"{web3_stats.get('solana_programs_verified', 0)} Solana program(s)",
                        progress=66,
                    )

            all_findings: list[dict] = []
            captured_dicts = [record.to_dict() for record in captured_records]
            offensive_records = list(captured_dicts)
            hidden_report: Dict[str, Any] = {"endpoints": [], "baas_projects": []}
            hidden_stats: Dict[str, Any] = {}
            # First-class modern frontend discovery.  It shares the task's
            # scope manager and traffic controller; no secondary downloader
            # or ambient browser profile is created.  The legacy JS/BaaS
            # analyzers remain in the pipeline for backwards-compatible
            # fields, while this layer supplies correlated evidence.
            discovery_enabled = any(("hidden_assets" in modules, task.deep_assets, task.secret_discovery,
                                     task.auth_flow, task.source_maps, task.browser_verify))
            if discovery_enabled:
                await task.emit_log(
                    "INFO",
                    "[ASSET] Deep hidden asset/config/credential discovery with shared scope + traffic controls",
                    "Hidden Asset Discovery",
                    68,
                )
                discovery_verifier = HTTPVerifier(
                    timeout=task.traffic_controller.config["timeout"],
                    traffic_controller=task.traffic_controller,
                    scope_manager=task.scope_manager,
                    module="hidden_assets",
                )
                if task.login and verifier._auth_headers:
                    discovery_verifier.set_session_auth(
                        verifier._auth_headers, netloc=verifier._auth_netloc,
                        cookies=verifier._auth_cookies, origin=verifier._auth_origin)
                hidden_engine = HiddenAssetEngine(
                    verifier=discovery_verifier,
                    scope_manager=task.scope_manager,
                    traffic_controller=task.traffic_controller,
                    js_analyzer=js_analyzer,
                    cloud_baas_hunter=baas_hunter,
                    deep_exploit_engine=deep_exploit_engine,
                    reference_intel=bypass_engine.reference_intel,
                    request_budget=40,
                    asset_budget=25,
                    source_map_budget=8,
                    verification_budget=4,
                    max_depth=3,
                    kill_switch=lambda: task.traffic_controller.stats().get("kill_switch", False),
                    seed_cache=getattr(js_analyzer, "_cache", {}),
                )
                hidden_report = await asyncio.to_thread(
                    hidden_engine.discover,
                    target_url,
                    deep_assets=bool("hidden_assets" in modules or task.deep_assets),
                    secret_discovery=bool("hidden_assets" in modules or task.secret_discovery),
                    auth_flow=bool("hidden_assets" in modules or task.auth_flow),
                    source_maps=bool("hidden_assets" in modules or task.source_maps),
                    browser_verify=task.browser_verify,
                    auth_context=task.auth_context,
                    verify_baas=bool("cloud_baas" in modules or (task.auth_context.get("verify_baas") if task.auth_context else False)),
                    raw_local_results=task.show_secrets,
                    request_budget=40,
                )
                task.results["hidden_assets"] = hidden_report
                hidden_stats = hidden_report.get("stats", {})
                task.results["stats"]["hidden_assets"] = hidden_stats.get("assets", 0)
                task.results["stats"]["hidden_endpoints"] = hidden_stats.get("endpoints", 0)
                task.results["stats"]["hidden_credentials"] = hidden_stats.get("credentials", 0)
                task.results["stats"]["source_maps_parsed"] = hidden_stats.get("source_maps", 0)
                task.results["stats"]["auth_flows"] = hidden_stats.get("auth_flows", 0)
                task.results["stats"]["credential_relationships"] = hidden_stats.get("relationships", 0)
                captured_public_dicts = []
                for record in captured_dicts:
                    public_record = dict(record)
                    public_record["url"] = self.redactor.redact_url(record.get("url", ""))
                    captured_public_dicts.append(public_record)
                for endpoint_record in [*hidden_report.get("endpoints", []), *captured_dicts]:
                    hidden_url = endpoint_record.get("url")
                    if hidden_url and hidden_url not in endpoints:
                        endpoints.append(hidden_url)
                existing_endpoint_records = task.results.get("endpoint_records", [])
                existing_keys = {(item.get("url"), item.get("method", "GET")) for item in existing_endpoint_records if isinstance(item, dict)}
                for endpoint_record in [*hidden_report.get("endpoints", []), *captured_public_dicts]:
                    key = (endpoint_record.get("url"), endpoint_record.get("method", "GET"))
                    if key in existing_keys:
                        continue
                    existing_endpoint_records.append(endpoint_record)
                    existing_keys.add(key)
                task.results["endpoint_records"] = existing_endpoint_records
                all_findings.extend(hidden_report.get("findings", []))
                offensive_records = [*captured_dicts, *hidden_report.get("endpoints", [])]
            endpoints = list(dict.fromkeys(endpoints))
            task.results["endpoints"] = endpoints
            task.results["stats"]["endpoints"] = len(endpoints)
            offensive_urls = {
                (str(item.get("url") or ""), str(item.get("method") or "GET").upper())
                for item in offensive_records if isinstance(item, dict)
            }
            for endpoint_record in task.results.get("endpoint_records", []):
                if not isinstance(endpoint_record, dict):
                    continue
                endpoint = str(endpoint_record.get("url") or "")
                fields = list(endpoint_record.get("body_fields") or [])
                methods = list(endpoint_record.get("methods") or [endpoint_record.get("method") or "GET"])
                if not urllib.parse.urlparse(endpoint).query and not fields and set(methods) <= {"GET", "HEAD", "OPTIONS"}:
                    continue
                for method in methods:
                    key = (endpoint, str(method).upper())
                    if key in offensive_urls:
                        continue
                    offensive_records.append({
                        "url": endpoint, "method": key[1], "body_shape": {"fields": fields},
                        "auth_required": False,
                        "source_file": ",".join(endpoint_record.get("sources") or []) or "crawler_endpoint",
                        "metadata": {"priority_reasons": endpoint_record.get("priority_reasons") or []},
                    })
                    offensive_urls.add(key)
            # Keep supplemental SSTI and browser/static XSS checks separate
            # from the focused RCE, SSRF, and SQLi planner.
            if task.offensive:
                from redteam_agent.core.modern_engine import ModernEngine
                modern = ModernEngine(verifier)
                selected_classes = {
                    str(item).strip().lower().replace("_", "-")
                    for item in task.hunt_focus.get("vulnerability_classes", [])
                }
                # Every behavioral detector is bound to an explicitly selected
                # engagement class: the class list is the authorization contract
                # for which attack behaviors may be exercised on the target.
                wants_sqli = bool(selected_classes & {"sqli", "sql-injection"})
                wants_ssti = "ssti" in selected_classes
                wants_cmd = bool(selected_classes & {
                    "rce", "remote-code-execution", "command-injection", "os-command-injection"})
                wants_cache = bool(selected_classes & {
                    "cache-poisoning", "cache-deception", "web-cache-poisoning"})
                wants_xss = "xss" in selected_classes
                # Aggressive engagements widen the per-sweep surface: more
                # endpoints, more parameters per endpoint.  The shared traffic
                # controller remains the hard request ceiling either way.
                endpoint_cap = 60 if task.aggressive else 25
                param_cap = 8 if task.aggressive else 4
                modern_budget = global_budget(16)
                if modern_budget is not None:
                    per_endpoint = max(1, param_cap * 3 + 1)
                    endpoint_cap = min(endpoint_cap, modern_budget // per_endpoint)
                cmd_param_tokens = ("host", "ip", "ping", "exec", "cmd", "command",
                                    "dst", "target", "domain", "url", "callback",
                                    "addr", "server", "endpoint", "webhook", "fetch")
                modern_targets = sorted(
                    [url for url in endpoints
                     if task.scope_manager.check_url(url, active=True).get("allowed")],
                    key=lambda u: 0 if urllib.parse.urlparse(u).query else 1,
                )[:endpoint_cap]
                modern_findings: List[Dict[str, Any]] = []
                modern_stats = {"endpoints_tested": 0, "sqli_boolean": 0,
                                "ssti_arithmetic": 0, "cmd_time": 0,
                                "cache_poisoning": 0, "dom_xss": 0}
                for endpoint in modern_targets:
                    modern_stats["endpoints_tested"] += 1
                    parsed = urllib.parse.urlparse(endpoint)
                    params = list(urllib.parse.parse_qs(parsed.query).keys())
                    for param in params[:param_cap]:
                        if wants_sqli:
                            finding = modern.sqli_boolean_differential(endpoint, param)
                            if finding:
                                modern_findings.append(finding)
                                modern_stats["sqli_boolean"] += 1
                        if wants_ssti:
                            finding = modern.ssti_arithmetic_multi_engine(endpoint, param)
                            if finding:
                                modern_findings.append(finding)
                                modern_stats["ssti_arithmetic"] += 1
                        if wants_cmd and any(token in param.lower() for token in cmd_param_tokens):
                            finding = modern.cmd_time_based_median(endpoint, param)
                            if finding:
                                modern_findings.append(finding)
                                modern_stats["cmd_time"] += 1
                    if wants_cache:
                        finding = modern.cache_poisoning(endpoint)
                        if finding:
                            modern_findings.append(finding)
                            modern_stats["cache_poisoning"] += 1
                dom_findings = modern.dom_xss_analysis(js_results.get("js_assets", [])) \
                    if wants_xss else []
                modern_stats["dom_xss"] = len(dom_findings)
                modern_findings.extend(dom_findings)
                task.results["modern_engine"] = {
                    "stats": modern_stats,
                    "findings": [f for f in modern_findings
                                 if f.get("status") != FindingStatus.REJECTED.value],
                }
                task.results["stats"]["modern_findings"] = len(modern_findings)
                all_findings.extend(modern_findings)
                if modern_findings:
                    await task.emit_log(
                        "ALERT",
                        f"[MODERN] {len(modern_findings)} behavioral finding(s): "
                        f"{modern_stats['sqli_boolean']} sqli-oracle, "
                        f"{modern_stats['ssti_arithmetic']} ssti, "
                        f"{modern_stats['cmd_time']} cmd-time, "
                        f"{modern_stats['cache_poisoning']} cache-poison, "
                        f"{modern_stats['dom_xss']} dom-xss",
                        "Modern Behavioral Engine", 79,
                    )
                elif any((wants_sqli, wants_ssti, wants_cmd, wants_cache,
                          wants_xss)):
                    await task.emit_log(
                        "INFO",
                        f"[MODERN] No behavioral finding on {modern_stats['endpoints_tested']} endpoint(s)",
                        "Modern Behavioral Engine", 79,
                    )

                if task.offensive and offensive_records:
                    await task.emit_log(
                        "ALERT",
                        "[OFFENSIVE] Executing target-specific hypotheses from discovered methods, body fields, auth headers, and BaaS relationships",
                        "Deep Offensive Exploit Planner",
                        76,
                    )
                    live_budget = global_budget(8)
                    offensive_budget = (pipeline_bypass_budget if live_budget is None
                                        else min(pipeline_bypass_budget, live_budget))
                    offensive_audit = await asyncio.to_thread(
                        deep_exploit_engine.run_discovered,
                        offensive_records,
                        baas_projects=hidden_report.get("baas_projects", []),
                        auth_context=task.auth_context,
                        request_budget=offensive_budget,
                        max_depth=task.max_depth,
                        techniques=task.hunt_focus.get("vulnerability_classes"),
                    )
                    task.results["deep_exploit"] = offensive_audit
                    task.results["deep_exploit_plan"] = offensive_audit.get("plan", [])
                    task.results["deep_exploit_reports"] = offensive_audit.get("reports", [])
                    task.results["deep_exploit_primitives"] = offensive_audit.get("primitives", [])
                    task.results["deep_exploit_chains"] = offensive_audit.get("chains", [])
                    task.results["stats"]["offensive_hypotheses"] = len(offensive_audit.get("plan", []))
                    task.results["stats"]["offensive_requests"] = offensive_audit.get("requests_used", 0)
                    task.results["stats"]["offensive_verified_primitives"] = len(offensive_audit.get("primitives", []))
                    all_findings.extend(offensive_audit.get("findings", []))
                    await task.emit_log(
                        "SUCCESS" if not offensive_audit.get("verified_findings") else "ALERT",
                        f"[OFFENSIVE] {len(offensive_audit.get('plan', []))} hypotheses, "
                        f"{offensive_audit.get('requests_used', 0)} requests, "
                        f"{len(offensive_audit.get('verified_findings', []))} verified finding(s), "
                        f"{len(offensive_audit.get('primitives', []))} primitive(s)",
                        progress=79,
                    )
                await task.emit_log("SUCCESS", f"[ASSET] {hidden_stats.get('assets', 0)} assets, "
                    f"{hidden_stats.get('source_maps', 0)} maps, {hidden_stats.get('endpoints', 0)} endpoints, "
                    f"{hidden_stats.get('credentials', 0)} redacted credential records, "
                    f"{hidden_stats.get('relationships', 0)} graph relationships", progress=72)
            else:
                await task.emit_log("INFO", f"[ASSET] hidden discovery skipped by preset {task.preset}")

            # Post-auth behavioral hunt: differential auth, BOLA with session,
            # excessive data exposure, and mass assignment on the surface that
            # only becomes reachable after login.  Behavioral, context-specific,
            # adaptive — no signature matching.
            if task.offensive and verifier.has_session_auth():
                from redteam_agent.core.post_auth_hunter import PostAuthHunter
                hunter = PostAuthHunter(verifier)
                post_auth_targets = [
                    url for url in endpoints
                    if task.scope_manager.check_url(url, active=True).get("allowed")
                ]
                post_auth_findings: List[Dict[str, Any]] = []
                post_auth_stats = {"endpoints_tested": 0, "differential_auth": 0,
                                   "bola": 0, "excessive_data": 0, "mass_assignment": 0}
                for endpoint in post_auth_targets[:25]:
                    post_auth_stats["endpoints_tested"] += 1
                    finding = hunter.differential_auth(endpoint)
                    if finding:
                        post_auth_findings.append(finding)
                        post_auth_stats["differential_auth"] += 1
                    finding = hunter.bola_sequential_auth(endpoint)
                    if finding:
                        post_auth_findings.append(finding)
                        post_auth_stats["bola"] += 1
                    finding = hunter.excessive_data_exposure(endpoint)
                    if finding:
                        post_auth_findings.append(finding)
                        post_auth_stats["excessive_data"] += 1
                    finding = hunter.mass_assignment(endpoint)
                    if finding:
                        post_auth_findings.append(finding)
                        post_auth_stats["mass_assignment"] += 1
                task.results["post_auth_hunt"] = {
                    "stats": post_auth_stats,
                    "findings": [f for f in post_auth_findings
                                 if f.get("status") != FindingStatus.REJECTED.value],
                }
                task.results["stats"]["post_auth_findings"] = len(post_auth_findings)
                all_findings.extend(post_auth_findings)
                if post_auth_findings:
                    await task.emit_log(
                        "ALERT",
                        f"[POST-AUTH] {len(post_auth_findings)} behavioral finding(s) on "
                        f"{post_auth_stats['endpoints_tested']} post-auth endpoint(s): "
                        f"{post_auth_stats['differential_auth']} unauth-access, "
                        f"{post_auth_stats['bola']} BOLA, "
                        f"{post_auth_stats['excessive_data']} data-exposure, "
                        f"{post_auth_stats['mass_assignment']} mass-assignment",
                        "Post-Auth Behavioral Hunt", 78,
                    )
                else:
                    await task.emit_log(
                        "INFO",
                        f"[POST-AUTH] No behavioral finding on {post_auth_stats['endpoints_tested']} post-auth endpoint(s)",
                        "Post-Auth Behavioral Hunt", 78,
                    )

            if "cloud_baas" in modules:
                await task.emit_log("INFO", "[BAAS] Correlating provider/config boundaries and validating only linked in-scope projects", "Cloud BaaS Correlation", 70)
                if discovery_enabled:
                    # The first-class engine has already applied exact
                    # createClient/config pairing. Do not run the legacy
                    # global URL/key auto-pairer on the same bundle.
                    hidden_projects = (task.results.get("hidden_assets", {}) or {}).get("baas_projects", [])
                    task.results["cloud_baas"]["discovery_projects"] = hidden_projects
                    task.results["cloud_baas"]["supabase"] = [
                        {"target_url": project.get("url"), "source": "hidden_asset_correlation",
                         "auth_used": bool(project.get("key_fingerprint")),
                         "is_service_role": project.get("key_type") == "service_role-like",
                         "discovered_tables": [], "vulnerable_tables_rls_bypass": [],
                         "verification": project.get("verification", {}),
                         "project_ref": project.get("project_ref"),
                         "public_identifiers": project.get("public_identifiers", {})}
                        for project in hidden_projects if project.get("provider") == "Supabase"
                    ]
                    task.results["cloud_baas"]["firebase"] = [
                        {"target_url": project.get("url"), "source": "hidden_asset_correlation",
                         "auth_used": False, "project_ref": project.get("project_ref"),
                         "verification": project.get("verification", {}),
                         "public_identifiers": project.get("public_identifiers", {})}
                        for project in hidden_projects if project.get("provider") == "Firebase"
                    ]
                    task.results["stats"]["cloud_misconfigs"] = len([
                        finding for finding in all_findings
                        if finding.get("source_module") == "hidden_assets" and finding.get("status") == FindingStatus.VERIFIED.value
                    ])
                    if hidden_projects:
                        await task.emit_log("SUCCESS", f"[BAAS] {len(hidden_projects)} project(s) correlated without cross-pairing; raw keys redacted")
                else:
                    # Preserve the legacy audit path for callers that disable
                    # the new discovery module explicitly.
                    recon_hosts = [h.get("host") or h.get("url") for h in live_hosts if h.get("observed")]
                    recon_hosts += [s for s in subdomains if s]
                    audit = await asyncio.to_thread(baas_hunter.audit_discovered_assets,
                        js_results.get("secrets", []), hosts=recon_hosts, target_url=target_url)
                    task.results["cloud_baas"]["supabase"] = audit.get("supabase_audits", [])
                    task.results["cloud_baas"]["firebase"] = audit.get("firebase_audits", [])
                    task.results["cloud_baas"]["vercel"] = audit.get("vercel_audits", [])
                    task.results["external_discoveries"].extend(audit.get("skipped_external", []))
                    all_findings.extend(audit.get("findings", []))
                    task.results["stats"]["cloud_misconfigs"] = len(audit.get("verified_findings", []))
            task.results["cloud_baas"]["harvested_tokens"] = [
                self._safe_secret(s, reveal=task.show_secrets) for s in js_results.get("secrets", [])
            ]

            if "param_miner" in modules:
                params = await recon.run_param_miner(target_url)
                task.results["hidden_params"] = sorted(set(task.results["hidden_params"]) | set(params))
            ffuf_done = False
            if "ffuf" in modules:
                ffuf_results = await recon.run_ffuf(target_url)
                task.results["ffuf_results"] = ffuf_results
                ffuf_done = any(run.get("tool") == "ffuf" and run.get("status") in {"success", "no_output"}
                                for run in task.results.get("tool_runs", []))
            if not ffuf_done and ("sensitive_path_fuzz" in modules or "exploit_verifier" in modules
                                  or "ffuf" in modules):
                task.results["sensitive_path_candidates"] = await recon.run_sensitive_path_fuzzing(target_url)

            if "recon_depth" in modules:
                await task.emit_log("INFO", "[DEPTH] WAF fingerprint, TLS inspection, optional port scan", "Recon Depth", 66)
                task.results["recon_depth"] = await recon_depth.run_all(target_url)

            db_hunter = DBHunter(scope_manager=task.scope_manager, verifier=verifier)
            if "db_hunter" in modules:
                db_report = db_hunter.hunt(
                    secrets=js_results.get("secrets", []),
                    grep_matches=task.results.get("js_grep", []),
                    ports=task.results.get("recon_depth", {}).get("ports", []),
                    endpoints=endpoints,
                    reveal_raw=task.show_secrets)
                task.results["db_hunter"] = {"connection_strings": db_report["connection_strings"],
                    "exposed_ports": db_report["exposed_ports"],
                    "admin_panels": db_report.get("admin_panels", []),
                    "backup_files": db_report.get("backup_files", []),
                    "hidden_db_strings": db_report.get("hidden_db_strings", []),
                    "total_connection_strings": db_report["total_connection_strings"],
                    "total_exposed_ports": db_report["total_exposed_ports"],
                    "total_admin_panels": db_report.get("total_admin_panels", 0),
                    "total_backup_files": db_report.get("total_backup_files", 0),
                    "total_hidden_db_strings": db_report.get("total_hidden_db_strings", 0)}
                task.results["stats"]["db_connection_strings"] = db_report["total_connection_strings"]
                task.results["stats"]["db_exposed_ports"] = db_report["total_exposed_ports"]
                task.results["stats"]["db_admin_panels"] = db_report.get("total_admin_panels", 0)
                task.results["stats"]["db_backup_files"] = db_report.get("total_backup_files", 0)
                task.results["stats"]["db_hidden_strings"] = db_report.get("total_hidden_db_strings", 0)
                all_findings.extend(db_report["findings"])
                if db_report["findings"]:
                    await task.emit_log("ALERT", f"[DB] {len(db_report['findings'])} database exposure finding(s)")

            active_endpoints = [
                url for url in endpoints
                if task.scope_manager.check_url(url, active=True).get("allowed")
            ]
            if "exploit_verifier" in modules and task.offensive:
                await task.emit_log("INFO", "[VERIFY] Target-specific offensive planner consumed observed/captured endpoint records", "Deep Exploit Verification", 80)
            elif "exploit_verifier" in modules:
                task.results["exploit_coverage"] = [{
                    "status": "NOT_EXECUTED",
                    "reason": "Generic endpoint/payload guessing is disabled; load a request corpus and select one or two vulnerability classes in authorized offensive mode",
                    "observed_endpoints": len(active_endpoints),
                }]
                await task.emit_log(
                    "INFO",
                    "[VERIFY] Generic verifier disabled; retained endpoint evidence without sending guessed payloads",
                    "Deep Exploit Verification",
                    80,
                )
            else:
                await task.emit_log("INFO", f"[VERIFY] active verifier skipped by preset {task.preset}")

            if "bypass_engine" in modules and task.offensive:
                await task.emit_log("INFO", "[BYPASS] Adaptive mutations were executed inside DeepExploitEngine against discovered primitives", "Deep Adaptive Bypass", 84)
                offensive_audit = task.results.get("deep_exploit", {}) or {}
                task.results["bypass_engine"] = {
                    "engine": "DeepExploitEngine",
                    "reports": offensive_audit.get("reports", []),
                    "findings": offensive_audit.get("findings", []),
                    "verified_findings": offensive_audit.get("verified_findings", []),
                    "primitives": offensive_audit.get("primitives", []),
                    "chains": offensive_audit.get("chains", []),
                    "request_budget": offensive_audit.get("request_budget", task.bypass_budget),
                    "requests_used": offensive_audit.get("requests_used", 0),
                    "requests_remaining": offensive_audit.get("requests_remaining", task.bypass_budget),
                    "protection_fingerprints": [],
                }
                task.results["bypass_primitives"] = offensive_audit.get("primitives", [])
                task.results["bypass_chains"] = offensive_audit.get("chains", [])
                task.results["stats"]["bypass_requests"] = offensive_audit.get("requests_used", 0)
                task.results["stats"]["bypass_verified_primitives"] = len(offensive_audit.get("primitives", []))
            elif "bypass_engine" in modules:
                task.results["bypass_engine"]["status"] = "NOT_EXECUTED"
                task.results["bypass_engine"]["reason"] = (
                    "Generic mutation is disabled; use authorized focused mode with observed request shapes"
                )
                await task.emit_log(
                    "INFO",
                    "[BYPASS] Generic mutation disabled; no guessed payloads were sent",
                    "Deep Adaptive Bypass",
                    84,
                )
            else:
                await task.emit_log("INFO", f"[BYPASS] adaptive engine skipped by preset {task.preset}")

            # Offline JWT analysis on tokens harvested from JS bundles/sourcemaps.
            jwt_secrets = [s for s in js_results.get("secrets", [])
                           if s.get("secret_type") in {"jwt_token", "supabase_anon_key"}]
            jwt_findings = []
            for secret_record in jwt_secrets:
                raw = secret_record.get("_raw_value") or secret_record.get("value", "")
                finding = exploit_engine.test_jwt_weak_secret(raw, source_label=secret_record.get("source", "discovered"))
                if finding:
                    finding["target"] = target_url
                    finding["endpoint"] = target_url
                    jwt_findings.append(finding)
            all_findings.extend(jwt_findings)
            if jwt_findings:
                await task.emit_log("ALERT", f"[FINDING] offline JWT analysis: {len(jwt_findings)} token issue(s)")

            task.results["findings"] = all_findings
            verified = [finding for finding in all_findings if finding.get("status") == "VERIFIED"]
            for finding in verified:
                finding["report_markdown"] = self.report_builder.generate_markdown_report(finding, target_url)

            # VRT triage: anti-N/A annotation on every retained finding.
            triage = VRTTriageEngine()
            vrt_summary = {"approved": 0, "rejected_anti_na": 0, "rejected_no_poc": 0, "total": len(all_findings)}
            for finding in all_findings:
                verdict = triage.evaluate_finding(
                    str(finding.get("type") or finding.get("vuln_type", "")),
                    str(finding.get("observed_impact") or ""),
                    poc_verified=finding.get("status") == FindingStatus.VERIFIED.value,
                    possesses_active_exploit=finding.get("status") == FindingStatus.VERIFIED.value)
                finding["vrt_triage"] = verdict
                if verdict.get("is_approved"):
                    vrt_summary["approved"] += 1
                elif verdict.get("rule_triggered"):
                    vrt_summary["rejected_anti_na"] += 1
                else:
                    vrt_summary["rejected_no_poc"] += 1
            task.results["vrt_summary"] = vrt_summary

            # False-Positive Kill Gate: only clean findings become submission-ready.
            kill_report = kill_pass(all_findings)
            task.results["quarantined_findings"] = kill_report["quarantined"]
            task.results["fp_kill_summary"] = kill_report["summary"]
            task.results["vulnerabilities"] = kill_report["submission_ready"]
            task.results["stats"]["vulnerabilities"] = len(kill_report["submission_ready"])
            task.results["stats"]["quarantined"] = len(kill_report["quarantined"])
            if kill_report["quarantined"]:
                await task.emit_log("WARN", f"[FP-KILL] Quarantined {len(kill_report['quarantined'])} finding(s) before submission: "
                    + ", ".join(f"{k.get('type') or 'finding'} ({'/'.join(k.get('fp_kill', {}).get('reasons', []))})" for k in kill_report["quarantined"][:5]))

            if "threat_intel" in modules:
                task_threat_intel.fetch_live_cisa_kev()
                observed_tech = [tech for host in live_hosts if host.get("observed") for tech in host.get("tech", [])]
                task.results["cisa_intel"] = task_threat_intel.match_technologies(observed_tech)
                task.results["stats"]["cisa_threats"] = len(task.results["cisa_intel"])

            task.results["stats"]["endpoints"] = len(task.results.get("endpoints", []))
            task.results["traffic"] = task.traffic_controller.stats()
            # Keep raw legacy analyzer values available only to the in-process
            # verification path; CLI/Web JSON, HTML reports, and terminal log
            # history are public surfaces and are scrubbed before completion.
            self._redact_public_state(
                task,
                [item.get("_raw_value") for item in js_results.get("secrets", [])
                 if isinstance(item, dict)]
                + self._context_strings(task.auth_context)
                + self._context_strings(task.authorization_identities),
                preserve_raw_values=task.show_secrets,
            )
            task.auth_context = {}
            task.authorization_identities = []
            task.request_corpus = None
            task.status = "completed"
            task.results["status"] = "completed"
            task.current_step = "Scan Completed"
            task.progress = 100
            task.completed_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
            await task.emit_log("SUCCESS", f"[FINDING] Scan finished: {len(all_findings)} candidates, {len(verified)} VERIFIED", "Finished", 100)
        except asyncio.CancelledError:
            # A stopped scan is an operational outcome, not a failed finding.
            # The task-level registry owns child processes and is safe to call
            # here even when cancellation originated outside the Web API.
            await task.process_registry.cancel_all()
            task.status = "stopped"
            task.results["status"] = "stopped"
            task.results["traffic"] = task.traffic_controller.stats()
            task.completed_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
            await task.emit_log("WARN", "[KILL-SWITCH] Scan pipeline cancelled and owned processes terminated",
                                "Stopped", task.progress)
            raise
        except Exception as exc:
            task.status = "failed"
            task.results["status"] = "failed"
            task.results["failure"] = {"status": "failed", "reason": str(exc), "verified": False}
            task.results["traffic"] = task.traffic_controller.stats()
            # Failure responses still pass through the same public result
            # boundary.  A late exception must not expose a raw value that was
            # observed by the legacy JS compatibility analyzer earlier in the
            # pipeline.
            failed_js_results = locals().get("js_results", {})
            raw_values = [item.get("_raw_value") for item in failed_js_results.get("secrets", [])
                          if isinstance(item, dict)] if isinstance(failed_js_results, dict) else []
            sensitive_values = (raw_values + self._context_strings(task.auth_context)
                                + self._context_strings(task.authorization_identities))
            safe_error = self.redactor.redact_text(str(exc), sensitive_values)
            self._redact_public_state(task, sensitive_values,
                                      preserve_raw_values=task.show_secrets)
            task.auth_context = {}
            task.authorization_identities = []
            task.request_corpus = None
            await task.emit_log("ALERT", f"[RECON] Scan failed explicitly: {safe_error}", "Error", task.progress)
        finally:
            # Close any browser left by an exception or an external stop. The
            # adapter owns no ambient profile and keeps no browser state after
            # the scan boundary.
            if browser_verifier is not None:
                browser_verifier.stop()
            task.browser_verifier = None

    def audit_target(self, target_url: str, params_to_test: List[str] = None, preset: str = "full",
                     traffic_preset: str = "NORMAL", max_requests: int | None = DEFAULT_REQUEST_BUDGET,
                     scope_include: List[str] | None = None, scope_exclude: List[str] | None = None,
                     exact_urls: List[str] | None = None, allow_private: bool = False,
                     aggressive: bool = False,
                     offensive: bool = False,
                     bypass_budget: int = DEFAULT_BYPASS_REQUEST_BUDGET,
                     max_depth: int = MAX_BYPASS_DEPTH,
                     authorization_identities: List[Dict[str, Any]] | None = None,
                     deep_assets: bool = False, secret_discovery: bool = False,
                     auth_flow: bool = False, source_maps: bool = False,
                     browser_verify: bool = False, auth_context: Dict[str, Any] | None = None,
                     engagement=None, hunt_focus: Dict[str, Any] | None = None,
                     request_corpus: Any = None,
                     request_corpus_source: str = "researcher_capture",
                     show_secrets: bool = False,
                     login: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Synchronous compatibility entrypoint used by the CLI."""
        from redteam_agent.core.task_manager import task_manager
        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
            task = task_manager.create_task(target_url, preset=preset, traffic_preset=traffic_preset,
                max_requests=max_requests, scope_in=scope_include, scope_exclude=scope_exclude,
                exact_urls=exact_urls, allow_private=allow_private, aggressive=aggressive,
                offensive=offensive,
                bypass_budget=bypass_budget, max_depth=max_depth,
                authorization_identities=authorization_identities,
                deep_assets=deep_assets, secret_discovery=secret_discovery,
                auth_flow=auth_flow, source_maps=source_maps,
                browser_verify=browser_verify, auth_context=auth_context,
                engagement=engagement, hunt_focus=hunt_focus,
                request_corpus=request_corpus, request_corpus_source=request_corpus_source,
                show_secrets=show_secrets, login=login)
            loop.run_until_complete(self.run_full_scan_pipeline(task))
            return task.results
        finally:
            loop.close()
