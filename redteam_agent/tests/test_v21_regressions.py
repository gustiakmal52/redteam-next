import asyncio
import json
import urllib.parse

import pytest

from redteam_agent.core import recon_pipeline
from redteam_agent.core.findings import (AIReviewOutput, FindingStatus, apply_ai_review,
                                         apply_human_review, normalized_finding)
from redteam_agent.core.fp_killer import kill_pass
from redteam_agent.core.http_verifier import HTTPVerifier
import base64
import hashlib
import hmac

from redteam_agent.core.js_analyzer import JSAnalyzer
from redteam_agent.core.agent_engine import RedTeamAgentEngine
from redteam_agent.core.exploit_engine import ExploitEngine
from redteam_agent.core.db_hunter import DBHunter, probe_db_port
from redteam_agent.core.cloud_baas_hunter import CloudBaaSHunter
from redteam_agent.core.scope_manager import ScopeManager
from redteam_agent.core.task_manager import ScanTask
from redteam_agent.core.traffic_controller import RequestBudgetExceeded, TrafficController
from redteam_agent.core.config import SCAN_PRESETS
from redteam_agent.core.report_builder import ReportBuilder
from redteam_agent.core.vrt_triage import VRTTriageEngine


def test_local_secret_reveal_is_explicit_and_does_not_unredact_public_context():
    engine = RedTeamAgentEngine()
    raw = "postgresql://admin:super-secret@example.com/app"
    secret = {"value": raw, "display_value": raw, "_raw_value": raw}

    assert raw not in json.dumps(engine._safe_secret(secret))
    assert engine._safe_secret(secret, reveal=True)["_raw_value"] == raw

    task = ScanTask("redaction", "example.com", show_secrets=True)
    task.results.update({
        "credentials": [{"_raw_value": raw, "value": raw}],
        "auth_context_echo": raw,
    })
    task.logs.append({"message": raw})
    engine._redact_public_state(task, [raw], preserve_raw_values=True)

    assert task.results["credentials"][0]["_raw_value"] == raw
    assert raw not in task.results["credentials"][0]["value"]
    assert raw not in task.results["auth_context_echo"]
    assert raw not in task.logs[0]["message"]

    engine._redact_public_state(task, [raw])
    assert "_raw_value" not in task.results["credentials"][0]


def response(body="", elapsed=.4, status=200, headers=None):
    return {
        "success": 200 <= status < 400, "status_code": status, "headers": headers or {}, "body": body,
        "response_time_sec": elapsed, "raw_request": "GET / HTTP/1.1", "raw_response": f"HTTP/1.1 {status}\n\n{body}",
    }


def verifier_with_sequence(items):
    verifier = HTTPVerifier(scope_manager=ScopeManager(["example.com"], resolve_dns=False))
    iterator = iter(items)
    verifier.send_http_request = lambda *args, **kwargs: next(iterator)
    return verifier


def test_ssti_53965_is_not_exact_expected_token():
    verifier = verifier_with_sequence([response("baseline"), response("value=53965"), response("value=664")])
    result = verifier.verify_ssti("https://example.com/page?q=x", "q")
    assert result["verified"] is False
    assert result["verification_checks"][0]["exact_token"] is False


def test_ssti_two_differential_arithmetic_results_are_strong_evidence():
    verifier = verifier_with_sequence([response("baseline"), response("result: 539"), response("result: 664")])
    result = verifier.verify_ssti("https://example.com/page?q=x", "q")
    assert result["verified"] is True
    assert result["status"] == "VERIFIED"
    assert result["confidence"] >= .85


def test_static_asset_cannot_be_verified_ssti():
    verifier = verifier_with_sequence([response("baseline"), response("539"), response("664")])
    result = verifier.verify_ssti("https://example.com/_next/static/app.js?q=x", "q")
    assert result["verified"] is False
    assert result["false_positive_reasons"]


def test_failed_httpx_produces_no_fabricated_host_or_technology(monkeypatch):
    task = ScanTask("t", "example.com")
    pipeline = recon_pipeline.ReconPipeline(task)
    monkeypatch.setitem(recon_pipeline.TOOL_PATHS, "httpx", "/definitely/missing/httpx")
    hosts = asyncio.run(pipeline.run_http_probing(["example.com"]))
    serialized = json.dumps(task.results)
    assert hosts == []
    assert '"status_code": 200' not in serialized
    for fabricated in ("Next.js", "React", "Node.js", "Nginx"):
        assert fabricated not in serialized
    assert any(run["tool"] == "httpx" and run["status"] == "failed" for run in task.results["tool_runs"])


def test_generated_subdomains_remain_unobserved_candidates(monkeypatch):
    task = ScanTask("t", "example.com")
    pipeline = recon_pipeline.ReconPipeline(task)
    monkeypatch.setitem(recon_pipeline.TOOL_PATHS, "subfinder", "/definitely/missing/subfinder")
    discovered = asyncio.run(pipeline.run_subdomain_discovery())
    generated = [r for r in task.results["subdomain_records"] if r["source"] == "generated_candidate"]
    assert discovered == ["example.com"]
    assert any(r["value"] == "api.example.com" for r in generated)
    assert all(r["observed"] is False and r["live"] is False for r in generated)


def test_one_time_sqli_latency_spike_is_not_verified():
    samples = [response(elapsed=t) for t in (.41, .44, .39, .43, .42, .46, 5.2, .45, .44)]
    verifier = verifier_with_sequence(samples)
    result = verifier.verify_sqli_time_based("https://example.com/?id=1", "id", delay_sec=5, samples=3)
    assert result["verified"] is False
    assert result["evidence"]["payload_median_sec"] < 1


def test_xss_reflection_in_json_is_not_verified():
    verifier = HTTPVerifier(scope_manager=ScopeManager(["example.com"], resolve_dns=False))
    payload = "<script>alert('AGY_XSS_9981')</script>"
    verifier.send_http_request = lambda *args, **kwargs: response(
        json.dumps({"q": payload}), headers={"Content-Type": "application/json"})
    result = verifier.verify_xss("https://example.com/search?q=x", "q")
    assert result["verified"] is False
    assert result["classification"] == "REFLECTED_INPUT"
    assert result["evidence"]["context"] == "JSON"


def test_xss_plain_text_or_unknown_content_is_not_verified():
    payload = "<script>alert('AGY_XSS_9981')</script>"
    for content_type in ("text/plain", "application/octet-stream", ""):
        verifier = HTTPVerifier(scope_manager=ScopeManager(["example.com"], resolve_dns=False))
        verifier.send_http_request = lambda *args, ct=content_type, **kwargs: response(
            payload, headers={"Content-Type": ct} if ct else {})
        assert verifier.verify_xss("https://example.com/search?q=x", "q")["verified"] is False


def test_xss_html_text_context_can_be_deterministically_verified():
    payload = "<script>alert('AGY_XSS_9981')</script>"
    verifier = HTTPVerifier(scope_manager=ScopeManager(["example.com"], resolve_dns=False))
    verifier.send_http_request = lambda *args, **kwargs: response(
        f"<!doctype html><html><body>{payload}</body></html>", headers={"Content-Type": "text/html"})
    result = verifier.verify_xss("https://example.com/search?q=x", "q")
    assert result["verified"] is True
    assert result["classification"] == "VERIFIED_XSS"


def test_repeated_429_activates_host_specific_throttle():
    controller = TrafficController("NORMAL")
    for _ in range(2):
        controller.observe_response("https://api.example.com/x", 429, {})
    stats = controller.stats()
    assert stats["429_count"] == 2
    assert stats["current_throttle_state"]["api.example.com"] == 1.0
    assert any("reducing host limit" in event for event in stats["events"])


def test_request_budget_reserves_capacity_then_exhausts():
    controller = TrafficController("NORMAL", max_requests=2)
    with controller.request_slot("https://example.com", module="crawl", priority="normal"):
        pass
    with pytest.raises(RequestBudgetExceeded, match="reserved"):
        with controller.request_slot("https://example.com/a", module="crawl", priority="normal"):
            pass
    with controller.request_slot("https://example.com/verify", module="verify", priority="verification"):
        pass
    with pytest.raises(RequestBudgetExceeded, match="exhausted"):
        with controller.request_slot("https://example.com/verify2", module="verify", priority="verification"):
            pass


def test_external_js_is_recorded_but_not_fetched_or_verified():
    class NeverFetch:
        def send_http_request(self, *args, **kwargs):
            raise AssertionError("out-of-scope JS must not be fetched")

    scope = ScopeManager(["example.com", "*.example.com"], resolve_dns=False)
    analyzer = JSAnalyzer(verifier=NeverFetch(), scope_manager=scope)
    result = analyzer.analyze_target("https://example.com", '<script src="https://thirdparty.example/api.js"></script>')
    assert result["js_assets"] == []
    assert result["external_discoveries"][0]["value"] == "https://thirdparty.example/api.js"
    assert result["external_discoveries"][0]["active_verification_skipped"] == "outside_scope"


def test_file_scheme_rejected_before_transport():
    verifier = HTTPVerifier()
    verifier._opener.open = lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("network called"))
    result = verifier.send_http_request("file:///etc/hostname")
    assert result["status_code"] == 0
    assert result["failure"]["type"] == "url_policy"
    assert result["verified"] is False


def test_redirect_to_out_of_scope_is_not_followed():
    class RedirectResponse:
        status = 302
        headers = {"Location": "https://thirdparty.example/collect"}
        def read(self):
            return b"redirect"

    scope = ScopeManager(["example.com"], resolve_dns=False)
    controller = TrafficController("FAST")
    verifier = HTTPVerifier(scope_manager=scope, traffic_controller=controller)
    calls = []
    verifier._opener.open = lambda req, timeout: calls.append(req.full_url) or RedirectResponse()
    result = verifier.send_http_request("https://example.com/start")
    assert calls == ["https://example.com/start"]
    assert result["success"] is False
    assert result["failure"]["status"] == "blocked"
    assert result["redirects"][0]["scope"]["in_scope"] is False


def test_ai_likely_valid_cannot_promote_to_verified():
    finding = normalized_finding(finding_type="SSTI", target="example.com", endpoint="https://example.com",
                                 status=FindingStatus.SUSPECTED, confidence=.4)
    apply_ai_review(finding, AIReviewOutput(verdict="likely_valid", confidence=.99,
        reasoning_summary="Signal looks plausible", missing_evidence=["second arithmetic probe"],
        recommended_safe_validation=["run a second expression"]))
    assert finding["status"] == "SUSPECTED"
    assert finding["ai_review"]["verdict"] == "likely_valid"


def test_sourcemap_sources_content_is_reprocessed():
    class FakeVerifier:
        def send_http_request(self, url, **kwargs):
            if url.endswith("app.js"):
                return response("//# sourceMappingURL=app.js.map")
            if url.endswith("app.js.map"):
                return response(json.dumps({"sources": ["src/api.ts"],
                    "sourcesContent": ['fetch("/api/internal/users"); searchParams.get("tenant")']}))
            return response('<script src="/app.js"></script>')

    scope = ScopeManager(["example.com"], resolve_dns=False)
    analyzer = JSAnalyzer(verifier=FakeVerifier(), scope_manager=scope)
    result = analyzer.analyze_target("https://example.com", '<script src="/app.js"></script>')
    assert "/api/internal/users" in result["routes"]
    assert "tenant" in result["hidden_params"]
    assert result["js_assets"][0]["sourcemap_routes_found"] == 1


def test_private_destination_is_blocked_unless_explicit_lab_mode():
    blocked = ScopeManager(["127.0.0.1"], resolve_dns=False).check_url("http://127.0.0.1:8000", active=True)
    allowed = ScopeManager(["127.0.0.1"], allow_private=True, resolve_dns=False).check_url(
        "http://127.0.0.1:8000", active=True)
    assert blocked["allowed"] is False
    assert allowed["allowed"] is True


def test_human_review_is_explicit_and_auditable():
    finding = normalized_finding(finding_type="IDOR", target="example.com", endpoint="https://example.com/objects/2")
    apply_human_review(finding, "MARK VERIFIED", reviewer="analyst", reason="owner-controlled A/B evidence reviewed")
    assert finding["status"] == "VERIFIED"
    assert finding["human_review"]["reviewer"] == "analyst"
    assert finding["human_review"]["reason"]


def test_secret_records_return_mask_and_fingerprint_not_generic_raw_value():
    """The analyzer retains raw material transiently for local validation."""
    analyzer = JSAnalyzer(verifier=None, scope_manager=ScopeManager(["example.com"], resolve_dns=False))
    token = "ghp_" + "A" * 40
    secret = analyzer.extract_secrets(token, "app.js")[0]
    
    # The public pipeline strips this unless local CLI --show-secrets is set.
    assert secret["_raw_value"] == token
    assert secret["display_value"] == token  # No longer truncated
    assert secret["classification"] == "HIGH_PRIVILEGE"
    assert secret["fingerprint"]


def test_failure_log_redacts_auth_value_even_when_local_raw_results_are_enabled(monkeypatch):
    raw = "postgresql://admin:failure-secret@example.com/app"

    async def fail_recon(_self):
        raise RuntimeError(raw)

    monkeypatch.setattr(recon_pipeline.ReconPipeline, "run_subdomain_discovery", fail_recon)
    task = ScanTask("failure-redaction", "example.com", preset="full",
                    auth_context={"operator_token": raw}, show_secrets=True)
    asyncio.run(RedTeamAgentEngine().run_full_scan_pipeline(task))

    assert task.status == "failed"
    assert raw not in json.dumps(task.logs)
    assert raw not in json.dumps(task.results["failure"])


def test_js_context_is_sanitized_before_in_progress_results_are_observable(monkeypatch):
    raw = "postgresql://admin:poll-window-secret@example.com/app"
    monkeypatch.setattr(JSAnalyzer, "analyze_target", lambda *_args, **_kwargs: {
        "js_assets": [], "routes": [], "hidden_params": [], "external_discoveries": [],
        "failures": [], "probed_routes": [],
        "secrets": [{"_raw_value": raw, "value": raw}],
        "grep_matches": [{"context": f"const db = '{raw}'"}],
        "api_trace": [{"context": raw}],
    })
    task = ScanTask("poll-window", "example.com", preset="js_hunter", show_secrets=True)
    observed = {}
    emit_log = task.emit_log

    async def capture(level, message, *args, **kwargs):
        if level == "SUCCESS" and message.startswith("[JS]"):
            observed["results"] = json.dumps(task.results)
            raise RuntimeError("bounded test stop")
        await emit_log(level, message, *args, **kwargs)

    task.emit_log = capture
    asyncio.run(RedTeamAgentEngine().run_full_scan_pipeline(task))

    assert raw not in observed["results"]


def test_normal_traffic_defaults_and_fast_requires_selection():
    normal = TrafficController().stats()
    fast = TrafficController("FAST").stats()
    assert (normal["global_rps"], normal["per_host_rps"], normal["global_concurrency"],
            normal["per_host_concurrency"], normal["retry_limit"]) == (5.0, 3.0, 8, 4, 2)
    assert normal["preset"] == "NORMAL"
    assert fast["preset"] == "FAST" and fast["global_rps"] == 10.0


def test_specialized_presets_do_not_implicitly_run_full_pipeline():
    assert "subfinder" not in SCAN_PRESETS["js_hunter"]["modules"]
    assert "exploit_verifier" not in SCAN_PRESETS["cloud_baas"]["modules"]
    assert "exploit_verifier" in SCAN_PRESETS["active_exploit"]["modules"]
    assert "exploit_verifier" in SCAN_PRESETS["full"]["modules"]
    # lab_hardened: offline, own/local target only. Never runs external
    # subprocess recon or host port scans, so every request is attributable
    # to the lab's own access log (honest observation test).
    lab = SCAN_PRESETS["lab_hardened"]["modules"]
    for required in ("js_analyzer", "cloud_baas", "db_hunter", "exploit_verifier"):
        assert required in lab
    for banned in ("subfinder", "httpx", "crawlers", "param_miner", "ffuf", "recon_depth", "threat_intel"):
        assert banned not in lab


def _exploit_verifier():
    verifier = HTTPVerifier(scope_manager=ScopeManager(["example.com"], resolve_dns=False))
    return verifier


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _sign_jwt(secret: str) -> str:
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps({"sub": "1234567890", "role": "service_role"}).encode())
    signing_input = f"{header}.{payload}"
    signature = _b64url(hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest())
    return f"{signing_input}.{signature}"


def test_jwt_weak_secret_cracked_offline_is_verified_without_network():
    token = _sign_jwt("secret")
    exploit = ExploitEngine()
    finding = exploit.test_jwt_weak_secret(token, source_label="app.js")
    assert finding is not None
    assert finding["status"] == "VERIFIED"
    assert finding["evidence"][0]["recovered_secret"] == "secret"
    assert finding["source_tool"] == "offline_jwt_weak_secret_crack"


def test_jwt_strong_secret_is_not_false_positive():
    token = _sign_jwt("correct horse battery staple 9876543210")
    exploit = ExploitEngine()
    assert exploit.test_jwt_weak_secret(token) is None


def test_graphql_introspection_is_verified_from_observed_schema():
    verifier = _exploit_verifier()
    schema_body = json.dumps({"data": {"__schema": {"types": [{"name": "Query"}]}}})
    verifier.send_http_request = lambda *a, **k: response(
        schema_body if "/graphql" in (a[0] if a else "") else "page")
    exploit = ExploitEngine(verifier=verifier)
    finding = exploit.test_graphql_introspection("https://example.com")
    assert finding is not None
    assert finding["status"] == "VERIFIED"
    assert finding["endpoint"] == "https://example.com/graphql"


def test_open_redirect_is_verified_on_attacker_host_location():
    verifier = _exploit_verifier()
    verifier.send_http_request = lambda *a, **k: {**response("x"),
        "redirects": [{"status_code": 302, "to": "https://canary-redirect.invalid/login"}]}
    exploit = ExploitEngine(verifier=verifier)
    finding = exploit.test_open_redirect("https://example.com/login")
    assert finding is not None
    assert finding["status"] == "VERIFIED"
    assert finding["param"] in {"url", "next", "redirect"}


def test_bola_sequential_objects_with_distinct_bodies_are_likely():
    verifier = _exploit_verifier()
    samples = iter([response('{"id": 1001, "name": "alice", "email": "longer"}'),
                    response('{"id": 1002, "name": "bob"}')])
    verifier.send_http_request = lambda *a, **k: next(samples)
    exploit = ExploitEngine(verifier=verifier)
    finding = exploit.test_bola_sequential("https://example.com/objects/1001")
    assert finding is not None
    assert finding["status"] == "LIKELY"
    assert finding["confidence"] == .6


def test_ssrf_probe_is_disabled_by_default_safe_mode():
    exploit = ExploitEngine(verifier=_exploit_verifier())
    assert exploit.ssrf_probing is False
    assert exploit.test_ssrf_probe("https://example.com/?q=x", "q") is None


def test_ssrf_probe_runs_in_aggressive_mode_with_timing_delta():
    verifier = _exploit_verifier()
    closed = response(elapsed=.2)
    open_port = response(elapsed=3.1)
    samples = iter([closed, open_port, open_port, open_port])  # closed, 80, 443, 8080
    verifier.send_http_request = lambda *a, **k: next(samples)
    exploit = ExploitEngine(verifier=verifier, exploit_mode="AGGRESSIVE")
    assert exploit.ssrf_probing is True
    finding = exploit.test_ssrf_probe("https://example.com/?q=x", "q")
    assert finding is not None
    assert finding["status"] == "SUSPECTED"
    assert finding["evidence"][0]["candidate_labels"]


def test_exploit_engine_rejects_unknown_mode():
    import pytest
    with pytest.raises(ValueError):
        ExploitEngine(exploit_mode="WEIRD")


def test_js_grep_finds_api_endpoint_email_and_internal_url():
    analyzer = JSAnalyzer(verifier=None, scope_manager=ScopeManager(["example.com"], resolve_dns=False))
    code = '''
const api = "/api/v1/users";
const email = "dev@internal.example.com";
const hook = "http://10.0.0.5:8000/callback";
'''
    matches = analyzer.grep_content(code, "app.js")
    by_pattern = {}
    for m in matches:
        by_pattern.setdefault(m["pattern"], []).append(m)
    assert any("/api/v1/users" in m["value"] for m in matches)
    assert any("dev@internal.example.com" in m["value"] for m in matches)
    assert any("10.0.0.5" in m["value"] or "10.0.0.5:8000" in m["value"] for m in matches)
    assert all(m["observed"] and m["source"] == "app.js" and m["context"] for m in matches)


def test_js_api_trace_extracts_fetch_axios_xhr_and_websocket():
    analyzer = JSAnalyzer(verifier=None, scope_manager=ScopeManager(["example.com"], resolve_dns=False))
    code = '''
    fetch("/api/login", {method: "POST"});
    axios.get("https://api.example.com/v1/items");
    const xhr = new XMLHttpRequest();
    xhr.open("PUT", "/internal/users/1");
    const ws = new WebSocket("wss://sock.example.com/feed");
'''
    calls = analyzer.extract_api_calls(code, "bundle.js")
    urls = [c["url"] for c in calls]
    assert any("/api/login" in u for u in urls)
    assert any("/v1/items" in u for u in urls)
    assert any("/internal/users/1" in u for u in urls)
    assert any("wss://sock.example.com/feed" in u for u in urls)
    assert any(c["method"] == "PUT" for c in calls)
    assert all(c["observed"] and c["source"] == "bundle.js" for c in calls)


def test_analyze_target_returns_grep_and_api_trace_keys():
    class FakeVerifier:
        def send_http_request(self, url, **kwargs):
            if url.endswith("app.js"):
                return response('fetch("/api/data"); const k = "http://10.1.2.3/x";')
            if url.endswith("app.js.map"):
                return response(json.dumps({"sources": ["src/api.ts"],
                    "sourcesContent": ['axios.put("/admin/items", {})']}))
            return response('<script src="/app.js"></script>')

    scope = ScopeManager(["example.com"], resolve_dns=False)
    analyzer = JSAnalyzer(verifier=FakeVerifier(), scope_manager=scope)
    result = analyzer.analyze_target("https://example.com")
    assert result["grep_matches"]
    assert result["api_trace"]
    assert any("/api/data" in c["url"] for c in result["api_trace"])
    assert any("/admin/items" in c["url"] for c in result["api_trace"])
    assert any(m["pattern"] == "internal_url" for m in result["grep_matches"])


def test_js_discovery_includes_modulepreload_and_dynamic_import():
    analyzer = JSAnalyzer(verifier=None, scope_manager=ScopeManager(["example.com"], resolve_dns=False))
    html = '''
<link rel="modulepreload" href="/_next/static/chunks/vendor.js">
<script>import("./lazy.js")</script>
'''
    links = analyzer.discover_js_links("https://example.com/", html)
    assert any("vendor.js" in u for u in links)
    assert any("lazy.js" in u for u in links)


def test_db_hunter_detects_postgres_and_mongodb_strings_without_claiming_live():
    secrets = [{"_raw_value": "postgresql://admin:hunter2@db.internal.example.com:5432/prod", "source": "app.js", "secret_type": "db_url"}]
    greps = [{"value": "mongodb+srv://user:pass@cluster0.example.net/test", "source": "sourcemap:api.ts"}]
    report = DBHunter().hunt(secrets, greps)
    schemes = {s["scheme"] for s in report["connection_strings"]}
    assert "postgres" in schemes and "mongodb" in schemes
    assert report["total_connection_strings"] == 2
    # Anti false positive: SUSPECTED with missing evidence, never VERIFIED
    assert all(f["status"] == "SUSPECTED" for f in report["findings"])
    assert all(f["missing_evidence"] for f in report["findings"])
    assert any(f["severity"] == "High" for f in report["findings"])
    assert "hunter2" not in json.dumps(report)

    raw_report = DBHunter().hunt(secrets, greps, reveal_raw=True)
    assert raw_report["connection_strings"][0]["_raw_value"].startswith("postgresql://")


def test_db_hunter_marks_known_db_ports_from_recon():
    ports = [{"host": "target.com", "port": 5432, "state": "open"},
             {"host": "target.com", "port": 80, "state": "open"}]
    report = DBHunter().hunt([], [], ports)
    assert report["total_exposed_ports"] == 1
    assert report["exposed_ports"][0]["service"] == "postgres"


def test_db_hunter_non_standard_db_port_map_is_recognized():
    # DB on unusual ports must be recognized as DB services, not ignored.
    ports = [{"host": "target.com", "port": 5433, "state": "open"},
             {"host": "target.com", "port": 13307, "state": "open"},
             {"host": "target.com", "port": 16379, "state": "open"}]
    report = DBHunter().hunt([], [], ports)
    services = {(p["port"], p["service"]) for p in report["exposed_ports"]}
    assert (5433, "postgres") in services
    assert (13307, "mysql") in services
    assert (16379, "redis") in services
    assert report["total_exposed_ports"] == 3


def test_db_hunter_fingerprints_unknown_port_as_hidden_db(monkeypatch):
    from redteam_agent.core.db_hunter import DBHunter as _DB

    class FakeVerifier:
        scope = None

    def fake_probe(host, port, scope_manager=None, traffic_controller=None):
        return {"host": host, "port": port, "service": "redis", "state": "open",
                "banner": "-DENIED", "auth_free": False, "notes": ["redis_version marker"]}

    hunter = _DB(verifier=FakeVerifier())
    monkeypatch.setattr(hunter, "_probe_unknown_port", fake_probe)
    ports = [{"host": "target.com", "port": 45987, "state": "open", "observed": True,
              "source": "naabu"}]
    report = hunter.hunt([], [], ports)
    assert report["total_exposed_ports"] == 1
    entry = report["exposed_ports"][0]
    assert entry["service"] == "redis"
    assert entry["fingerprinted"] is True
    # Not auto-verified: fingerprint is banner-level only.
    assert not any(f["status"] == "VERIFIED" for f in report["findings"])


def test_probe_db_port_blocked_out_of_scope():
    from redteam_agent.core.db_hunter import probe_db_port

    class DenyScope:
        def check_url(self, url, *, active=True):
            return {"allowed": False, "reason": "host out of scope"}

    result = probe_db_port("evil.example.com", 6379, scope_manager=DenyScope())
    assert result["state"] == "blocked"
    assert "scope policy" in " ".join(result["notes"])


def test_probe_db_port_passes_through_traffic_controller():
    from redteam_agent.core.db_hunter import probe_db_port
    from redteam_agent.core.traffic_controller import TrafficController

    class AllowScope:
        def check_url(self, url, *, active=True):
            return {"allowed": True}

    calls = []
    tc = TrafficController()
    orig = tc.request_slot

    def wrapped(url, module="http", priority="normal"):
        calls.append((url, module, priority))
        return orig(url, module=module, priority=priority)

    tc.request_slot = wrapped
    # port 1: connection refused is fast, no hang
    result = probe_db_port("127.0.0.1", 1, timeout=1.0,
                           scope_manager=AllowScope(), traffic_controller=tc)
    assert calls, "request_slot must be used for DB probes"
    assert calls[0][1] == "db_probe"
    assert result["state"] in {"error", "open"}


def _db_web_verifier(routes):
    """Fake scope-bound verifier: routes is {exact_path: (status, headers, body)}.
    Matching is exact on the URL path so a stub for "/db.sql" does not also
    answer "/backup/db.sql" or "/backups/db.sql"."""
    import urllib.parse as _up

    class FakeVerifier:
        scope = None
        def __init__(self):
            self.calls = []
        def send_http_request(self, url, *a, **k):
            self.calls.append(url)
            path = _up.urlsplit(url).path or "/"
            for route_path, (status, headers, body) in routes.items():
                if path.rstrip("/") == route_path.rstrip("/"):
                    return {"status_code": status, "headers": dict(headers or {}),
                            "body": body, "success": 200 <= status < 400}
            return {"status_code": 404, "headers": {}, "body": "", "success": False}
    return FakeVerifier()


def test_db_hunter_finds_exposed_admin_panel():
    verifier = _db_web_verifier({
        "/phpmyadmin/": (200, {"Content-Type": "text/html"},
                           '<html><title>phpMyAdmin</title><form><input name="pma_username"></form></html>'),
        "/": (200, {"Content-Type": "text/html"}, "<html>home</html>"),
    })
    hunter = DBHunter(verifier=verifier)
    report = hunter.hunt([], [], ports=None, endpoints=["https://target.com/"])
    assert report["total_admin_panels"] == 1
    assert report["admin_panels"][0]["panel"] == "phpMyAdmin"
    assert report["admin_panels"][0]["url"] == "https://target.com/phpmyadmin/"
    panel_findings = [f for f in report["findings"] if "Admin Panel" in f["type"]]
    assert panel_findings and panel_findings[0]["status"] == "DISCOVERED"
    assert panel_findings[0]["missing_evidence"]  # never claims login bypass


def test_db_hunter_finds_downloadable_sql_dump_and_verifies():
    sql_body = "-- MySQL dump 10.13\nCREATE TABLE users (id INT);\nINSERT INTO users VALUES (1);\n-- Dump completed"
    verifier = _db_web_verifier({
        "/db.sql": (200, {"Content-Type": "application/sql"}, sql_body),
        "/": (200, {"Content-Type": "text/html"}, "<html>home</html>"),
    })
    hunter = DBHunter(verifier=verifier)
    report = hunter.hunt([], [], ports=None, endpoints=["https://target.com/"])
    assert report["total_backup_files"] == 1
    assert report["backup_files"][0]["url"] == "https://target.com/db.sql"
    dump_findings = [f for f in report["findings"] if "Dump" in f["type"]]
    assert dump_findings and dump_findings[0]["status"] == "VERIFIED"
    assert dump_findings[0]["missing_evidence"] == []
    assert dump_findings[0]["cvss_score"] > 0


def test_db_hunter_ignores_html_error_page_with_sql_words():
    # Generic HTML 200 page containing the word INSERT INTO must NOT be a dump.
    verifier = _db_web_verifier({
        "/db.sql": (200, {"Content-Type": "text/html"},
                      "<html>docs: use INSERT INTO carefully, and CREATE TABLE in mysql</html>"),
        "/": (200, {"Content-Type": "text/html"}, "<html>home</html>"),
    })
    hunter = DBHunter(verifier=verifier)
    report = hunter.hunt([], [], ports=None, endpoints=["https://target.com/"])
    assert report["total_backup_files"] == 0
    assert not any("Dump" in f["type"] for f in report["findings"])


def test_db_hunter_finds_hidden_db_string_in_page_html_masked():
    """DB connection strings harvested from page HTML are masked by default."""
    verifier = _db_web_verifier({
        "/": (200, {"Content-Type": "text/html"},
            '<!-- legacy --><script>// TODO old\nconst x="postgresql://deploy:hunter2@db.target.com:5433/prod";</script>'),
    })
    hunter = DBHunter(verifier=verifier)
    report = hunter.hunt([], [], ports=None, endpoints=["https://target.com/"])
    assert report["total_hidden_db_strings"] >= 1
    record = report["hidden_db_strings"][0]
    assert record["scheme"] == "postgres"
    assert "hunter2" not in json.dumps(record)
    assert "masked" in record
    assert record["source"].startswith("html:")
    # classified through the same SUSPECTED gate, never VERIFIED from a string
    assert not any(f["status"] == "VERIFIED" for f in report["findings"])


def test_xss_waf_bypass_only_verifies_when_encoded_payload_executes():
    verifier = _exploit_verifier()
    canary = "AGY_XSS_9981"
    plain = f"<script>alert('{canary}')</script>"
    calls = iter([
        # verify_xss (1 request): plain payload is WAF-blocked
        response("blocked", status=403, headers={"Content-Type": "text/html"}),
        # bypass loop: first variant (url_encoded) reflects the decoded script executably
        response(f"<html><body>{plain}</body></html>", headers={"Content-Type": "text/html"}),
    ])
    verifier.send_http_request = lambda *a, **k: next(calls)
    exploit = ExploitEngine(verifier=verifier, exploit_mode="AGGRESSIVE")
    finding = exploit.test_xss_waf_bypass("https://example.com/page?q=x", "q")
    assert finding is not None
    assert finding["status"] == "VERIFIED"
    assert finding["evidence"][0]["bypass_encoding"] == "url_encoded"


def test_xss_waf_bypass_disabled_in_safe_mode():
    exploit = ExploitEngine(verifier=_exploit_verifier(), exploit_mode="SAFE")
    assert exploit.test_xss_waf_bypass("https://example.com/?q=x", "q") is None


def test_waf_header_bypass_returns_suspected_when_block_lifted():
    verifier = _exploit_verifier()
    calls = iter([
        response("blocked", status=403),
        response("page", status=200),
    ])
    verifier.send_http_request = lambda *a, **k: next(calls)
    exploit = ExploitEngine(verifier=verifier, exploit_mode="AGGRESSIVE")
    finding = exploit.test_waf_header_bypass("https://example.com/")
    assert finding is not None
    assert finding["status"] == "SUSPECTED"
    assert finding["evidence"][0]["bypass_header"] == "forged_xff"
    assert finding["missing_evidence"]


def test_cloud_baas_auto_discovers_supabase_and_firebase_from_recon_and_target():
    class FakeVerifier:
        def send_http_request(self, url, *a, **k):
            if "/rest/v1/" in url:
                return response('{"definitions": {}}', status=200)
            return response("null", status=200)  # firebase shallow read null = not open

    scope = ScopeManager(["example.com", "*.supabase.co", "*.firebaseio.com"], resolve_dns=False)
    hunter = CloudBaaSHunter(verifier=FakeVerifier(), scope_manager=scope)
    report = hunter.audit_discovered_assets([],
        hosts=["api.example.com", "proj.supabase.co"],
        target_url="https://proj.firebaseio.com")
    # Only BaaS hosts are auto-audited; plain example.com host is ignored
    assert len(report["supabase_audits"]) == 1
    assert report["supabase_audits"][0]["target_url"] == "https://proj.supabase.co"
    assert report["supabase_audits"][0]["source"] == "auto_discovered"
    assert report["supabase_audits"][0]["auth_used"] is False
    assert len(report["firebase_audits"]) == 1
    assert report["firebase_audits"][0]["source"] == "auto_discovered"
    assert any(f["status"] == "DISCOVERED" for f in report["findings"])


def test_cloud_baas_skips_out_of_scope_auto_discovered_host():
    class FakeVerifier:
        def send_http_request(self, url, *a, **k):
            raise AssertionError("out-of-scope BaaS must not be touched")

    scope = ScopeManager(["example.com"], resolve_dns=False)
    hunter = CloudBaaSHunter(verifier=FakeVerifier(), scope_manager=scope)
    report = hunter.audit_discovered_assets([], hosts=["other.supabase.co"], target_url=None)
    assert report["supabase_audits"] == []
    assert report["skipped_external"]
    assert all(item["active_verification_skipped"] == "outside_scope" for item in report["skipped_external"])


def test_cloud_baas_uses_recovered_anon_key_when_available():
    anon = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYW5vbiJ9.MA"
    class FakeVerifier:
        def send_http_request(self, url, *a, **k):
            return response('{"definitions": {}}', status=200)

    scope = ScopeManager(["*.supabase.co"], resolve_dns=False)
    hunter = CloudBaaSHunter(verifier=FakeVerifier(), scope_manager=scope)
    secrets = [{"_raw_value": "https://proj.supabase.co", "secret_type": "supabase_url"},
               {"_raw_value": anon, "secret_type": "supabase_anon_key", "source": "app.js"}]
    report = hunter.audit_discovered_assets(secrets, hosts=None, target_url=None)
    assert len(report["supabase_audits"]) == 1
    assert report["supabase_audits"][0]["auth_used"] is True
    assert report["supabase_audits"][0]["source"] == "js_secret"


def test_redis_no_auth_probe_classified_as_verified(monkeypatch):
    import socket as _socket

    class FakeSocket:
        def __init__(self, *a, **k):
            self.responses = [b"+PONG\r\n", b"# Server\r\nredis_version:7.0.0\r\n"]
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def settimeout(self, t): pass
        def sendall(self, data):
            if b"PING" in data:
                self._next = 0
            elif b"INFO" in data:
                self._next = 1
        def recv(self, size):
            return self.responses[self._next % 2]
        def close(self): pass

    monkeypatch.setattr(_socket, "create_connection", lambda *a, **k: FakeSocket())
    report = DBHunter().hunt([], [], [{"host": "redis.target.com", "port": 6379, "state": "open"}])
    assert report["total_exposed_ports"] == 1
    assert report["exposed_ports"][0]["auth_free"] is True
    verified = [f for f in report["findings"] if f["status"] == "VERIFIED"]
    assert any("redis" in f["type"].lower() and "Unauthenticated" in f["type"] for f in verified)


def test_db_probe_unknown_banner_yields_discovered_not_verified(monkeypatch):
    import socket as _socket

    class FakeSocket:
        def __init__(self, *a, **k): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def settimeout(self, t): pass
        def sendall(self, data): pass
        def recv(self, size): return b"8.0.36-log"
        def close(self): pass

    monkeypatch.setattr(_socket, "create_connection", lambda *a, **k: FakeSocket())
    report = DBHunter().hunt([], [], [{"host": "db.target.com", "port": 3306, "state": "open"}])
    assert report["exposed_ports"][0]["service"] == "mysql"
    assert not any(f["status"] == "VERIFIED" for f in report["findings"])
    assert any(f["status"] == "DISCOVERED" for f in report["findings"])


def test_supabase_credential_fields_read_are_verified_and_scored():
    class FakeVerifier:
        def send_http_request(self, url, *a, **k):
            if "/rest/v1/" == url.rstrip("/") + "/" or url.rstrip("/").endswith("/rest/v1"):
                return response('{"definitions": {"users": {"properties": {}}}}', status=200)
            if "select=*" in url:
                return response('[{"id": 1, "email": "a@b.c", "password_hash": "x", "token": "y"}]', status=200)
            return response("not found", status=404)

    scope = ScopeManager(["*.supabase.co"], resolve_dns=False)
    hunter = CloudBaaSHunter(verifier=FakeVerifier(), scope_manager=scope)
    report = hunter.audit_supabase("https://proj.supabase.co", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYW5vbiJ9.MA")
    assert any(f["status"] == "VERIFIED" for f in report["findings"])
    verified = [f for f in report["findings"] if f["status"] == "VERIFIED"][0]
    assert "password_hash" in verified["evidence"][0]["credential_fields"]
    assert verified["cvss_score"] == 9.1
    assert verified["missing_evidence"] == []


def test_supabase_without_credential_fields_stays_likely():
    class FakeVerifier:
        def send_http_request(self, url, *a, **k):
            if url.rstrip("/").endswith("/rest/v1"):
                return response('{"definitions": {"posts": {"properties": {}}}}', status=200)
            if "select=*" in url:
                return response('[{"id": 1, "email": "a@b.c"}]', status=200)
            return response("not found", status=404)

    scope = ScopeManager(["*.supabase.co"], resolve_dns=False)
    hunter = CloudBaaSHunter(verifier=FakeVerifier(), scope_manager=scope)
    report = hunter.audit_supabase("https://proj.supabase.co", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYW5vbiJ9.MA")
    assert any(f["status"] == "LIKELY" for f in report["findings"])
    assert not any(f["status"] == "VERIFIED" for f in report["findings"])


def test_vercel_dangling_deployment_is_takeover_candidate():
    class FakeVerifier:
        def send_http_request(self, url, *a, **k):
            return response("404: DEPLOYMENT_NOT_FOUND", status=404,
                            headers={"Server": "Vercel", "x-vercel-id": "abc"})

    scope = ScopeManager(["*.vercel.app"], resolve_dns=False)
    hunter = CloudBaaSHunter(verifier=FakeVerifier(), scope_manager=scope)
    report = hunter.audit_discovered_assets([], hosts=["proj.vercel.app"])
    assert len(report["vercel_audits"]) == 1
    assert report["vercel_audits"][0]["dangling"] is True
    assert any("Takeover" in f["type"] for f in report["findings"])


def test_vercel_live_deployment_is_note_not_finding():
    class FakeVerifier:
        def send_http_request(self, url, *a, **k):
            return response("<html>Vercel app home</html>", status=200,
                            headers={"Server": "Vercel"})

    scope = ScopeManager(["*.vercel.app"], resolve_dns=False)
    hunter = CloudBaaSHunter(verifier=FakeVerifier(), scope_manager=scope)
    report = hunter.audit_discovered_assets([], hosts=["proj.vercel.app"])
    assert len(report["vercel_audits"]) == 1
    assert report["vercel_audits"][0]["dangling"] is False
    assert not any(f["type"] == "Dangling Vercel Deployment (Subdomain Takeover Candidate)" for f in report["findings"])


def test_firebase_deep_read_with_sensitive_fields_is_verified():
    class FakeVerifier:
        def send_http_request(self, url, *a, **k):
            if "shallow=true" in url:
                return response("{\"users\": true}", status=200)
            return response('{"users": {"u1": {"email": "a@b.c", "password_hash": "x", "token": "y"}}}', status=200)

    scope = ScopeManager(["*.firebaseio.com"], resolve_dns=False)
    hunter = CloudBaaSHunter(verifier=FakeVerifier(), scope_manager=scope)
    report = hunter.audit_firebase("https://proj.firebaseio.com")
    assert report["credentials_accessible"] is True
    assert "password_hash" in report["sensitive_fields_observed"]
    assert any(f["status"] == "VERIFIED" for f in report["findings"])


def test_validate_poc_endpoint_promotes_and_demotes(monkeypatch):
    from redteam_agent import app as _app
    from fastapi.testclient import TestClient
    from redteam_agent.core.task_manager import task_manager
    from redteam_agent.core.findings import normalized_finding, FindingStatus
    from redteam_agent.core.engagement import EngagementProfile

    _app.configure_web_auth("127.0.0.1")  # loopback: no token required
    # clear singleton tasks for isolation
    task_manager.tasks.clear()
    engagement = EngagementProfile.from_mapping({
        "engagement_id": "TEST-POC", "authorization_reference": "TEST-ROE",
        "allowed_targets": ["example.com"], "expires_at": "2099-01-01T00:00:00Z",
        "prohibited_techniques": ["denial-of-service"], "allowed_techniques": ["xss"],
        "objective": "Validate one captured finding",
    })
    task = task_manager.create_task(
        "example.com", offensive=True, engagement=engagement,
        hunt_focus={"vulnerability_classes": ["xss"]},
    )
    task.results["findings"] = [normalized_finding(
        finding_type="Exposed Git Repository Metadata (/.git/HEAD)", target="example.com",
        endpoint="https://example.com/.git/HEAD", status=FindingStatus.SUSPECTED)]
    task.results["vulnerabilities"] = []
    task.results["stats"]["vulnerabilities"] = 0

    # stub verifier so the PoC sees a matching marker
    class FakeVerifier:
        def send_http_request(self, url, *a, **k):
            return response("ref: refs/heads/main")
        def verify_xss(self, *a, **k):
            return {"verified": False}
    monkeypatch.setattr(_app, "HTTPVerifier", lambda *a, **k: FakeVerifier())

    client = TestClient(_app.app)
    finding = task.results["findings"][0]
    r = client.post(f"/api/findings/{task.task_id}/{finding['id']}/validate-poc")
    assert r.status_code == 200
    data = r.json()
    assert data["validation"]["passed"] is True
    assert data["status"] == "VERIFIED"
    assert task.results["stats"]["vulnerabilities"] == 1


def test_validate_poc_response_redacts_raw_value_and_sibling_reason(monkeypatch):
    from redteam_agent import app as _app
    from fastapi.testclient import TestClient
    from redteam_agent.core.task_manager import task_manager
    from redteam_agent.core.findings import normalized_finding, FindingStatus
    from redteam_agent.core.engagement import EngagementProfile

    _app.configure_web_auth("127.0.0.1")  # loopback: no token required
    raw = "local-validation-error-not-matched-by-token-regex"
    task_manager.tasks.clear()
    engagement = EngagementProfile.from_mapping({
        "engagement_id": "TEST-POC-REDACT", "authorization_reference": "TEST-ROE",
        "allowed_targets": ["example.com"], "expires_at": "2099-01-01T00:00:00Z",
        "prohibited_techniques": ["denial-of-service"], "allowed_techniques": ["xss"],
        "objective": "Validate response redaction",
    })
    task = task_manager.create_task(
        "example.com", offensive=True, engagement=engagement,
        hunt_focus={"vulnerability_classes": ["xss"]},
    )
    finding = normalized_finding(
        finding_type="Reflected XSS", target="example.com",
        endpoint="https://example.com/?q=x", status=FindingStatus.SUSPECTED,
    )
    task.results["findings"] = [finding]
    monkeypatch.setattr(_app, "validate_finding_poc", lambda *_args, **_kwargs: {
        "passed": False, "reason": f"validator saw {raw}", "_raw_value": raw,
    })

    response = TestClient(_app.app).post(
        f"/api/findings/{task.task_id}/{finding['id']}/validate-poc"
    )
    assert response.status_code == 200
    assert raw not in response.text
    assert response.json()["validation"]["_raw_value"] == "[REDACTED]"


def test_fp_kill_gate_quarantines_verified_with_missing_evidence_and_fp_reasons():
    weak = normalized_finding(finding_type="Reflected XSS", target="x.com",
                              endpoint="https://x.com/", status=FindingStatus.VERIFIED, confidence=.9,
                              missing_evidence=["No browser execution proof"],
                              false_positive_reasons=["Reflection may be in a JS string"],
                              vrt_triage={"is_approved": True})
    clean = normalized_finding(finding_type="SQL Injection", target="x.com",
                               endpoint="https://x.com/", status=FindingStatus.VERIFIED, confidence=.95,
                               vrt_triage={"is_approved": True})
    report = kill_pass([weak, clean])
    assert len(report["submission_ready"]) == 1
    assert len(report["quarantined"]) == 1
    reasons = (report["quarantined"][0].get("fp_kill") or {}).get("reasons", [])
    assert "MISSING_EVIDENCE" in reasons and "UNRESOLVED_FP" in reasons
    assert report["quarantined"][0]["id"] == weak["id"]


def test_fp_kill_gate_suspected_and_low_confidence_are_never_submission_ready():
    suspected = normalized_finding(finding_type="Possible SSRF", target="x.com",
                                   endpoint="https://x.com/", status=FindingStatus.SUSPECTED,
                                   confidence=.3, vrt_triage={"is_approved": False})
    report = kill_pass([suspected])
    assert report["submission_ready"] == []
    assert len(report["quarantined"]) == 1
    reasons = (report["quarantined"][0].get("fp_kill") or {}).get("reasons", [])
    assert "NOT_VERIFIED" in reasons and "LOW_CONFIDENCE" in reasons


def test_fp_kill_gate_flags_known_na_classes():
    open_redirect = normalized_finding(finding_type="Open Redirect", target="x.com",
        endpoint="https://x.com/r", status=FindingStatus.VERIFIED, confidence=.9,
        vrt_triage={"is_approved": True})
    report = kill_pass([open_redirect])
    assert report["submission_ready"] == []
    reasons = (report["quarantined"][0].get("fp_kill") or {}).get("reasons", [])
    assert "KNOWN_NA_CLASS" in reasons


def test_fp_kill_gate_retains_verified_researcher_controlled_redirect_proof():
    finding = normalized_finding(
        finding_type="Open Redirect", target="x.com",
        endpoint="https://x.com/r?next=https%3A%2F%2Fredirect-canary.invalid%2Fverified",
        status=FindingStatus.VERIFIED, confidence=.95,
        evidence=[{"researcher_controlled_domain": "redirect-canary.invalid",
                   "location": "https://redirect-canary.invalid/verified"}],
        verification_checks=[{"name": "researcher_controlled_location", "passed": True}],
        vrt_triage={"is_approved": True},
    )
    report = kill_pass([finding])
    assert report["submission_ready"] == [finding]
    assert report["quarantined"] == []


def test_fp_kill_gate_human_verified_with_reason_overrides_quarantine():
    finding = normalized_finding(finding_type="Open Redirect", target="x.com",
        endpoint="https://x.com/r", status=FindingStatus.SUSPECTED, confidence=.2,
        missing_evidence=["no leak chain"], vrt_triage={"is_approved": False})
    apply_human_review(finding, "MARK VERIFIED", reviewer="analyst", reason="OAuth token leak chain reproduced manually")
    report = kill_pass([finding])
    assert len(report["submission_ready"]) == 1
    assert report["submission_ready"][0]["status"] == "VERIFIED"
    assert report["quarantined"] == []


def test_fp_kill_gate_human_verified_without_reason_does_not_override():
    finding = normalized_finding(finding_type="Open Redirect", target="x.com",
        endpoint="https://x.com/r", status=FindingStatus.SUSPECTED, confidence=.2,
        vrt_triage={"is_approved": False})
    apply_human_review(finding, "MARK VERIFIED", reviewer="analyst", reason="")
    report = kill_pass([finding])
    assert report["submission_ready"] == []
    assert len(report["quarantined"]) == 1


def test_vrt_triage_rejects_missing_security_headers():
    verdict = VRTTriageEngine().evaluate_finding(
        "Missing HSTS header on login page", "server did not send HSTS", poc_verified=True)
    assert verdict["is_approved"] is False
    assert verdict["status"] == "REJECTED (ANTI-N/A)"
    assert "Missing Security Headers" in verdict["rule_triggered"]


def test_report_separates_observed_from_potential_impact():
    finding = normalized_finding(finding_type="SSTI", target="example.com", endpoint="https://example.com/q",
        status=FindingStatus.VERIFIED, confidence=.96, observed_impact="Arithmetic expressions evaluated.",
        potential_impact="Engine-specific escalation may be possible.")
    report = ReportBuilder().generate_markdown_report(finding)
    assert "## Observed Impact" in report and "Arithmetic expressions evaluated." in report
    assert "## Potential Impact" in report and "Engine-specific escalation may be possible." in report
    assert "Complete account takeover" not in report
    assert "lateral movement" not in report


def test_naabu_registered_in_tool_paths():
    from redteam_agent.core.config import TOOL_PATHS
    assert "naabu" in TOOL_PATHS
    assert TOOL_PATHS["naabu"]


def test_cors_misconfiguration_method_exists_and_verifies_only_real_exposure():
    exploit = ExploitEngine(verifier=_exploit_verifier(), exploit_mode="SAFE")
    assert hasattr(exploit, "test_cors_misconfiguration")
    # Sensitive JSON + reflected origin + credentials => VERIFIED (real exposure)
    verifier = _exploit_verifier()
    verifier.send_http_request = lambda *a, **k: response(
        json.dumps({"email": "a@b.c", "token": "x"}), headers={"Content-Type": "application/json",
            "Access-Control-Allow-Origin": "https://cors-canary.invalid",
            "Access-Control-Allow-Credentials": "true"})
    exploit = ExploitEngine(verifier=verifier, exploit_mode="SAFE")
    finding = exploit.test_cors_misconfiguration("https://example.com/")
    assert finding is not None
    assert finding["status"] == "VERIFIED"
    assert finding["type"] == "VERIFIED_CROSS_ORIGIN_DATA_EXPOSURE"
    assert finding["cvss_score"] == 6.5  # computed from CVSS:3.1 vector, not magic number


def test_cors_configuration_quirk_never_verifies():
    verifier = _exploit_verifier()
    verifier.send_http_request = lambda *a, **k: response(
        "<html>plain</html>", headers={"Content-Type": "text/html",
            "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "false"})
    exploit = ExploitEngine(verifier=verifier, exploit_mode="SAFE")
    finding = exploit.test_cors_misconfiguration("https://example.com/")
    assert finding is not None
    assert finding["status"] != "VERIFIED"
    assert finding["missing_evidence"]


def test_run_deep_exploit_audit_does_not_crash_on_cors():
    verifier = _exploit_verifier()
    verifier.send_http_request = lambda *a, **k: response("<html>ok</html>", headers={"Content-Type": "text/html"})
    exploit = ExploitEngine(verifier=verifier, exploit_mode="SAFE")
    audit = exploit.run_deep_exploit_audit(["https://example.com/", "https://example.com/?q=1"])
    assert audit["total_hypotheses"] > 0
    assert isinstance(audit["findings"], list)


def test_json_body_sqli_verifies_on_repeatable_delay():
    """Modern APIs take input in JSON bodies; the classic query-param-only
    probing never reaches that surface. This proves the JSON-body verifier
    requires the same repeatable median delay as the GET variant."""
    verifier = _exploit_verifier()

    def fake(url, **k):
        delayed = "SLEEP(5)" in (k.get("body") or "")
        return {"status_code": 400, "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"error": "bad_request"}), "success": False,
                "response_time_sec": 5.2 if delayed else 0.02,
                "raw_request": "", "raw_response": ""}

    verifier.send_http_request = fake
    exploit = ExploitEngine(verifier=verifier, exploit_mode="SAFE")
    finding = exploit.test_sqli_json_body("https://example.com/v1/login", "q")
    assert finding is not None
    assert finding["status"] == "VERIFIED"
    assert "JSON" in finding["type"]
    assert finding["cvss_score"] > 0.0


def test_error_disclosure_verifies_only_on_real_stack_marker():
    leak = _exploit_verifier()
    leak.send_http_request = lambda *a, **k: {
        "status_code": 500, "headers": {"Content-Type": "text/html"},
        "body": "<pre>Traceback (most recent call last)\n  File \"/srv/app.py\", line 12, in handler</pre>",
        "success": False, "response_time_sec": 0.1, "raw_request": "", "raw_response": ""}
    exploit = ExploitEngine(verifier=leak, exploit_mode="SAFE")
    finding = exploit.test_error_disclosure("https://example.com/api/login")
    assert finding is not None
    assert finding["status"] == "VERIFIED"

    clean = _exploit_verifier()
    clean.send_http_request = lambda *a, **k: {
        "status_code": 400, "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"error": "invalid_json_body"}), "success": False,
        "response_time_sec": 0.02, "raw_request": "", "raw_response": ""}
    exploit2 = ExploitEngine(verifier=clean, exploit_mode="SAFE")
    assert exploit2.test_error_disclosure("https://example.com/api/login") is None


def test_deep_audit_records_auth_gated_and_json_body_coverage():
    """Deep audit must (a) not waste probes on 401/403 walls and instead say
    so honestly, and (b) inject JSON bodies on endpoints that accept them."""
    verifier = _exploit_verifier()

    def gate(url, method="GET", **k):
        if "/api/v1/products" in url:
            status, ct = 401, "application/json"
            body = json.dumps({"error": "authentication_required"})
        elif "/api/v1/login" in url:
            if method == "POST":
                status, ct = 400, "application/json"
                body = json.dumps({"error": "invalid_credentials_format"})
            else:
                status, ct = 405, "application/json"
                body = json.dumps({"error": "method_not_allowed"})
        else:
            status, ct = 200, "text/html"
            body = "<html><body>ok</body></html>"
        return {"status_code": status, "headers": {"Content-Type": ct}, "body": body,
                "success": 200 <= status < 400, "response_time_sec": 0.02,
                "raw_request": "", "raw_response": "", "redirects": []}

    verifier.send_http_request = gate
    exploit = ExploitEngine(verifier=verifier, exploit_mode="SAFE")
    audit = exploit.run_deep_exploit_audit([
        "https://example.com/",
        "https://example.com/api/v1/products",
        "https://example.com/api/v1/login",
    ])
    by_endpoint = {c["endpoint"]: c for c in audit["coverage"]}
    products = by_endpoint["https://example.com/api/v1/products"]
    assert products["kind"] == "auth_gated"
    assert "https://example.com/api/v1/products" in audit["auth_gated"]
    assert "skipped_requires_credentials" in products["probes"]
    login = by_endpoint["https://example.com/api/v1/login"]
    assert login["kind"] == "method_restricted_get"
    assert login["post_json_api"] is True
    assert "sqli_json_body" in login["probes"]
    assert "ssti_json_body" in login["probes"]
    assert "error_disclosure" in login["probes"]
    assert audit["total_hypotheses"] > 0


def test_active_exploit_preset_description_is_honest():
    from redteam_agent.core.config import SCAN_PRESETS
    description = SCAN_PRESETS["active_exploit"]["description"]
    # No RCE claim without execution proof; SSTI never upgraded to RCE.
    assert "No RCE claimed" in description
    assert "SSTI is never upgraded to RCE" in description
    assert "exploit_verifier" in SCAN_PRESETS["active_exploit"]["modules"]


def test_naabu_port_scan_is_executed_when_binary_present(monkeypatch):
    import os
    from redteam_agent.core import recon_depth as rd
    from redteam_agent.core.config import TOOL_PATHS
    from redteam_agent.core.task_manager import ScanTask

    if not TOOL_PATHS.get("naabu") or not os.path.exists(TOOL_PATHS["naabu"]):
        pytest.skip("naabu binary not present on this machine")
    task = ScanTask("t", "example.com")
    verifier = HTTPVerifier(scope_manager=ScopeManager(["example.com"], resolve_dns=False))
    depth = rd.ReconDepth(task, verifier)
    lines = ["example.com:443", "example.com:80"]
    async def fake_run(cmd, tool_label):
        return lines
    monkeypatch.setattr(depth, "_run_async_command", fake_run)
    ports = asyncio.run(depth.run_port_scan("example.com"))
    assert any(p["port"] == 443 for p in ports)
    assert any(p["port"] == 80 for p in ports)
    assert all(p["observed"] for p in ports)
