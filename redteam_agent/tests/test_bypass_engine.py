"""Offline contracts for the adaptive bypass and authorization engines."""

from __future__ import annotations

import json
from urllib.parse import parse_qsl, urlsplit

from redteam_agent.core.bypass_engine import (
    AuthorizationBypassEngine,
    BypassBudget,
    BypassEngine,
    PayloadMutationEngine,
    ProtectionFingerprintEngine,
    ReferenceIntelService,
    SQLPayload,
    classify_response,
    redact_headers,
    response_differential,
)


def response(status=200, body="ok", headers=None, elapsed=0.01):
    return {
        "status_code": status, "success": 200 <= status < 400,
        "headers": headers or {"Content-Type": "text/plain"},
        "body": body, "response_time_sec": elapsed,
        "raw_request": "GET / HTTP/1.1\nAuthorization: Bearer secret-token",
        "raw_response": f"HTTP/1.1 {status}\n\n{body}",
    }


def test_response_features_include_learning_fields_and_200_error_is_not_allowed():
    features = classify_response(response(200, "error page"))
    assert features.classification == "application_error"
    assert features.body_hash and features.body_length == len("error page")
    diff = response_differential(response(403, "Request blocked"), response(200, "error page"))
    assert diff["status_changed"] is True
    assert diff["status_change_is_not_proof"] is True
    assert diff["classification_after"] == "application_error"


def test_fingerprint_requires_more_than_one_signal_family_for_high_confidence():
    one_header = ProtectionFingerprintEngine().fingerprint(
        [response(403, "generic", {"cf-ray": "abc"})])
    assert one_header["fingerprints"][0]["confidence"] <= .48

    cloudflare = ProtectionFingerprintEngine().fingerprint([
        response(200, "normal", {"Server": "cloudflare"}),
        response(403, "Attention Required! | Cloudflare",
                 {"Server": "cloudflare", "Set-Cookie": "cf_clearance=secret"}),
    ])
    assert "Cloudflare" in cloudflare["detected"]
    assert cloudflare["primary"]["confidence"] >= .55
    assert cloudflare["primary"]["signal_families"] >= ["body", "cookie"]


def test_mutation_engine_selects_by_context_and_keeps_sql_semantics():
    engine = PayloadMutationEngine()
    xss = engine.generate_mutations(
        "<script>AGY</script>", vulnerability_class="xss",
        input_context={"context": "HTML attribute"}, max_mutations=4)
    assert xss
    assert all(item.category in {"delimiter_mutation", "html_entity_encoding", "case_mutation"}
               for item in xss)

    sql = engine.generate_mutations(
        SQLPayload("boolean_true", dialect="postgres"),
        vulnerability_class="sqli", max_mutations=5)
    assert sql
    assert all(item.semantic == "boolean_true" and item.dialect == "postgres" for item in sql)
    assert any(item.category == "double_url_encoding" for item in sql)


def test_budget_preserves_two_control_requests_and_never_exceeds_total():
    budget = BypassBudget(8)
    assert budget.phase_limits["baseline_control"] == 2
    for phase in ("baseline_control", "initial_strategies",
                  "adaptive_bypass", "confirmation"):
        for _ in range(20):
            budget.claim(phase)
    assert budget.total_consumed <= 8
    assert budget.remaining() == 0


class AdaptiveVerifier:
    """First request is normal, second is blocked, third reaches a backend."""

    def __init__(self):
        self.calls = []

    def send_http_request(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if len(self.calls) == 1:
            return response(200, "normal")
        if len(self.calls) == 2:
            return response(403, "Request blocked")
        return response(200, "<html><body>BACKEND_CANARY</body></html>",
                        {"Content-Type": "text/html"})


def test_adaptive_bypass_stops_after_verified_relevant_behavior_and_records_primitive():
    verifier = AdaptiveVerifier()
    engine = BypassEngine(verifier, exploit_mode="AGGRESSIVE", request_budget=8)
    report = engine.run(
        "https://example.com/search", vulnerability_class="generic",
        payload="<script>canary</script>", parameter="q",
        context={"expected_marker": "BACKEND_CANARY"},
        confirm_on_success=False,
    )
    assert report["status"] == "verified"
    assert report["primitives"][0]["status"] == "VERIFIED"
    assert report["findings"][0]["status"] == "VERIFIED"
    assert report["budget"]["consumed"] <= 8
    assert report["attempts"][0]["difference"]["status_changed"] is True


def test_safe_mode_still_runs_bounded_non_destructive_mutation():
    verifier = AdaptiveVerifier()
    report = BypassEngine(verifier, exploit_mode="SAFE", request_budget=8).run(
        "https://example.com/search", vulnerability_class="generic",
        payload="blocked", parameter="q",
        context={"expected_marker": "BACKEND_CANARY"},
        confirm_on_success=False,
    )
    assert report["enabled_mutations"] is True
    assert report["status"] == "verified"


class StatusOnlyVerifier:
    def __init__(self):
        self.calls = 0

    def send_http_request(self, url, **kwargs):
        self.calls += 1
        if self.calls == 1:
            return response(200, "normal")
        if self.calls == 2:
            return response(403, "Request blocked")
        return response(200, "error page")


def test_status_flip_to_200_error_page_is_not_verified():
    report = BypassEngine(
        StatusOnlyVerifier(), exploit_mode="AGGRESSIVE", request_budget=8
    ).run(
        "https://example.com/search", vulnerability_class="generic",
        payload="blocked", parameter="q", context={"expected_marker": "MISSING"},
        confirm_on_success=False,
    )
    assert report["status"] != "verified"
    assert not report["primitives"]
    assert all(item["verification"]["verified"] is False for item in report["attempts"])


class IdentityVerifier:
    def send_http_request(self, url, **kwargs):
        headers = kwargs.get("headers") or {}
        if headers.get("Authorization") == "Bearer A-secret":
            return response(200, '{"owner":"A-marker","secret":"redacted"}',
                            {"Content-Type": "application/json"})
        if headers.get("Authorization") == "Bearer B-secret":
            return response(200, '{"owner":"B-marker"}',
                            {"Content-Type": "application/json"})
        return response(401, '{"error":"unauthorized"}',
                        {"Content-Type": "application/json"})


def test_authorization_engine_requires_cross_identity_owner_marker_and_redacts_headers():
    engine = AuthorizationBypassEngine(IdentityVerifier(), request_budget=4)
    result = engine.compare_identities(
        "https://example.com/api/object/1",
        {"name": "user_a", "headers": {"Authorization": "Bearer A-secret"}},
        {"name": "user_b", "headers": {"Authorization": "Bearer B-secret"}},
        owner_marker="A-marker",
    )
    assert result["verified"] is False
    assert result["checks"][3]["passed"] is False
    assert result["owner"]["headers"]["Authorization"] == "[REDACTED]"

    class Leaky(IdentityVerifier):
        def send_http_request(self, url, **kwargs):
            return response(200, '{"owner":"A-marker"}',
                            {"Content-Type": "application/json"})

    result = AuthorizationBypassEngine(Leaky(), request_budget=2).compare_identities(
        "https://example.com/api/object/1",
        {"name": "user_a", "headers": {"Authorization": "Bearer A-secret"}},
        {"name": "user_b", "headers": {"Authorization": "Bearer B-secret"}},
        owner_marker="A-marker",
    )
    assert result["verified"] is True
    assert "A-secret" not in json.dumps(result)


class PollutionVerifier:
    def send_http_request(self, url, **kwargs):
        values = [item for key, item in parse_qsl(urlsplit(url).query)
                  if key == "a"]
        return response(200, values[-1] if values else "none")


def test_parameter_pollution_reports_observed_last_parser_without_claiming_impact():
    result = BypassEngine(PollutionVerifier()).test_parameter_pollution(
        "https://example.com/api?a=base", "a",
        values=("one", "two"), request_budget=4)
    assert result["parser_winner"] == "last_value"
    assert result["verified"] is False
    assert result["missing_evidence"]
    assert result["requests_used"] == 4


class ContentTypeVerifier:
    def send_http_request(self, url, **kwargs):
        content_type = (kwargs.get("headers") or {}).get("Content-Type", "")
        if content_type.startswith("application/json"):
            return response(400, '{"error":"validation"}',
                            {"Content-Type": "application/json"})
        if content_type.startswith("application/x-www-form-urlencoded"):
            return response(415, "unsupported media type")
        return response(200, "normal", {"Content-Type": "text/plain"})


def test_content_type_variation_uses_only_proven_supported_formats():
    engine = BypassEngine(ContentTypeVerifier())
    capabilities = engine.probe_supported_content_types(
        "https://example.com/api", field="q", request_budget=4)
    assert "application/json" in capabilities["supported_content_types"]
    assert "application/x-www-form-urlencoded" not in capabilities["supported_content_types"]
    result = engine.test_content_type_variation(
        "https://example.com/api", field="q", payload="canary",
        accepted_content_types=capabilities["supported_content_types"], request_budget=2)
    assert set(result["accepted_content_types_used"]).issubset(
        set(capabilities["supported_content_types"])
    )


def test_method_variation_never_sends_destructive_methods():
    class MethodVerifier:
        def __init__(self):
            self.methods = []

        def send_http_request(self, url, **kwargs):
            self.methods.append(kwargs.get("method"))
            return response(200, "safe")

    verifier = MethodVerifier()
    result = BypassEngine(verifier).test_method_variation(
        "https://example.com/api", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        request_budget=10)
    assert "PUT" in result["destructive_methods_never_sent"]
    assert "PATCH" in result["destructive_methods_never_sent"]
    assert "DELETE" in result["destructive_methods_never_sent"]
    assert all(method not in {"PUT", "PATCH", "DELETE"} for method in verifier.methods)


def test_pipeline_skips_destructive_base_method_without_calling_verifier():
    class GuardedVerifier:
        def __init__(self):
            self.calls = 0

        def send_http_request(self, url, **kwargs):
            self.calls += 1
            raise AssertionError("destructive method reached verifier")

    verifier = GuardedVerifier()
    report = BypassEngine(verifier).run(
        "https://example.com/api/object", method="DELETE", payload="x", parameter="id"
    )
    assert report["status"] == "skipped_destructive_method"
    assert verifier.calls == 0


def test_reference_and_patch_intelligence_are_hypotheses_only():
    service = ReferenceIntelService([
        {"source": "NVD", "component": "example parser", "text": "duplicate query parser issue"}
    ])
    hypotheses = service.select_hypotheses("parser", "query", limit=2)
    assert hypotheses[0]["hypothesis_only"] is True
    diff = service.analyze_patch_diff(
        "- parse(query)\n+ authorize(request)\n+ normalize(path)\n")
    assert diff["read_only"] is True
    assert "added_authorization_check" in diff["hypothesis"]
    assert diff["automatic_exploit_execution"] is False


def test_chain_keeps_unverified_primitive_as_potential():
    engine = BypassEngine()
    potential = engine.build_chain([
        {"id": "a", "type": "waf_normalization_bypass", "status": "VERIFIED"},
        {"id": "b", "type": "sqli", "status": "SUSPECTED"},
    ])
    confirmed = engine.build_chain([
        {"id": "a", "type": "waf_normalization_bypass", "status": "VERIFIED"},
        {"id": "b", "type": "sqli", "status": "VERIFIED"},
    ])
    assert potential["status"] == "POTENTIAL CHAIN"
    assert confirmed["status"] == "CONFIRMED"


def test_header_redaction_is_stable():
    safe = redact_headers({"Authorization": "Bearer secret", "Accept": "application/json"})
    assert safe["Authorization"] == "[REDACTED]"
    assert safe["Accept"] == "application/json"
