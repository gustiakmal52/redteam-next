"""Adaptive, evidence-first filter and authorization bypass verification.

This module keeps representation separate from meaning. A mutation can change
how a request is encoded, parsed, routed, or transported, but it does not
become a vulnerability finding until the relevant backend behaviour is
observed and verified.

The engine is bounded:

* every live request goes through HTTPVerifier and inherits scope, destination,
  traffic, retry, and global kill-switch controls;
* a local phase budget prevents mutation spraying;
* 200/30x status changes are observations, never proof;
* context-specific proof is required for XSS, CORS, SSRF, redirects, SQLi,
  SSTI, and authorization claims;
* evidence returned by this module is redacted before persistence.
"""

from __future__ import annotations

import hashlib
import html
import json
import re
import urllib.parse
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Any, Callable, Iterable, Mapping, Optional, Sequence

from redteam_agent.core.findings import FindingStatus, normalized_finding
from redteam_agent.core.http_verifier import HTTPVerifier
from redteam_agent.core.sql_strategies import render_sql_payload
from redteam_agent.core.ssrf_verifier import (callback_proof, callback_variants,
                                                deterministic_marker_proof)

__all__ = [
    "AuthorizationBypassEngine", "BypassBudget", "BypassEngine", "DeepExploitEngine", "Identity",
    "MUTATION_CATEGORIES", "MutationCandidate", "PayloadMutationEngine",
    "ProtectionFingerprintEngine", "REFERENCE_SOURCES", "ReferenceIntelService",
    "ResponseFeatures", "ResponseLearner", "SQLPayload", "StrategyScore",
    "classify_response", "redact_body", "redact_headers",
    "response_differential", "safe_request_evidence", "safe_response_evidence",
]


# ---------------------------------------------------------------------------
# Evidence hygiene
# ---------------------------------------------------------------------------

_SENSITIVE_HEADER_NAMES = {
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "api-key", "x-auth-token", "x-csrf-token", "x-xsrf-token",
}
_SENSITIVE_KEY_RE = re.compile(
    r"(?:pass(?:word)?|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|"
    r"session|cookie|credential|authorization|client_secret|database_url)", re.I
)
_BEARER_RE = re.compile(r"(?i)(\bBearer\s+)[A-Za-z0-9._~+/=-]+")
_URL_SECRET_RE = re.compile(
    r"(?i)([?&](?:token|secret|password|api[_-]?key|access[_-]?token)=)[^&#\s]+"
)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_SENSITIVE_HEADERS = {
    "authorization", "cookie", "set-cookie", "proxy-authorization",
    "x-api-key", "api-key", "x-auth-token", "x-access-token",
    "x-csrf-token", "x-xsrf-token", "x-amz-security-token",
}


def _redact_scalar(value: Any, key: str = "") -> Any:
    """Redact bearer tokens, URL secrets, and JWT-like values from a scalar."""
    if value is None:
        return None
    text = str(value)
    if not text:
        return text
    text = _BEARER_RE.sub(r"\1[REDACTED]", text)
    text = _URL_SECRET_RE.sub(r"\1[REDACTED]", text)
    text = _JWT_RE.sub("[REDACTED]", text)
    return text


def _status_code(response: Optional[Mapping[str, Any]]) -> int:
    """Read either the verifier's canonical key or a compact test-fixture key."""
    response = response or {}
    raw = response.get("status_code", response.get("status", 0))
    try:
        return int(raw or 0)
    except (TypeError, ValueError):
        return 0


def _elapsed_seconds(response: Optional[Mapping[str, Any]]) -> float:
    response = response or {}
    raw = response.get("response_time_sec", response.get("timing_sec", 0.0))
    try:
        return float(raw or 0.0)
    except (TypeError, ValueError):
        return 0.0


def redact_headers(headers: Optional[Mapping[str, Any]]) -> dict[str, str]:
    """Redact sensitive header values; keep benign headers readable."""
    result: dict[str, str] = {}
    for key, value in (headers or {}).items():
        str_key = str(key)
        if str_key.lower() in _SENSITIVE_HEADERS:
            result[str_key] = "[REDACTED]"
        else:
            result[str_key] = str(_redact_scalar(value, str_key))
    return result


def redact_json_value(value: Any, key: str = "") -> Any:
    """Recursively redact sensitive values inside JSON-like structures."""
    if isinstance(value, dict):
        return {str(k): redact_json_value(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_json_value(v, key) for v in value]
    if isinstance(value, str):
        return _redact_scalar(value, key)
    return value


def redact_body(body: Any, limit: int = 4000) -> str:
    """Redact sensitive values from a body string, then truncate."""
    if body is None:
        return ""
    text = str(body)
    text = str(_redact_scalar(text))
    return text[:limit] + ("\n... [truncated]" if len(text) > limit else "")


def redact_http_text(value: Any, limit: int = 4000) -> str:
    """Redact sensitive values from raw HTTP text, then truncate."""
    if value is None:
        return ""
    text = str(value)
    text = str(_redact_scalar(text))
    return text[:limit] + ("\n... [truncated]" if len(text) > limit else "")


def safe_response_evidence(response: Optional[Mapping[str, Any]], body_limit: int = 4000) -> dict[str, Any]:
    """Serialize an observed verifier response without credential material."""
    response = response or {}
    return {
        "status_code": _status_code(response),
        "headers": redact_headers(response.get("headers", {})),
        "body": redact_body(response.get("body", ""), body_limit),
        "response_time_sec": round(_elapsed_seconds(response), 4),
        "raw_request": redact_http_text(response.get("raw_request", ""), body_limit),
        "raw_response": redact_http_text(response.get("raw_response", ""), body_limit),
        "redirects": [
            {key: (redact_http_text(value, 500) if key in {"from", "to"} else value)
             for key, value in item.items() if key != "scope"}
            for item in (response.get("redirects", []) or [])
            if isinstance(item, Mapping)
        ],
    }


def safe_request_evidence(request: Optional[Mapping[str, Any]]) -> dict[str, Any]:
    request = request or {}
    return {
        "url": redact_http_text(request.get("url", "")),
        "method": str(request.get("method", "GET")).upper(),
        "headers": redact_headers(request.get("headers", {})),
        "body": redact_body(request.get("body", ""), 4000),
    }


# ---------------------------------------------------------------------------
# Response learning and differential evidence
# ---------------------------------------------------------------------------

RESPONSE_CLASSES = {
    "allowed", "blocked", "challenge", "application_error", "backend_response", "unknown"
}
DESTRUCTIVE_METHODS = frozenset({"PUT", "PATCH", "DELETE"})

_BLOCK_BODY_MARKERS: tuple[tuple[str, str], ...] = (
    ("cloudflare_challenge", "attention required! | cloudflare"),
    ("cloudflare_challenge", "just a moment..."),
    ("cloudflare_block", "cf-error-details"),
    ("aws_block", "request blocked"),
    ("aws_block", "generated by cloudfront"),
    ("akamai_block", "reference #"),
    ("imperva_block", "incapsula incident id"),
    ("imperva_block", "incapsula"),
    ("modsecurity_block", "mod_security"),
    ("modsecurity_block", "owasp modsecurity core rule set"),
    ("fastly_block", "fastly error"),
    ("nginx_block", "nginx 403"),
    ("generic_access_denied", "access denied"),
    ("generic_request_blocked", "request rejected"),
    ("generic_request_blocked", "request blocked"),
    ("custom_application_filter", "blocked by policy"),
    ("custom_application_filter", "policy denied"),
    ("custom_application_filter", "filtered request"),
    ("custom_application_filter", "custom filter"),
    ("generic_captcha", "captcha"),
    ("generic_challenge", "verify you are human"),
)

_ERROR_BODY_MARKERS = (
    "traceback", "stack trace", "exception", "internal server error", "syntax error",
    "invalid json", "validation error", '"error"', "error:", "unhandled", "parse error",
)


def _header_values(response: Mapping[str, Any]) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in (response.get("headers", {}) or {}).items()}


def _response_body(response: Mapping[str, Any]) -> str:
    return str(response.get("body", "") or "")


def _block_signature(status_code: int, headers: Mapping[str, str], body: str) -> tuple[Optional[str], bool]:
    lowered = body.lower()
    for name, marker in _BLOCK_BODY_MARKERS:
        if marker in lowered:
            return f"body:{name}", name.endswith("challenge") or "challenge" in name or "captcha" in name
    header_markers = (
        ("cf-mitigated", "cloudflare_challenge"),
        ("x-amzn-waf-action", "aws_block"),
        ("x-sucuri-block", "sucuri_block"),
        ("x-iinfo", "imperva_block"),
        ("x-akamai-session-info", "akamai_block"),
    )
    for key, name in header_markers:
        if key in headers:
            return f"header:{name}", "challenge" in name
    if status_code in {401, 403, 406, 407, 409, 413, 418, 429, 444, 451, 503}:
        return f"status:{status_code}", status_code in {429, 503}
    return None, False


@dataclass(frozen=True)
class ResponseFeatures:
    status_code: int
    body_hash: str
    body_length: int
    headers: dict[str, str]
    content_type: str
    response_time_sec: float
    block_signature: Optional[str]
    challenge: bool
    classification: str
    location: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status_code,
            "status_code": self.status_code,
            "body_hash": self.body_hash,
            "body_length": self.body_length,
            "headers": dict(self.headers),
            "content_type": self.content_type,
            "timing_sec": round(self.response_time_sec, 4),
            "block_signature": self.block_signature,
            "challenge": self.challenge,
            "classification": self.classification,
            "location": redact_http_text(self.location, 1000) if self.location else None,
        }


def classify_response(response: Optional[Mapping[str, Any]], baseline: Optional[Mapping[str, Any]] = None) -> ResponseFeatures:
    """Classify status, body, headers, and timing conservatively."""
    response = response or {}
    status = _status_code(response)
    body = _response_body(response)
    headers = _header_values(response)
    body_hash = hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()
    signature, challenge = _block_signature(status, headers, body)
    lowered = body.lower()
    content_type = headers.get("content-type", "")
    if signature:
        classification = "challenge" if challenge else "blocked"
    elif status == 0:
        classification = "unknown"
    elif status >= 500 or (status in {400, 422} and any(marker in lowered for marker in _ERROR_BODY_MARKERS)):
        classification = "application_error"
    elif 200 <= status < 400:
        # Some reverse proxies return a friendly 200 page after a failed
        # upstream/filter decision. Treat explicit error envelopes/pages as an
        # application error so a status flip cannot be mistaken for origin
        # access.
        looks_error_page = bool(
            re.search(r"<title>[^<]*(?:error|not found|denied|blocked)[^<]*</title>", lowered)
            or re.search(r"\b(?:application|upstream|gateway)\s+(?:error|failure)\b", lowered)
            or re.search(r"\b(?:error page|request failed|backend failure)\b", lowered)
            or body.strip().startswith(("{\"error\"", "{\"errors\"", "[{\"error\""))
        )
        classification = "application_error" if looks_error_page else "allowed"
    elif status in {400, 422} and ("json" in content_type.lower() or body.lstrip().startswith(("{", "["))):
        classification = "application_error"
    else:
        classification = "unknown"
    if baseline is not None and classification == "allowed":
        base_body = _response_body(baseline)
        base_status = _status_code(baseline)
        base_hash = hashlib.sha256(base_body.encode("utf-8", "replace")).hexdigest()
        if status != base_status or body_hash != base_hash:
            classification = "backend_response"
    return ResponseFeatures(
        status_code=status,
        body_hash=body_hash,
        body_length=len(body),
        headers=redact_headers(response.get("headers", {})),
        content_type=content_type,
        response_time_sec=_elapsed_seconds(response),
        block_signature=signature,
        challenge=challenge,
        classification=classification,
        location=next((value for key, value in (response.get("headers", {}) or {}).items()
                        if str(key).lower() == "location"), None),
    )


def response_differential(original: Optional[Mapping[str, Any]], mutated: Optional[Mapping[str, Any]]) -> dict[str, Any]:
    """Compare observed responses; never equate a status change with proof."""
    original = original or {}
    mutated = mutated or {}
    left = classify_response(original)
    right = classify_response(mutated, baseline=original)
    left_body = _response_body(original)
    right_body = _response_body(mutated)
    left_headers = _header_values(original)
    right_headers = _header_values(mutated)
    changed_headers = sorted(set(left_headers) | set(right_headers))
    header_changes = {
        key: {
            "before": redact_headers({key: left_headers.get(key, "")}).get(key, ""),
            "after": redact_headers({key: right_headers.get(key, "")}).get(key, ""),
        }
        for key in changed_headers if left_headers.get(key) != right_headers.get(key)
    }
    return {
        "status_before": left.status_code,
        "status_after": right.status_code,
        "status_changed": left.status_code != right.status_code,
        "classification_before": left.classification,
        "classification_after": right.classification,
        "body_hash_before": left.body_hash,
        "body_hash_after": right.body_hash,
        "body_length_before": left.body_length,
        "body_length_after": right.body_length,
        "body_length_delta": right.body_length - left.body_length,
        "body_similarity": round(SequenceMatcher(None, left_body, right_body).ratio(), 4),
        "body_changed": left.body_hash != right.body_hash,
        "header_changes": header_changes,
        "timing_before_sec": round(left.response_time_sec, 4),
        "timing_after_sec": round(right.response_time_sec, 4),
        "timing_delta_sec": round(right.response_time_sec - left.response_time_sec, 4),
        "block_signature_before": left.block_signature,
        "block_signature_after": right.block_signature,
        "normalization_layers": {
            "frontend_proxy": {
                "classification": left.classification,
                "status": left.status_code,
                "note": "Observed edge response; proxy internals are not directly visible.",
            },
            "waf_or_filter": {
                "classification": left.classification,
                "block_signature": left.block_signature,
                "note": "A filter interpretation is a hypothesis unless independently fingerprinted.",
            },
            "backend": {
                "classification": right.classification,
                "status": right.status_code,
                "content_type": right.content_type,
            },
            "framework_parser": {
                "content_type": right.content_type,
                "body_length": right.body_length,
                "note": "Parser semantics require an explicit differential or behavior proof.",
            },
        },
        "status_change_is_not_proof": True,
    }


# ---------------------------------------------------------------------------
# Protection fingerprinting
# ---------------------------------------------------------------------------

_VENDOR_SIGNATURES: dict[str, dict[str, Any]] = {
    "Cloudflare": {
        "headers": {"cf-ray": "", "server": "cloudflare", "cf-mitigated": ""},
        "cookies": ("__cf_bm", "cf_clearance", "__cfduid"),
        "body": ("attention required! | cloudflare", "cf-error-details", "just a moment..."),
    },
    "AWS WAF / CloudFront": {
        "headers": {"x-amz-cf-id": "", "x-amzn-requestid": "", "x-amzn-waf-action": "", "server": "cloudfront"},
        "cookies": ("awsalb", "aws-waf-token"),
        "body": ("generated by cloudfront", "request blocked"),
    },
    "Akamai": {
        "headers": {"x-akamai-transformed": "", "server": "akamaighost", "x-akamai-session-info": ""},
        "cookies": ("ak_bmsc", "bm_sz"),
        "body": ("reference #", "akamai"),
    },
    "Imperva": {
        "headers": {"x-iinfo": ""},
        "cookies": ("incap_ses_", "visid_incap_"),
        "body": ("incapsula incident id", "incapsula"),
    },
    "ModSecurity": {
        "headers": {"server": "modsecurity", "x-modsecurity": "", "x-mod-security": ""},
        "cookies": (),
        "body": ("mod_security", "modsecurity", "owasp modsecurity core rule set",
                 "this error was generated by mod_security"),
    },
    "Fastly": {
        "headers": {"via": "fastly", "x-served-by": "", "x-cache": ""},
        "cookies": (),
        "body": ("fastly error", "unknown domain"),
    },
    "nginx rules": {
        "headers": {"server": "nginx"},
        "cookies": (),
        "body": ("nginx 403", "nginx error"),
    },
}


class ProtectionFingerprintEngine:
    """Multi-signal WAF/filter fingerprinting.

    A vendor is not high-confidence from one header name alone. Header,
    cookie/body, and blocked/challenge behaviour are scored independently.
    """

    def fingerprint(self, responses: Sequence[Mapping[str, Any]] | Mapping[str, Any]) -> dict[str, Any]:
        if isinstance(responses, Mapping):
            response_list = [responses]
        else:
            response_list = [item for item in responses if isinstance(item, Mapping)]
        feature_rows = [classify_response(item).to_dict() for item in response_list]
        blocked = [row for row in feature_rows if row["classification"] in {"blocked", "challenge"}]
        scores: dict[str, float] = defaultdict(float)
        signals: dict[str, list[dict[str, Any]]] = defaultdict(list)
        families: dict[str, set[str]] = defaultdict(set)

        for index, response in enumerate(response_list):
            headers = _header_values(response)
            body = _response_body(response).lower()
            cookies = headers.get("set-cookie", "").lower()
            status = _status_code(response)
            is_block = status in {403, 406, 413, 418, 429, 444, 451, 503} or bool(
                _block_signature(status, headers, body)[0])
            for vendor, spec in _VENDOR_SIGNATURES.items():
                for key, expected in spec.get("headers", {}).items():
                    if key not in headers or (expected and expected.lower() not in headers[key].lower()):
                        continue
                    weight = 0.32 if key not in {"server", "x-cache", "x-served-by"} else 0.18
                    scores[vendor] += weight
                    families[vendor].add("header")
                    signals[vendor].append({
                        "family": "header", "key": key,
                        "value": redact_headers({key: headers[key]})[key],
                        "response_index": index, "weight": weight,
                    })
                for cookie in spec.get("cookies", ()):
                    if cookie.lower() in cookies:
                        weight = 0.28
                        scores[vendor] += weight
                        families[vendor].add("cookie")
                        signals[vendor].append({
                            "family": "cookie", "marker": cookie,
                            "response_index": index, "weight": weight,
                        })
                for marker in spec.get("body", ()):
                    if marker.lower() in body:
                        weight = 0.34
                        scores[vendor] += weight
                        families[vendor].add("body")
                        signals[vendor].append({
                            "family": "body", "marker": marker,
                            "response_index": index, "weight": weight,
                        })
                if is_block and vendor == "nginx rules" and "nginx" in headers.get("server", "").lower():
                    scores[vendor] += 0.4
                    families[vendor].add("blocked_behavior")
                    signals[vendor].append({
                        "family": "blocked_behavior", "status": status,
                        "response_index": index, "weight": 0.16,
                    })

        fingerprints = []
        for vendor, score in sorted(scores.items(), key=lambda item: item[1], reverse=True):
            family_count = len(families[vendor])
            confidence = min(0.98, score)
            if family_count < 2:
                confidence = min(confidence, 0.48)
            elif family_count == 2:
                confidence = min(confidence, 0.82)
            fingerprints.append({
                "vendor": vendor,
                "confidence": round(confidence, 3),
                "signal_families": sorted(families[vendor]),
                "signals": signals[vendor],
                "evidence": [
                    safe_response_evidence(response_list[item["response_index"]], body_limit=800)
                    for item in signals[vendor][:3]
                ],
            })

        # Two independent signal families are enough to surface a vendor
        # hypothesis. A single header remains capped at .48, so this cannot
        # turn a lone vendor header into a confident fingerprint.
        high_confidence = [item for item in fingerprints if item["confidence"] >= 0.50]
        baseline_timing = _elapsed_seconds(response_list[0]) if response_list else 0.0
        timing_differential = [
            {
                "response_index": index,
                "baseline_sec": round(baseline_timing, 4),
                "observed_sec": round(_elapsed_seconds(item), 4),
                "delta_sec": round(
                    _elapsed_seconds(item) - baseline_timing, 4,
                ),
            }
            for index, item in enumerate(response_list[1:], start=1)
            if _elapsed_seconds(item) - baseline_timing >= 1.0
        ]
        if high_confidence:
            detected = [item["vendor"] for item in high_confidence]
            primary = high_confidence[0]
        elif blocked:
            explicit_filter_body = any(
                row.get("block_signature")
                and not str(row["block_signature"]).startswith("status:")
                for row in feature_rows
            )
            detected = ["custom application filters"] if fingerprints or explicit_filter_body else ["unknown filter"]
            primary = {
                "vendor": detected[0],
                "confidence": 0.42 if fingerprints else 0.28,
                "signal_families": ["blocked_behavior"],
                "signals": [{"family": "blocked_behavior", "count": len(blocked)}],
                "evidence": [
                    safe_response_evidence(response_list[index], body_limit=800)
                    for index, row in enumerate(feature_rows)
                    if row["classification"] in {"blocked", "challenge"}
                ][:2],
            }
        else:
            detected = ["unknown filter"] if response_list and any(
                row["classification"] in {"application_error", "unknown"} for row in feature_rows) else []
            primary = None

        return {
            "detected": detected,
            "primary": primary,
            "confidence": (primary or {}).get("confidence", 0.0),
            "fingerprints": fingerprints,
            "responses": feature_rows,
            "blocked": bool(blocked),
            "challenge": any(row["classification"] == "challenge" for row in feature_rows),
            "observed": bool(fingerprints or blocked),
            "method": "multi_signal_headers_body_cookie_status_timing",
            "timing_differential": timing_differential,
        }

    detect = fingerprint
    fingerprint_protection = fingerprint


# ---------------------------------------------------------------------------
# Mutation generation
# ---------------------------------------------------------------------------

MUTATION_CATEGORIES = (
    "url_encoding", "double_url_encoding", "mixed_encoding", "case_mutation",
    "whitespace_mutation", "separator_mutation", "delimiter_mutation",
    "unicode_representation", "html_entity_encoding", "json_escaping",
    "path_normalization", "duplicate_parameter", "parameter_pollution",
    "header_variation", "content_type_variation", "http_method_variation",
)


@dataclass(frozen=True)
class SQLPayload:
    """Semantic SQL probe separated from its wire representation."""

    semantic: str
    dialect: str = "generic"
    value: str = ""

    def render(self) -> str:
        if self.value:
            return self.value
        return render_sql_payload(self.semantic, self.dialect)


@dataclass
class MutationCandidate:
    category: str
    label: str
    value: str = ""
    semantic: str = ""
    dialect: str = ""
    method: Optional[str] = None
    headers: dict[str, str] = field(default_factory=dict)
    content_type: Optional[str] = None
    path: Optional[str] = None
    parameter: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)
    cost: int = 1
    risk: float = 0.1
    id: str = field(default_factory=lambda: f"mutation_{uuid.uuid4().hex[:10]}")

    def to_dict(self, redact: bool = True) -> dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category,
            "label": self.label,
            "value": redact_body(self.value, 1200) if redact else self.value,
            "semantic": self.semantic,
            "dialect": self.dialect,
            "method": self.method,
            "headers": redact_headers(self.headers) if redact else dict(self.headers),
            "content_type": self.content_type,
            "path": self.path,
            "parameter": self.parameter,
            "metadata": redact_json_value(self.metadata) if redact else dict(self.metadata),
            "cost": self.cost,
            "risk": self.risk,
        }


class PayloadMutationEngine:
    """Generate a small, ranked set of context-aware representations."""

    categories = MUTATION_CATEGORIES

    @staticmethod
    def _base_payload(payload: str | SQLPayload) -> tuple[str, str, str]:
        if isinstance(payload, SQLPayload):
            return payload.render(), payload.semantic, payload.dialect
        return str(payload or ""), "", ""

    @staticmethod
    def _normalise_waf(detected_waf: Any) -> set[str]:
        if isinstance(detected_waf, str):
            return {detected_waf.lower()}
        if isinstance(detected_waf, Mapping):
            values = detected_waf.get("detected", []) or []
        else:
            values = detected_waf or []
        return {str(value).lower() for value in values}

    def select_categories(
        self, vulnerability_class: str = "generic", input_context: Any = None,
        detected_waf: Any = None, response_behavior: Any = None,
        attempt_history: Optional[Sequence[Mapping[str, Any]]] = None,
    ) -> list[str]:
        vuln = str(vulnerability_class or "generic").lower()
        context = input_context if isinstance(input_context, Mapping) else {"value": input_context}
        context_text = json.dumps(context, default=str).lower()
        behavior = response_behavior if isinstance(response_behavior, Mapping) else {}
        behavior_text = json.dumps(behavior, default=str).lower()
        waf = self._normalise_waf(detected_waf)
        previous = {str(item.get("category")) for item in (attempt_history or [])}
        ranked: list[str] = []

        def add(*items: str) -> None:
            for item in items:
                if item in self.categories and item not in ranked and item not in previous:
                    ranked.append(item)

        is_path = any(token in vuln for token in ("path", "route", "redirect", "ssrf")) or any(
            token in context_text for token in ("path", "url", "route"))
        is_json = any(token in vuln for token in ("json", "api", "graphql")) or any(
            token in context_text for token in ("json", "application/json", "body"))
        is_xss = "xss" in vuln or "html" in context_text or "javascript" in context_text
        is_sql = any(token in vuln for token in ("sql", "sqli", "injection"))
        is_auth = any(token in vuln for token in ("auth", "authorization", "bola", "idor"))

        if is_path:
            add("path_normalization", "url_encoding", "double_url_encoding", "separator_mutation")
        if is_xss:
            if "attribute" in context_text:
                add("delimiter_mutation", "html_entity_encoding", "case_mutation")
            elif "javascript" in context_text or "dom" in context_text:
                add("unicode_representation", "json_escaping", "delimiter_mutation", "whitespace_mutation")
            elif "url" in context_text:
                add("url_encoding", "double_url_encoding", "unicode_representation")
            else:
                add("html_entity_encoding", "case_mutation", "whitespace_mutation", "delimiter_mutation")
        if "ssti" in vuln or "template" in vuln:
            add("delimiter_mutation", "whitespace_mutation", "unicode_representation",
                "json_escaping")
        if is_sql:
            add("url_encoding", "double_url_encoding", "mixed_encoding", "case_mutation",
                "whitespace_mutation", "separator_mutation", "delimiter_mutation")
        if is_json:
            add("json_escaping", "duplicate_parameter", "parameter_pollution", "content_type_variation")
        if context.get("accepted_content_types") or context.get("supported_content_types"):
            add("content_type_variation")
        if is_auth:
            add("http_method_variation", "path_normalization", "url_encoding", "parameter_pollution")
        waf_text = " ".join(waf)
        if "cloudflare" in waf_text or "imperva" in waf_text:
            add("double_url_encoding", "mixed_encoding", "whitespace_mutation")
        if "modsecurity" in waf_text:
            add("mixed_encoding", "case_mutation", "separator_mutation", "json_escaping")
        if "fastly" in waf_text or "akamai" in waf_text:
            add("path_normalization", "url_encoding", "header_variation")
        if "blocked" in behavior_text or "challenge" in behavior_text or "403" in behavior_text:
            add("mixed_encoding", "whitespace_mutation", "delimiter_mutation")
        if "duplicate" in context_text or "pollution" in context_text:
            add("duplicate_parameter", "parameter_pollution")
        if any(token in context_text for token in ("header", "routing", "access-control")):
            add("header_variation")
        if any(token in context_text for token in ("content-type", "media")):
            add("content_type_variation")
        if "method" in context_text:
            add("http_method_variation")
        if not ranked:
            # Routing/proxy headers are a separate trust-boundary hypothesis;
            # never spray them as a generic fallback against every payload.
            add("url_encoding", "case_mutation", "whitespace_mutation")
        return ranked

    @staticmethod
    def _encode_mixed(payload: str) -> str:
        output = []
        for index, char in enumerate(payload):
            if char in "<>\"' /\\=&%" and index % 2 == 0:
                output.append("%" + format(ord(char), "02X"))
            else:
                output.append(char)
        return "".join(output)

    @staticmethod
    def _alternate_case(payload: str) -> str:
        return "".join(char.upper() if index % 2 == 0 else char.lower()
                       for index, char in enumerate(payload))

    @staticmethod
    def _json_string(payload: str) -> str:
        encoded = json.dumps(payload, ensure_ascii=True)
        return encoded[1:-1] if len(encoded) >= 2 else encoded

    def generate_mutations(
        self, payload: str | SQLPayload, *, vulnerability_class: str = "generic",
        input_context: Any = None, detected_waf: Any = None,
        response_behavior: Any = None, attempt_history: Optional[Sequence[Mapping[str, Any]]] = None,
        max_mutations: int = 12,
    ) -> list[MutationCandidate]:
        raw, semantic, dialect = self._base_payload(payload)
        if not raw or max_mutations <= 0:
            return []
        context = input_context if isinstance(input_context, Mapping) else {}
        parameter = context.get("parameter") or context.get("param")
        categories = self.select_categories(
            vulnerability_class, input_context, detected_waf, response_behavior, attempt_history)
        generated: list[MutationCandidate] = []

        def add(category: str, label: str, value: str = "", **kwargs: Any) -> None:
            if category not in categories or len(generated) >= max_mutations:
                return
            candidate = MutationCandidate(
                category=category, label=label, value=value or raw,
                semantic=semantic, dialect=dialect, parameter=parameter, **kwargs)
            if any(item.category == candidate.category and item.value == candidate.value
                   and item.method == candidate.method and item.content_type == candidate.content_type
                   and item.headers == candidate.headers for item in generated):
                return
            generated.append(candidate)

        for category in categories:
            if len(generated) >= max_mutations:
                break
            if category == "url_encoding":
                add(category, "url_encoded", urllib.parse.quote(raw, safe=""))
            elif category == "double_url_encoding":
                add(category, "double_url_encoded",
                    urllib.parse.quote(urllib.parse.quote(raw, safe=""), safe=""))
            elif category == "mixed_encoding":
                add(category, "mixed_percent_encoding", self._encode_mixed(raw))
            elif category == "case_mutation":
                add(category, "alternating_case", self._alternate_case(raw))
            elif category == "whitespace_mutation":
                add(category, "tab_or_encoded_whitespace", raw.replace(" ", "%09"))
                if len(generated) < max_mutations:
                    add(category, "comment_whitespace", raw.replace(" ", "/**/"))
            elif category == "separator_mutation":
                value = raw.replace("/", "%2F").replace("\\", "%5C")
                if value == raw:
                    value = raw.replace(" ", "/**/")
                add(category, "encoded_or_comment_separator", value)
            elif category == "delimiter_mutation":
                if "ssti" in str(vulnerability_class).lower() or "template" in str(vulnerability_class).lower():
                    syntax_variants = [
                        chr(36) + "{7*77}", "<%= 7*77 %>", "#{7*77}", "*{7*77}",
                    ]
                    for syntax in syntax_variants:
                        if len(generated) >= max_mutations:
                            break
                        add(category, "alternate_template_syntax", syntax,
                            metadata={"harmless_expression": "7*77"})
                    continue
                if "xss" in str(vulnerability_class).lower() or "html" in json.dumps(context).lower():
                    value = raw.replace("<script", "<sCrIpT").replace("</script", "</sCrIpT")
                else:
                    value = raw.replace("'", "\"", 1) if "'" in raw else f"({raw})"
                add(category, "alternate_delimiter", value)
            elif category == "unicode_representation":
                value = (raw.replace("<", "\\u003c").replace(">", "\\u003e")
                         .replace("'", "\\u0027").replace("\"", "\\u0022"))
                add(category, "unicode_escape_representation", value)
            elif category == "html_entity_encoding":
                add(category, "html_entity_representation", html.escape(raw, quote=True))
            elif category == "json_escaping":
                add(category, "json_escaped_string", self._json_string(raw))
            elif category == "path_normalization":
                add(category, "duplicate_slash", raw,
                    metadata={"path_mutations": ["//", "/./", "/../", "trailing_slash"]})
            elif category in {"duplicate_parameter", "parameter_pollution"}:
                add(category, "duplicate_first_last", raw,
                    metadata={"values": [raw, raw], "order": ["first", "last"]})
            elif category == "header_variation":
                add(category, "same_host_routing_headers", raw, headers={
                    "X-Forwarded-Proto": "https",
                    "X-Original-URL": str(context.get("path") or "/"),
                    "X-Rewrite-URL": str(context.get("path") or "/"),
                }, risk=0.35)
            elif category == "content_type_variation":
                accepted = context.get("accepted_content_types") or context.get("supported_content_types") or []
                for content_type in accepted:
                    if len(generated) >= max_mutations:
                        break
                    add(category, f"proven_{str(content_type)}", raw,
                        content_type=str(content_type),
                        headers={"Content-Type": str(content_type)},
                        metadata={"requires_proven_parser": True}, risk=0.2)
            elif category == "http_method_variation":
                methods = context.get("safe_methods") or ["GET", "HEAD", "OPTIONS"]
                for selected in methods:
                    selected = str(selected).upper()
                    if selected not in {"GET", "HEAD", "OPTIONS", "POST"}:
                        continue
                    if len(generated) >= max_mutations:
                        break
                    add(category, f"safe_method_{selected.lower()}", raw,
                        method=selected, risk=0.15)
        return generated[:max_mutations]

    generate = generate_mutations
    mutate = generate_mutations
    generate_mutation = generate_mutations


# ---------------------------------------------------------------------------
# Strategy learning and bounded request budget
# ---------------------------------------------------------------------------

@dataclass
class StrategyScore:
    strategy: str
    success_count: int = 0
    attempt_count: int = 0
    request_count: int = 0
    confidence: float = 0.0
    cost: float = 1.0
    risk: float = 0.1
    prior: float = 0.2

    @property
    def success_rate(self) -> float:
        return self.prior if not self.attempt_count else self.success_count / self.attempt_count

    @property
    def expected_value(self) -> float:
        confidence = max(0.2, self.confidence or self.prior)
        exploration = 0.08 if self.attempt_count == 0 else 0.0
        return max(0.0, (self.success_rate * confidence + exploration) /
                   max(0.1, self.cost * (1.0 + self.risk)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategy": self.strategy,
            "success_rate": round(self.success_rate, 4),
            "success_count": self.success_count,
            "attempt_count": self.attempt_count,
            "request_count": self.request_count,
            "confidence": round(self.confidence, 4),
            "cost": self.cost,
            "risk": self.risk,
            "expected_value": round(self.expected_value, 4),
        }


class ResponseLearner:
    def __init__(self) -> None:
        self.strategies: dict[str, StrategyScore] = {}
        self.history: list[dict[str, Any]] = []

    def _score(self, strategy: str, candidate: Optional[MutationCandidate] = None) -> StrategyScore:
        if strategy not in self.strategies:
            self.strategies[strategy] = StrategyScore(
                strategy=strategy,
                cost=float(candidate.cost if candidate else 1),
                risk=float(candidate.risk if candidate else 0.1))
        return self.strategies[strategy]

    def record(self, strategy: str, response_class: str, *, verified: bool = False,
               confidence: float = 0.0, candidate: Optional[MutationCandidate] = None) -> StrategyScore:
        score = self._score(strategy, candidate)
        score.attempt_count += 1
        score.request_count += 1
        if verified:
            score.success_count += 1
        score.confidence = max(score.confidence, min(1.0, max(0.0, float(confidence or 0.0))))
        self.history.append({
            "strategy": strategy, "response_class": response_class,
            "verified": verified, "confidence": confidence})
        return score

    def rank(self, candidates: Sequence[MutationCandidate]) -> list[MutationCandidate]:
        return sorted(candidates, key=lambda item: self._score(item.category, item).expected_value, reverse=True)

    choose = rank

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategies": {key: value.to_dict() for key, value in self.strategies.items()},
            "history": list(self.history),
        }


@dataclass
class BypassBudget:
    total: int = 40
    phase_limits: dict[str, int] = field(default_factory=dict)
    consumed_by_phase: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    total_consumed: int = 0

    def __post_init__(self) -> None:
        self.total = max(0, int(self.total))
        if not self.phase_limits:
            raw = {
                "baseline_control": 0.125, "initial_strategies": 0.25,
                "adaptive_bypass": 0.5, "confirmation": 0.125}
            limits = {phase: int(self.total * ratio) for phase, ratio in raw.items()}
            remainder = self.total - sum(limits.values())
            for phase in ("baseline_control", "initial_strategies", "adaptive_bypass", "confirmation"):
                if remainder <= 0:
                    break
                limits[phase] += 1
                remainder -= 1
            # A payload-aware run needs two control observations (normal
            # baseline + unmutated semantic payload) before it can decide that
            # a filter blocked anything. Preserve that invariant for small
            # custom budgets by borrowing from later phases.
            if self.total >= 2 and limits["baseline_control"] < 2:
                needed = 2 - limits["baseline_control"]
                for phase in ("adaptive_bypass", "initial_strategies", "confirmation"):
                    take = min(needed, limits[phase])
                    limits[phase] -= take
                    limits["baseline_control"] += take
                    needed -= take
                    if needed <= 0:
                        break
            self.phase_limits = limits
        else:
            self.phase_limits = {str(key): max(0, int(value)) for key, value in self.phase_limits.items()}
            for phase in ("baseline_control", "initial_strategies", "adaptive_bypass", "confirmation"):
                self.phase_limits.setdefault(phase, 0)
        self.consumed_by_phase = defaultdict(int, self.consumed_by_phase)

    def claim(self, phase: str) -> bool:
        phase = str(phase)
        if self.total_consumed >= self.total:
            return False
        if self.consumed_by_phase[phase] >= self.phase_limits.get(phase, 0):
            return False
        self.consumed_by_phase[phase] += 1
        self.total_consumed += 1
        return True

    def remaining(self) -> int:
        return max(0, self.total - self.total_consumed)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "consumed": self.total_consumed,
            "remaining": self.remaining(),
            "phase_limits": dict(self.phase_limits),
            "consumed_by_phase": dict(self.consumed_by_phase),
        }


# ---------------------------------------------------------------------------
# Reference-aware hypothesis support (read-only)
# ---------------------------------------------------------------------------

REFERENCE_SOURCES = (
    "vendor_advisory", "CVE", "CVE records", "NVD", "CISA KEV", "GitHub Security Advisory",
    "Google Project Zero", "Google Bug Hunters", "security patch commit",
)


class ReferenceIntelService:
    """Select hypotheses from references; never an exploit runner.

    References are supplied as dictionaries or text. No URL is fetched by this
    class automatically, which keeps scope and provenance explicit and avoids
    copying arbitrary exploit code into a live request.
    """

    def __init__(self, references: Optional[Iterable[Mapping[str, Any] | str]] = None):
        self.references: list[dict[str, Any]] = []
        for reference in references or []:
            self.add_reference(reference)

    def add_reference(self, reference: Mapping[str, Any] | str,
                      *, source: str = "operator_supplied") -> dict[str, Any]:
        if isinstance(reference, Mapping):
            record = {str(key): value for key, value in reference.items()}
        else:
            record = {"text": str(reference)}
        record.setdefault("source", source)
        record["read_only"] = True
        record["automatic_exploit_execution"] = False
        self.references.append(record)
        return record

    ingest = add_reference

    def select_hypotheses(self, component: str = "", vulnerability_class: str = "",
                          *, limit: int = 10) -> list[dict[str, Any]]:
        if int(limit) <= 0:
            return []
        terms = {
            item for item in re.split(r"[^a-z0-9]+", f"{component} {vulnerability_class}".lower())
            if len(item) >= 3
        }
        selected = []
        for record in self.references:
            text = json.dumps(record, default=str).lower()
            matched = sorted(term for term in terms if term in text)
            if matched or not terms:
                selected.append({
                    "reference": redact_json_value(record), "matched_terms": matched,
                    "known_affected_component": record.get("known_affected_component")
                    or record.get("affected_component") or record.get("component"),
                    "patched_behavior": record.get("patched_behavior"),
                    "historical_bypass_pattern": record.get("historical_bypass_pattern"),
                    "known_parser_inconsistency": record.get("known_parser_inconsistency")
                    or record.get("parser_inconsistency"),
                    "relevant_vulnerability_class": record.get("vulnerability_class")
                    or record.get("class"),
                    "hypothesis_only": True,
                    "proof_required": "live deterministic behaviour on the authorized target",
                })
            if len(selected) >= max(0, limit):
                break
        return selected

    hypotheses = select_hypotheses

    def ingest_official_metadata(self, metadata: Mapping[str, Any]) -> int:
        """Ingest already-fetched advisory metadata as hypothesis records."""
        added = 0
        if not isinstance(metadata, Mapping):
            return added
        for key in ("records",):
            for record in metadata.get(key, []) or []:
                if isinstance(record, Mapping):
                    self.add_reference(record, source=str(record.get("source") or metadata.get("source") or "official_reference"))
                    added += 1
        for key in ("nvd", "cisa_kev"):
            nested = metadata.get(key)
            if isinstance(nested, Mapping):
                added += self.ingest_official_metadata(nested)
        return added

    def fetch_official_metadata(self, component: str, vulnerability_class: str = "",
                                *, client: Any = None, limit: int = 10) -> Dict[str, Any]:
        """Explicitly fetch NVD/CISA metadata; never runs exploit code.

        A caller running inside a scan should pass a ReferenceIntelClient whose
        HTTPVerifier uses that scan's shared TrafficController and reference
        ScopeManager. The default client is intended for an operator-invoked
        reference lookup, not implicit per-target spraying.
        """
        if client is None:
            from redteam_agent.core.reference_clients import ReferenceIntelClient
            client = ReferenceIntelClient()
        result = client.enrich(component, vulnerability_class, limit=limit)
        self.ingest_official_metadata(result)
        return result

    @staticmethod
    def analyze_patch_diff(diff: str, *, component: str = "") -> dict[str, Any]:
        """Extract read-only clues from a supplied patch/commit diff."""
        text = str(diff or "")
        lower = text.lower()
        patterns = {
            "changed_validation": ("validate", "validation", "allowlist", "schema"),
            "changed_route": ("route", "endpoint", "/api/", "path("),
            "changed_parser": ("parse", "parser", "json", "query", "duplicate", "normalize"),
            "added_authorization_check": ("authorize", "authorization", "permission", "role", "acl", "access check"),
            "added_sanitization": ("sanitize", "escape", "encode", "outputencoding", "canonical"),
        }
        signals = []
        for name, markers in patterns.items():
            matched = [marker for marker in markers if marker in lower]
            if matched:
                signals.append({"signal": name, "markers": matched})
        changed_lines = [
            line.strip() for line in text.splitlines()
            if line.startswith(("+", "-")) and not line.startswith(("+++", "---"))
        ]
        return {
            "component": component,
            "read_only": True,
            "signals": signals,
            "changed_line_count": len(changed_lines),
            "changed_lines_preview": [redact_http_text(line, 500) for line in changed_lines[:20]],
            "hypothesis": [item["signal"] for item in signals],
            "proof_required": "A patch clue is not proof; reproduce the relevant behavior against the authorized target.",
            "automatic_exploit_execution": False,
        }

    patch_diff_intelligence = analyze_patch_diff


# ---------------------------------------------------------------------------
# Authorization bypass engine
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Identity:
    name: str
    headers: dict[str, str] = field(default_factory=dict)
    role: str = ""
    markers: tuple[str, ...] = ()

    @classmethod
    def from_value(cls, value: Any, fallback_name: str = "identity") -> "Identity":
        if isinstance(value, Identity):
            return value
        if isinstance(value, Mapping):
            name = str(value.get("name") or value.get("id") or fallback_name)
            headers = {str(key): str(item) for key, item in (value.get("headers") or {}).items()}
            role = str(value.get("role") or "")
            markers = tuple(str(item) for item in (value.get("markers") or value.get("owner_markers") or []))
            return cls(name=name, headers=headers, role=role, markers=markers)
        return cls(name=fallback_name, headers={})

    def public(self) -> dict[str, Any]:
        return {
            "name": self.name, "role": self.role,
            "headers": redact_headers(self.headers), "markers": list(self.markers),
        }


def _contains_marker(body: str, marker: Optional[str | Sequence[str]]) -> bool:
    if not marker:
        return False
    markers = [marker] if isinstance(marker, str) else list(marker)
    return any(str(item) and str(item) in body for item in markers)


class AuthorizationBypassEngine:
    """Compare operator-provided identities without credential brute force."""

    SAFE_METHODS = ("GET", "HEAD", "OPTIONS")
    STRATEGIES = (
        "anonymous_vs_authenticated", "user_A_vs_user_B", "role_A_vs_role_B",
        "method_differences", "alternate_endpoint_form", "path_normalization",
        "api_version_difference", "field_level_authorization",
    )

    def __init__(self, verifier: Optional[HTTPVerifier] = None, request_budget: int = 20):
        self.verifier = verifier or HTTPVerifier(module="authorization_bypass")
        self.request_budget = max(0, int(request_budget))
        self.requests_used = 0

    def _send(self, url: str, *, identity: Optional[Identity] = None,
              method: str = "GET", headers: Optional[Mapping[str, str]] = None,
              body: Optional[str] = None) -> dict[str, Any]:
        selected_method = str(method or "GET").upper()
        if selected_method in DESTRUCTIVE_METHODS:
            return {
                "status_code": 0, "success": False,
                "error": f"{selected_method} not sent: state-changing method is not allowed in authorization comparison",
                "failure": {"type": "destructive_method_skipped", "verified": False},
            }
        if self.requests_used >= self.request_budget:
            return {
                "status_code": 0, "success": False, "error": "authorization sub-budget exhausted",
                "failure": {"type": "sub_budget", "verified": False},
            }
        self.requests_used += 1
        merged = dict(identity.headers if identity else {})
        merged.update({str(key): str(value) for key, value in (headers or {}).items()})
        try:
            return self.verifier.send_http_request(
                url, method=method, headers=merged or None, body=body, priority="verification")
        except TypeError:
            return self.verifier.send_http_request(
                url, method=method, headers=merged or None, body=body)

    @staticmethod
    def _outcome(identity: Identity, response: Mapping[str, Any]) -> dict[str, Any]:
        features = classify_response(response)
        return {
            "identity": identity.public(), "response": safe_response_evidence(response),
            "features": features.to_dict(),
        }

    def compare_identities(
        self, url: str, owner_identity: Any, other_identity: Any, *,
        owner_marker: Optional[str] = None, other_marker: Optional[str] = None,
        method: str = "GET", body: Optional[str] = None,
        proof_callback: Optional[Callable[..., Any]] = None,
    ) -> dict[str, Any]:
        owner = Identity.from_value(owner_identity, "owner")
        other = Identity.from_value(other_identity, "other")
        owner_response = self._send(url, identity=owner, method=method, body=body)
        other_response = self._send(url, identity=other, method=method, body=body)
        owner_body = _response_body(owner_response)
        other_body = _response_body(other_response)
        owner_features = classify_response(owner_response)
        other_features = classify_response(other_response, baseline=owner_response)
        owner_accessible = owner_features.classification in {"allowed", "backend_response"}
        other_accessible = other_features.classification in {"allowed", "backend_response"}
        owner_marker_observed = _contains_marker(owner_body, owner_marker or owner.markers)
        crossed = _contains_marker(other_body, owner_marker or owner.markers)
        other_marker_observed = _contains_marker(other_body, other_marker or other.markers)
        proof_detail: Any = None
        if proof_callback:
            try:
                proof_detail = proof_callback(owner_response, other_response, owner, other)
            except TypeError:
                proof_detail = proof_callback(owner_response, other_response)
        callback_passed = bool(
            proof_detail.get("verified") if isinstance(proof_detail, Mapping) else proof_detail)
        verified = bool(
            owner_accessible and other_accessible and owner_marker_observed and crossed
            and (not other_marker_observed or crossed)
        ) or callback_passed
        checks = [
            {"name": "owner_identity_accessible", "passed": owner_accessible},
            {"name": "other_identity_response_observed", "passed": other_accessible},
            {"name": "owner_marker_observed_in_owner_response", "passed": owner_marker_observed},
            {"name": "owner_marker_crossed_identity_boundary", "passed": crossed},
            {"name": "explicit_proof_callback", "passed": callback_passed},
        ]
        return {
            "strategy": "user_A_vs_user_B",
            "verified": verified,
            "status": FindingStatus.VERIFIED.value if verified else FindingStatus.SUSPECTED.value,
            "confidence": 0.97 if verified else (0.55 if crossed else 0.2),
            "url": url, "owner": owner.public(), "other": other.public(),
            "owner_response": safe_response_evidence(owner_response),
            "other_response": safe_response_evidence(other_response),
            "difference": response_differential(owner_response, other_response),
            "checks": checks, "proof": proof_detail,
            "missing_evidence": [] if verified else [
                "Owner-controlled marker or explicit authorization proof must cross into the other identity response"
            ],
        }

    test_cross_identity = compare_identities
    verify = compare_identities

    def compare_roles(self, url: str, role_a: Any, role_b: Any, *,
                      protected_marker: Optional[str] = None, method: str = "GET",
                      body: Optional[str] = None) -> dict[str, Any]:
        result = self.compare_identities(
            url, role_a, role_b, owner_marker=protected_marker, method=method, body=body)
        result["strategy"] = "role_A_vs_role_B"
        return result

    test_role_differences = compare_roles

    def compare_anonymous_authenticated(self, url: str, authenticated: Any, *,
                                        protected_marker: Optional[str] = None,
                                        method: str = "GET", body: Optional[str] = None) -> dict[str, Any]:
        result = self.compare_identities(
            url, authenticated, Identity("anonymous"), owner_marker=protected_marker,
            method=method, body=body)
        result["strategy"] = "anonymous_vs_authenticated"
        return result

    def test_method_differences(
        self, url: str, identity: Any, *, protected_marker: Optional[str] = None,
        methods: Optional[Iterable[str]] = None, body: Optional[str] = None,
    ) -> dict[str, Any]:
        actor = Identity.from_value(identity)
        requested = [str(item).upper() for item in (methods or self.SAFE_METHODS)]
        safe = [item for item in requested if item in self.SAFE_METHODS]
        observations = []
        for method in safe:
            response = self._send(
                url, identity=actor, method=method, body=body if method != "HEAD" else None)
            features = classify_response(response)
            marker = _contains_marker(_response_body(response), protected_marker or actor.markers)
            observations.append({
                "method": method, "response": safe_response_evidence(response),
                "features": features.to_dict(), "protected_marker": marker,
            })
        accessible = [
            item for item in observations
            if item["features"]["classification"] in {"allowed", "backend_response"}
            and item["protected_marker"]
        ]
        baseline_denied = any(item["features"]["status_code"] in {401, 403} for item in observations)
        verified = bool(accessible and baseline_denied)
        return {
            "strategy": "method_differences", "verified": verified,
            "status": FindingStatus.VERIFIED.value if verified else FindingStatus.SUSPECTED.value,
            "confidence": .94 if verified else .25, "url": url,
            "observations": observations,
            "checks": [
                {"name": "protected_method_denied", "passed": baseline_denied},
                {"name": "alternate_safe_method_returns_protected_content", "passed": bool(accessible)},
            ],
            "missing_evidence": [] if verified else [
                "A denied method and a safe alternate method must be compared with a protected marker"
            ],
        }

    def test_alternate_endpoint_forms(
        self, urls: Sequence[str], identity: Any, *,
        protected_marker: Optional[str] = None,
    ) -> dict[str, Any]:
        actor = Identity.from_value(identity)
        observations = []
        for url in list(urls)[:8]:
            response = self._send(url, identity=actor)
            features = classify_response(response)
            marker = _contains_marker(_response_body(response), protected_marker or actor.markers)
            observations.append({
                "url": url, "response": safe_response_evidence(response),
                "features": features.to_dict(), "protected_marker": marker,
            })
        denied = [item for item in observations if item["features"]["status_code"] in {401, 403}]
        allowed = [
            item for item in observations
            if item["features"]["classification"] in {"allowed", "backend_response"}
            and item["protected_marker"]
        ]
        verified = bool(denied and allowed)
        return {
            "strategy": "alternate_endpoint_form", "verified": verified,
            "status": FindingStatus.VERIFIED.value if verified else FindingStatus.SUSPECTED.value,
            "confidence": .93 if verified else .2, "observations": observations,
            "checks": [
                {"name": "protected_form_denied", "passed": bool(denied)},
                {"name": "alternate_form_allows_protected_content", "passed": bool(allowed)},
            ],
            "missing_evidence": [] if verified else [
                "Explicit alternate endpoint must return protected owner-controlled content"
            ],
        }

    @staticmethod
    def _path_variants(url: str) -> list[str]:
        parsed = urllib.parse.urlsplit(url)
        path = parsed.path or "/"
        variants = []
        clean_path = "/" + path.lstrip("/")
        duplicate = clean_path.replace("/", "//", 1) if clean_path != "/" else "//"
        dot_segment = (
            clean_path.rstrip("/") + "/./"
            if clean_path != "/" else "/./"
        )
        for label, value in (
            ("duplicate_slash", duplicate),
            ("dot_segment", dot_segment),
            ("encoded_separator", path.replace("/", "%2F")),
            ("trailing_separator", path if path.endswith("/") else path + "/"),
        ):
            candidate = urllib.parse.urlunsplit(parsed._replace(path=value))
            if candidate != url and candidate not in variants:
                variants.append(candidate)
        return variants

    def test_path_normalization(
        self, url: str, identity: Any, *, protected_marker: Optional[str] = None,
        variants: Optional[Sequence[str]] = None,
    ) -> dict[str, Any]:
        actor = Identity.from_value(identity)
        urls = list(variants or self._path_variants(url))[:6]
        base = self._send(url, identity=actor)
        base_features = classify_response(base)
        observations = []
        for candidate_url in urls:
            response = self._send(candidate_url, identity=actor)
            features = classify_response(response, baseline=base)
            marker = _contains_marker(_response_body(response), protected_marker or actor.markers)
            observations.append({
                "url": candidate_url, "response": safe_response_evidence(response),
                "features": features.to_dict(), "protected_marker": marker,
                "difference": response_differential(base, response),
            })
        base_denied = base_features.status_code in {401, 403}
        allowed = [
            item for item in observations
            if item["features"]["classification"] in {"allowed", "backend_response"}
            and item["protected_marker"]
        ]
        verified = bool(base_denied and allowed)
        return {
            "strategy": "path_normalization", "verified": verified,
            "status": FindingStatus.VERIFIED.value if verified else FindingStatus.SUSPECTED.value,
            "confidence": .94 if verified else .2,
            "base": safe_response_evidence(base), "observations": observations,
            "checks": [
                {"name": "base_path_denied", "passed": base_denied},
                {"name": "normalized_path_returns_protected_content", "passed": bool(allowed)},
            ],
            "missing_evidence": [] if verified else [
                "A normalized alternate path must return protected owner-controlled content"
            ],
        }

    def test_api_version_bypass(
        self, urls: Sequence[str], identity: Any, *,
        protected_marker: Optional[str] = None,
    ) -> dict[str, Any]:
        """Compare explicitly discovered API versions/routes only."""
        result = self.test_alternate_endpoint_forms(
            urls, identity, protected_marker=protected_marker)
        result["strategy"] = "api_version_difference"
        result["api_versions"] = list(urls)[:8]
        return result

    @staticmethod
    def _graphql_request(
        verifier: Any, url: str, identity: Identity, query: str,
        variables: Optional[dict] = None,
    ) -> dict[str, Any]:
        graphql_body = json.dumps({
            "query": query, "variables": variables or {},
        }, separators=(",", ":"))
        headers = {
            **identity.headers, "Content-Type": "application/json",
            "Accept": "application/json",
        }
        return verifier.send_http_request(
            url, method="POST", headers=headers, body=graphql_body,
            priority="verification")

    def test_graphql_authorization(
        self, url: str, identity_a: Any, identity_b: Any, *, query: str,
        owner_marker: Optional[str] = None, alias_query: Optional[str] = None,
        fragment_query: Optional[str] = None,
        field_queries: Optional[Sequence[str]] = None,
        alternate_resolver_queries: Optional[Sequence[str]] = None,
        safe_mutation: Optional[str] = None, allow_safe_mutation: bool = False,
    ) -> dict[str, Any]:
        """Check aliases, field resolvers, and explicit safe operations.

        Query amplification and destructive mutation probing are intentionally
        absent. A mutation is sent only when the caller supplies a known safe
        mutation and opts in.
        """
        actor_a = Identity.from_value(identity_a, "user_a")
        actor_b = Identity.from_value(identity_b, "user_b")
        operations: list[dict[str, Any]] = []

        def add_operation(label: str, operation: str, actor: Identity) -> None:
            response = self._send_graphql(url, actor, operation)
            operations.append({
                "label": label, "identity": actor.public(),
                "query": redact_body(operation, 4000),
                "response": safe_response_evidence(response),
                "features": classify_response(response).to_dict(),
                "owner_marker": _contains_marker(_response_body(response), owner_marker),
            })

        add_operation("query_identity_a", query, actor_a)
        add_operation("query_identity_b", query, actor_b)
        if alias_query:
            add_operation("alias_identity_b", alias_query, actor_b)
        if fragment_query:
            add_operation("fragment_identity_b", fragment_query, actor_b)
        for index, operation in enumerate(list(field_queries or [])[:8]):
            add_operation(f"field_{index}_identity_b", operation, actor_b)
        for index, operation in enumerate(list(alternate_resolver_queries or [])[:8]):
            add_operation(f"alternate_resolver_{index}_identity_b", operation, actor_b)
        skipped_mutation = bool(safe_mutation and not allow_safe_mutation)
        if safe_mutation and allow_safe_mutation:
            add_operation("explicit_safe_mutation_identity_b", safe_mutation, actor_b)

        owner_a = next(
            (item for item in operations if item["label"] == "query_identity_a"), None)
        user_b = [item for item in operations if item["identity"]["name"] == actor_b.name]
        leaked = [
            item for item in user_b if item["owner_marker"]
            and item["features"]["classification"] in {"allowed", "backend_response"}
        ]
        owner_accessible = bool(
            owner_a
            and owner_a["features"]["classification"] in {"allowed", "backend_response"}
            and owner_a["owner_marker"]
        )
        verified = bool(owner_accessible and leaked)
        return {
            "strategy": "graphql_field_level_authorization", "verified": verified,
            "status": FindingStatus.VERIFIED.value if verified else FindingStatus.SUSPECTED.value,
            "confidence": .96 if verified else .25, "operations": operations,
            "checks": [
                {"name": "owner_query_returns_owner_marker", "passed": owner_accessible},
                {"name": "other_identity_reads_owner_marker", "passed": bool(leaked)},
                {"name": "safe_mutation_not_implicitly_executed",
                 "passed": not (safe_mutation and allow_safe_mutation is False)},
            ],
            "skipped": ["destructive_or_unapproved_mutation"] if skipped_mutation else [],
            "missing_evidence": [] if verified else [
                "Owner-controlled GraphQL field data must be readable by the other identity"
            ],
        }

    test_field_level_authorization = test_graphql_authorization

    def _send_graphql(self, url: str, identity: Identity, query: str) -> dict[str, Any]:
        if self.requests_used >= self.request_budget:
            return {"status_code": 0, "error": "authorization sub-budget exhausted", "success": False}
        self.requests_used += 1
        try:
            return self._graphql_request(self.verifier, url, identity, query)
        except TypeError:
            body = json.dumps({"query": query, "variables": {}}, separators=(",", ":"))
            return self.verifier.send_http_request(
                url, method="POST",
                headers={**identity.headers, "Content-Type": "application/json"},
                body=body)

    def test(
        self, url: str, *, identities: Sequence[Any],
        owner_marker: Optional[str] = None, other_marker: Optional[str] = None,
        method: str = "GET", body: Optional[str] = None,
        api_versions: Optional[Sequence[str]] = None,
        alternate_forms: Optional[Sequence[str]] = None,
        path_normalization: bool = False,
    ) -> dict[str, Any]:
        normalized = [
            Identity.from_value(item, f"identity_{index}")
            for index, item in enumerate(identities)
        ]
        primitives = []
        if len(normalized) >= 2:
            primitives.append(self.compare_identities(
                url, normalized[0], normalized[1],
                owner_marker=owner_marker, other_marker=other_marker,
                method=method, body=body))
        if api_versions:
            primitives.append(self.test_api_version_bypass(
                api_versions, normalized[0], protected_marker=owner_marker))
        if alternate_forms:
            primitives.append(self.test_alternate_endpoint_forms(
                alternate_forms, normalized[0], protected_marker=owner_marker))
        if path_normalization and normalized:
            primitives.append(self.test_path_normalization(
                url, normalized[0], protected_marker=owner_marker))
        for primitive in primitives:
            primitive.setdefault("id", f"auth_primitive_{uuid.uuid4().hex[:10]}")
            primitive.setdefault(
                "type", str(primitive.get("strategy") or "authorization_differential"))
            primitive.setdefault("depth", 1)
        return {
            "requests_used": self.requests_used,
            "request_budget": self.request_budget,
            "primitives": primitives,
            "verified_primitives": [item for item in primitives if item.get("verified")],
            "findings": self.findings_from_primitives(primitives, target=url),
        }

    @staticmethod
    def findings_from_primitives(
        primitives: Sequence[Mapping[str, Any]], *, target: str
    ) -> list[dict[str, Any]]:
        findings = []
        for primitive in primitives:
            if not primitive.get("verified") and not primitive.get("observations") and not primitive.get("owner_response") and not primitive.get("operations"):
                continue
            verified = bool(primitive.get("verified"))
            findings.append(normalized_finding(
                finding_type=(
                    "Authorization Bypass / Cross-Identity Object Access"
                    if verified else "Authorization Differential Candidate"
                ),
                target=target, endpoint=target,
                status=FindingStatus.VERIFIED if verified else FindingStatus.SUSPECTED,
                confidence=primitive.get("confidence", .2),
                source_module="authorization_bypass_engine",
                source_tool="AuthorizationBypassEngine",
                evidence=[dict(primitive)],
                verification_checks=primitive.get("checks", []),
                missing_evidence=primitive.get("missing_evidence", []),
                false_positive_reasons=[] if verified else [
                    "Status/access differentials without owner-controlled data are not proof"
                ],
                severity="High" if verified else "Info", param="authorization",
                reproduction_curl=(
                    "Use the recorded redacted identity-specific requests within the authorized engagement."
                ),
                verification_note=(
                    "Owner-controlled content crossed into another identity response."
                    if verified else
                    "Authorization behavior differed, but cross-identity protected content was not proven."
                ),
                observed_impact=(
                    "A protected owner-controlled marker was readable in another identity context."
                    if verified else
                    "An authorization differential was observed without a complete impact proof."
                ),
                potential_impact=(
                    "Cross-user or cross-role data access may be possible if the differential is reproduced with real records."
                ),
                vrt_category="Broken Access Control > Authorization Bypass",
            ))
        return findings


# ---------------------------------------------------------------------------
# Bypass engine
# ---------------------------------------------------------------------------

def _invoke_proof_callback(
    callback: Callable[..., Any], mutated: Mapping[str, Any],
    candidate: MutationCandidate, difference: Mapping[str, Any],
) -> Any:
    for args in (
        (mutated, candidate, difference),
        (mutated, candidate),
        (mutated,),
        (),
    ):
        try:
            return callback(*args)
        except TypeError:
            continue
    return False


class BypassEngine:
    """Adaptive bypass pipeline with response learning and bounded evidence."""

    def __init__(
        self, verifier: Optional[HTTPVerifier] = None, exploit_mode: str = "SAFE",
        request_budget: int = 40, max_depth: int = 3,
        mutation_engine: Optional[PayloadMutationEngine] = None,
        fingerprint_engine: Optional[ProtectionFingerprintEngine] = None,
        reference_intel: Optional[ReferenceIntelService] = None,
    ):
        self.verifier = verifier or HTTPVerifier(module="bypass_engine")
        self.exploit_mode = str(exploit_mode or "SAFE").upper()
        # SAFE, AGGRESSIVE, and OFFENSIVE all use the same scope/traffic
        # controller. OFFENSIVE additionally tells the orchestrator that it
        # may execute target-specific hypotheses built from discovered
        # request shapes. It never authorizes blind spraying or destructive
        # state changes by itself.
        self.enabled = self.exploit_mode in {"SAFE", "AGGRESSIVE", "OFFENSIVE"}
        self.default_request_budget = max(0, int(request_budget))
        self.max_depth = min(3, max(0, int(max_depth)))
        self.mutations = mutation_engine or PayloadMutationEngine()
        self.fingerprinter = fingerprint_engine or ProtectionFingerprintEngine()
        self.reference_intel = reference_intel or ReferenceIntelService()
        self.last_run: Optional[dict[str, Any]] = None

    # ----- request construction -----------------------------------------

    @staticmethod
    def _url_with_duplicate_param(
        url: str, parameter: str, values: Sequence[str]
    ) -> str:
        parsed = urllib.parse.urlsplit(url)
        pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        pairs = [(key, value) for key, value in pairs if key != parameter]
        pairs.extend((parameter, value) for value in values)
        return urllib.parse.urlunsplit(
            parsed._replace(
                query=urllib.parse.urlencode(pairs, doseq=True), fragment=""
            )
        )

    @staticmethod
    def _json_body_with_value(
        body: Optional[str], field: str, value: str
    ) -> Optional[str]:
        if body is None:
            return None
        try:
            parsed = json.loads(body)
            if isinstance(parsed, Mapping):
                updated = dict(parsed)
                updated[field] = value
                return json.dumps(updated, ensure_ascii=False, separators=(",", ":"))
        except (TypeError, ValueError, json.JSONDecodeError):
            pass
        return str(body).replace(str(body), value, 1) if body else value

    @staticmethod
    def _path_variant_url(url: str, label: str) -> str:
        parsed = urllib.parse.urlsplit(url)
        path = parsed.path or "/"
        if label in {"duplicate_slash", "path_normalization"}:
            normalized = "/" + path.lstrip("/")
            value = normalized.replace("/", "//", 1) if "/" in normalized[1:] else normalized + "/"
        elif label == "dot_segment":
            value = "/" + "/".join(part for part in path.split("/") if part != ".")
        elif label == "encoded_separator":
            value = path.replace("/", "%2F")
        elif label == "trailing_separator":
            value = path if path.endswith("/") else path + "/"
        elif label == "case_variation":
            value = path.swapcase()
        else:
            value = path
        return urllib.parse.urlunsplit(parsed._replace(path=value))

    def _candidate_request(
        self, base_url: str, candidate: MutationCandidate, *,
        parameter: Optional[str], body: Optional[str],
        headers: Mapping[str, str], method: str, context: Mapping[str, Any],
    ) -> Optional[dict[str, Any]]:
        url = candidate.path or base_url
        selected_method = (candidate.method or method).upper()
        selected_headers = dict(headers)
        selected_headers.update(candidate.headers)
        selected_body = body
        location = context.get("input_location", "query")

        if candidate.category in {"duplicate_parameter", "parameter_pollution"}:
            param = candidate.parameter or parameter
            values = candidate.metadata.get("values") if isinstance(candidate.metadata, Mapping) else None
            if param and values:
                url = self._url_with_duplicate_param(
                    url, param, [str(item) for item in values])
            elif param:
                url = self._url_with_duplicate_param(
                    url, param, [str(candidate.value), str(candidate.value)])
        elif candidate.category == "path_normalization":
            url = self._path_variant_url(url, candidate.label)
        elif candidate.category == "header_variation" and context.get("header_only"):
            pass
        elif parameter and candidate.value and location in {"query", "url", "parameter"}:
            url = HTTPVerifier._url_with_param(url, parameter, candidate.value)
        elif candidate.value and location in {"json", "json_body", "body"}:
            field = str(context.get("json_field") or parameter or "q")
            selected_body = self._json_body_with_value(body, field, candidate.value)
        elif candidate.value and context.get("replace_body_payload"):
            selected_body = str(body or "").replace(
                str(context.get("replace_body_payload")), candidate.value, 1)

        if candidate.content_type:
            selected_headers["Content-Type"] = candidate.content_type
            if candidate.content_type == "application/x-www-form-urlencoded" and parameter:
                selected_body = urllib.parse.urlencode({parameter: candidate.value})
            elif candidate.content_type == "text/plain":
                selected_body = candidate.value
            elif candidate.content_type == "multipart/form-data":
                boundary = "----AGYBoundary" + candidate.id[-8:]
                selected_headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
                field = parameter or str(context.get("json_field") or "q")
                selected_body = (
                    f"--{boundary}\r\n"
                    f"Content-Disposition: form-data; name=\"{field}\"\r\n\r\n"
                    f"{candidate.value}\r\n--{boundary}--\r\n"
                )

        if selected_method == "HEAD":
            selected_body = None
        return {
            "url": url, "method": selected_method,
            "headers": selected_headers, "body": selected_body,
        }

    def _send(self, request: Mapping[str, Any]) -> dict[str, Any]:
        selected_method = str(request.get("method", "GET")).upper()
        if selected_method in DESTRUCTIVE_METHODS:
            return {
                "status_code": 0, "success": False,
                "error": f"{selected_method} not sent: state-changing method is not allowed in bypass verification",
                "failure": {"type": "destructive_method_skipped", "verified": False},
            }
        try:
            return self.verifier.send_http_request(
                request["url"], method=request.get("method", "GET"),
                headers=request.get("headers"), body=request.get("body"),
                priority="verification")
        except TypeError:
            return self.verifier.send_http_request(
                request["url"], method=request.get("method", "GET"),
                headers=request.get("headers"), body=request.get("body"))

    # ----- verification --------------------------------------------------

    def measure_impact(
        self, original: Mapping[str, Any], mutated: Mapping[str, Any],
        difference: Mapping[str, Any], *, context: Optional[Mapping[str, Any]] = None,
        proof: Any = None,
    ) -> dict[str, Any]:
        context = context or {}
        explicit_markers = context.get("impact_markers") or []
        body = _response_body(mutated)
        observed_markers = [
            str(marker) for marker in explicit_markers if str(marker) in body
        ]
        proof_verified = bool(
            proof.get("verified") if isinstance(proof, Mapping) else proof
        )
        return {
            "verified": proof_verified,
            "proof_type": (
                proof.get("type") if isinstance(proof, Mapping) else None
            ) or context.get("proof_type"),
            "observed_markers": observed_markers,
            "body_length_delta": difference.get("body_length_delta"),
            "content_type": _header_values(mutated).get("content-type", ""),
            "capabilities": list(context.get("verified_capabilities") or [])
            if proof_verified else [],
            "impact_claim_bounded": True,
            "note": "Only explicitly supplied or deterministic behaviour proof is counted as impact.",
        }

    def verify_bypass(
        self, original: Mapping[str, Any], mutated: Mapping[str, Any], *,
        vulnerability_class: str = "generic",
        candidate: Optional[MutationCandidate] = None,
        context: Optional[Mapping[str, Any]] = None,
        difference: Optional[Mapping[str, Any]] = None,
    ) -> dict[str, Any]:
        """Verify relevant behaviour; a successful HTTP status is insufficient."""
        context = context or {}
        candidate = candidate or MutationCandidate("generic", "unknown", "")
        difference = difference or response_differential(original, mutated)
        original_features = classify_response(original)
        mutated_features = classify_response(mutated, baseline=original)
        class_name = str(vulnerability_class or "generic").lower()
        filter_status = original_features.status_code in {403, 406, 413, 418, 429, 444, 451, 503}
        base_checks = [
            {
                "name": "original_filter_or_protection_observed",
                "passed": (
                    original_features.classification in {"blocked", "challenge"}
                    and filter_status
                ),
            },
            {
                "name": "mutated_response_not_blocked_or_challenge",
                "passed": mutated_features.classification in {"allowed", "backend_response"},
            },
            {
                "name": "mutated_response_not_application_error",
                "passed": mutated_features.classification != "application_error",
            },
        ]
        if not all(item["passed"] for item in base_checks):
            return {
                "verified": False, "confidence": .08, "checks": base_checks,
                "proof": None,
                "impact": self.measure_impact(
                    original, mutated, difference, context=context),
                "verification_note": (
                    "The original block or a clean backend response was not established; "
                    "status change is not proof."
                ),
            }

        proof: Any = None
        proof_type = None
        callback = context.get("behavior_verifier") or context.get("proof_callback")
        if callable(callback):
            proof = _invoke_proof_callback(callback, mutated, candidate, difference)
            proof_type = "operator_behavior_callback"
        elif "xss" in class_name:
            execution = context.get("browser_execution") or context.get("browser_execution_proof")
            canary = str(context.get("canary") or "AGY_XSS_BYPASS_CANARY")
            if isinstance(execution, Mapping):
                passed = bool(
                    execution.get("executed") and execution.get("canary") == canary
                )
                proof = {
                    "verified": passed, "type": "browser_execution_canary",
                    "canary": canary, "execution_context": execution.get("context"),
                }
            else:
                proof = False
            proof_type = "browser_execution_canary"
        elif "ssti" in class_name or "template" in class_name:
            expected = context.get("expected_evaluation") or context.get("expected_output")
            evaluated = bool(
                expected and str(expected) in _response_body(mutated)
                and str(candidate.value) not in _response_body(mutated)
            )
            proof = {
                "verified": evaluated, "type": "safe_template_arithmetic",
                "expected": expected,
            }
            proof_type = "safe_template_arithmetic"
        elif "redirect" in class_name:
            domain = str(
                context.get("researcher_controlled_domain")
                or "canary-redirect.invalid"
            ).lower()
            locations = [
                str(value).lower() for key, value in _header_values(mutated).items()
                if key == "location"
            ]
            locations.extend(
                str(item.get("to", "")).lower()
                for item in (mutated.get("redirects", []) or [])
                if isinstance(item, Mapping)
            )
            passed = any(domain in location for location in locations)
            proof = {
                "verified": passed, "type": "researcher_controlled_redirect",
                "domain": domain, "locations_observed": locations,
            }
            proof_type = "researcher_controlled_redirect"
        elif "ssrf" in class_name:
            callback_evidence = (
                context.get("controlled_callback")
                or context.get("callback_evidence")
            )
            callback_url = context.get("controlled_callback_url")
            callback_token = context.get("callback_token") or context.get("oast_token")
            deterministic_marker = context.get("deterministic_response_marker")
            oast = callback_proof(callback_evidence, token=str(callback_token)) \
                if callback_url and callback_token else {
                    "verified": False, "observed": bool(
                        isinstance(callback_evidence, Mapping) and callback_evidence.get("observed")),
                    "token_bound": False, "interaction_id_present": False,
                    "evidence_source": "unbound_callback", "redacted": True,
                }
            marker_proof = deterministic_marker_proof(
                _response_body(mutated), [_response_body(blocked)],
                str(deterministic_marker), echoed_input=str(candidate.value or "")
            ) if deterministic_marker else {"verified": False}
            passed = bool(oast.get("verified") or marker_proof.get("verified"))
            proof = {
                "verified": passed,
                "type": "token_bound_oast_or_deterministic_response",
                "callback": oast,
                "deterministic_marker": marker_proof,
            }
            proof_type = "token_bound_oast_or_deterministic_response"
        elif "cors" in class_name:
            browser_read = (
                context.get("browser_read_proof")
                or context.get("cors_browser_proof")
            )
            passed = bool(
                (
                    isinstance(browser_read, Mapping)
                    and browser_read.get("read_authenticated_response")
                )
                or browser_read is True
            )
            proof = {"verified": passed, "type": "browser_credentialed_read"}
            proof_type = "browser_credentialed_read"
        elif "sql" in class_name or "sqli" in class_name:
            true_marker = context.get("true_marker")
            false_marker = context.get("false_marker")
            if true_marker and false_marker:
                passed = (
                    str(true_marker) in _response_body(mutated)
                    and str(false_marker) not in _response_body(mutated)
                )
                proof = {
                    "verified": passed, "type": "semantic_boolean_differential",
                    "true_marker": str(true_marker), "false_marker": str(false_marker),
                }
            else:
                proof = False
            proof_type = "semantic_boolean_differential"
        else:
            expected_marker = context.get("expected_marker") or context.get("backend_marker")
            passed = bool(
                expected_marker and str(expected_marker) in _response_body(mutated)
            )
            proof = {
                "verified": passed, "type": "explicit_backend_marker",
                "marker": expected_marker,
            }
            proof_type = "explicit_backend_marker"

        verified = bool(
            proof.get("verified") if isinstance(proof, Mapping) else proof
        )
        checks = base_checks + [{
            "name": "relevant_behavior_proof", "passed": verified,
            "proof_type": proof_type,
        }]
        impact = self.measure_impact(
            original, mutated, difference,
            context={**context, "proof_type": proof_type}, proof=proof,
        )
        return {
            "verified": verified,
            "confidence": .98 if verified else .18,
            "checks": checks,
            "proof": proof,
            "impact": impact,
            "verification_note": (
                "The mutated representation reached the backend and the relevant "
                "behaviour proof passed."
                if verified else
                "A clean backend response was observed, but the relevant "
                "vulnerability behaviour was not proven."
            ),
        }

    # ----- pipeline ------------------------------------------------------

    def _finding_for_report(self, report: Mapping[str, Any]) -> Optional[dict[str, Any]]:
        attempts = report.get("attempts", []) or []
        verified_attempt = next(
            (item for item in attempts
             if item.get("verification", {}).get("verified")),
            None,
        ) if report.get("status") == "verified" else None
        if verified_attempt:
            candidate_data = dict(verified_attempt.get("candidate_object") or {})
            candidate = MutationCandidate(**candidate_data)
            verified = True
            attempt = verified_attempt
        elif attempts:
            attempt = attempts[-1]
            candidate_data = dict(attempt.get("candidate_object") or {})
            candidate = MutationCandidate(**candidate_data) if candidate_data else None
            verified = False
        else:
            return None

        original_request = (
            report.get("blocked_request")
            or report.get("baseline_request") or {}
        )
        original_response = (
            report.get("blocked_response")
            or report.get("baseline_response") or {}
        )
        mutated_request = attempt.get("request", {})
        mutated_response = attempt.get("response", {})
        proof = attempt.get("verification", {}).get("proof")
        return normalized_finding(
            finding_type=(
                "Verified Filter/WAF Bypass with Relevant Behaviour"
                if verified else "Filter/WAF Bypass Candidate"
            ),
            target=report.get("target", ""), endpoint=report.get("target", ""),
            status=FindingStatus.VERIFIED if verified else FindingStatus.SUSPECTED,
            confidence=.98 if verified else .25,
            method=mutated_request.get("method", "GET"),
            payload=candidate.value if candidate else "",
            source_module="bypass_engine", source_tool="BypassEngine",
            baseline={
                "request": safe_request_evidence(original_request),
                "response": safe_response_evidence(original_response),
            },
            test={
                "request": safe_request_evidence(mutated_request),
                "response": safe_response_evidence(mutated_response),
            },
            evidence=[{
                "original_request": safe_request_evidence(original_request),
                "original_response": safe_response_evidence(original_response),
                "mutated_request": safe_request_evidence(mutated_request),
                "mutated_response": safe_response_evidence(mutated_response),
                "difference": attempt.get("difference", {}),
                "bypass_primitive": (
                    {"category": candidate.category, "label": candidate.label}
                    if candidate else {}
                ),
                "final_vulnerability_proof": proof,
                "redacted": True,
            }],
            verification_checks=attempt.get("verification", {}).get("checks", []),
            false_positive_reasons=[] if verified else [
                "Response status/body change is not equivalent to verified backend behaviour"
            ],
            missing_evidence=[] if verified else [
                "Relevant backend/browser/callback behaviour is required; a status change alone is not proof"
            ],
            severity="High" if verified else "Info", cvss_score=0.0,
            param=candidate.parameter if candidate else report.get("parameter") or "",
            reproduction_curl=(
                "Use the recorded redacted mutated request within the authorized engagement."
            ),
            verification_note=attempt.get("verification", {}).get("verification_note", ""),
            raw_request=redact_http_text(mutated_response.get("raw_request", "")),
            raw_response=redact_http_text(mutated_response.get("raw_response", "")),
            observed_impact=(
                "The representation bypass reached the backend and the relevant proof passed."
                if verified else
                "A response differential was observed without a verified relevant impact."
            ),
            potential_impact=(
                "Impact remains bounded to the explicitly verified behaviour; "
                "no untested chain is claimed."
            ),
            bypass_report={key: value for key, value in report.items() if key != "attempts"},
            vrt_category="Server-Side Misconfiguration > WAF / Filter Bypass",
        )

    @staticmethod
    def _safe_request(url: str, method: str, headers: Mapping[str, Any],
                      body: Optional[str]) -> dict[str, Any]:
        return {
            "url": redact_http_text(url), "method": method.upper(),
            "headers": redact_headers(headers), "body": redact_body(body, 2000),
        }

    def run(
        self, url: str, *, vulnerability_class: str = "generic",
        payload: str | SQLPayload | None = None, parameter: Optional[str] = None,
        method: str = "GET", headers: Optional[Mapping[str, str]] = None,
        body: Optional[str] = None, input_context: Optional[Mapping[str, Any]] = None,
        context: Optional[Mapping[str, Any]] = None,
        baseline_response: Optional[Mapping[str, Any]] = None,
        blocked_response: Optional[Mapping[str, Any]] = None,
        request_budget: Optional[int] = None, max_depth: Optional[int] = None,
        enable_mutations: Optional[bool] = None,
        confirm_on_success: bool = True,
    ) -> dict[str, Any]:
        """Run Baseline -> Protection -> Fingerprint -> Mutation -> Verify."""
        context_map: dict[str, Any] = dict(context or {})
        context_map.update(dict(input_context or {}))
        budget = BypassBudget(
            self.default_request_budget if request_budget is None else request_budget)
        depth_limit = (
            self.max_depth if max_depth is None
            else min(3, max(0, int(max_depth)))
        )
        mutations_enabled = self.enabled if enable_mutations is None else bool(enable_mutations)
        base_headers = dict(headers or {})
        safe_method = str(method or "GET").upper()
        baseline_request = {
            "url": url, "method": safe_method,
            "headers": base_headers, "body": body,
        }
        if safe_method in DESTRUCTIVE_METHODS:
            skipped_response = {
                "status_code": 0, "success": False,
                "error": f"{safe_method} not sent: state-changing method is not allowed in bypass verification",
                "failure": {"type": "destructive_method_skipped", "verified": False},
            }
            empty_protection = self.fingerprinter.fingerprint([])
            report = {
                "engine": "BypassEngine", "target": url,
                "vulnerability_class": vulnerability_class, "depth": 0,
                "max_depth": depth_limit,
                "pipeline": [
                    "Baseline", "Protection Detection", "Fingerprint",
                    "Mutation Strategy Selection", "Controlled Bypass Attempt",
                    "Response Differential", "Verification", "Evidence",
                ],
                "baseline_request": self._safe_request(
                    url, safe_method, base_headers, body),
                "baseline_response": safe_response_evidence(skipped_response),
                "blocked_request": None, "blocked_response": None,
                "protection": empty_protection, "fingerprint": empty_protection,
                "reference_hypotheses": self.reference_intel.select_hypotheses(
                    str(context_map.get("component") or context_map.get("framework") or ""),
                    vulnerability_class,
                ),
                "response_learning": {"observations": []}, "attempts": [],
                "primitives": [], "chains": [], "findings": [],
                "budget": budget.to_dict(), "strategy_scores": {},
                "status": "skipped_destructive_method",
                "skip_reason": "State-changing methods are never sent by bypass verification",
                "parameter": parameter, "enabled_mutations": False,
            }
            self.last_run = report
            return report
        baseline = dict(baseline_response or {})
        if not baseline:
            if budget.claim("baseline_control"):
                baseline = self._send(baseline_request)
            else:
                baseline = {"status_code": 0, "error": "baseline sub-budget exhausted"}

        raw_payload = (
            payload.render() if isinstance(payload, SQLPayload)
            else (str(payload) if payload is not None else "")
        )
        blocked = dict(blocked_response or {})
        blocked_request = None
        if blocked_response:
            if raw_payload and parameter:
                blocked_request = self._candidate_request(
                    url,
                    MutationCandidate(
                        "semantic_control", "unmutated_semantic_payload", raw_payload,
                        parameter=parameter,
                        semantic=payload.semantic if isinstance(payload, SQLPayload) else "",
                        dialect=payload.dialect if isinstance(payload, SQLPayload) else "",
                    ),
                    parameter=parameter, body=body, headers=base_headers,
                    method=safe_method, context=context_map,
                )
            else:
                blocked_request = baseline_request
        if (not blocked_response and raw_payload and mutations_enabled and parameter
                and depth_limit >= 1):
            if budget.claim("baseline_control"):
                raw_candidate = MutationCandidate(
                    "semantic_control", "unmutated_semantic_payload", raw_payload,
                    parameter=parameter,
                    semantic=payload.semantic if isinstance(payload, SQLPayload) else "",
                    dialect=payload.dialect if isinstance(payload, SQLPayload) else "",
                )
                blocked_request = self._candidate_request(
                    url, raw_candidate, parameter=parameter, body=body,
                    headers=base_headers, method=safe_method, context=context_map)
                blocked = (
                    self._send(blocked_request) if blocked_request
                    else {"status_code": 0, "error": "cannot build control request"}
                )
        elif not blocked and classify_response(baseline).classification in {"blocked", "challenge"}:
            blocked = baseline
            blocked_request = baseline_request

        observed_responses = [item for item in (baseline, blocked) if item]
        protection = self.fingerprinter.fingerprint(observed_responses)
        blocked_features = classify_response(blocked) if blocked else classify_response({})
        report: dict[str, Any] = {
            "engine": "BypassEngine", "target": url,
            "vulnerability_class": vulnerability_class,
            "depth": 0 if not raw_payload else min(
                depth_limit, 2 if mutations_enabled else 1),
            "max_depth": depth_limit,
            "pipeline": [
                "Baseline", "Protection Detection", "Fingerprint",
                "Mutation Strategy Selection", "Controlled Bypass Attempt",
                "Response Differential", "Verification", "Evidence",
            ],
            "baseline_request": self._safe_request(
                url, safe_method, base_headers, body),
            "baseline_response": safe_response_evidence(baseline),
            "blocked_request": (
                self._safe_request(
                    blocked_request["url"], blocked_request["method"],
                    blocked_request.get("headers", {}), blocked_request.get("body"))
                if blocked_request else None
            ),
            "blocked_response": safe_response_evidence(blocked) if blocked else None,
            "protection": protection, "fingerprint": protection,
            "reference_hypotheses": self.reference_intel.select_hypotheses(
                str(context_map.get("component") or context_map.get("framework") or ""),
                vulnerability_class,
            ),
            "response_learning": {
                "observations": [
                    classify_response(item).to_dict() for item in observed_responses
                ]
            },
            "attempts": [], "primitives": [], "chains": [], "findings": [],
            "budget": budget.to_dict(), "strategy_scores": {},
            "status": "not_proven", "parameter": parameter,
            "enabled_mutations": mutations_enabled,
        }

        if depth_limit < 2 or not mutations_enabled or not raw_payload:
            report["status"] = (
                "protection_observed" if protection.get("observed")
                else "baseline_only"
            )
            report["budget"] = budget.to_dict()
            self.last_run = report
            return report

        filter_status = blocked_features.status_code in {
            403, 406, 413, 418, 429, 444, 451, 503
        }
        originally_blocked = (
            blocked_features.classification in {"blocked", "challenge"}
            and filter_status
        )
        if not originally_blocked:
            report["status"] = "no_filter_block_observed"
            report["missing_evidence"] = [
                "An unmutated payload must be blocked before a bypass can be claimed"
            ]
            report["budget"] = budget.to_dict()
            self.last_run = report
            return report

        learner = ResponseLearner()
        history: list[dict[str, Any]] = []
        candidates = self.mutations.generate_mutations(
            payload if payload is not None else raw_payload,
            vulnerability_class=vulnerability_class,
            input_context={**context_map, "parameter": parameter},
            detected_waf=protection,
            response_behavior=blocked_features.to_dict(),
            max_mutations=(
                budget.phase_limits.get("initial_strategies", 0)
                + budget.phase_limits.get("adaptive_bypass", 0)
            ),
        )
        remaining_candidates = learner.rank(candidates)
        used_ids: set[str] = set()
        proof_found = False
        attempt_index = 0

        while remaining_candidates and budget.remaining() > 0:
            candidate = remaining_candidates.pop(0)
            phase = (
                "initial_strategies"
                if attempt_index < budget.phase_limits.get("initial_strategies", 0)
                else "adaptive_bypass"
            )
            attempt_index += 1
            if not budget.claim(phase):
                break
            if candidate.category == "content_type_variation":
                accepted = context_map.get("accepted_content_types") or context_map.get("supported_content_types") or []
                if candidate.content_type not in [str(item) for item in accepted]:
                    history.append({
                        "candidate": candidate.to_dict(),
                        "skipped": "content_type_not_proven_supported",
                    })
                    budget.consumed_by_phase[phase] -= 1
                    budget.total_consumed -= 1
                    continue
            if candidate.category == "http_method_variation" and (
                candidate.method or "GET"
            ) in {"PUT", "PATCH", "DELETE"}:
                history.append({
                    "candidate": candidate.to_dict(),
                    "skipped": "state_changing_method_not_allowed",
                })
                budget.consumed_by_phase[phase] -= 1
                budget.total_consumed -= 1
                continue
            request = self._candidate_request(
                url, candidate, parameter=parameter, body=body,
                headers=base_headers, method=safe_method, context=context_map)
            if not request:
                continue
            used_ids.add(candidate.id)
            response = self._send(request)
            difference = response_differential(blocked, response)
            verification = self.verify_bypass(
                blocked, response, vulnerability_class=vulnerability_class,
                candidate=candidate, context=context_map, difference=difference)
            feature = classify_response(response, baseline=blocked)
            attempt = {
                "candidate": candidate.to_dict(),
                # Keep enough structure to identify/reconstruct the chosen
                # strategy, but never persist the raw candidate object.
                "candidate_object": candidate.to_dict(),
                "request": self._safe_request(
                    request["url"], request["method"],
                    request.get("headers", {}), request.get("body")),
                "response": safe_response_evidence(response),
                "features": feature.to_dict(),
                "difference": difference, "verification": verification,
            }
            report["attempts"].append(attempt)
            history.append({
                "category": candidate.category,
                "response_class": feature.classification,
                "verified": verification.get("verified", False),
            })
            learner.record(
                candidate.category, feature.classification,
                verified=bool(verification.get("verified")),
                confidence=verification.get("confidence", 0),
                candidate=candidate)
            if verification.get("verified"):
                proof_found = True
                if confirm_on_success and budget.claim("confirmation"):
                    confirmation_response = self._send(request)
                    confirmation_diff = response_differential(
                        blocked, confirmation_response)
                    confirmation = self.verify_bypass(
                        blocked, confirmation_response,
                        vulnerability_class=vulnerability_class,
                        candidate=candidate, context=context_map,
                        difference=confirmation_diff)
                    report["confirmation"] = {
                        "request": self._safe_request(
                            request["url"], request["method"],
                            request.get("headers", {}), request.get("body")),
                        "response": safe_response_evidence(confirmation_response),
                        "difference": confirmation_diff,
                        "verification": confirmation,
                    }
                    if not confirmation.get("verified"):
                        proof_found = False
                break

            # Learn from the response before selecting the next candidate.
            remaining_candidates = learner.rank(remaining_candidates)

        report["strategy_scores"] = learner.to_dict()
        report["response_learning"] = {
            "observations": [
                {
                    "features": item.get("features"),
                    "difference": item.get("difference"),
                    "candidate": {
                        "category": item.get("candidate", {}).get("category"),
                        "label": item.get("candidate", {}).get("label"),
                    },
                }
                for item in report["attempts"]
            ],
            "history": history,
        }
        report["budget"] = budget.to_dict()
        report["status"] = (
            "verified" if proof_found
            else ("bypass_candidate" if report["attempts"] else "blocked_no_mutation")
        )
        if proof_found:
            verified_attempt = next(
                item for item in report["attempts"]
                if item["verification"].get("verified")
            )
            primitive = {
                "id": f"primitive_{uuid.uuid4().hex[:10]}",
                "type": "filter_normalization_bypass",
                "status": "VERIFIED", "depth": 2,
                "category": verified_attempt["candidate"]["category"],
                "target": url,
                "evidence": {
                    "original_request": report["blocked_request"],
                    "original_response": report["blocked_response"],
                    "mutated_request": verified_attempt["request"],
                    "mutated_response": verified_attempt["response"],
                    "difference": verified_attempt["difference"],
                    "final_vulnerability_proof": verified_attempt["verification"].get("proof"),
                    "redacted": True,
                },
            }
            report["primitives"].append(primitive)
        finding = self._finding_for_report(report)
        if finding:
            report["findings"].append(finding)
        self.last_run = report
        return report

    run_pipeline = run
    audit = run
    execute = run

    @staticmethod
    def _discovered_api_forms(endpoint: str, endpoints: Sequence[str]) -> list[str]:
        """Return only same-origin versioned forms already discovered by recon."""
        parsed = urllib.parse.urlsplit(endpoint)
        if not parsed.scheme or not parsed.netloc:
            return []
        version_re = re.compile(r"(?:^|/)(?:api/)?v\d+(?:/|$)", re.I)
        if not version_re.search(parsed.path or ""):
            return []
        forms = []
        for candidate in endpoints:
            candidate_parsed = urllib.parse.urlsplit(candidate)
            if (candidate == endpoint
                    or candidate_parsed.scheme != parsed.scheme
                    or candidate_parsed.netloc != parsed.netloc
                    or not version_re.search(candidate_parsed.path or "")):
                continue
            if candidate not in forms:
                forms.append(candidate)
        return forms[:8]

    def run_many(
        self, endpoints: Sequence[str], *, request_budget: Optional[int] = None,
        max_depth: Optional[int] = None,
        contexts: Optional[Mapping[str, Mapping[str, Any]]] = None,
        authorization_identities: Optional[Sequence[Any]] = None,
    ) -> dict[str, Any]:
        """Run bounded observations across discovered endpoints.

        Without explicit payload/context this performs baseline protection
        detection only. The engine never invents injection semantics because
        an endpoint exists.
        """
        total = (
            self.default_request_budget if request_budget is None
            else max(0, int(request_budget))
        )
        reports = []
        findings = []
        remaining = total
        for endpoint in list(dict.fromkeys(endpoints))[:20]:
            if remaining <= 0:
                break
            supplied = dict((contexts or {}).get(endpoint, {}))
            local_budget = min(
                remaining, 5 if not supplied.get("payload") else 12)
            vuln = supplied.pop("vulnerability_class", "generic")
            payload = supplied.pop("payload", None)
            parameter = supplied.pop("parameter", None)
            explicit_api_versions = supplied.pop("api_versions", None)
            alternate_forms = supplied.pop("alternate_forms", None)
            result = self.run(
                endpoint, vulnerability_class=vuln, payload=payload,
                parameter=parameter, context=supplied,
                request_budget=local_budget, max_depth=max_depth,
            )
            reports.append(result)
            findings.extend(result.get("findings", []))
            used = int(result.get("budget", {}).get("consumed", 0))
            remaining -= used

            if authorization_identities and len(authorization_identities) >= 2 and remaining > 0:
                auth = AuthorizationBypassEngine(
                    self.verifier, request_budget=min(remaining, 8))
                auth_result = auth.test(
                    endpoint, identities=authorization_identities,
                    owner_marker=supplied.get("owner_marker"),
                    api_versions=(list(explicit_api_versions)
                                  if explicit_api_versions is not None
                                  else self._discovered_api_forms(endpoint, endpoints)),
                    alternate_forms=list(alternate_forms or []),
                    path_normalization=bool(
                        supplied.get("test_path_normalization")),
                )
                reports.append({
                    "engine": "AuthorizationBypassEngine",
                    "target": endpoint, "authorization": auth_result,
                    "requests_used": auth.requests_used,
                    "primitives": auth_result.get("primitives", []),
                })
                findings.extend(auth_result.get("findings", []))
                remaining -= auth.requests_used
        primitive_rows = [
            primitive for report in reports
            for primitive in report.get("primitives", [])
        ]
        chains = []
        if len(primitive_rows) >= 2 and (max_depth is None or int(max_depth) >= 3):
            chains.append(self.build_chain(
                primitive_rows, max_depth=max_depth,
                chain_name="adaptive_bypass_exploit_chain"))
        return {
            "engine": "BypassEngine", "reports": reports, "findings": findings,
            "verified_findings": [
                item for item in findings
                if item.get("status") == FindingStatus.VERIFIED.value
            ],
            "primitives": primitive_rows,
            "chains": chains, "request_budget": total,
            "requests_used": total - remaining,
            "requests_remaining": remaining,
            "protection_fingerprints": [
                {"target": report.get("target"),
                 "fingerprint": report.get("fingerprint")}
                for report in reports if report.get("fingerprint")
            ],
        }

    def build_chain(
        self, primitives: Sequence[Mapping[str, Any]], *,
        max_depth: Optional[int] = None,
        chain_name: str = "bypass_chain",
    ) -> dict[str, Any]:
        limit = (
            self.max_depth if max_depth is None
            else min(3, max(0, int(max_depth)))
        )
        selected = [dict(item) for item in primitives[:limit]]
        all_verified = bool(selected) and all(
            str(item.get("status", "")).upper() == "VERIFIED"
            for item in selected
        )
        capability_map = {
            "waf_normalization_bypass": {"provides": {"filter_bypass"}},
            "filter_normalization_bypass": {"provides": {"filter_bypass"}},
            "dialect_aware_sql_injection": {"requires": {"filter_bypass"}, "provides": {"database_query"}},
            "sqli": {"requires": {"filter_bypass"}, "provides": {"database_query"}},
            "oast_verified_ssrf": {"provides": {"outbound_fetch"}},
            "server_side_request_forgery": {"provides": {"outbound_fetch"}},
            "authorization_bypass": {"provides": {"cross_identity_access"}},
            "server_side_template_evaluation": {"provides": {"template_evaluation"}},
        }
        semantic_edges = []
        explicit_semantics = False
        for index, item in enumerate(selected):
            inferred = capability_map.get(str(item.get("type", "")).lower(), {})
            provides = set(item.get("provides") or inferred.get("provides") or [])
            requires = set(item.get("requires") or inferred.get("requires") or [])
            if item.get("provides") or item.get("requires") or inferred:
                explicit_semantics = True
            if index == 0:
                continue
            previous = selected[index - 1]
            previous_inferred = capability_map.get(str(previous.get("type", "")).lower(), {})
            previous_provides = set(previous.get("provides") or previous_inferred.get("provides") or [])
            linked = bool(requires & previous_provides)
            semantic_edges.append({
                "from": previous.get("id"), "to": item.get("id"),
                "provided": sorted(previous_provides), "required": sorted(requires),
                "linked": linked,
            })
        semantic_chain = (not explicit_semantics) or all(edge["linked"] for edge in semantic_edges)
        status = (
            "CONFIRMED"
            if all_verified and len(selected) >= 2 and semantic_chain else "POTENTIAL CHAIN"
        )
        return {
            "id": f"chain_{uuid.uuid4().hex[:10]}",
            "name": chain_name, "status": status,
            "depth": len(selected), "max_depth": limit,
            "semantic_chain": semantic_chain,
            "semantic_edges": semantic_edges,
            "primitives": [
                {
                    "id": item.get("id"), "type": item.get("type"),
                    "status": item.get("status"),
                    "evidence": item.get("evidence", {}),
                }
                for item in selected
            ],
            "rule": (
                "Each primitive remains separate; a chain is CONFIRMED only "
                "when every primitive is VERIFIED."
            ),
        }

    # ----- standalone differential helpers ------------------------------

    def detect_protection(
        self, url: str = "", *, responses: Optional[Sequence[Mapping[str, Any]]] = None,
        request: Optional[Mapping[str, Any]] = None,
    ) -> dict[str, Any]:
        """Fingerprint an observed response, or make one scoped baseline call."""
        observed = list(responses or [])
        if not observed:
            request = request or {"url": url, "method": "GET", "headers": {}, "body": None}
            observed.append(self._send(request))
        return self.fingerprinter.fingerprint(observed)

    detect_filter = detect_protection
    fingerprint_protection = detect_protection
    fingerprint = detect_protection

    @staticmethod
    def _same_parameter_url(url: str, parameter: str, value: str) -> str:
        parsed = urllib.parse.urlsplit(url)
        pairs = [
            (key, item) for key, item in urllib.parse.parse_qsl(
                parsed.query, keep_blank_values=True
            ) if key != parameter
        ]
        pairs.append((parameter, value))
        return urllib.parse.urlunsplit(
            parsed._replace(
                query=urllib.parse.urlencode(pairs, doseq=True), fragment=""
            )
        )

    def test_parameter_pollution(
        self, url: str, parameter: str, *,
        values: Sequence[str] = ("AGY_FIRST", "AGY_SECOND"),
        method: str = "GET", headers: Optional[Mapping[str, str]] = None,
        body: Optional[str] = None, request_budget: int = 6,
        expected_marker: Optional[str] = None,
        proof_callback: Optional[Callable[..., Any]] = None,
    ) -> dict[str, Any]:
        """Compare first/last/duplicate parser interpretations empirically."""
        values = [str(item) for item in values]
        if len(values) < 2:
            return {
                "strategy": "parameter_pollution", "verified": False,
                "status": "SUSPECTED", "requests_used": 0,
                "missing_evidence": ["At least two distinct duplicate values are required"],
            }
        limit = max(0, int(request_budget))
        sent = 0

        def send(candidate_url: str) -> dict[str, Any]:
            nonlocal sent
            if sent >= limit:
                return {
                    "status_code": 0, "success": False,
                    "error": "parameter pollution sub-budget exhausted",
                }
            sent += 1
            request = {
                "url": candidate_url, "method": method,
                "headers": dict(headers or {}), "body": body,
            }
            return self._send(request)

        first = send(self._same_parameter_url(url, parameter, values[0]))
        last = send(self._same_parameter_url(url, parameter, values[1]))
        duplicate = send(self._url_with_duplicate_param(url, parameter, values[:2]))
        reverse = (
            send(self._url_with_duplicate_param(url, parameter, values[1::-1]))
            if sent < limit else
            {"status_code": 0, "error": "reverse duplicate comparison not budgeted"}
        )

        def signature(response: Mapping[str, Any]) -> tuple[Any, Any]:
            feature = classify_response(response)
            return feature.status_code, feature.body_hash

        first_signature, last_signature = signature(first), signature(last)
        duplicate_signature = signature(duplicate)
        reverse_signature = signature(reverse)
        if duplicate_signature == first_signature and duplicate_signature != last_signature:
            parser_winner = "first_value"
        elif duplicate_signature == last_signature and duplicate_signature != first_signature:
            parser_winner = "last_value"
        elif (
            _response_body(duplicate).find(values[0]) >= 0
            and _response_body(duplicate).find(values[1]) >= 0
        ):
            parser_winner = "merged_or_echoed"
        elif duplicate_signature == reverse_signature:
            parser_winner = "order_insensitive_or_normalized"
        else:
            parser_winner = "unknown"

        difference = response_differential(first, duplicate)
        behavior_proof: Any = None
        if callable(proof_callback):
            behavior_proof = _invoke_proof_callback(
                proof_callback, duplicate, MutationCandidate(
                    "parameter_pollution", "duplicate_first_last",
                    values[0], parameter=parameter,
                    metadata={"values": values[:2]}), difference)
        elif expected_marker:
            behavior_proof = {
                "verified": expected_marker in _response_body(duplicate),
                "type": "explicit_backend_marker",
                "marker": expected_marker,
            }
        verified = bool(
            behavior_proof.get("verified")
            if isinstance(behavior_proof, Mapping) else behavior_proof
        )
        front_block_backend_allowed = (
            classify_response(first).classification in {"blocked", "challenge"}
            and classify_response(duplicate).classification in {"allowed", "backend_response"}
        )
        return {
            "strategy": "parameter_pollution", "verified": verified,
            "status": "VERIFIED" if verified else "SUSPECTED",
            "requests_used": sent, "url": url, "parameter": parameter,
            "values": values[:2], "parser_winner": parser_winner,
            "first": safe_response_evidence(first),
            "last": safe_response_evidence(last),
            "duplicate": safe_response_evidence(duplicate),
            "reverse_duplicate": safe_response_evidence(reverse),
            "difference": difference,
            "front_block_backend_allowed": front_block_backend_allowed,
            "behavior_proof": behavior_proof,
            "checks": [
                {"name": "first_value_response_observed", "passed": bool(_status_code(first))},
                {"name": "last_value_response_observed", "passed": bool(_status_code(last))},
                {"name": "duplicate_response_observed", "passed": bool(_status_code(duplicate))},
                {"name": "parser_interpretation_determined", "passed": parser_winner != "unknown"},
                {"name": "relevant_behavior_proof", "passed": verified},
            ],
            "missing_evidence": [] if verified else [
                "Parser ambiguity is observed, but a security-relevant protected behaviour proof is required"
            ],
            "note": (
                "Parser behavior is reported from response comparisons; first/last/merge behavior is never assumed."
            ),
        }

    test_parser_differential = test_parameter_pollution
    test_query_parser_differential = test_parameter_pollution

    @staticmethod
    def _multipart_body(field: str, value: str, boundary: str) -> str:
        return (
            f"--{boundary}\r\n"
            f"Content-Disposition: form-data; name=\"{field}\"\r\n\r\n"
            f"{value}\r\n--{boundary}--\r\n"
        )

    def probe_supported_content_types(
        self, url: str, *, field: str = "q",
        method: str = "POST",
        content_types: Sequence[str] = (
            "application/json", "application/x-www-form-urlencoded",
            "multipart/form-data", "text/plain",
        ),
        headers: Optional[Mapping[str, str]] = None,
        request_budget: int = 6,
    ) -> dict[str, Any]:
        """Prove parser acceptance before content-type variation is offered."""
        sent = 0
        observations = []
        canary = "AGY_CONTENT_PROBE"
        for content_type in content_types:
            if sent >= max(0, int(request_budget)):
                break
            boundary = "----AGYContentBoundary"
            if content_type == "application/json":
                request_body = json.dumps({field: canary}, separators=(",", ":"))
                request_headers = {"Content-Type": content_type, "Accept": "application/json"}
            elif content_type == "application/x-www-form-urlencoded":
                request_body = urllib.parse.urlencode({field: canary})
                request_headers = {"Content-Type": content_type, "Accept": "application/json"}
            elif content_type == "multipart/form-data":
                request_body = self._multipart_body(field, canary, boundary)
                request_headers = {
                    "Content-Type": f"{content_type}; boundary={boundary}",
                    "Accept": "application/json",
                }
            elif content_type == "text/plain":
                request_body = canary
                request_headers = {"Content-Type": content_type, "Accept": "application/json"}
            else:
                continue
            request_headers.update(dict(headers or {}))
            response = self._send({
                "url": url, "method": method.upper(),
                "headers": request_headers, "body": request_body,
            })
            sent += 1
            feature = classify_response(response)
            status = feature.status_code
            unsupported_media = bool(re.search(
                r"unsupported\s+(?:media|content[- ]?type)|invalid\s+content[- ]?type|"
                r"content[- ]?type\s+not\s+supported",
                _response_body(response), re.I,
            ))
            parser_accepted = (
                status in {200, 201, 202, 400, 422}
                and status not in {401, 403}
                and status not in {405, 415}
                and feature.classification not in {"blocked", "challenge"}
                and not unsupported_media
            )
            observations.append({
                "content_type": content_type, "parser_accepted": parser_accepted,
                "unsupported_media": unsupported_media,
                "features": feature.to_dict(), "response": safe_response_evidence(response),
            })
        accepted = [
            item["content_type"] for item in observations if item["parser_accepted"]
        ]
        return {
            "url": url, "field": field, "method": method.upper(),
            "supported_content_types": accepted,
            "observations": observations, "requests_used": sent,
            "proof_rule": (
                "Only non-auth, non-unsupported-media responses to the controlled parser probe are treated as acceptance."
            ),
        }

    detect_supported_content_types = probe_supported_content_types

    def test_content_type_variation(
        self, url: str, *, field: str = "q", payload: str = "AGY_CONTENT_CANARY",
        accepted_content_types: Sequence[str],
        method: str = "POST", headers: Optional[Mapping[str, str]] = None,
        request_budget: int = 8, vulnerability_class: str = "filter bypass",
        context: Optional[Mapping[str, Any]] = None,
        expected_marker: Optional[str] = None,
        proof_callback: Optional[Callable[..., Any]] = None,
    ) -> dict[str, Any]:
        """Try only formats previously proven to reach an endpoint parser."""
        observations = []
        sent = 0
        for content_type in [str(item) for item in accepted_content_types]:
            if sent >= max(0, int(request_budget)):
                break
            boundary = "----AGYContentVariation"
            if content_type == "application/json":
                request_body = json.dumps({field: payload}, separators=(",", ":"))
                actual_content_type = content_type
            elif content_type == "application/x-www-form-urlencoded":
                request_body = urllib.parse.urlencode({field: payload})
                actual_content_type = content_type
            elif content_type == "multipart/form-data":
                request_body = self._multipart_body(field, payload, boundary)
                actual_content_type = f"{content_type}; boundary={boundary}"
            elif content_type == "text/plain":
                request_body = payload
                actual_content_type = content_type
            else:
                continue
            request = {
                "url": url, "method": method.upper(),
                "headers": {**dict(headers or {}), "Content-Type": actual_content_type},
                "body": request_body,
            }
            response = self._send(request)
            sent += 1
            observations.append({
                "content_type": content_type, "request": safe_request_evidence(request),
                "response": safe_response_evidence(response),
                "features": classify_response(response).to_dict(),
            })
        proof: Any = None
        if expected_marker:
            proof = {
                "verified": any(
                    item["features"]["classification"] in {"allowed", "backend_response"}
                    and expected_marker in item["response"]["body"]
                    for item in observations
                ),
                "type": "explicit_backend_marker", "marker": expected_marker,
            }
        elif callable(proof_callback):
            try:
                proof = proof_callback(observations)
            except TypeError:
                proof = proof_callback()
        verified = bool(
            proof.get("verified") if isinstance(proof, Mapping) else proof
        )
        return {
            "strategy": "content_type_variation", "verified": verified,
            "status": "VERIFIED" if verified else "SUSPECTED", "behavior_proof": proof,
            "requests_used": sent,
            "accepted_content_types_used": [
                item["content_type"] for item in observations
            ],
            "observations": observations,
            "missing_evidence": [] if verified else [
                "A supported format differential still needs relevant backend behaviour proof"
            ],
            "context": dict(context or {}),
        }

    test_content_type_bypass = test_content_type_variation

    def test_method_variation(
        self, url: str, *, methods: Optional[Sequence[str]] = None,
        headers: Optional[Mapping[str, str]] = None, body: Optional[str] = None,
        request_budget: int = 8, allow_safe_post: bool = False,
        expected_marker: Optional[str] = None,
    ) -> dict[str, Any]:
        """Use only safe method probes; destructive methods are recorded/skipped."""
        requested = [str(item).upper() for item in (methods or ["GET", "POST", "HEAD", "OPTIONS"])]
        allowed = {"GET", "HEAD", "OPTIONS"} | ({"POST"} if allow_safe_post else set())
        skipped = [item for item in requested if item not in allowed]
        observations = []
        sent = 0
        for selected in requested:
            if selected not in allowed or sent >= max(0, int(request_budget)):
                continue
            request = {
                "url": url, "method": selected,
                "headers": dict(headers or {}),
                "body": None if selected == "HEAD" else body,
            }
            response = self._send(request)
            sent += 1
            observations.append({
                "method": selected, "request": safe_request_evidence(request),
                "response": safe_response_evidence(response),
                "features": classify_response(response).to_dict(),
            })
        accessible = [
            item for item in observations
            if item["features"]["classification"] in {"allowed", "backend_response"}
        ]
        denied = [
            item for item in observations
            if item["features"]["status_code"] in {401, 403}
        ]
        protected_accessible = [
            item for item in accessible
            if expected_marker and expected_marker in item["response"]["body"]
        ]
        verified = bool(denied and protected_accessible)
        return {
            "strategy": "http_method_variation", "verified": verified,
            "status": "VERIFIED" if verified else "SUSPECTED",
            "confidence": .94 if verified else .2,
            "observations": observations, "skipped_methods": skipped,
            "authorization_differential": bool(denied and accessible),
            "protected_content_via_alternate_method": bool(protected_accessible),
            "missing_evidence": [
                "Method/routing differential requires protected content proof; status alone is insufficient"
            ] if not verified else [],
            "destructive_methods_never_sent": sorted(
                set(skipped) & {"PUT", "PATCH", "DELETE"}
            ),
        }

    test_methods = test_method_variation

    def test_header_variation(
        self, url: str, *, headers: Optional[Sequence[Mapping[str, str]]] = None,
        purpose: str = "routing discrepancy", method: str = "GET",
        body: Optional[str] = None, request_budget: int = 8,
        vulnerability_class: str = "filter bypass",
        context: Optional[Mapping[str, Any]] = None,
        expected_marker: Optional[str] = None,
    ) -> dict[str, Any]:
        """Try same-host routing/metadata headers only for an explicit purpose."""
        allowed_purposes = {
            "access-control mismatch", "routing discrepancy",
            "waf/backend disagreement",
        }
        if purpose not in allowed_purposes:
            return {
                "strategy": "header_variation", "verified": False,
                "status": "SKIPPED",
                "reason": "Header bypass testing is restricted to routing/access-control/WAF disagreement",
                "requests_used": 0,
            }
        variants = list(headers or [
            {"X-Original-URL": urllib.parse.urlsplit(url).path or "/"},
            {"X-Rewrite-URL": urllib.parse.urlsplit(url).path or "/"},
            {"X-Forwarded-Proto": urllib.parse.urlsplit(url).scheme or "https"},
            {"Forwarded": f"proto={urllib.parse.urlsplit(url).scheme or 'https'}"},
            {"X-HTTP-Method-Override": "GET"},
        ])
        sent = 0
        baseline = self._send({
            "url": url, "method": method.upper(),
            "headers": {}, "body": body,
        }) if request_budget > 0 else {"status_code": 0}
        if request_budget > 0:
            sent += 1
        observations = []
        for variant in variants:
            if sent >= max(0, int(request_budget)):
                break
            request = {
                "url": url, "method": method.upper(),
                "headers": dict(variant), "body": body,
            }
            response = self._send(request)
            sent += 1
            observations.append({
                "headers": redact_headers(variant),
                "request": safe_request_evidence(request),
                "response": safe_response_evidence(response),
                "difference": response_differential(baseline, response),
            })
        marker = expected_marker or (context or {}).get("expected_marker")
        verified = bool(
            classify_response(baseline).status_code in {403, 406, 429, 503}
            and any(
                classify_response(item["response"]).classification in {"allowed", "backend_response"}
                and marker and marker in item["response"].get("body", "")
                for item in observations
            )
        )
        return {
            "strategy": "header_variation", "verified": verified,
            "status": "VERIFIED" if verified else "SUSPECTED",
            "confidence": .94 if verified else .2,
            "purpose": purpose,
            "baseline": safe_response_evidence(baseline),
            "observations": observations, "requests_used": sent,
            "missing_evidence": [] if verified else [
                "Origin routing or protected behaviour must be verified independently of a status change"
            ],
            "context": dict(context or {}),
        }

    test_header_bypass = test_header_variation

    def test_path_normalization(
        self, url: str, *, method: str = "GET",
        headers: Optional[Mapping[str, str]] = None, body: Optional[str] = None,
        request_budget: int = 8, case_relevant: bool = False,
        expected_marker: Optional[str] = None,
    ) -> dict[str, Any]:
        """Compare reverse-proxy/backend path forms without crossing host scope."""
        parsed = urllib.parse.urlsplit(url)
        path = parsed.path or "/"
        clean_path = "/" + path.lstrip("/")
        variants = [
            ("duplicate_slash", clean_path.replace("/", "//", 1) if clean_path != "/" else "//"),
            ("dot_segment", clean_path.rstrip("/") + "/./" if clean_path != "/" else "/./"),
            ("encoded_separator", path.replace("/", "%2F")),
            ("trailing_separator", path if path.endswith("/") else path + "/"),
        ]
        if case_relevant and path:
            variants.append(("case_variation", path.swapcase()))
        baseline_request = {
            "url": url, "method": method.upper(),
            "headers": dict(headers or {}), "body": body,
        }
        sent = 0
        baseline = (
            self._send(baseline_request) if request_budget > 0
            else {"status_code": 0, "error": "path normalization sub-budget exhausted"}
        )
        if request_budget > 0:
            sent += 1
        observations = []
        for label, candidate_path in variants:
            if candidate_path == path or sent >= max(0, int(request_budget)):
                continue
            candidate_url = urllib.parse.urlunsplit(parsed._replace(path=candidate_path))
            response = self._send({
                "url": candidate_url, "method": method.upper(),
                "headers": dict(headers or {}), "body": body,
            })
            sent += 1
            feature = classify_response(response, baseline=baseline)
            marker = bool(expected_marker and expected_marker in _response_body(response))
            observations.append({
                "variant": label, "url": candidate_url,
                "response": safe_response_evidence(response),
                "features": feature.to_dict(),
                "difference": response_differential(baseline, response),
                "expected_marker": marker,
            })
        baseline_denied = classify_response(baseline).status_code in {
            403, 406, 429, 503
        }
        verified = bool(
            baseline_denied and any(
                item["features"]["classification"] in {"allowed", "backend_response"}
                and item["expected_marker"] for item in observations
            )
        )
        return {
            "strategy": "path_normalization", "verified": verified,
            "status": "VERIFIED" if verified else "SUSPECTED",
            "confidence": .94 if verified else .2,
            "baseline": safe_response_evidence(baseline),
            "observations": observations,
            "missing_evidence": [] if verified else [
                "A routing/authorization impact proof is required; equivalent response alone is not a bypass"
            ],
        }

    test_normalization_differential = test_path_normalization

    def test_json_filter_variants(
        self, url: str, *, field: str = "q",
        value: str = "AGY_JSON_CANARY", method: str = "POST",
        headers: Optional[Mapping[str, str]] = None,
        request_budget: int = 8,
        expected_marker: Optional[str] = None,
        proof_callback: Optional[Callable[..., Any]] = None,
    ) -> dict[str, Any]:
        """Compare JSON shapes at validation and business-logic boundaries."""
        variants = [
            ("scalar", json.dumps({field: value}, separators=(",", ":"))),
            ("nested_object", json.dumps({field: {"value": value}}, separators=(",", ":"))),
            ("type_number", json.dumps({field: 7}, separators=(",", ":"))),
            ("null_value", json.dumps({field: None}, separators=(",", ":"))),
            ("boolean_string", json.dumps({field: "true"}, separators=(",", ":"))),
            ("array_scalar", json.dumps({field: [value]}, separators=(",", ":"))),
            ("unknown_field", json.dumps({field: value, "__agy_unknown__": value}, separators=(",", ":"))),
            # Keep duplicate keys as raw JSON; json.dumps would erase the
            # ambiguity before it reached the target parser.
            ("duplicate_key", (
                "{" + json.dumps(field) + ":" + json.dumps(f"{value}-first")
                + "," + json.dumps(field) + ":" + json.dumps(f"{value}-last") + "}"
            )),
        ]
        sent = 0
        observations = []
        for label, request_body in variants:
            if sent >= max(0, int(request_budget)):
                break
            request = {
                "url": url, "method": method.upper(),
                "headers": {**dict(headers or {}), "Content-Type": "application/json",
                            "Accept": "application/json"},
                "body": request_body,
            }
            response = self._send(request)
            sent += 1
            observations.append({
                "variant": label, "request": safe_request_evidence(request),
                "response": safe_response_evidence(response),
                "features": classify_response(response).to_dict(),
            })
        baseline = next(
            (item for item in observations if item["variant"] == "scalar"), None)
        changed = [
            item for item in observations
            if baseline and item["features"]["body_hash"] != baseline["features"]["body_hash"]
        ]
        proof: Any = None
        if expected_marker:
            proof = {
                "verified": any(
                    expected_marker in item["response"]["body"] for item in observations
                ),
                "type": "explicit_backend_marker", "marker": expected_marker,
            }
        elif callable(proof_callback):
            proof = proof_callback(observations)
        verified = bool(
            proof.get("verified") if isinstance(proof, Mapping) else proof)
        return {
            "strategy": "json_filter_shape_differential",
            "verified": verified, "status": "VERIFIED" if verified else "SUSPECTED",
            "requests_used": sent, "field": field,
            "observations": observations, "response_shape_changes": len(changed),
            "behavior_proof": proof,
            "checks": [
                {"name": "json_variants_sent", "passed": bool(observations)},
                {"name": "duplicate_keys_preserved_on_wire",
                 "passed": any(item["variant"] == "duplicate_key" for item in observations)},
                {"name": "relevant_behavior_proof", "passed": verified},
            ],
            "missing_evidence": [] if verified else [
                "Validation/logic shape differences require a security-relevant backend proof"
            ],
        }

    test_json_api_filter_bypass = test_json_filter_variants

    def test_ssrf_parser_differential(
        self, url: str, parameter: str, *,
        url_values: Sequence[str] = (
            "https://ssrf-canary.invalid/AGY",
            "https%3A%2F%2Fssrf-canary.invalid%2FAGY",
            "HTTPS://ssrf-canary.invalid/AGY",
        ),
        headers: Optional[Mapping[str, str]] = None,
        request_budget: int = 8,
        controlled_callback: Optional[Mapping[str, Any]] = None,
        deterministic_response_marker: Optional[str] = None,
        controlled_callback_url: Optional[str] = None,
        callback_token: Optional[str] = None,
    ) -> dict[str, Any]:
        """Exercise URL-parser/redirect representations against a researcher canary.

        When a callback URL is supplied, each representation carries a unique
        token and only a token-bound interaction can satisfy the OAST proof.
        The old fixed canary inputs remain available as discovery candidates,
        but never become VERIFIED from timing/status differences alone.
        """
        token = str(callback_token or f"rt-{uuid.uuid4().hex[:12]}")
        if controlled_callback_url:
            generated = callback_variants(controlled_callback_url, token=token)
            if generated:
                url_values = tuple(item["url"] for item in generated)
        sent = 0
        observations = []
        for value in list(url_values)[:8]:
            if sent >= max(0, int(request_budget)):
                break
            request_url = self._same_parameter_url(url, parameter, value)
            request = {
                "url": request_url, "method": "GET",
                "headers": dict(headers or {}), "body": None,
            }
            response = self._send(request)
            sent += 1
            observations.append({
                "input_representation": value,
                "request": safe_request_evidence(request),
                "response": safe_response_evidence(response),
                "features": classify_response(response).to_dict(),
            })
        oast = callback_proof(controlled_callback, token=token) if controlled_callback_url else {
            "verified": False, "observed": bool(isinstance(controlled_callback, Mapping)
                                                 and controlled_callback.get("observed")),
            "token_bound": False, "interaction_id_present": False,
            "evidence_source": "legacy_unbound_callback", "redacted": True,
        }
        marker_seen = False
        marker_proof = {"verified": False, "marker_present": False,
                        "marker_absent_from_baseline": False, "input_echo_only": False}
        if deterministic_response_marker:
            baseline_bodies = [item["response"].get("body", "") for item in observations[:1]]
            for item in observations[1:]:
                marker_proof = deterministic_marker_proof(
                    item["response"].get("body", ""), baseline_bodies,
                    deterministic_response_marker, echoed_input=item.get("input_representation"))
                if marker_proof.get("verified"):
                    marker_seen = True
                    break
        verified = bool(oast.get("verified") or marker_seen)
        return {
            "strategy": "ssrf_url_parser_differential",
            "verified": verified, "status": "VERIFIED" if verified else "SUSPECTED",
            "requests_used": sent, "observations": observations,
            "controlled_callback": oast,
            "deterministic_response_marker": deterministic_response_marker,
            "checks": [
                {"name": "multiple_url_representations_observed", "passed": len(observations) >= 2},
                {"name": "token_bound_oast_or_deterministic_response", "passed": verified},
            ],
            "missing_evidence": [] if verified else [
                "SSRF requires a token-bound controlled callback or deterministic in-scope response proof"
            ],
        }

    test_ssrf_bypass = test_ssrf_parser_differential

    def test_open_redirect_variants(
        self, url: str, parameter: str, *,
        researcher_controlled_domain: str = "redirect-canary.invalid",
        request_budget: int = 8,
        headers: Optional[Mapping[str, str]] = None,
    ) -> dict[str, Any]:
        """Test allowlist/parser forms using a researcher-owned destination."""
        domain = str(researcher_controlled_domain).lower().strip()
        if not domain or "/" in domain or "@" in domain:
            return {
                "strategy": "open_redirect_parser_differential",
                "verified": False, "status": "SKIPPED",
                "reason": "researcher_controlled_domain must be a host name",
                "requests_used": 0,
            }
        values = [
            f"https://{domain}/AGY",
            f"//{domain}/AGY",
            urllib.parse.quote(f"https://{domain}/AGY", safe=""),
            urllib.parse.quote(urllib.parse.quote(f"https://{domain}/AGY", safe=""), safe=""),
            f"https://target.invalid@{domain}/AGY",
            f"https://{domain}\\AGY",
        ]
        sent = 0
        observations = []
        for value in values:
            if sent >= max(0, int(request_budget)):
                break
            request = {
                "url": self._same_parameter_url(url, parameter, value),
                "method": "GET", "headers": dict(headers or {}), "body": None,
            }
            response = self._send(request)
            sent += 1
            locations = [
                str(item.get("to", "")) for item in (response.get("redirects", []) or [])
                if isinstance(item, Mapping)
            ]
            location = _header_values(response).get("location")
            if location:
                locations.append(location)
            observed = any(domain in item.lower() for item in locations)
            observations.append({
                "representation": value, "request": safe_request_evidence(request),
                "response": safe_response_evidence(response),
                "locations": locations, "researcher_domain_observed": observed,
            })
        verified = any(item["researcher_domain_observed"] for item in observations)
        return {
            "strategy": "open_redirect_parser_differential",
            "verified": verified, "status": "VERIFIED" if verified else "SUSPECTED",
            "requests_used": sent, "researcher_controlled_domain": domain,
            "observations": observations,
            "checks": [
                {"name": "researcher_controlled_location_observed", "passed": verified},
                {"name": "no_phishing_flow_created", "passed": True},
            ],
            "missing_evidence": [] if verified else [
                "A redirect to the researcher-controlled domain was not observed"
            ],
        }

    test_redirect_bypass = test_open_redirect_variants

    def test_cors_origin_variants(
        self, url: str, *,
        authenticated_headers: Optional[Mapping[str, str]] = None,
        researcher_domain: str = "cors-canary.invalid",
        request_budget: int = 8,
        browser_read_proof: Any = None,
    ) -> dict[str, Any]:
        """Analyze origin matching; browser-readable data is still required."""
        domain = str(researcher_domain).lower().strip()
        origins = [
            f"https://{domain}",
            f"https://sub.{domain}",
            f"https://{domain}.attacker.invalid",
            f"https://attacker-{domain}",
            "null",
            f"http://{domain}",
            f"https://{domain}:8443",
        ]
        sent = 0
        observations = []
        for origin in origins:
            if sent >= max(0, int(request_budget)):
                break
            request = {
                "url": url, "method": "GET",
                "headers": {**dict(authenticated_headers or {}), "Origin": origin},
                "body": None,
            }
            response = self._send(request)
            sent += 1
            response_headers = _header_values(response)
            observations.append({
                "origin": origin, "request": safe_request_evidence(request),
                "response": safe_response_evidence(response),
                "allow_origin": response_headers.get("access-control-allow-origin", ""),
                "allow_credentials": response_headers.get(
                    "access-control-allow-credentials", "").lower() == "true",
            })
        if callable(browser_read_proof):
            proof = browser_read_proof(observations)
        else:
            proof = browser_read_proof
        browser_verified = bool(
            proof.get("read_authenticated_response")
            if isinstance(proof, Mapping) else proof
        )
        reflected = [
            item for item in observations
            if item["allow_origin"] == item["origin"]
            and item["allow_credentials"]
        ]
        verified = bool(reflected and browser_verified)
        return {
            "strategy": "cors_origin_matching_differential",
            "verified": verified, "status": "VERIFIED" if verified else "SUSPECTED",
            "requests_used": sent, "observations": observations,
            "reflected_credentialed_origins": [item["origin"] for item in reflected],
            "browser_read_proof": proof,
            "checks": [
                {"name": "origin_matching_observed", "passed": bool(reflected)},
                {"name": "browser_can_read_authenticated_response", "passed": browser_verified},
            ],
            "missing_evidence": [] if verified else [
                "CORS headers alone are insufficient; browser credentialed read proof is required"
            ],
        }

    test_cors_bypass = test_cors_origin_variants


# Compatibility import.  The canonical implementation now lives in
# ``core.deep_exploit_engine``; lazy resolution avoids a circular import while
# preserving ``from redteam_agent.core.bypass_engine import DeepExploitEngine``.
def __getattr__(name: str):
    if name == "DeepExploitEngine":
        from redteam_agent.core.deep_exploit_engine import DeepExploitEngine
        return DeepExploitEngine
    raise AttributeError(name)
