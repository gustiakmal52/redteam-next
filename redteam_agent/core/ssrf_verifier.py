"""Target-specific SSRF request construction and OAST proof handling.

This module never contacts a callback host itself. The callback URL is an
operator-supplied researcher endpoint placed into the in-scope request. A
finding becomes VERIFIED only when the operator supplies callback evidence tied
to the per-attempt token, or when an in-scope deterministic marker returned by
the target proves that the server fetched the controlled resource.
"""

from __future__ import annotations

import ipaddress
import re
import urllib.parse
import uuid
from typing import Any, Mapping, Optional, Sequence


def _safe_callback_url(value: str) -> str:
    url = str(value or "").strip()
    if "{token}" not in url:
        return url
    return url.replace("{token}", "")


def _with_token(callback_url: str, token: str) -> str:
    value = str(callback_url or "").strip()
    if "{token}" in value:
        return value.replace("{token}", token)
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("controlled callback must be an absolute http(s) URL")
    pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    pairs.append(("rt_token", token))
    return urllib.parse.urlunsplit(parsed._replace(query=urllib.parse.urlencode(pairs)))


def validate_callback_url(callback_url: str) -> dict[str, Any]:
    """Validate an operator-provided callback without making a network call."""
    raw = _safe_callback_url(callback_url)
    try:
        parsed = urllib.parse.urlsplit(raw)
        host = parsed.hostname or ""
        port = parsed.port
    except ValueError as exc:
        return {"allowed": False, "reason": f"invalid callback URL: {exc}"}
    if parsed.scheme.lower() not in {"http", "https"} or not host:
        return {"allowed": False, "reason": "callback must use an absolute http(s) URL"}
    if parsed.username or parsed.password:
        return {"allowed": False, "reason": "callback userinfo is not accepted"}
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None and not address.is_global:
        return {"allowed": False, "reason": "callback must not target a private or link-local address"}
    return {"allowed": True, "scheme": parsed.scheme.lower(), "host": host.lower(), "port": port}


def callback_variants(callback_url: str, *, token: Optional[str] = None,
                      include_redirect_form: bool = False,
                      redirector_url: Optional[str] = None) -> list[dict[str, str]]:
    """Create a small, ranked set of parser representations.

    The redirect form is included only when the researcher supplies a
    researcher-controlled redirector. No third-party redirector is guessed.
    """
    validation = validate_callback_url(callback_url)
    if not validation.get("allowed"):
        return []
    token = token or f"rt-{uuid.uuid4().hex[:12]}"
    direct = _with_token(callback_url, token)
    parsed = urllib.parse.urlsplit(direct)
    variants: list[dict[str, str]] = [{"label": "direct", "url": direct}]
    encoded = urllib.parse.quote(direct, safe="")
    variants.append({"label": "percent_encoded", "url": encoded})
    variants.append({
        "label": "scheme_case", "url": urllib.parse.urlunsplit(
            parsed._replace(scheme=parsed.scheme.upper()))
    })
    if parsed.hostname and ":" not in parsed.hostname and not parsed.hostname.endswith("."):
        variants.append({
            "label": "trailing_dot_host", "url": urllib.parse.urlunsplit(
                parsed._replace(netloc=parsed.hostname + "." + (f":{parsed.port}" if parsed.port else "")))
        })
    # Scheme-relative URLs are a common allowlist/parser boundary and remain
    # researcher-controlled; they do not cause the engine to contact the host.
    variants.append({
        "label": "scheme_relative", "url": "//" + parsed.netloc + (parsed.path or "/")
        + (("?" + parsed.query) if parsed.query else "")
    })
    if include_redirect_form and redirector_url:
        redirect_validation = validate_callback_url(redirector_url)
        if redirect_validation.get("allowed"):
            redirect_target = urllib.parse.urlencode({"url": direct})
            variants.append({
                "label": "researcher_redirector", "url": redirector_url +
                ("&" if "?" in redirector_url else "?") + redirect_target
            })
    deduped: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in variants:
        if item["url"] not in seen:
            seen.add(item["url"])
            deduped.append(item)
    return deduped


def callback_proof(callback_evidence: Optional[Mapping[str, Any]], *, token: str) -> dict[str, Any]:
    """Require a token-bound OAST observation rather than a bare boolean."""
    evidence = dict(callback_evidence or {})
    observed = bool(evidence.get("observed"))
    serialized = str(evidence).lower()
    token_seen = token.lower() in serialized
    request_id = evidence.get("request_id") or evidence.get("interaction_id")
    valid = observed and token_seen and bool(request_id or evidence.get("request_url") or evidence.get("path"))
    return {
        "verified": valid, "observed": observed, "token_bound": token_seen,
        "interaction_id_present": bool(request_id),
        "evidence_source": str(evidence.get("source") or "operator_callback"),
        "redacted": True,
    }


def deterministic_marker_proof(response_body: str, baseline_bodies: Sequence[str],
                               marker: Optional[str], *, echoed_input: Optional[str] = None) -> dict[str, Any]:
    marker = str(marker or "")
    body = str(response_body or "")
    baseline = "\n".join(str(item or "") for item in baseline_bodies)
    present = bool(marker and marker in body)
    absent_from_baseline = bool(marker and marker not in baseline)
    echoed = bool(echoed_input and echoed_input in body)
    verified = present and absent_from_baseline and not echoed
    return {
        "verified": verified, "marker_present": present,
        "marker_absent_from_baseline": absent_from_baseline,
        "input_echo_only": echoed, "redacted": True,
    }


__all__ = [
    "callback_proof", "callback_variants", "deterministic_marker_proof",
    "validate_callback_url",
]
