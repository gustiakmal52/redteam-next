"""Turn researcher-captured HTTP traffic into target-specific endpoint evidence."""

from __future__ import annotations

import json
import urllib.parse
from typing import Any, Iterable, Mapping, Optional

from redteam_agent.core.scope_manager import ScopeManager
from redteam_agent.discovery.models import EndpointRecord


AUTH_HEADER_NAMES = {
    "authorization", "cookie", "x-api-key", "api-key", "x-auth-token",
    "x-access-token", "x-csrf-token", "x-xsrf-token", "x-mw-authentication",
}


class RequestCorpusError(ValueError):
    pass


def _header_map(value: Any) -> dict[str, str]:
    if isinstance(value, Mapping):
        return {str(key): str(item) for key, item in value.items()}
    if isinstance(value, list):
        result: dict[str, str] = {}
        for item in value:
            if isinstance(item, Mapping) and item.get("name") is not None:
                result[str(item["name"])] = str(item.get("value") or "")
        return result
    return {}


def _shape_from_body(body: Any, content_type: str = "") -> dict[str, Any]:
    if body in (None, ""):
        return {"fields": [], "content_type": content_type or None}
    parsed: Any = body
    if isinstance(body, str) and ("json" in content_type.lower() or body.lstrip().startswith(("{", "["))):
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            parsed = body
    if isinstance(parsed, Mapping):
        return {
            "fields": [str(key) for key in parsed.keys()],
            "content_type": content_type or "application/json",
            "shape": "object",
        }
    if isinstance(body, str) and "application/x-www-form-urlencoded" in content_type.lower():
        return {
            "fields": list(dict.fromkeys(
                key for key, _ in urllib.parse.parse_qsl(body, keep_blank_values=True)
            )),
            "content_type": content_type,
            "shape": "form",
        }
    return {"fields": [], "content_type": content_type or None, "shape": "opaque"}


def _entries(document: Any) -> list[Mapping[str, Any]]:
    if isinstance(document, Mapping) and isinstance(document.get("log"), Mapping):
        entries = document["log"].get("entries")
        if not isinstance(entries, list):
            raise RequestCorpusError("HAR log.entries must be a list")
        return [item for item in entries if isinstance(item, Mapping)]
    if isinstance(document, Mapping) and isinstance(document.get("requests"), list):
        return [item for item in document["requests"] if isinstance(item, Mapping)]
    if isinstance(document, list):
        return [item for item in document if isinstance(item, Mapping)]
    raise RequestCorpusError("request corpus must be a HAR object, {requests: [...]}, or a JSON list")


def _request_from_entry(entry: Mapping[str, Any]) -> Mapping[str, Any]:
    request = entry.get("request")
    return request if isinstance(request, Mapping) else entry


def endpoint_records_from_corpus(
    document: Any,
    *,
    scope_manager: ScopeManager,
    source_name: str = "researcher_capture",
) -> tuple[list[EndpointRecord], dict[str, Any]]:
    """Parse captured traffic without retaining header/body secret values."""
    records: list[EndpointRecord] = []
    rejected: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    entries = _entries(document)
    for index, entry in enumerate(entries):
        request = _request_from_entry(entry)
        url = str(request.get("url") or "").strip()
        method = str(request.get("method") or "GET").upper()
        if not url or urllib.parse.urlsplit(url).scheme.lower() not in {"http", "https"}:
            rejected.append({"index": index, "reason": "missing or non-http(s) URL"})
            continue
        scope = scope_manager.check_url(url, active=False)
        if not scope.get("in_scope"):
            rejected.append({"index": index, "url": url, "reason": "outside active engagement scope"})
            continue
        headers = _header_map(request.get("headers"))
        lower_headers = {key.lower(): value for key, value in headers.items()}
        content_type = lower_headers.get("content-type", "")
        post_data = request.get("postData")
        if isinstance(post_data, Mapping):
            content_type = str(post_data.get("mimeType") or content_type)
            body = post_data.get("text")
            if body in (None, "") and isinstance(post_data.get("params"), list):
                body = {
                    str(item.get("name")): ""
                    for item in post_data["params"] if isinstance(item, Mapping) and item.get("name")
                }
        else:
            body = request.get("body")
        shape = _shape_from_body(body, content_type)
        descriptor_headers = {
            key: "captured-present"
            for key in headers
            if key.lower() in AUTH_HEADER_NAMES or key.lower() in {"accept", "content-type", "origin", "referer"}
        }
        key = (url, method)
        if key in seen:
            continue
        seen.add(key)
        records.append(EndpointRecord(
            url=url,
            method=method,
            source_file=source_name,
            source_line=index + 1,
            request_type="GraphQL" if "graphql" in url.lower() else "REST",
            headers=descriptor_headers,
            body_shape=shape,
            auth_required=any(name in AUTH_HEADER_NAMES for name in lower_headers),
            auth_source="captured request header" if any(name in AUTH_HEADER_NAMES for name in lower_headers) else None,
            confidence=0.98,
            evidence=[{
                "source": "researcher_capture",
                "capture_index": index,
                "query_fields": list(dict.fromkeys(
                    name for name, _ in urllib.parse.parse_qsl(
                        urllib.parse.urlsplit(url).query, keep_blank_values=True
                    )
                )),
                "body_fields": shape.get("fields", []),
                "authorization_material_retained": False,
            }],
            metadata={"target_specific": True, "capture_source": source_name},
        ))
    summary = {
        "source": source_name,
        "entries_seen": len(entries),
        "in_scope_unique_requests": len(records),
        "rejected": rejected,
        "credentials_retained": False,
    }
    return records, summary


__all__ = ["RequestCorpusError", "endpoint_records_from_corpus"]
