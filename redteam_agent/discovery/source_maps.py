"""Bounded source-map discovery and source-content hand-off."""

from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
from typing import Any, Dict, Iterable, List, Optional

from redteam_agent.discovery.models import SourceMapRecord
from redteam_agent.discovery.redaction import SecretRedactor


class SourceMapAnalyzer:
    """Find and parse source maps without retaining an entire map in results."""

    COMMENT_RE = re.compile(r"(?:\/\/[#@]\s*sourceMappingURL\s*=|\/\*[@#]\s*sourceMappingURL\s*=)\s*([^\s*'\"]+)")

    def __init__(self, *, max_source_map_size: int = 5 * 1024 * 1024,
                 max_sources_content: int = 100, max_source_length: int = 2 * 1024 * 1024,
                 redactor: Optional[SecretRedactor] = None, kill_switch: Any = None):
        self.max_source_map_size = max(1024, int(max_source_map_size))
        self.max_sources_content = max(1, int(max_sources_content))
        self.max_source_length = max(1024, int(max_source_length))
        self.redactor = redactor or SecretRedactor()
        self.kill_switch = kill_switch

    def stopped(self) -> bool:
        if callable(self.kill_switch):
            try:
                return bool(self.kill_switch())
            except Exception:
                return True
        return bool(self.kill_switch)

    def discover_url(self, asset_url: str, javascript: str) -> Optional[str]:
        match = self.COMMENT_RE.search(javascript or "")
        if match:
            return urllib.parse.urljoin(asset_url, match.group(1).strip())
        # A fallback is useful for production bundles which omit the comment,
        # but it remains a candidate until the exact .map request succeeds.
        if asset_url.lower().split("?", 1)[0].endswith((".js", ".mjs", ".cjs")):
            return asset_url.split("?", 1)[0] + ".map"
        return None

    # Compatibility with callers that use the common source-map terminology.
    discover = discover_url

    def parse(self, map_url: str, body: str, *, parent_asset: Optional[str] = None,
              content_type: Optional[str] = None) -> Dict[str, Any]:
        body = body or ""
        body_size = len(body.encode("utf-8", errors="replace"))
        base = {
            "map_url": map_url, "parent_asset": parent_asset, "size": body_size,
            "body_hash": hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest(),
            "content_type": content_type,
        }
        if self.stopped():
            record = SourceMapRecord(map_url, parent_asset=parent_asset, status="CANCELLED",
                                     size=body_size, body_hash=base["body_hash"],
                                     skipped_reason="kill switch activated")
            return {**base, "record": record, "source_units": [], "status": record.status}
        if body_size > self.max_source_map_size:
            record = SourceMapRecord(map_url, parent_asset=parent_asset, status="SKIPPED_SIZE_LIMIT",
                                     size=body_size, body_hash=base["body_hash"],
                                     skipped_reason="source map exceeds max_source_map_size")
            return {**base, "record": record, "source_units": [], "status": record.status}
        try:
            parsed = json.loads(body)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            record = SourceMapRecord(map_url, parent_asset=parent_asset, status="PARSE_ERROR",
                                     size=body_size, body_hash=base["body_hash"],
                                     skipped_reason=f"invalid source map JSON: {exc}")
            return {**base, "record": record, "source_units": [], "status": record.status}
        if not isinstance(parsed, dict) or not isinstance(parsed.get("sources", []), list):
            record = SourceMapRecord(map_url, parent_asset=parent_asset, status="NOT_SOURCE_MAP",
                                     size=body_size, body_hash=base["body_hash"],
                                     skipped_reason="JSON object has no sources array")
            return {**base, "record": record, "source_units": [], "status": record.status}

        sources = [str(value) for value in parsed.get("sources", [])[: self.max_sources_content]]
        contents = parsed.get("sourcesContent", [])
        if not isinstance(contents, list):
            contents = []
        source_units: List[Dict[str, Any]] = []
        for index, source_name in enumerate(sources):
            if self.stopped():
                break
            source_code = contents[index] if index < len(contents) else None
            if not isinstance(source_code, str) or not source_code:
                continue
            if len(source_code.encode("utf-8", errors="replace")) > self.max_source_length:
                source_units.append({
                    "source_file": source_name, "status": "SKIPPED_SIZE_LIMIT",
                    "source_map": map_url, "parent_asset": parent_asset,
                    "discovered_asset": source_name,
                    "evidence": {"map_url": map_url, "source_file": source_name,
                                 "reason": "source exceeds max_source_length"},
                })
                continue
            # The source itself is intentionally handed to the in-process
            # analyzers and never copied into the report object.
            source_units.append({
                "source_file": source_name,
                "source_code": source_code,
                "source_map": map_url,
                "parent_asset": parent_asset,
                "status": "READY",
                "evidence": {"map_url": map_url, "source_file": source_name,
                             "discovered_asset": source_name},
            })
        record = SourceMapRecord(
            map_url=map_url, parent_asset=parent_asset, status="PARSED",
            sources=sources, sources_content_count=len([unit for unit in source_units if unit.get("status") == "READY"]),
            source_root=str(parsed.get("sourceRoot")) if parsed.get("sourceRoot") is not None else None,
            names_count=len(parsed.get("names", [])) if isinstance(parsed.get("names", []), list) else 0,
            body_hash=base["body_hash"], size=body_size,
            evidence=[{"map_url": map_url, "source_file": source_name,
                       "discovered_asset": source_name}
                      for source_name in sources[: self.max_sources_content]],
        )
        return {**base, "record": record, "source_units": source_units, "status": record.status}

    def evidence_for(self, map_url: str, source_file: str, discovered_asset: Optional[str] = None,
                     context: str = "") -> Dict[str, Any]:
        return {
            "map_url": map_url,
            "source_file": source_file,
            "discovered_asset": discovered_asset or source_file,
            "context": self.redactor.redact_text(context)[:500],
        }


__all__ = ["SourceMapAnalyzer"]

