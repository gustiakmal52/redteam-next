"""Endpoint/credential/asset relationship graph builder."""

from __future__ import annotations

import hashlib
import urllib.parse
from collections import defaultdict
from typing import Any, Dict, Iterable, List, Optional

from redteam_agent.discovery.models import EndpointRecord, RelationshipRecord


class EndpointGraphBuilder:
    """Deduplicate endpoint records while preserving every source edge."""

    def __init__(self):
        self.endpoints: Dict[tuple[str, str], EndpointRecord] = {}
        self.relationships: Dict[tuple[str, str, str], RelationshipRecord] = {}

    @staticmethod
    def endpoint_key(url: str, method: str = "GET") -> tuple[str, str]:
        parsed = urllib.parse.urlsplit(url or "")
        query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        normalized_query = urllib.parse.urlencode(query, doseq=True)
        normalized = urllib.parse.urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/",
                                              normalized_query, ""))
        return normalized, (method or "GET").upper()

    @staticmethod
    def asset_node(url: str) -> str:
        return f"asset:{url}"

    @staticmethod
    def endpoint_node(record: EndpointRecord) -> str:
        endpoint, method = EndpointGraphBuilder.endpoint_key(record.url, record.method)
        return f"endpoint:{method} {endpoint}"

    @staticmethod
    def credential_node(sha256: str, credential_type: str = "credential") -> str:
        return f"credential:{credential_type}:{sha256}"

    def add_endpoint(self, record: EndpointRecord) -> EndpointRecord:
        key = self.endpoint_key(record.url, record.method)
        existing = self.endpoints.get(key)
        if existing is None:
            self.endpoints[key] = record
            existing = record
        else:
            existing.confidence = max(existing.confidence, record.confidence)
            existing.headers.update(record.headers)
            existing.body_shape.update(record.body_shape)
            existing.auth_required = record.auth_required if record.auth_required is not None else existing.auth_required
            existing.auth_source = record.auth_source or existing.auth_source
            existing.source_map = record.source_map or existing.source_map
            existing.evidence.extend(item for item in record.evidence if item not in existing.evidence)
            if record.source_file not in {existing.source_file, "unknown"}:
                existing.metadata.setdefault("source_files", []).append(record.source_file)
        return existing

    def add_relationship(self, relationship_type: str, from_node: str, to_node: str, *, source: Optional[str] = None,
                         evidence: Optional[Dict[str, Any]] = None, confidence: float = .7) -> RelationshipRecord:
        key = (relationship_type, from_node, to_node)
        record = self.relationships.get(key)
        if record is None:
            record = RelationshipRecord(relationship_type, from_node, to_node, source=source,
                                        evidence=evidence or {}, confidence=confidence)
            self.relationships[key] = record
        else:
            record.confidence = max(record.confidence, confidence)
            if source and source != record.source:
                record.evidence.setdefault("sources", []).append(source)
            if evidence:
                record.evidence.update(evidence)
        return record

    def add_asset_to_endpoint(self, asset_url: str, endpoint: EndpointRecord, *, source: Optional[str] = None) -> None:
        self.add_relationship("asset_to_endpoint", self.asset_node(asset_url), self.endpoint_node(endpoint),
                              source=source or endpoint.source_file,
                              evidence={"source_file": endpoint.source_file, "source_line": endpoint.source_line},
                              confidence=endpoint.confidence)

    def add_credential_to_endpoint(self, credential: Any, endpoint: EndpointRecord, *, usage: Optional[str] = None) -> None:
        fingerprint = getattr(credential, "sha256", None) or (credential.get("sha256") if isinstance(credential, dict) else None)
        ctype = getattr(credential, "credential_type", "credential") or (credential.get("credential_type", "credential") if isinstance(credential, dict) else "credential")
        if not fingerprint:
            return
        node = self.credential_node(fingerprint, ctype)
        self.add_relationship("credential_to_endpoint", node, self.endpoint_node(endpoint),
                              source=getattr(credential, "source_file", None) or (credential.get("source_file") if isinstance(credential, dict) else None),
                              evidence={"usage": usage or "authentication/header reference"}, confidence=.8)

    def add_asset_to_credential(self, asset_url: str, credential: Any) -> None:
        fingerprint = getattr(credential, "sha256", None) or (credential.get("sha256") if isinstance(credential, dict) else None)
        ctype = getattr(credential, "credential_type", "credential") or (credential.get("credential_type", "credential") if isinstance(credential, dict) else "credential")
        if not fingerprint:
            return
        self.add_relationship("asset_to_credential", self.asset_node(asset_url),
                              self.credential_node(fingerprint, ctype),
                              source=getattr(credential, "source_file", None) or (credential.get("source_file") if isinstance(credential, dict) else None),
                              evidence={"source_url": asset_url}, confidence=.85)

    def add_frontend_route(self, route: str, asset_url: str, *, source: Optional[str] = None) -> None:
        self.add_relationship("frontend_route_to_asset", f"route:{route}", self.asset_node(asset_url), source=source)

    def build(self) -> Dict[str, Any]:
        return {
            "endpoints": [item.to_dict() for item in self.endpoints.values()],
            "relationships": [item.to_dict() for item in self.relationships.values()],
            "nodes": self.node_summary(),
        }

    def node_summary(self) -> Dict[str, int]:
        counts = defaultdict(int)
        for record in self.endpoints.values():
            counts["endpoint"] += 1
            if record.parent_asset:
                counts["asset"] += 1
        for record in self.relationships.values():
            counts[record.relationship_type] += 1
        return dict(counts)

    def relationship_records(self) -> List[RelationshipRecord]:
        return list(self.relationships.values())


__all__ = ["EndpointGraphBuilder"]

