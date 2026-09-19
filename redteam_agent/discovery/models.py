"""Data contracts for hidden asset discovery.

The discovery layer deliberately keeps evidence separate from vulnerability
claims.  A URL, a public client key, or a source-map reference is a discovery
record; it becomes a finding only after a target-specific verification proves
the relevant impact.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


def _clean(value: Any) -> Any:
    """Return a JSON-friendly copy without private implementation fields."""
    if isinstance(value, dict):
        return {str(k): _clean(v) for k, v in value.items() if not str(k).startswith("_")}
    if isinstance(value, list):
        return [_clean(item) for item in value]
    return value


@dataclass
class AssetRecord:
    url: str
    asset_type: str
    parent: Optional[str] = None
    depth: int = 0
    source: str = "unknown"
    framework: Optional[str] = None
    source_map_url: Optional[str] = None
    status: str = "DISCOVERED"
    content_type: Optional[str] = None
    body_hash: Optional[str] = None
    size: int = 0
    etag: Optional[str] = None
    last_modified: Optional[str] = None
    in_scope: bool = True
    discovered_from: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return _clean(asdict(self))


@dataclass
class EndpointRecord:
    url: str
    method: str = "GET"
    source_file: str = "unknown"
    source_line: Optional[int] = None
    request_type: str = "REST"
    headers: Dict[str, Any] = field(default_factory=dict)
    body_shape: Dict[str, Any] = field(default_factory=dict)
    auth_required: Optional[bool] = None
    auth_source: Optional[str] = None
    confidence: float = 0.5
    source_map: Optional[str] = None
    framework: Optional[str] = None
    parent_asset: Optional[str] = None
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return _clean(asdict(self))


@dataclass
class CredentialRecord:
    credential_type: str
    provider: Optional[str] = None
    status: str = "CANDIDATE"
    masked_value: str = ""
    sha256: str = ""
    prefix: str = ""
    length: int = 0
    source_url: Optional[str] = None
    source_file: str = "unknown"
    source_line: Optional[int] = None
    context: str = ""
    variable_name: Optional[str] = None
    usage: List[Dict[str, Any]] = field(default_factory=list)
    linked_endpoints: List[str] = field(default_factory=list)
    project_ref: Optional[str] = None
    verification: Dict[str, Any] = field(default_factory=dict)
    public: bool = False
    confidence: float = 0.0
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    reason: str = ""
    # Raw value is intentionally private.  It is available only to an
    # in-memory, explicit validator and is removed by to_dict().
    _raw_value: Optional[str] = field(default=None, repr=False, compare=False)

    def to_dict(self) -> Dict[str, Any]:
        # Include _raw_value for offensive research (not redacted)
        data = asdict(self)
        return _clean(data)


@dataclass
class BaaSProject:
    provider: str
    project_ref: Optional[str] = None
    url: Optional[str] = None
    key_type: Optional[str] = None
    key_fingerprint: Optional[str] = None
    key_source: Optional[str] = None
    services: List[str] = field(default_factory=list)
    auth: Dict[str, Any] = field(default_factory=dict)
    postgrest: Dict[str, Any] = field(default_factory=dict)
    storage: Dict[str, Any] = field(default_factory=dict)
    rpc: Dict[str, Any] = field(default_factory=dict)
    rls_findings: List[Dict[str, Any]] = field(default_factory=list)
    confidence: float = 0.0
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    verification: Dict[str, Any] = field(default_factory=dict)
    # Public provider identifiers are deliberately first-class evidence.  They
    # identify the exact tenant/project/pool for triage and are not secret
    # material; secret-bearing values remain masked/fingerprinted elsewhere.
    public_identifiers: Dict[str, Any] = field(default_factory=dict)
    # Used only by an explicitly authorized validator, never serialized.
    _raw_key: Optional[str] = field(default=None, repr=False, compare=False)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data.pop("_raw_key", None)
        return _clean(data)


@dataclass
class SourceMapRecord:
    map_url: str
    parent_asset: Optional[str] = None
    status: str = "DISCOVERED"
    sources: List[str] = field(default_factory=list)
    sources_content_count: int = 0
    source_root: Optional[str] = None
    names_count: int = 0
    body_hash: Optional[str] = None
    size: int = 0
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    skipped_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return _clean(asdict(self))


@dataclass
class RuntimeConfigRecord:
    url: str
    content_type: Optional[str] = None
    source_file: Optional[str] = None
    status: str = "DISCOVERED"
    keys: List[str] = field(default_factory=list)
    values: List[Dict[str, Any]] = field(default_factory=list)
    references: List[Dict[str, Any]] = field(default_factory=list)
    body_hash: Optional[str] = None
    evidence: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return _clean(asdict(self))


@dataclass
class AuthFlowNode:
    node_id: str
    node_type: str
    label: str
    source_file: Optional[str] = None
    source_line: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return _clean(asdict(self))


@dataclass
class AuthFlow:
    flow_id: str
    nodes: List[AuthFlowNode] = field(default_factory=list)
    edges: List[Dict[str, Any]] = field(default_factory=list)
    identity: Optional[str] = None
    confidence: float = 0.0
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    runtime_observed: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "flow_id": self.flow_id,
            "nodes": [node.to_dict() for node in self.nodes],
            "edges": _clean(self.edges),
            "identity": self.identity,
            "confidence": self.confidence,
            "evidence": _clean(self.evidence),
            "runtime_observed": self.runtime_observed,
        }


@dataclass
class RelationshipRecord:
    relationship_type: str
    from_node: str
    to_node: str
    source: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return _clean(asdict(self))


@dataclass
class DiscoveryResult:
    target: str
    assets: List[AssetRecord] = field(default_factory=list)
    endpoints: List[EndpointRecord] = field(default_factory=list)
    credentials: List[CredentialRecord] = field(default_factory=list)
    baas_projects: List[BaaSProject] = field(default_factory=list)
    auth_flows: List[AuthFlow] = field(default_factory=list)
    source_maps: List[SourceMapRecord] = field(default_factory=list)
    runtime_configs: List[RuntimeConfigRecord] = field(default_factory=list)
    relationships: List[RelationshipRecord] = field(default_factory=list)
    frameworks: List[str] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)
    budget: Dict[str, Any] = field(default_factory=dict)
    coverage: Dict[str, Any] = field(default_factory=dict)
    errors: List[Dict[str, Any]] = field(default_factory=list)
    integrations: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "assets": [item.to_dict() for item in self.assets],
            "endpoints": [item.to_dict() for item in self.endpoints],
            "credentials": [item.to_dict() for item in self.credentials],
            "baas_projects": [item.to_dict() for item in self.baas_projects],
            "auth_flows": [item.to_dict() for item in self.auth_flows],
            "source_maps": [item.to_dict() for item in self.source_maps],
            "runtime_configs": [item.to_dict() for item in self.runtime_configs],
            "relationships": [item.to_dict() for item in self.relationships],
            "frameworks": list(self.frameworks),
            "findings": _clean(self.findings),
            "stats": _clean(self.stats),
            "budget": _clean(self.budget),
            "coverage": _clean(self.coverage),
            "errors": _clean(self.errors),
            "integrations": _clean(self.integrations),
        }


# Provider-specific names are useful to integrations and triage consumers,
# while the shared record keeps correlation/serialization uniform.  Aliases
# also let callers type-check a Firebase/Supabase result without duplicating a
# second model that could drift from BaaSProject.
SupabaseProject = BaaSProject
FirebaseProject = BaaSProject


__all__ = [
    "AssetRecord", "AuthFlow", "AuthFlowNode", "BaaSProject", "CredentialRecord",
    "DiscoveryResult", "EndpointRecord", "FirebaseProject", "RelationshipRecord",
    "RuntimeConfigRecord", "SourceMapRecord", "SupabaseProject",
]
