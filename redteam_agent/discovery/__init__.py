"""Hidden asset, configuration, credential, and auth-flow discovery."""

from redteam_agent.discovery.auth_flow import AuthFlowAnalyzer
from redteam_agent.discovery.asset_crawler import AssetCrawler
from redteam_agent.discovery.baas_correlation import BaaSCorrelationEngine
from redteam_agent.discovery.credentials import CredentialDiscoveryEngine
from redteam_agent.discovery.endpoint_graph import EndpointGraphBuilder
from redteam_agent.discovery.hidden_assets import DiscoveryBudget, HiddenAssetEngine
from redteam_agent.discovery.js_deep import JSDeepAnalyzer, LightDataFlowAnalyzer
from redteam_agent.discovery.models import (
    AssetRecord, AuthFlow, AuthFlowNode, BaaSProject, CredentialRecord, DiscoveryResult,
    EndpointRecord, FirebaseProject, RelationshipRecord, RuntimeConfigRecord, SourceMapRecord,
    SupabaseProject,
)
from redteam_agent.discovery.redaction import SecretRedactor
from redteam_agent.discovery.runtime_config import RuntimeConfigAnalyzer
from redteam_agent.discovery.source_maps import SourceMapAnalyzer

__all__ = [
    "AssetCrawler", "AssetRecord", "AuthFlow", "AuthFlowAnalyzer", "AuthFlowNode", "BaaSProject",
    "BaaSCorrelationEngine", "CredentialDiscoveryEngine", "CredentialRecord",
    "DiscoveryBudget", "DiscoveryResult", "EndpointGraphBuilder", "EndpointRecord", "FirebaseProject",
    "HiddenAssetEngine", "JSDeepAnalyzer", "LightDataFlowAnalyzer", "RelationshipRecord",
    "RuntimeConfigAnalyzer", "RuntimeConfigRecord", "SecretRedactor", "SourceMapAnalyzer",
    "SourceMapRecord", "SupabaseProject",
]
