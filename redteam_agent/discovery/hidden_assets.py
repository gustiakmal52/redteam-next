"""First-class hidden asset/config/credential discovery orchestration."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
import urllib.parse
from collections import deque
from typing import Any, Deque, Dict, Iterable, List, Optional, Tuple

from redteam_agent.core.findings import FindingStatus, normalized_finding
from redteam_agent.core.http_verifier import HTTPVerifier
from redteam_agent.core.scope_manager import ScopeManager, URLPolicyError, normalize_url
from redteam_agent.discovery.asset_crawler import AssetCrawler
from redteam_agent.discovery.auth_flow import AuthFlowAnalyzer
from redteam_agent.discovery.baas_correlation import BaaSCorrelationEngine
from redteam_agent.discovery.credentials import CredentialDiscoveryEngine
from redteam_agent.discovery.endpoint_graph import EndpointGraphBuilder
from redteam_agent.discovery.js_deep import JSDeepAnalyzer
from redteam_agent.discovery.models import (
    AssetRecord, BaaSProject, CredentialRecord, DiscoveryResult, EndpointRecord,
    RelationshipRecord, RuntimeConfigRecord,
)
from redteam_agent.discovery.redaction import SecretRedactor
from redteam_agent.discovery.runtime_config import RuntimeConfigAnalyzer
from redteam_agent.discovery.source_maps import SourceMapAnalyzer


class DiscoveryBudget:
    """Independent asset/source-map/verification counters."""

    def __init__(self, asset_budget: int, source_map_budget: int, verification_budget: int,
                 request_budget: Optional[int] = None):
        self.limits = {
            "asset_budget": max(0, int(asset_budget)),
            "source_map_budget": max(0, int(source_map_budget)),
            "verification_budget": max(0, int(verification_budget)),
        }
        if request_budget is not None:
            self.limits["request_budget"] = max(0, int(request_budget))
        self.used = {key: 0 for key in self.limits}

    def claim(self, name: str) -> bool:
        if name not in self.limits:
            return False
        if self.used[name] >= self.limits[name]:
            return False
        self.used[name] += 1
        return True

    def remaining(self, name: str) -> int:
        return max(0, self.limits.get(name, 0) - self.used.get(name, 0))

    def report(self) -> Dict[str, Any]:
        return {"limits": dict(self.limits), "used": dict(self.used),
                "remaining": {key: self.remaining(key) for key in self.limits}}


class HiddenAssetEngine:
    """Shared CLI/Web discovery engine with bounded in-scope fetching.

    The engine is intentionally a coordinator.  Parsing, source-map handling,
    redaction, auth graphing, and BaaS pairing live in separate modules so a
    finding can be traced back to a source and a specific relationship.
    """

    def __init__(self, *, verifier: Optional[Any] = None, scope_manager: Optional[ScopeManager] = None,
                 traffic_controller: Any = None, http_verifier: Optional[Any] = None,
                 js_analyzer: Any = None, cloud_baas_hunter: Any = None,
                 deep_exploit_engine: Any = None, reference_intel: Any = None,
                 request_budget: int = 40, asset_budget: int = 25, source_map_budget: int = 8,
                 verification_budget: int = 4, max_depth: int = 3, max_assets: int = 100,
                 max_js_size: int = 2 * 1024 * 1024, max_source_map_size: int = 5 * 1024 * 1024,
                 max_sources_content: int = 100, max_source_length: int = 2 * 1024 * 1024,
                 kill_switch: Any = None, seed_cache: Optional[Dict[str, Dict[str, Any]]] = None):
        self.scope = scope_manager
        self.traffic = traffic_controller
        self.verifier = verifier or http_verifier or HTTPVerifier(
            traffic_controller=traffic_controller, scope_manager=scope_manager, module="hidden_assets"
        )
        self.legacy_js_analyzer = js_analyzer
        self.legacy_cloud_hunter = cloud_baas_hunter
        self.deep_exploit_engine = deep_exploit_engine
        self.reference_intel = reference_intel
        self.redactor = SecretRedactor()
        self.js = JSDeepAnalyzer(redactor=self.redactor)
        self.source_maps = SourceMapAnalyzer(
            max_source_map_size=max_source_map_size, max_sources_content=max_sources_content,
            max_source_length=max_source_length, redactor=self.redactor, kill_switch=self._stopped
        )
        self.runtime = RuntimeConfigAnalyzer(self.redactor)
        self.crawler = AssetCrawler(js_analyzer=self.js, runtime_config=self.runtime)
        self.credentials = CredentialDiscoveryEngine(self.redactor)
        self.auth = AuthFlowAnalyzer(redactor=self.redactor)
        self.baas = BaaSCorrelationEngine(redactor=self.redactor, cloud_hunter=cloud_baas_hunter)
        self.graph = EndpointGraphBuilder()
        self.request_budget = max(0, int(request_budget))
        self.asset_budget = max(0, int(asset_budget))
        self.source_map_budget = max(0, int(source_map_budget))
        self.verification_budget = max(0, int(verification_budget))
        self.max_depth = min(8, max(0, int(max_depth)))
        self.max_assets = max(1, int(max_assets))
        self.max_js_size = max(1024, int(max_js_size))
        self.max_source_map_size = max(1024, int(max_source_map_size))
        self.max_sources_content = max(1, int(max_sources_content))
        self.max_source_length = max(1024, int(max_source_length))
        self.kill_switch = kill_switch
        self._cache: Dict[str, Dict[str, Any]] = {}
        # A legacy JSAnalyzer may already have fetched the document or an
        # initial script.  Reuse its response in-process so enabling this
        # first-class layer does not double the same request.  The traffic
        # controller already accounted for the seeded request; only parsing and
        # this engine's asset budget are charged here.
        self._prefetched: Dict[str, Dict[str, Any]] = {}
        for raw_url, raw_response in (seed_cache or {}).items():
            if not isinstance(raw_response, dict):
                continue
            try:
                cache_url = normalize_url(str(raw_url))
            except URLPolicyError:
                continue
            self._prefetched[cache_url] = {
                "success": raw_response.get("success", False),
                "status_code": raw_response.get("status_code", raw_response.get("status", 0)),
                "headers": dict(raw_response.get("headers") or {}),
                "body": str(raw_response.get("body") or ""),
                "failure": raw_response.get("failure"),
            }
        self._seen_assets: set[str] = set()
        self._seen_maps: set[str] = set()
        self._source_entries: List[Dict[str, Any]] = []
        self._result: Optional[DiscoveryResult] = None
        self._budget: Optional[DiscoveryBudget] = None
        self._secret_discovery_active = True
        self._auth_flow_active = True

    def _stopped(self) -> bool:
        if callable(self.kill_switch):
            try:
                return bool(self.kill_switch())
            except Exception:
                return True
        if self.kill_switch:
            return True
        if self.traffic is not None:
            try:
                if self.traffic.stats().get("kill_switch"):
                    return True
            except Exception:
                pass
        return False

    def _scope(self, url: str, *, active: bool = True) -> Dict[str, Any]:
        if self.scope is None:
            return {"allowed": True, "in_scope": True, "url": url, "reason": "no explicit scope manager"}
        return self.scope.check_url(url, active=active)

    def _record_out_of_scope(self, url: str, *, parent: Optional[str], depth: int, source: str,
                             asset_type: str, decision: Dict[str, Any]) -> AssetRecord:
        record = AssetRecord(url=self.redactor.redact_url(url), asset_type=asset_type,
                             parent=self.redactor.redact_url(parent) if parent else parent,
                             depth=depth, source=source,
                             status="OUT_OF_SCOPE", in_scope=bool(decision.get("in_scope")),
                             discovered_from=decision.get("reason"), metadata={"active_fetch_skipped": True})
        if self._result is not None:
            self._result.assets.append(record)
            self._result.coverage.setdefault("out_of_scope", []).append({"url": self.redactor.redact_url(url), "reason": decision.get("reason")})
        return record

    @staticmethod
    def _header(headers: Optional[Dict[str, Any]], name: str) -> Optional[str]:
        wanted = name.lower()
        for key, value in (headers or {}).items():
            if str(key).lower() == wanted:
                return str(value)
        return None

    def _fetch(self, url: str, *, parent: Optional[str], depth: int, source: str,
               asset_type: str = "javascript") -> Tuple[AssetRecord, Optional[Dict[str, Any]]]:
        assert self._result is not None and self._budget is not None
        try:
            normalized = normalize_url(url)
        except URLPolicyError as exc:
            record = AssetRecord(url=self.redactor.redact_url(url), asset_type=asset_type,
                                 parent=self.redactor.redact_url(parent) if parent else parent,
                                 depth=depth, source=source,
                                 status="REJECTED_URL", in_scope=False, metadata={"reason": str(exc)})
            self._result.assets.append(record)
            return record, None
        decision = self._scope(normalized, active=True)
        if not decision.get("allowed"):
            return self._record_out_of_scope(normalized, parent=parent, depth=depth, source=source,
                                             asset_type=asset_type, decision=decision), None
        if normalized in self._cache:
            cached = self._cache[normalized]
            record = cached["record"]
            return record, cached.get("response")
        if self._stopped():
            record = AssetRecord(url=self.redactor.redact_url(normalized), asset_type=asset_type,
                                 parent=self.redactor.redact_url(parent) if parent else parent,
                                 depth=depth,
                                 source=source, status="CANCELLED", in_scope=True,
                                 metadata={"reason": "kill switch activated"})
            self._result.assets.append(record)
            return record, None
        if normalized in self._prefetched:
            response = self._prefetched[normalized]
            body = str(response.get("body") or "")
            headers = response.get("headers") or {}
            content_type = self._header(headers, "Content-Type")
            status_code = int(response.get("status_code") or 0)
            if not self._budget.claim("asset_budget"):
                record = AssetRecord(url=self.redactor.redact_url(normalized), asset_type=asset_type,
                                     parent=self.redactor.redact_url(parent) if parent else parent, depth=depth,
                                     source=source, status="SKIPPED_ASSET_BUDGET", in_scope=True,
                                     metadata={"seeded_response": True})
                self._result.assets.append(record)
                self._result.coverage.setdefault("budget_skips", []).append({"url": normalized, "budget": "asset_budget"})
                return record, None
            body_hash = hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest() if body else None
            record = AssetRecord(
                url=self.redactor.redact_url(normalized), asset_type=asset_type,
                parent=self.redactor.redact_url(parent) if parent else parent, depth=depth, source=source,
                status="FETCHED" if status_code == 200 else ("HTTP_ERROR" if status_code else "FETCH_FAILED"),
                content_type=content_type, body_hash=body_hash,
                size=len(body.encode("utf-8", errors="replace")),
                etag=self._header(headers, "ETag"), last_modified=self._header(headers, "Last-Modified"),
                in_scope=True,
                metadata={"status_code": status_code, "success": bool(response.get("success")),
                          "seeded_response": True, "traffic_request_reused": True},
            )
            self._cache[normalized] = {"record": record, "response": response}
            self._result.assets.append(record)
            return record, response if status_code == 200 else None
        if not self._budget.claim("asset_budget"):
            record = AssetRecord(url=self.redactor.redact_url(normalized), asset_type=asset_type,
                                 parent=self.redactor.redact_url(parent) if parent else parent, depth=depth,
                                 source=source, status="SKIPPED_ASSET_BUDGET", in_scope=True)
            self._result.assets.append(record)
            self._result.coverage.setdefault("budget_skips", []).append({"url": normalized, "budget": "asset_budget"})
            return record, None
        if "request_budget" in self._budget.limits and not self._budget.claim("request_budget"):
            record = AssetRecord(url=self.redactor.redact_url(normalized), asset_type=asset_type,
                                 parent=self.redactor.redact_url(parent) if parent else parent, depth=depth,
                                 source=source, status="SKIPPED_REQUEST_BUDGET", in_scope=True)
            self._result.assets.append(record)
            self._result.coverage.setdefault("budget_skips", []).append({"url": normalized, "budget": "request_budget"})
            return record, None
        try:
            response = self.verifier.send_http_request(normalized, priority="normal")
        except TypeError:
            response = self.verifier.send_http_request(normalized)
        body = str(response.get("body") or "") if isinstance(response, dict) else ""
        headers = response.get("headers") or {} if isinstance(response, dict) else {}
        content_type = self._header(headers, "Content-Type")
        status_code = int(response.get("status_code") or response.get("status") or 0) if isinstance(response, dict) else 0
        body_hash = hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest() if body else None
        record = AssetRecord(
            url=self.redactor.redact_url(normalized), asset_type=asset_type,
            parent=self.redactor.redact_url(parent) if parent else parent, depth=depth, source=source,
            status="FETCHED" if status_code == 200 else ("HTTP_ERROR" if status_code else "FETCH_FAILED"),
            content_type=content_type, body_hash=body_hash, size=len(body.encode("utf-8", errors="replace")),
            etag=self._header(headers, "ETag"), last_modified=self._header(headers, "Last-Modified"), in_scope=True,
            metadata={"status_code": status_code, "success": bool(response.get("success")) if isinstance(response, dict) else False},
        )
        self._cache[normalized] = {"record": record, "response": response}
        self._result.assets.append(record)
        return record, response if status_code == 200 else None

    def _add_source(self, text: str, *, source_url: str, source_file: str,
                    source_map: Optional[str] = None, asset: Optional[AssetRecord] = None) -> None:
        assert self._result is not None
        if not text or self._stopped():
            return
        if len(text.encode("utf-8", errors="replace")) > self.max_js_size:
            if asset:
                asset.status = "SKIPPED_SIZE_LIMIT"
                asset.metadata["reason"] = "max_js_size exceeded"
            self._result.coverage.setdefault("size_skips", []).append({"url": source_url, "limit": self.max_js_size})
            return
        analysis = self.js.analyze(text, source_file=source_file, source_url=source_url,
                                   source_map=source_map, framework=asset.framework if asset else None)
        frameworks = analysis.get("frameworks", [])
        for framework in frameworks:
            if framework not in self._result.frameworks:
                self._result.frameworks.append(framework)
        if asset and analysis.get("framework"):
            asset.framework = analysis["framework"]
        for route in analysis.get("frontend_routes", []):
            if asset:
                self.graph.add_frontend_route(route, asset.url, source=source_file)
        framework_signals = analysis.get("framework_signals") or {}
        if framework_signals.get("next_rsc_or_flight") or framework_signals.get("next_server_actions"):
            next_info = self._result.integrations.setdefault("next", {"detected": True})
            next_info["detected"] = True
            if framework_signals.get("next_rsc_or_flight"):
                next_info["rsc_or_flight_indicators"] = True
            if framework_signals.get("next_server_actions"):
                next_info["server_action_indicators"] = True
        if framework_signals.get("service_worker"):
            self._result.coverage["service_worker_observed"] = True
        if self.legacy_js_analyzer is not None:
            try:
                legacy_trace = self.legacy_js_analyzer.extract_api_calls(text, source_file)
                self._result.integrations.setdefault("legacy_js_analyzer", {"observed_call_count": 0})
                self._result.integrations["legacy_js_analyzer"]["observed_call_count"] += len(legacy_trace or [])
            except (AttributeError, TypeError, ValueError):
                self._result.integrations.setdefault("legacy_js_analyzer", {"status": "available_but_not_invoked"})
        self._source_entries.append({"text": text, "source_code": text, "source_url": source_url,
                                     "source_file": source_file, "source_map": source_map})

        endpoint_records: List[EndpointRecord] = analysis.get("endpoints", [])
        for endpoint in endpoint_records:
            endpoint.parent_asset = endpoint.parent_asset or source_url
            if self.scope:
                endpoint.metadata["scope"] = self._scope(endpoint.url, active=False)
            stored = self.graph.add_endpoint(endpoint)
            if asset:
                self.graph.add_asset_to_endpoint(asset.url, stored)
            self.credentials.link_endpoint(stored)
        for relationship in analysis.get("data_flow", {}).get("relationships", []):
            from_node = str(relationship.get("from") or "")
            to_node = str(relationship.get("to") or "")
            if from_node and to_node:
                self.graph.add_relationship(str(relationship.get("relationship_type") or "data_flow"),
                                            from_node, to_node, source=source_file,
                                            evidence={"source_line": relationship.get("source_line")}, confidence=.65)
        if self._result is not None:
            for endpoint in endpoint_records:
                self._result.endpoints.append(endpoint)
        if self._result is not None and self._secret_discovery_active:
            discovered = self.credentials.discover(text, source_url=source_url, source_file=source_file, source_map=source_map)
            for credential in discovered:
                if asset:
                    self.graph.add_asset_to_credential(asset.url, credential)
                for endpoint in endpoint_records:
                    if ((credential.variable_name and (credential.variable_name in str(endpoint.headers) or credential.variable_name in str(endpoint.auth_source)))
                            or (credential.credential_type == "BEARER_REFERENCE" and endpoint.auth_required)):
                        if endpoint.url not in credential.linked_endpoints:
                            credential.linked_endpoints.append(endpoint.url)
                        self.graph.add_credential_to_endpoint(credential, endpoint,
                                                             usage=credential.variable_name or "literal/auth reference")
                if credential.variable_name:
                    self.graph.add_relationship("credential_definition", f"credential:{credential.sha256}",
                                                f"variable:{credential.variable_name}", source=source_file,
                                                evidence={"source_line": credential.source_line}, confidence=.9)
        if self._result is not None:
            for ref in analysis.get("config_references", []):
                self._result.coverage.setdefault("config_references", []).append(ref)
            if analysis.get("config_references"):
                config_record = self.runtime.parse(
                    source_url, text, content_type="application/javascript", source_file=source_file,
                    references=analysis["config_references"])
                self._result.runtime_configs.append(config_record)
        if self._result is not None and self._auth_flow_active:
            flow = self.auth.analyze(text, source_file=source_file, source_url=source_url,
                                     endpoints=endpoint_records, data_flow=analysis.get("data_flow"), source_map=source_map)
            if flow.nodes or flow.evidence:
                self._result.auth_flows.append(flow)

        if asset and analysis.get("source_map_url"):
            asset.source_map_url = analysis["source_map_url"]
        # Asset recursion is handled by the caller so all refs pass the same
        # scope/budget gate.  Store refs in a queue-owned list on result.
        self._result.coverage.setdefault("pending_references", []).extend([
            {**ref, "parent": source_url, "depth": asset.depth + 1 if asset else 1}
            for ref in self.crawler.from_script(text, source_url, source_file=source_file)
        ])
        # SPA route strings are useful discovery inputs as well as graph
        # metadata.  Fetching a route is what causes route-local lazy chunks
        # and runtime configuration to appear in a server-rendered shell;
        # the normal scope/depth/budget gates decide whether it is attempted.
        for route in analysis.get("frontend_routes", []):
            route_url = urllib.parse.urljoin(source_url, route)
            self._result.coverage.setdefault("pending_references", []).append({
                "url": route_url, "asset_type": "frontend_route", "source_file": source_file,
                "source_line": None, "parent": source_url, "depth": asset.depth + 1 if asset else 1,
                "source": "frontend_route_discovery",
            })
        if asset:
            for endpoint in endpoint_records:
                self.graph.add_asset_to_endpoint(asset.url, endpoint)

    def _process_next_manifest(self, body: str, asset: AssetRecord, target_url: str,
                               queue: Deque[Dict[str, Any]], depth: int) -> None:
        """Parse exposed Next build/routes metadata and queue exact chunks.

        Next's client build manifest is normally JavaScript rather than JSON,
        so a JSON-only parser misses the page-to-chunk relationship.  This
        method reads only route keys and string chunk names; it never executes
        the manifest.  Every derived chunk still enters the normal scope,
        depth, asset, request, and kill-switch gates.
        """
        assert self._result is not None
        next_info = self._result.integrations.setdefault("next", {"detected": True})
        route_chunks: Dict[str, List[str]] = {}
        source_text = body or ""
        # Build manifests commonly contain {"/route":["static/chunks/...js"]}
        # or the same object inside a JS assignment/function wrapper.
        for match in re.finditer(
            r"(?P<quote>['\"])(?P<route>/[^'\"]{0,240})(?P=quote)\s*:\s*\[(?P<chunks>[^\]]{0,8000})\]",
            source_text,
        ):
            route = match.group("route")
            chunks = [value for value in re.findall(r"['\"]([^'\"]+\.(?:m?js))['\"]", match.group("chunks"), re.IGNORECASE)]
            if chunks:
                route_chunks.setdefault(route, []).extend(chunks)

        # Routes manifests are JSON in deployments that expose them.  Only
        # route names are retained; arbitrary values and rewrite destinations
        # are not copied into the discovery graph.
        try:
            parsed = json.loads(source_text)
        except (TypeError, ValueError, json.JSONDecodeError):
            parsed = None
        if isinstance(parsed, dict):
            for key in ("pages", "sortedPages", "staticPages", "routes"):
                values = parsed.get(key)
                if isinstance(values, list):
                    for value in values:
                        if isinstance(value, str) and value.startswith("/"):
                            route_chunks.setdefault(value, [])
            dynamic = parsed.get("dynamicRoutes")
            if isinstance(dynamic, list):
                for item in dynamic:
                    if isinstance(item, dict) and isinstance(item.get("page"), str):
                        route_chunks.setdefault(item["page"], [])

        build_id = str(next_info.get("buildId") or "")
        queued_chunks: set[str] = set()
        for route, chunks in route_chunks.items():
            next_info.setdefault("page_routes", [])
            if route not in next_info["page_routes"]:
                next_info["page_routes"].append(route)
            self.graph.add_relationship("next_route_to_manifest", f"route:{route}",
                                        self.graph.asset_node(asset.url), source=asset.url,
                                        evidence={"source_file": asset.source, "manifest": asset.url}, confidence=.9)
            for chunk in chunks:
                if chunk.startswith(("http://", "https://")):
                    chunk_url = chunk
                elif chunk.startswith("/_next/"):
                    chunk_url = urllib.parse.urljoin(target_url, chunk)
                elif build_id:
                    chunk_url = urllib.parse.urljoin(target_url, f"/_next/static/{build_id}/{chunk.lstrip('/')}")
                else:
                    chunk_url = urllib.parse.urljoin(asset.url, chunk)
                if chunk_url in queued_chunks:
                    continue
                queued_chunks.add(chunk_url)
                next_info.setdefault("manifest_assets", []).append(self.redactor.redact_url(chunk_url))
                self.graph.add_relationship("next_manifest_to_chunk", self.graph.asset_node(asset.url),
                                            self.graph.asset_node(self.redactor.redact_url(chunk_url)),
                                            source=asset.url, evidence={"route": route, "chunk": chunk}, confidence=.88)
                chunk_file = urllib.parse.urlsplit(chunk_url).path.rsplit("/", 1)[-1] or "next_chunk"
                queue.append({"url": chunk_url, "asset_type": "next_chunk", "source_file": chunk_file,
                              "parent": asset.url, "depth": depth + 1, "source": "next_build_manifest"})
        next_info["page_routes"] = sorted(set(next_info.get("page_routes", [])))
        next_info["manifest_assets"] = sorted(set(next_info.get("manifest_assets", [])))

    def _process_html(self, html: str, target_url: str, asset: AssetRecord, queue: Deque[Dict[str, Any]]) -> None:
        assert self._result is not None
        # Keep the document as a transient correlation source so provider
        # configuration embedded in __NEXT_DATA__, data attributes, or inline
        # JSON is not lost before the BaaS pass.  The body is released during
        # finalization and never copied to the public result.
        self._source_entries.append({"text": html or "", "source_code": html or "",
                                     "source_url": target_url, "source_file": "document",
                                     "source_map": None})
        frameworks = self.js.detect_frameworks(html)
        for framework in frameworks:
            if framework not in self._result.frameworks:
                self._result.frameworks.append(framework)
        for ref in self.crawler.from_html(html, target_url, source_file="document"):
            ref["parent"] = target_url
            ref["depth"] = 1
            queue.append(ref)
        # Inline scripts include __NEXT_DATA__, JSON-LD, and application code.
        for index, match in enumerate(re.finditer(r"<script\b(?P<attrs>[^>]*)>(?P<body>.*?)</script\s*>", html or "", re.IGNORECASE | re.DOTALL)):
            attrs = match.group("attrs") or ""
            body = match.group("body") or ""
            if re.search(r"\bid\s*=\s*['\"]__NEXT_DATA__['\"]", attrs, re.IGNORECASE):
                self._parse_next_data(body, target_url)
                continue
            if re.search(r"type\s*=\s*['\"]application/(?:ld\+json|json)['\"]", attrs, re.IGNORECASE):
                continue
            if body.strip():
                inline = AssetRecord(url=f"{target_url}#inline-script-{index + 1}", asset_type="inline_javascript",
                                     parent=target_url, depth=0, source="html_inline", framework=None,
                                     status="ANALYZED", size=len(body.encode("utf-8", errors="replace")), in_scope=True)
                self._result.assets.append(inline)
                self._add_source(body, source_url=target_url, source_file="inline_html", asset=inline)
        next_info = self._result.integrations.get("next", {})
        build_id = next_info.get("buildId")
        if next_info.get("detected") and build_id:
            # These are exact same-origin candidates derived from the observed
            # buildId, not a broad wordlist.  The scope/budget queue still
            # decides whether they can be fetched.
            for path in (f"/_next/static/{build_id}/_buildManifest.js",
                         f"/_next/static/{build_id}/_ssgManifest.js",
                         f"/_next/static/{build_id}/_middlewareManifest.json",
                         "/_next/routes-manifest.json", "/routes-manifest.json"):
                queue.append({"url": urllib.parse.urljoin(target_url, path), "asset_type": "next_manifest",
                              "source_file": "__NEXT_DATA__", "parent": target_url, "depth": 1})
            next_info["manifest_candidates"] = [urllib.parse.urljoin(target_url, path) for path in (
                f"/_next/static/{build_id}/_buildManifest.js",
                f"/_next/static/{build_id}/_ssgManifest.js",
                f"/_next/static/{build_id}/_middlewareManifest.json")]
            next_info["routes_manifest_candidates"] = [urllib.parse.urljoin(target_url, path) for path in
                                                        ("/_next/routes-manifest.json", "/routes-manifest.json")]
        # Referenced runtime configs in HTML or inline code.
        for ref in self.crawler.runtime_config_references(html, target_url, source_file="document"):
            ref["parent"] = target_url
            ref["depth"] = 1
            ref["asset_type"] = "runtime_config"
            queue.append(ref)

    def _parse_next_data(self, body: str, target_url: str) -> None:
        assert self._result is not None
        try:
            data = json.loads(body.strip())
        except (TypeError, ValueError, json.JSONDecodeError):
            self._result.coverage.setdefault("next", {})["parse_status"] = "PARSE_ERROR"
            return
        if not isinstance(data, dict):
            return
        public_keys: List[str] = []
        for key in ("buildId", "page", "runtimeConfig", "assetPrefix", "locale", "locales", "defaultLocale"):
            if key in data:
                public_keys.append(key)
        next_info = self._result.integrations.setdefault("next", {})
        next_info.update({"detected": True, "keys": sorted(set(next_info.get("keys", [])) | set(public_keys)),
                          "buildId": data.get("buildId"), "page": data.get("page"),
                          "middleware_indicators": [key for key in ("middleware", "middlewareManifest") if key in data],
                          "rsc_or_flight_indicators": bool("rsc" in json.dumps(data).lower() or "flight" in json.dumps(data).lower()),
                          "values_retained": False})
        runtime = data.get("runtimeConfig")
        if isinstance(runtime, dict):
            record = RuntimeConfigRecord(url=target_url, content_type="application/json", source_file="__NEXT_DATA__",
                                         status="PARSED_JSON", keys=list(runtime.keys()),
                                         values=[self.redactor.safe_config_value(str(value), name=key)
                                                 | {"name": key} if isinstance(value, str)
                                                 else {"name": key, "value_type": type(value).__name__}
                                                 for key, value in runtime.items()],
                                         evidence=[{"source_url": target_url, "source_file": "__NEXT_DATA__",
                                                    "keys": list(runtime.keys()), "values_retained": False}])
            self._result.runtime_configs.append(record)

    def _process_runtime_config(self, body: str, record: AssetRecord, source_file: str,
                                references: Optional[List[Dict[str, Any]]] = None) -> None:
        assert self._result is not None
        config_record = self.runtime.parse(record.url, body, content_type=record.content_type,
                                           source_file=source_file, references=references)
        self._result.runtime_configs.append(config_record)
        # Keep the response as a transient source unit so provider correlation
        # can pair a URL and key that live in runtime JSON/config rather than
        # in a JavaScript bundle.  The source is cleared by _finalize and no
        # body is copied into the public RuntimeConfigRecord.
        self._source_entries.append({"text": body, "source_code": body,
                                     "source_url": record.url, "source_file": source_file,
                                     "source_map": None})
        # Runtime JSON/config resources are not JavaScript, so they would
        # otherwise bypass the static credential and endpoint passes.  Feed
        # them through the same bounded analyzers without treating a config
        # observation as an impact finding.
        discovered: List[CredentialRecord] = []
        if self._secret_discovery_active:
            discovered = self.credentials.discover(body, source_url=record.url, source_file=source_file)
            for credential in discovered:
                self.graph.add_asset_to_credential(record.url, credential)
        try:
            config_endpoints = self.js.extract_endpoints(body, source_file=source_file, source_url=record.url)
        except (TypeError, ValueError):
            config_endpoints = []
        for endpoint in config_endpoints:
            endpoint.parent_asset = endpoint.parent_asset or record.url
            if self.scope:
                endpoint.metadata["scope"] = self._scope(endpoint.url, active=False)
            stored = self.graph.add_endpoint(endpoint)
            self.graph.add_asset_to_endpoint(record.url, stored)
            self.credentials.link_endpoint(stored)
            for credential in discovered:
                if ((credential.variable_name and (credential.variable_name in str(stored.headers)
                                                    or credential.variable_name in str(stored.auth_source)))
                        or (credential.credential_type == "BEARER_REFERENCE" and stored.auth_required)):
                    if stored.url not in credential.linked_endpoints:
                        credential.linked_endpoints.append(stored.url)
                    self.graph.add_credential_to_endpoint(
                        credential, stored, usage=credential.variable_name or "literal/auth reference")

    def _process_source_map(self, map_url: str, body: str, parent_asset: AssetRecord) -> None:
        assert self._result is not None and self._budget is not None
        if map_url in self._seen_maps:
            return
        self._seen_maps.add(map_url)
        if not self._budget.claim("source_map_budget"):
            self._result.coverage.setdefault("budget_skips", []).append({"url": map_url, "budget": "source_map_budget"})
            return
        safe_map_url = self.redactor.redact_url(map_url)
        parsed = self.source_maps.parse(safe_map_url, body, parent_asset=parent_asset.url,
                                        content_type=parent_asset.content_type)
        source_record = parsed["record"]
        self._result.source_maps.append(source_record)
        for unit in parsed.get("source_units", []):
            source_file = unit.get("source_file") or "source_map_source"
            source_asset_url = urllib.parse.urljoin(safe_map_url, source_file)
            source_decision = self._scope(source_asset_url, active=False)
            source_scheme = urllib.parse.urlsplit(source_asset_url).scheme.lower()
            # webpack:/// and similar virtual source roots are not network
            # destinations.  Their sourcesContent was already delivered by
            # the in-scope map, so it remains eligible for static analysis.
            source_content_allowed = bool(source_decision.get("allowed", True)) or source_scheme not in {"http", "https"}
            source_asset = AssetRecord(url=self.redactor.redact_url(source_asset_url), asset_type="source_map_content",
                                       parent=safe_map_url,
                                       depth=parent_asset.depth + 1, source="source_map", framework=parent_asset.framework,
                                       source_map_url=safe_map_url, status=unit.get("status", "READY"),
                                       size=len(str(unit.get("source_code") or "").encode("utf-8", errors="replace")),
                                       in_scope=bool(source_decision.get("in_scope", True)) if source_scheme in {"http", "https"} else parent_asset.in_scope,
                                       metadata={"discovered_asset": source_file,
                                                 "active_fetch_skipped": not bool(source_decision.get("allowed", True)),
                                                 "source_content_from_authorized_map": True})
            if not source_content_allowed:
                source_asset.status = "OUT_OF_SCOPE"
            self._result.assets.append(source_asset)
            if unit.get("status") == "READY" and source_content_allowed:
                self._add_source(unit.get("source_code", ""), source_url=source_asset.url,
                                 source_file=source_file, source_map=safe_map_url, asset=source_asset)

    def _maybe_source_map(self, asset: AssetRecord, body: str) -> Optional[str]:
        return self.source_maps.discover_url(asset.url, body)

    def _reference_hypotheses(self) -> Dict[str, Any]:
        technologies = list(self._result.frameworks if self._result else [])
        providers = sorted({project.provider for project in (self._result.baas_projects if self._result else [])})
        component = ",".join(technologies + providers)
        if not self.reference_intel or not hasattr(self.reference_intel, "select_hypotheses"):
            return {"sources": [], "component": component}
        return {"sources": self.reference_intel.select_hypotheses(component=component, limit=10), "component": component}

    def _build_findings(self) -> List[Dict[str, Any]]:
        assert self._result is not None
        findings: List[Dict[str, Any]] = []
        for credential in self.credentials.records.values():
            verification = credential.verification or {}
            if credential.status != "VERIFIED" or not verification.get("credential_accepted"):
                continue
            if credential.public:
                continue
            if not credential.linked_endpoints and not credential.project_ref:
                continue
            project = next((item for item in self._result.baas_projects
                            if item.key_fingerprint and item.key_fingerprint == credential.sha256), None)
            endpoint = credential.linked_endpoints[0] if credential.linked_endpoints else (
                project.url if project and project.url else credential.source_url or self._result.target)
            checks = verification.get("checks") or []
            accepted_check = next((item for item in checks if isinstance(item, dict) and item.get("accepted")), None)
            proof_url = endpoint
            proof_suffix = accepted_check.get("endpoint") if accepted_check else None
            if project and project.url and proof_suffix:
                proof_url = project.url.rstrip("/") + str(proof_suffix)
            proof_url = self.redactor.redact_url(proof_url)
            parsed_proof = urllib.parse.urlsplit(proof_url)
            proof_path = parsed_proof.path or "/"
            if parsed_proof.query:
                proof_path += "?" + parsed_proof.query
            status_code = accepted_check.get("status_code") if accepted_check else verification.get("status_code", 0)
            body_length = accepted_check.get("body_length") if accepted_check else verification.get("body_length", 0)
            redacted_request = "\n".join([
                f"GET {proof_path} HTTP/1.1",
                f"Host: {parsed_proof.netloc}",
                "apikey: [REDACTED]",
                "Authorization: Bearer [REDACTED]",
            ])
            redacted_response = (f"HTTP/1.1 {status_code or 0}\n\n"
                                 f"Linked-provider acceptance observed; response body length: {body_length or 0} bytes")
            reproduction = "\n".join([
                "SUPABASE_KEY='[RESEARCHER_HELD_VALUE]' \\",
                f"curl -i --globoff '{proof_url}' \\",
                "  -H \"apikey: ${SUPABASE_KEY}\" \\",
                "  -H \"Authorization: Bearer ${SUPABASE_KEY}\"",
            ])
            public_ids = project.public_identifiers if project else {}
            evidence = [{"credential_type": credential.credential_type, "provider": credential.provider,
                         "masked_value": credential.masked_value, "sha256": credential.sha256,
                         "source_file": credential.source_file, "source_line": credential.source_line,
                         "usage": credential.usage, "linked_endpoints": credential.linked_endpoints,
                         "project_ref": credential.project_ref or (project.project_ref if project else None),
                         "public_identifiers": public_ids,
                         "verification": verification}]
            findings.append(normalized_finding(
                finding_type="Verified Sensitive Client Credential Exposure",
                target=self._result.target, endpoint=endpoint, status=FindingStatus.VERIFIED,
                confidence=max(.85, credential.confidence), method="GET", payload="",
                param="apikey / Authorization",
                raw_request=redacted_request, raw_response=redacted_response,
                reproduction_curl=reproduction, evidence=evidence,
                verification_checks=[{"name": "provider_format_or_role", "passed": True},
                                     {"name": "linked_project_or_endpoint", "passed": True},
                                     {"name": "credential_accepted_by_linked_target", "passed": True}],
                missing_evidence=[], false_positive_reasons=[], source_module="hidden_assets",
                source_tool="CredentialDiscoveryEngine + linked provider verifier",
                severity="Critical" if credential.credential_type == "POTENTIAL_SECRET" else "High",
                observed_impact=(f"The non-public {credential.provider or 'provider'} credential referenced by "
                                 f"{credential.source_file}:{credential.source_line or 'unknown'} was accepted by the "
                                 f"exact correlated project `{credential.project_ref or (project.project_ref if project else 'unknown')}` "
                                 f"at `{proof_url}` with HTTP {status_code or 0}; the response body was not retained."),
                potential_impact=("The accepted credential is classified as service-role-like/high-privilege by its "
                                  "provider-specific claims; administrative or cross-user access is not claimed without a separate data marker."),
                verification_note=("Static format/role, exact source relationship, public project identifiers, and "
                                   "bounded linked-target acceptance are recorded. The reproduction uses a researcher-held value; raw credential redacted."),
                poc_verified=True, possesses_active_exploit=True,
            ))
        return findings

    def _finalize(self, *, raw_local_results: bool = False) -> Dict[str, Any]:
        assert self._result is not None and self._budget is not None
        # Replace the internal pending queue with a count; no unprocessed raw
        # source references belong in a report.
        self._result.coverage.pop("pending_references", None)
        self._result.endpoints = list(self.graph.endpoints.values())
        self._result.relationships = self.graph.relationship_records()
        self._result.credentials = list(self.credentials.records.values())
        self._result.baas_projects = list(self._result.baas_projects)
        self._result.findings = self._build_findings()
        self._result.integrations.setdefault("reference_intel", self._reference_hypotheses())
        self._result.stats.update({
            "assets": len(self._result.assets), "javascript_assets": sum(1 for item in self._result.assets if "javascript" in item.asset_type or item.asset_type in {"module", "dynamic_chunk", "web_worker", "service_worker", "worker_asset"}),
            "source_maps": len(self._result.source_maps), "endpoints": len(self._result.endpoints),
            "credentials": len(self._result.credentials), "baas_projects": len(self._result.baas_projects),
            "auth_flows": len(self._result.auth_flows), "relationships": len(self._result.relationships),
            "verified_findings": len(self._result.findings),
        })
        self._result.budget = self._budget.report()
        self._result.coverage.setdefault("cache", {"entries": len(self._cache), "key": "normalized URL + validator/body hash"})
        self._result.integrations.setdefault("shared_components", {
            "scope_manager": bool(self.scope), "traffic_controller": bool(self.traffic),
            "http_verifier": type(self.verifier).__name__,
            "js_analyzer": type(self.legacy_js_analyzer).__name__ if self.legacy_js_analyzer else "JSDeepAnalyzer",
            "cloud_baas_hunter": type(self.legacy_cloud_hunter).__name__ if self.legacy_cloud_hunter else "BaaSCorrelationEngine",
            "deep_exploit_engine": type(self.deep_exploit_engine).__name__ if self.deep_exploit_engine else "not supplied",
            "fp_killer": "agent pipeline applies deterministic kill_pass to findings",
        })
        self._result.coverage["redaction"] = {
            "raw_values_persisted": False,
            "raw_values_exported": raw_local_results,
            "runtime_auth_values_retained": False,
            "scope": "live CLI result only" if raw_local_results else "sanitized",
        }
        safe = self._result.to_dict()
        # Context snippets are generated before all source relationships are
        # known.  Scrub every known in-memory credential/project key one final
        # time so a value cannot survive in another record's nearby context.
        known_values = [record._raw_value for record in self.credentials.records.values() if record._raw_value]
        known_values.extend(project._raw_key for project in self._result.baas_projects if project._raw_key)

        if raw_local_results:
            raw_by_fingerprint = {
                record.sha256: record._raw_value
                for record in self.credentials.records.values() if record._raw_value
            }
            for record in safe.get("credentials", []):
                raw = raw_by_fingerprint.get(record.get("sha256"))
                if raw:
                    record["_raw_value"] = raw

        def scrub(value: Any, field: str = "") -> Any:
            if isinstance(value, dict):
                return {
                    key: item if raw_local_results and key == "_raw_value" else scrub(item, key)
                    for key, item in value.items()
                }
            if isinstance(value, list):
                return [scrub(item, field) for item in value]
            if isinstance(value, str):
                return self.redactor.redact_text(value, known_values)
            return value

        output = scrub(safe)
        # The engine is a per-scan object in the CLI/Web pipeline.  Once the
        # public export is built, release source-map bodies, response bodies,
        # and validator-only raw values instead of retaining them on the
        # long-lived task object.  Provider validation has already completed
        # at this point; only masked/fingerprint evidence remains.
        self.credentials.purge_raw_values()
        for project in self._result.baas_projects:
            project._raw_key = None
        self._source_entries.clear()
        self._cache.clear()
        self._prefetched.clear()
        return output

    def discover(self, target_url: str, *, deep_assets: bool = True, secret_discovery: bool = True,
                 auth_flow: bool = True, source_maps: bool = True, browser_verify: bool = False,
                 auth_context: Optional[Dict[str, Any]] = None, verify_baas: bool = False,
                 raw_local_results: bool = False,
                 max_depth: Optional[int] = None, request_budget: Optional[int] = None,
                 asset_budget: Optional[int] = None, source_map_budget: Optional[int] = None,
                 verification_budget: Optional[int] = None) -> Dict[str, Any]:
        """Run discovery with adaptive queues and explicit sub-budgets.

        ``auth_context`` is a researcher-owned in-memory object.  Only identity
        labels are reflected in coverage; header/token values never enter the
        returned result.
        """
        raw_target = target_url
        if not target_url.startswith(("http://", "https://")):
            target_url = f"https://{target_url}"
        try:
            target_url = normalize_url(target_url)
        except URLPolicyError as exc:
            return {"target": raw_target, "assets": [], "endpoints": [], "credentials": [], "baas_projects": [],
                    "auth_flows": [], "source_maps": [], "runtime_configs": [], "relationships": [],
                    "frameworks": [], "findings": [], "stats": {}, "budget": {}, "coverage": {},
                    "errors": [{"status": "REJECTED", "reason": str(exc)}], "integrations": {}}
        if self.scope is None:
            self.scope = ScopeManager.from_target(target_url)
            if hasattr(self.verifier, "scope") and getattr(self.verifier, "scope", None) is None:
                self.verifier.scope = self.scope
        initial_decision = self._scope(target_url, active=True)
        if not initial_decision.get("allowed"):
            return {"target": target_url, "assets": [], "endpoints": [], "credentials": [], "baas_projects": [],
                    "auth_flows": [], "source_maps": [], "runtime_configs": [], "relationships": [],
                    "frameworks": [], "findings": [], "stats": {}, "budget": {}, "coverage": {},
                    "errors": [{"status": "OUT_OF_SCOPE", "reason": initial_decision.get("reason")}], "integrations": {}}

        self.request_budget = self.request_budget if request_budget is None else max(0, int(request_budget))
        self.asset_budget = self.asset_budget if asset_budget is None else max(0, int(asset_budget))
        self.source_map_budget = self.source_map_budget if source_map_budget is None else max(0, int(source_map_budget))
        self.verification_budget = self.verification_budget if verification_budget is None else max(0, int(verification_budget))
        effective_depth = self.max_depth if max_depth is None else min(self.max_depth, max(0, int(max_depth)))
        # The target document is the baseline and is always eligible for one
        # fetch.  ``deep_assets=False`` disables recursion, not the baseline.
        self._budget = DiscoveryBudget(self.asset_budget if deep_assets else min(1, max(1, self.asset_budget)),
                                       self.source_map_budget if source_maps else 0,
                                       self.verification_budget, self.request_budget)
        self._secret_discovery_active = bool(secret_discovery)
        self._auth_flow_active = bool(auth_flow)
        self._result = DiscoveryResult(target=target_url, budget={"request_budget": self.request_budget,
                                                                  "max_depth": effective_depth},
                                       coverage={"scope": self.scope.summary() if self.scope else {},
                                                 "browser_verify": bool(browser_verify),
                                                 "auth_context_loaded": bool(auth_context),
                                                 "auth_identities": sorted((auth_context or {}).get("identities", {}).keys()) if isinstance(auth_context, dict) else []})
        self._seen_assets.clear(); self._seen_maps.clear(); self._cache.clear(); self._source_entries.clear()
        self.credentials.records.clear(); self.graph = EndpointGraphBuilder()
        queue: Deque[Dict[str, Any]] = deque()
        page_asset, page_response = self._fetch(target_url, parent=None, depth=0, source="configured_target", asset_type="html")
        if page_response and page_asset.status == "FETCHED":
            self._seen_assets.add(page_asset.url)
            body = str(page_response.get("body") or "")
            self._process_html(body, target_url, page_asset, queue)
            # The HTML itself may contain inline env/config and auth flow.
            if secret_discovery:
                discovered = self.credentials.discover(body, source_url=target_url, source_file="document")
                for credential in discovered:
                    self.graph.add_asset_to_credential(page_asset.url, credential)
            if not deep_assets:
                # The baseline document and inline analysis remain available,
                # but external chunks/configs are a caller-controlled feature.
                queue.clear()
        else:
            self._result.errors.append({"url": target_url, "status": page_asset.status,
                                        "reason": "target document was not fetched; asset discovery cannot continue"})

        processed = 0
        while (queue and processed < self.max_assets
               and len(self._seen_assets) < self.max_assets
               and not self._stopped()):
            item = queue.popleft()
            url = str(item.get("url") or "")
            if not url:
                continue
            depth = int(item.get("depth") or 1)
            if depth > effective_depth:
                self._result.coverage.setdefault("depth_skips", []).append({"url": url, "depth": depth})
                continue
            try:
                normalized = normalize_url(url)
            except URLPolicyError:
                continue
            if normalized in self._seen_assets:
                continue
            self._seen_assets.add(normalized)
            asset_type = str(item.get("asset_type") or "javascript")
            source_file_hint = str(item.get("source_file") or "")
            # HTML discovery labels the referring document as "document";
            # the fetched asset itself needs its filename for source tracing.
            source_file = source_file_hint if source_file_hint and source_file_hint != "document" else (normalized.rsplit("/", 1)[-1] or "asset")
            asset, response = self._fetch(normalized, parent=item.get("parent"), depth=depth,
                                          source=str(item.get("source") or "recursive_discovery"), asset_type=asset_type)
            processed += 1
            if not response or asset.status != "FETCHED":
                continue
            body = str(response.get("body") or "")
            content_type = asset.content_type or ""
            if asset_type == "frontend_route" or "text/html" in content_type.lower():
                self._process_html(body, normalized, asset, queue)
            if asset_type == "next_manifest" or "_buildmanifest" in asset.url.lower() or "routes-manifest" in asset.url.lower():
                self._process_next_manifest(body, asset, target_url, queue, depth)
            is_config = asset_type == "runtime_config" or self.runtime.is_runtime_config_url(asset.url) or "application/json" in content_type.lower()
            if is_config:
                self._process_runtime_config(body, asset, source_file, references=[item])
            if asset_type not in {"manifest", "runtime_config"} and ("javascript" in content_type.lower() or asset_type in {"javascript", "module", "dynamic_chunk", "web_worker", "service_worker", "worker_asset", "framework_asset"} or asset.url.lower().split("?", 1)[0].endswith((".js", ".mjs", ".cjs"))):
                if deep_assets or secret_discovery or auth_flow:
                    self._add_source(body, source_url=asset.url, source_file=source_file, asset=asset)
                if source_maps:
                    map_url = self._maybe_source_map(asset, body)
                    if map_url and map_url not in self._seen_maps:
                        map_decision = self._scope(map_url, active=True)
                        if map_decision.get("allowed") and self._budget and self._budget.remaining("source_map_budget") > 0:
                            map_asset, map_response = self._fetch(map_url, parent=asset.url, depth=depth + 1,
                                                                  source="source_mapping_url", asset_type="source_map")
                            if map_response and map_asset.status == "FETCHED":
                                self._process_source_map(map_url, str(map_response.get("body") or ""), asset)
                        elif not map_decision.get("allowed"):
                            self._record_out_of_scope(map_url, parent=asset.url, depth=depth + 1,
                                                      source="source_mapping_url", asset_type="source_map", decision=map_decision)
            # Consume references produced by this source before next loop;
            # config references are added here as well for direct JS fetches.
            pending = self._result.coverage.pop("pending_references", [])
            for ref in pending:
                if int(ref.get("depth") or depth + 1) <= effective_depth:
                    queue.append(ref)
            for ref in self.crawler.runtime_config_references(body, asset.url, source_file=source_file):
                ref.update({"asset_type": "runtime_config", "parent": asset.url, "depth": depth + 1})
                queue.append(ref)

        if queue and len(self._seen_assets) >= self.max_assets:
            self._result.coverage["max_assets_reached"] = True

        # Correlation is intentionally after all source-map content has been
        # reprocessed, so a hidden key and its project can be paired together.
        if secret_discovery:
            self._result.credentials = list(self.credentials.records.values())
        baas_sources = list(self._source_entries)
        correlation = self.baas.correlate(baas_sources, credentials=list(self.credentials.records.values()),
                                          endpoints=list(self.graph.endpoints.values()), config_refs=self._result.coverage.get("config_references", []))
        self._result.baas_projects = correlation.get("projects", [])
        self._result.coverage["baas_pairing"] = correlation.get("relationships", [])
        for relationship in correlation.get("relationships", []):
            self.graph.add_relationship(
                str(relationship.get("relationship_type") or "credential_to_baas_project"),
                str(relationship.get("from") or ""), str(relationship.get("to") or ""),
                source=relationship.get("source"), evidence=relationship.get("evidence") or {}, confidence=.9,
            )
        for project in self._result.baas_projects:
            for credential in self.credentials.records.values():
                if project.key_fingerprint and credential.sha256 == project.key_fingerprint:
                    credential.project_ref = project.project_ref
                    project.key_source = project.key_source or credential.source_file
            for endpoint in self.graph.endpoints.values():
                if project.url and endpoint.url.startswith(project.url):
                    self.graph.add_relationship("baas_project_to_endpoint",
                                                f"baas:{project.provider}:{project.project_ref or project.url}",
                                                self.graph.endpoint_node(endpoint), source=endpoint.source_file,
                                                evidence={"project_url": project.url}, confidence=.9)
        if verify_baas and self._budget and self._budget.remaining("verification_budget") > 0:
            # The caller has explicitly opted into linked-project validation;
            # an auth context is not required for a public client key.  If an
            # operator supplies an explicit authorization=false marker, honor
            # it and do not send the credential.
            authorized = bool(auth_context.get("authorized", True)) if isinstance(auth_context, dict) else True
            for project in self._result.baas_projects:
                if self._stopped() or self._budget.remaining("verification_budget") <= 0:
                    break
                if project.provider == "Supabase":
                    if not (authorized and project.url and project._raw_key):
                        continue
                    request_limit = min(2, self._budget.remaining("verification_budget"))
                    verification = self.baas.verify_supabase(
                        project, self.verifier, self.scope, authorized=authorized, request_limit=request_limit
                    )
                elif project.provider == "Firebase":
                    if not (authorized and project.url):
                        continue
                    request_limit = min(1, self._budget.remaining("verification_budget"))
                    verification = self.baas.verify_firebase(
                        project, self.verifier, self.scope, authorized=authorized, request_limit=request_limit
                    )
                else:
                    verification = {}
                requests_used = max(0, int(verification.get("requests_used", 0) or 0))
                for _ in range(requests_used):
                    if not self._budget.claim("verification_budget"):
                        break
                # Keep provider validation and credential status connected, but
                # never copy the raw key into the report.  This is what turns a
                # static service-role hypothesis into a target-specific finding
                # when the exact correlated project accepts it.
                if verification.get("credential_accepted") and project.key_fingerprint:
                    for credential in self.credentials.records.values():
                        if credential.sha256 != project.key_fingerprint:
                            continue
                        credential.verification = {
                            "verified": True,
                            "status": "VERIFIED",
                            "credential_accepted": True,
                            "provider": project.provider,
                            "project_ref": project.project_ref,
                            "requests_used": verification.get("requests_used", 0),
                            "status_code": verification.get("status_code"),
                            "checks": verification.get("checks", []),
                            "impact_proven": bool(verification.get("impact_proven")),
                        }
                        if not credential.public:
                            credential.status = "VERIFIED"
                        break
        if browser_verify:
            # Browser instrumentation supplies events through observe_runtime;
            # no ambient browser profile is opened by this engine.
            self._result.coverage["browser_policy"] = "fresh researcher-owned context required; no ambient profile access"
        self._result.findings = self._build_findings()
        return self._finalize(raw_local_results=raw_local_results)

    run = discover
    analyze = discover
    scan = discover

    def observe_runtime(self, requests: Optional[Iterable[Dict[str, Any]]] = None,
                        storage_events: Optional[Iterable[Dict[str, Any]]] = None, *,
                        runtime_assets: Optional[Iterable[Dict[str, Any] | str]] = None,
                        authorized_session: bool = False, browser_context: str = "") -> Dict[str, Any]:
        request_events = list(requests or [])
        storage_events_list = list(storage_events or [])
        flow = self.auth.observe_runtime(request_events, storage_events_list, authorized_session=authorized_session,
                                         browser_context=browser_context)
        if not authorized_session or browser_context != "researcher-owned":
            return flow.to_dict()
        if self._result is not None:
            self._result.auth_flows.append(flow)
            self._result.coverage["browser_runtime"] = {
                "status": "OBSERVED", "authorized_session": True,
                "browser_context": "researcher-owned", "values_retained": False,
            }
            for item in request_events:
                raw_url = item.get("url") if isinstance(item, dict) else None
                if not raw_url:
                    continue
                safe_url = self.redactor.redact_url(str(raw_url))
                decision = self._scope(safe_url, active=False)
                request_headers = {str(key): {"observed": True, "value_retained": False}
                                   for key in (item.get("headers") or {}).keys()} if isinstance(item, dict) else {}
                auth_header_names = {"authorization", "x-api-key", "api-key", "apikey", "x-auth-token",
                                     "x-access-token", "cookie"}
                observed_auth_headers = [key for key in request_headers if key.lower() in auth_header_names]
                runtime_endpoint = EndpointRecord(
                    url=safe_url, method=str(item.get("method") or "GET").upper(),
                    source_file="browser_runtime", request_type="RuntimeObserved",
                    headers=request_headers,
                    auth_required=bool(observed_auth_headers),
                    auth_source=", ".join(observed_auth_headers) if observed_auth_headers else None,
                    confidence=.9, evidence=[{"source": "browser_runtime", "values_retained": False}],
                    metadata={"scope": decision, "runtime_observed": True},
                )
                self.graph.add_endpoint(runtime_endpoint)
            for item in runtime_assets or []:
                raw_url = item if isinstance(item, str) else item.get("url")
                if not raw_url:
                    continue
                try:
                    normalized = normalize_url(str(raw_url))
                except URLPolicyError:
                    continue
                decision = self._scope(normalized, active=False)
                asset = AssetRecord(
                    url=self.redactor.redact_url(normalized), asset_type=(item.get("asset_type", "runtime_loaded_asset")
                                                if isinstance(item, dict) else "runtime_loaded_asset"),
                    parent=(item.get("parent") if isinstance(item, dict) else None),
                    depth=int(item.get("depth", 0) if isinstance(item, dict) else 0),
                    source="browser_runtime", status="RUNTIME_OBSERVED",
                    in_scope=bool(decision.get("in_scope")),
                    metadata={"active_fetch_skipped": True, "values_retained": False},
                )
                self._result.assets.append(asset)
                # A browser adapter may provide the response body for an
                # already-observed same-scope chunk.  Analyze that body
                # in-process without creating a second request; values still
                # pass the normal credential redaction and final scrubber.
                body = item.get("body") if isinstance(item, dict) else None
                if body and asset.in_scope:
                    self._add_source(str(body), source_url=asset.url,
                                     source_file=urllib.parse.urlsplit(asset.url).path.rsplit("/", 1)[-1] or "runtime_asset",
                                     asset=asset)
            self._result.endpoints = list(self.graph.endpoints.values())
            self._result.relationships = self.graph.relationship_records()
        return flow.to_dict()

    def standard_export(self) -> Dict[str, Any]:
        # ``DiscoveryResult.to_dict`` removes private dataclass fields, but
        # raw values intentionally remain in memory for an explicit validator.
        # Reuse the final scrubber for every public export path.
        return self._finalize() if self._result else {}


__all__ = ["AssetCrawler", "DiscoveryBudget", "HiddenAssetEngine"]
