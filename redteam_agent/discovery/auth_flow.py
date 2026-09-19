"""Static and researcher-owned runtime authentication-flow graphing."""

from __future__ import annotations

import hashlib
import re
import urllib.parse
from typing import Any, Dict, Iterable, List, Optional

from redteam_agent.discovery.js_deep import LightDataFlowAnalyzer, _line_number
from redteam_agent.discovery.models import AuthFlow, AuthFlowNode, EndpointRecord
from redteam_agent.discovery.redaction import SecretRedactor


class AuthFlowAnalyzer:
    TOKEN_FIELDS = ("access_token", "accessToken", "refresh_token", "refreshToken", "id_token", "idToken", "jwt", "token", "session", "authorization")
    STORAGE_RE = re.compile(r"\b(localStorage|sessionStorage)\.(setItem|getItem)\(\s*(['\"])([^'\"]+)\3", re.IGNORECASE)
    COOKIE_RE = re.compile(r"\bdocument\.cookie\b|\bcookies?\.(?:set|get)\b", re.IGNORECASE)
    INDEXEDDB_RE = re.compile(r"\bindexedDB\b|\bIDB(?:Database|ObjectStore|Request)\b", re.IGNORECASE)
    STATE_STORE_RE = re.compile(r"\b(?:redux|zustand|pinia|vuex|store|memoryStore|authStore)\b", re.IGNORECASE)
    BEARER_RE = re.compile(r"\bBearer\s*\$\{([^}]+)\}|\bBearer\s+([^`'\"\s}]+)", re.IGNORECASE)

    def __init__(self, *, redactor: Optional[SecretRedactor] = None):
        self.redactor = redactor or SecretRedactor()
        self.data_flow = LightDataFlowAnalyzer(self.redactor)

    @staticmethod
    def _node(flow: AuthFlow, node_type: str, label: str, *, source_file: Optional[str] = None,
              source_line: Optional[int] = None, metadata: Optional[Dict[str, Any]] = None) -> AuthFlowNode:
        node_id = f"{node_type}:{label}"
        for node in flow.nodes:
            if node.node_id == node_id:
                return node
        node = AuthFlowNode(node_id=node_id, node_type=node_type, label=label,
                            source_file=source_file, source_line=source_line, metadata=metadata or {})
        flow.nodes.append(node)
        return node

    @staticmethod
    def _edge(flow: AuthFlow, source: AuthFlowNode, target: AuthFlowNode, relationship: str, **metadata: Any) -> None:
        edge = {"from": source.node_id, "to": target.node_id, "relationship": relationship, **metadata}
        if edge not in flow.edges:
            flow.edges.append(edge)

    def _runtime_url(self, value: str) -> str:
        """Keep runtime request identity while removing query credential values."""
        return self.redactor.redact_url(str(value or ""))

    @staticmethod
    def _endpoint_for(endpoint: EndpointRecord, source_file: str) -> bool:
        return endpoint.source_file == source_file or endpoint.source_file == "unknown"

    def _add_endpoint_nodes(self, flow: AuthFlow, endpoints: Iterable[EndpointRecord], source_file: str) -> None:
        for endpoint in endpoints or []:
            if not self._endpoint_for(endpoint, source_file):
                continue
            lowered = endpoint.url.lower()
            if any(token in lowered for token in ("login", "signin", "/auth", "/oauth", "authorize")):
                node_type = "RefreshEndpoint" if "refresh" in lowered else "LogoutEndpoint" if "logout" in lowered else "LoginEndpoint"
            elif endpoint.auth_required or endpoint.auth_source or endpoint.headers:
                node_type = "ProtectedEndpoint"
            else:
                continue
            node = self._node(flow, node_type, f"{endpoint.method} {endpoint.url}", source_file=endpoint.source_file,
                              source_line=endpoint.source_line, metadata={"request_type": endpoint.request_type,
                                                                          "auth_source": endpoint.auth_source})
            if node_type in {"LoginEndpoint", "RefreshEndpoint"}:
                response_node = self._node(flow, "TokenResponse", f"{endpoint.method} {endpoint.url} response",
                                           source_file=endpoint.source_file, source_line=endpoint.source_line,
                                           metadata={"field_names_only": True})
                self._edge(flow, node, response_node, "returns_token_fields")

    def analyze(self, text: str, *, source_file: str = "unknown", source_url: str = "",
                endpoints: Optional[Iterable[EndpointRecord]] = None,
                data_flow: Optional[Dict[str, Any]] = None,
                source_map: Optional[str] = None) -> AuthFlow:
        text = text or ""
        flow_id = "auth:" + hashlib.sha256(f"{source_file}|{source_url}".encode()).hexdigest()[:16]
        flow = AuthFlow(flow_id=flow_id, confidence=0.0, evidence=[], runtime_observed=False)
        self._add_endpoint_nodes(flow, endpoints or [], source_file)
        token_fields = []
        for field in self.TOKEN_FIELDS:
            if field in {"token", "session", "authorization"}:
                field_seen = bool(re.search(
                    rf"(?:response|data|body|result|json)\s*[.\[]\s*['\"]?{re.escape(field)}\b|"
                    rf"['\"]{re.escape(field)}['\"]\s*:", text, re.IGNORECASE
                ))
            else:
                field_seen = bool(re.search(rf"\b{re.escape(field)}\b", text))
            if field_seen:
                token_fields.append(field)
        token_fields = sorted(set(token_fields))
        field_nodes: Dict[str, AuthFlowNode] = {}
        for field in token_fields:
            node = self._node(flow, "TokenResponse", f"response.{field}", source_file=source_file,
                              metadata={"field_name_only": True, "source_map": source_map})
            field_nodes[field] = node
        variables = (data_flow or self.data_flow.analyze(text, source_file=source_file, source_url=source_url)).get("variables", {})
        for match in re.finditer(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*))", text):
            variable, expression = match.group(1), match.group(2)
            field = expression.split(".")[-1]
            if field not in field_nodes:
                continue
            token_node = self._node(flow, "TokenVariable", variable, source_file=source_file,
                                    source_line=_line_number(text, match.start()))
            self._edge(flow, field_nodes[field], token_node, "assigned_to")

        storage_nodes: Dict[str, AuthFlowNode] = {}
        for match in self.STORAGE_RE.finditer(text):
            store, operation, key = match.group(1), match.group(2).lower(), match.group(4)
            storage_node = self._node(flow, "Storage", f"{store}.{key}", source_file=source_file,
                                      source_line=_line_number(text, match.start()),
                                      metadata={"storage": store, "key": key, "operation": operation})
            storage_nodes[f"{store}.{key}"] = storage_node
            if operation == "setitem":
                tail = text[match.end(): min(len(text), match.end() + 180)]
                value_expr = tail.split(")", 1)[0].strip(" ,")
                variable_match = re.search(r"\b([A-Za-z_$][\w$]*)\b", value_expr)
                if variable_match:
                    value = variable_match.group(1)
                    source_node = next((node for node in flow.nodes if node.node_type == "TokenVariable" and node.label == value), None)
                    if source_node:
                        self._edge(flow, source_node, storage_node, "stored_as")
                    else:
                        token_source = self._node(flow, "TokenVariable", value, source_file=source_file,
                                                  source_line=_line_number(text, match.start()))
                        self._edge(flow, token_source, storage_node, "stored_as")

        for match in self.COOKIE_RE.finditer(text):
            cookie = self._node(flow, "Storage", "cookie", source_file=source_file,
                                source_line=_line_number(text, match.start()), metadata={"storage": "cookie", "values_retained": False})
            storage_nodes["cookie"] = cookie
        for match in self.INDEXEDDB_RE.finditer(text):
            self._node(flow, "Storage", "IndexedDB", source_file=source_file,
                       source_line=_line_number(text, match.start()),
                       metadata={"storage": "IndexedDB", "values_retained": False})
        for match in self.STATE_STORE_RE.finditer(text):
            label = match.group(0)
            self._node(flow, "Storage", label, source_file=source_file,
                       source_line=_line_number(text, match.start()), metadata={"storage": "application_state", "values_retained": False})

        header_nodes: List[tuple[AuthFlowNode, str]] = []
        for match in self.BEARER_RE.finditer(text):
            reference = match.group(1) or match.group(2) or "runtime_token"
            header = self._node(flow, "AuthorizationHeader", "Authorization: Bearer", source_file=source_file,
                                source_line=_line_number(text, match.start()),
                                metadata={"reference": self.redactor.redact_text(reference), "value_retained": False})
            header_nodes.append((header, "authorization"))
            storage_ref = re.search(r"(?:localStorage|sessionStorage)\.getItem\(\s*['\"]([^'\"]+)", reference, re.IGNORECASE)
            if storage_ref:
                key = next((node_key for node_key in storage_nodes if node_key.endswith("." + storage_ref.group(1))), None)
                if key:
                    self._edge(flow, storage_nodes[key], header, "read_for_authorization")
            else:
                source_node = next((node for node in flow.nodes if node.node_type == "TokenVariable" and node.label in reference), None)
                if source_node:
                    self._edge(flow, source_node, header, "formatted_as_bearer")

        endpoint_list = [endpoint for endpoint in (endpoints or []) if self._endpoint_for(endpoint, source_file)]
        protected_nodes = [node for node in flow.nodes if node.node_type == "ProtectedEndpoint"]
        # Keep an auth header edge tied to the endpoint that declares it.  A
        # bundle can use an API key on one request and a bearer token on
        # another; a global edge would falsely merge those flows.
        for endpoint in endpoint_list:
            endpoint_node = next((node for node in protected_nodes
                                  if node.label == f"{endpoint.method} {endpoint.url}"), None)
            if endpoint_node is None:
                continue
            endpoint_header_names = {str(key).lower() for key in (endpoint.headers or {}).keys()}
            for key in endpoint_header_names:
                if key not in {"authorization", "x-api-key", "api-key", "apikey", "x-auth-token", "x-access-token", "x-csrf-token", "x-xsrf-token"}:
                    continue
                existing = next((item for item, header_name in header_nodes if header_name == key), None)
                if existing is None:
                    existing = self._node(flow, "AuthorizationHeader", key.title(),
                                          source_file=source_file, source_line=endpoint.source_line,
                                          metadata={"header_name": key, "value_retained": False})
                    header_nodes.append((existing, key))
                self._edge(flow, existing, endpoint_node, "sent_to")
        for field_node in field_nodes.values():
            if field_node.node_type == "TokenResponse":
                for endpoint_node in [node for node in flow.nodes if node.node_type in {"LoginEndpoint", "RefreshEndpoint"}]:
                    self._edge(flow, endpoint_node, field_node, "response_contains_field")
        flow.confidence = min(1.0, .25 + .12 * len(field_nodes) + .18 * len(storage_nodes) + .2 * len(header_nodes) + .12 * len(protected_nodes))
        flow.evidence.append({"source_file": source_file, "source_url": source_url, "source_map": source_map,
                              "token_field_names": token_fields, "storage_keys": sorted(storage_nodes),
                              "authorization_header_count": len(header_nodes),
                              "protected_endpoint_count": len(protected_nodes), "values_retained": False})
        return flow

    def observe_runtime(self, requests: Optional[Iterable[Dict[str, Any]]] = None,
                        storage_events: Optional[Iterable[Dict[str, Any]]] = None, *,
                        authorized_session: bool = False, browser_context: str = "") -> AuthFlow:
        """Build a redacted runtime graph from a researcher-owned session only."""
        flow = AuthFlow(flow_id="runtime-auth:" + hashlib.sha256(browser_context.encode()).hexdigest()[:16],
                        confidence=0.0, runtime_observed=True)
        if not authorized_session or browser_context != "researcher-owned":
            flow.evidence.append({"status": "NOT_RUN", "reason": "researcher-owned authorized session is required",
                                  "values_retained": False})
            return flow
        requests = list(requests or [])
        storage_events = list(storage_events or [])
        for item in requests:
            url = self._runtime_url(str(item.get("url") or ""))
            method = str(item.get("method") or "GET").upper()
            if not url:
                continue
            headers = {str(key).lower() for key in (item.get("headers") or {}).keys()}
            node_type = "ProtectedEndpoint" if any(key in headers for key in ("authorization", "x-api-key", "x-auth-token", "cookie")) else "RuntimeRequest"
            request_node = self._node(flow, node_type, f"{method} {url}", metadata={"header_names": sorted(headers), "values_retained": False})
            if node_type == "ProtectedEndpoint" and "authorization" in headers:
                header_node = self._node(flow, "AuthorizationHeader", "Authorization: Bearer", metadata={"value_retained": False})
                self._edge(flow, header_node, request_node, "sent_to")
            response_fields = item.get("response_token_fields") or item.get("token_fields") or []
            for field in response_fields:
                field_node = self._node(flow, "TokenResponse", f"response.{field}", metadata={"field_name_only": True})
                self._edge(flow, request_node, field_node, "response_contains_field")
        for event in storage_events:
            store = str(event.get("storage") or event.get("type") or "memory")
            key = str(event.get("key") or event.get("name") or "unknown")
            storage_node = self._node(flow, "Storage", f"{store}.{key}", metadata={"storage": store, "key": key,
                                                                                     "operation": event.get("operation"), "value_retained": False})
            if str(event.get("operation") or "").lower() in {"set", "write", "setitem"}:
                token_node = self._node(flow, "TokenVariable", "runtime token", metadata={"value_retained": False})
                self._edge(flow, token_node, storage_node, "stored_as")
        flow.confidence = min(1.0, .35 + .1 * len(flow.nodes)) if flow.nodes else 0.0
        flow.evidence.append({"status": "OBSERVED", "authorized_session": True, "browser_context": "researcher-owned",
                              "request_count": len(requests), "storage_event_count": len(storage_events),
                              "values_retained": False})
        return flow


__all__ = ["AuthFlowAnalyzer"]
