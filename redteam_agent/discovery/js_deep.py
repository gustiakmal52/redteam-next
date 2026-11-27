"""Modern JavaScript discovery with bounded, dependency-light data flow.

This is intentionally a tokenizer-plus-data-flow pass rather than a pile of
vendor-specific regular expressions.  It reconstructs the small set of
relationships that matter for discovery (constant -> header -> request,
config -> client, response field -> storage -> bearer header) and leaves
execution to the browser/target-specific verification layers.
"""

from __future__ import annotations

import base64
import codecs
import hashlib
import json
import re
import urllib.parse
from array import array
from bisect import bisect_right
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from redteam_agent.discovery.models import EndpointRecord
from redteam_agent.discovery.redaction import SecretRedactor
from redteam_agent.discovery.runtime_config import RuntimeConfigAnalyzer


_IDENTIFIER = r"[A-Za-z_$][\w$]*"
_STRING_RE = re.compile(r"(?P<quote>['\"`])(?P<value>(?:\\.|(?!\1).)*?)(?P=quote)", re.DOTALL)


def _line_number_lookup(text: str) -> Callable[[int], int]:
    line_starts = None

    def line_number(offset: int) -> int:
        nonlocal line_starts
        if line_starts is None:
            line_starts = array("Q", [0])
            source = text or ""
            newline = source.find("\n")
            while newline >= 0:
                line_starts.append(newline + 1)
                newline = source.find("\n", newline + 1)
        return bisect_right(line_starts, max(0, offset))

    return line_number


def _snippet(text: str, start: int, end: int, redactor: SecretRedactor) -> str:
    return redactor.redact_text(text[max(0, start - 100): min(len(text), end + 180)])[:600]


def _read_quoted(text: str, start: int) -> Tuple[str, int]:
    """Read one JS quoted/template expression without evaluating it."""
    if start >= len(text) or text[start] not in "'\"`":
        return "", start
    quote = text[start]
    cursor = start + 1
    escaped = False
    while cursor < len(text):
        char = text[cursor]
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == quote:
            return text[start + 1:cursor], cursor + 1
        cursor += 1
    return text[start + 1:], len(text)


def _read_expression(text: str, start: int, stops: str = ",)") -> Tuple[str, int]:
    """Read an argument until a top-level delimiter; strings are respected."""
    cursor = start
    begin = start
    stack: List[str] = []
    quote: Optional[str] = None
    escaped = False
    while cursor < len(text):
        char = text[cursor]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
        else:
            if char in "'\"`":
                quote = char
            elif char in "{[":
                stack.append(char)
            elif char in "}]" and stack:
                stack.pop()
            elif not stack and char in stops:
                break
        cursor += 1
    return text[begin:cursor].strip(), cursor


def _read_balanced(text: str, start: int, opening: str = "{", closing: str = "}") -> Tuple[str, int]:
    if start >= len(text) or text[start] != opening:
        return "", start
    depth = 0
    quote: Optional[str] = None
    escaped = False
    cursor = start
    while cursor < len(text):
        char = text[cursor]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
        else:
            if char in "'\"`":
                quote = char
            elif char == opening:
                depth += 1
            elif char == closing:
                depth -= 1
                if depth == 0:
                    return text[start:cursor + 1], cursor + 1
        cursor += 1
    return text[start:], len(text)


def _split_top_level(value: str, delimiter: str = "+") -> List[str]:
    parts: List[str] = []
    begin = 0
    depth = 0
    quote: Optional[str] = None
    escaped = False
    for index, char in enumerate(value):
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
        else:
            if char in "'\"`":
                quote = char
            elif char in "({[":
                depth += 1
            elif char in ")}]":
                depth = max(0, depth - 1)
            elif char == delimiter and depth == 0:
                parts.append(value[begin:index].strip())
                begin = index + 1
    parts.append(value[begin:].strip())
    return parts


class LightDataFlowAnalyzer:
    """Small, deterministic data-flow pass for common frontend request code."""

    ASSIGNMENT_RE = re.compile(
        rf"\b(?:const|let|var)\s+(?P<name>{_IDENTIFIER})\s*=\s*(?P<expr>[^;\n]+)", re.MULTILINE
    )
    PROPERTY_ASSIGNMENT_RE = re.compile(
        rf"\b(?P<object>{_IDENTIFIER})\.(?P<property>{_IDENTIFIER})\s*=\s*(?P<expr>[^;\n]+)"
    )
    STORAGE_SET_RE = re.compile(
        rf"(?P<store>localStorage|sessionStorage)\.setItem\(\s*(['\"])(?P<key>[^'\"]+)\2\s*,\s*(?P<value>[^)]+)\)",
        re.IGNORECASE,
    )
    STORAGE_GET_RE = re.compile(
        rf"(?P<store>localStorage|sessionStorage)\.getItem\(\s*(['\"])(?P<key>[^'\"]+)\2\s*\)",
        re.IGNORECASE,
    )

    def __init__(self, redactor: Optional[SecretRedactor] = None):
        self.redactor = redactor or SecretRedactor()

    @staticmethod
    def _kind(expr: str) -> str:
        normalized = expr.strip()
        if normalized.startswith(("'", '"', "`")):
            return "literal"
        if "process.env" in normalized or "import.meta.env" in normalized or "window.__" in normalized:
            return "runtime_config"
        if ".accessToken" in normalized or ".access_token" in normalized or ".token" in normalized:
            return "response_field"
        if "getItem" in normalized:
            return "storage_read"
        if "function" in normalized or "=>" in normalized:
            return "function_result"
        return "variable_reference"

    def analyze(self, text: str, source_file: str = "unknown", source_url: Optional[str] = None) -> Dict[str, Any]:
        line_at = _line_number_lookup(text)
        variables: Dict[str, Dict[str, Any]] = {}
        definitions: List[Dict[str, Any]] = []
        relationships: List[Dict[str, Any]] = []
        for match in self.ASSIGNMENT_RE.finditer(text or ""):
            name, expr = match.group("name"), match.group("expr").strip()
            literal_value = None
            if expr[:1] in "'\"`":
                literal_value, _ = _read_quoted(expr, 0)
            expression_for_report = (
                f"{expr[0]}{self.redactor.mask_secret(literal_value)}{expr[0]}"
                if literal_value and expr[:1] in "'\"`" else self.redactor.redact_text(expr)[:500]
            )
            variables[name] = {
                "name": name, "kind": self._kind(expr),
                "expression": expression_for_report[:500],
                "masked_value": self.redactor.mask_secret(literal_value) if literal_value else None,
                "sha256": self.redactor.fingerprint(literal_value) if literal_value else None,
                "source_file": source_file, "source_url": source_url,
                "source_line": line_at(match.start()),
            }
            definitions.append(variables[name])
            if "." in expr and not literal_value:
                relationships.append({
                    "relationship_type": "data_flow",
                    "from": expr[:200], "to": name, "source": source_file,
                    "source_line": line_at(match.start()),
                })

        for match in self.PROPERTY_ASSIGNMENT_RE.finditer(text or ""):
            target = f"{match.group('object')}.{match.group('property')}"
            expr = match.group("expr").strip()
            relationships.append({
                "relationship_type": "property_assignment", "from": self.redactor.redact_text(expr)[:200],
                "to": target, "source": source_file, "source_line": line_at(match.start()),
            })

        for match in self.STORAGE_SET_RE.finditer(text or ""):
            value_expr = self.redactor.redact_text(match.group("value").strip())[:300]
            relationships.append({
                "relationship_type": "storage_write",
                "from": value_expr, "to": f"{match.group('store')}.{match.group('key')}",
                "source": source_file, "source_line": line_at(match.start()),
                "storage": match.group("store"), "key": match.group("key"),
            })
        for match in self.STORAGE_GET_RE.finditer(text or ""):
            relationships.append({
                "relationship_type": "storage_read",
                "from": f"{match.group('store')}.{match.group('key')}", "to": "request_header_or_logic",
                "source": source_file, "source_line": line_at(match.start()),
                "storage": match.group("store"), "key": match.group("key"),
            })

        return {"variables": variables, "definitions": definitions, "relationships": relationships}


class JSDeepAnalyzer:
    """Extract assets, requests, config references, and contextual candidates."""

    FRAMEWORK_MARKERS: Sequence[Tuple[str, Sequence[str]]] = (
        ("Next.js", ("__NEXT_DATA__", "/_next/static/", "/_next/data/", "next/router", "next-flight")),
        ("Nuxt", ("/_nuxt/", "__NUXT__", "nuxtapp")),
        ("Vite", ("import.meta.env", "modulepreload", "@vite/client", "vite/")),
        ("Webpack", ("webpackjsonp", "webpack_require__", "webpackChunk", "__webpack_require__")),
        ("React", ("reactdom", "react.createelement", "__reactfiber", "data-reactroot")),
        ("Angular", ("ng-version", "@angular/core", "ngcomponent")),
        ("Svelte/SvelteKit", ("svelte", "__svelte", "__data.json")),
        ("Remix", ("__remixcontext", "__remix_manifest", "/build/")),
        ("Astro", ("astro-island", "/_astro/", "astro:page-load")),
    )
    ENV_RE = re.compile(
        r"\b(?:NEXT_PUBLIC_[A-Z0-9_]+|VITE_[A-Z0-9_]+|REACT_APP_[A-Z0-9_]+|"
        r"NUXT_PUBLIC_[A-Z0-9_]+|PUBLIC_[A-Z0-9_]+|process\.env\.[A-Za-z_$][\w$]*|"
        r"import\.meta\.env\.[A-Za-z_$][\w$]*|window\.__ENV__|window\.__CONFIG__|"
        r"import\.meta\.env|window\.config|globalThis\.__ENV__|globalThis\.__CONFIG__|globalThis\.config)\b",
        re.IGNORECASE,
    )
    ENDPOINT_PATH_RE = re.compile(
        r"(?P<quote>['\"`])(?P<value>(?:/|https?://|wss?://)[^'\"`\s]{1,500})(?P=quote)", re.IGNORECASE
    )
    FRONTEND_ROUTE_RE = re.compile(
        r"(?:router\.(?:push|replace|prefetch)|navigate|history\.pushState|href|to|path)"
        r"\s*(?:\(|:|=)\s*(['\"])(/[^'\"?#]{1,240})\1",
        re.IGNORECASE,
    )
    AUTH_HEADER_RE = re.compile(
        r"['\"]?(?P<key>authorization|x-api-key|api[-_]?key|apikey|x-auth-token|x-access-token|"
        r"x-csrf-token|x-xsrf-token)['\"]?\s*:\s*(?P<value>[^,}\n]+)", re.IGNORECASE
    )
    GENERIC_HEADER_RE = re.compile(
        r"['\"]?(?P<key>[A-Za-z][A-Za-z0-9_-]{1,79})['\"]?\s*:\s*(?P<value>[^,}\n]+)"
    )
    RESPONSE_FIELD_RE = re.compile(
        r"\b(access_token|accessToken|refresh_token|refreshToken|id_token|idToken|jwt|token|session|authorization)\b"
    )
    URL_LIKE_EXTENSIONS = (".js", ".mjs", ".cjs", ".json", ".map", ".css", ".png", ".jpg", ".svg", ".woff", ".woff2")

    def __init__(self, *, redactor: Optional[SecretRedactor] = None,
                 runtime_config: Optional[RuntimeConfigAnalyzer] = None,
                 data_flow: Optional[LightDataFlowAnalyzer] = None):
        self.redactor = redactor or SecretRedactor()
        self.runtime_config = runtime_config or RuntimeConfigAnalyzer(self.redactor)
        self.data_flow = data_flow or LightDataFlowAnalyzer(self.redactor)

    def detect_frameworks(self, text: str) -> List[str]:
        lowered = (text or "").lower()
        result = [name for name, markers in self.FRAMEWORK_MARKERS if any(marker.lower() in lowered for marker in markers)]
        return result or []

    @staticmethod
    def _decode_static(value: str) -> str:
        value = value or ""
        # Decode only literal escape forms; no JavaScript evaluation.
        try:
            value = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), value)
            value = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), value)
            value = codecs.decode(value, "unicode_escape")
        except (UnicodeDecodeError, ValueError):
            pass
        return value

    def _static_value(self, expression: str, variables: Dict[str, str]) -> Optional[str]:
        expression = expression.strip()
        if expression[:1] in "'\"`":
            raw, _ = _read_quoted(expression, 0)
            # For template literals, substitute only constants known to this
            # pass and preserve unknown placeholders as text.
            raw = re.sub(r"\$\{(" + _IDENTIFIER + r")\}", lambda m: variables.get(m.group(1), m.group(0)), raw)
            return self._decode_static(raw)
        atob_match = re.fullmatch(r"(?:window\.)?atob\(\s*(['\"])([^'\"]+)\1\s*\)", expression)
        if atob_match:
            try:
                return base64.b64decode(atob_match.group(2), validate=True).decode("utf-8")
            except (ValueError, UnicodeError):
                return None
        if expression in variables:
            return variables[expression]
        parts = _split_top_level(expression, "+")
        if len(parts) > 1:
            values = [self._static_value(part, variables) for part in parts]
            return "".join(values) if all(value is not None for value in values) else None
        join_match = re.fullmatch(r"\[\s*((?:['\"][^'\"]*['\"]\s*,?\s*)+)\s*\]\.join\(\s*(['\"])(.*?)\2\s*\)", expression)
        if join_match:
            literals = re.findall(r"['\"]([^'\"]*)['\"]", join_match.group(1))
            return join_match.group(3).join(literals)
        return None

    def _constant_values(self, text: str) -> Dict[str, str]:
        values: Dict[str, str] = {}
        # A few passes allow const B = A + "/path" to resolve without a full compiler.
        for _ in range(3):
            for match in re.finditer(rf"\b(?:const|let|var)\s+({_IDENTIFIER})\s*=\s*([^;\n]+)", text or ""):
                value = self._static_value(match.group(2), values)
                if value is not None and len(value) <= 2000:
                    values[match.group(1)] = value
        return values

    @staticmethod
    def _object_configs(text: str) -> Dict[str, str]:
        """Collect bounded object literals used as request options.

        This is intentionally structural rather than a JavaScript evaluator:
        it only records ``const opts = { ... }`` blocks and respects nested
        braces/quoted strings.  It is enough to connect common ``fetch(url,
        opts)`` and ``fetch(url, { ...opts })`` call sites to their headers and
        body shape without executing arbitrary bundle code.
        """
        configs: Dict[str, str] = {}
        for match in re.finditer(rf"\b(?:const|let|var)\s+({_IDENTIFIER})\s*=\s*\{{", text or ""):
            block, _ = _read_balanced(text, match.end() - 1)
            if block and len(block) <= 20000:
                configs[match.group(1)] = block
        return configs

    @staticmethod
    def _expand_object_spreads(config: str, object_configs: Dict[str, str]) -> str:
        expanded = config or ""
        for _ in range(3):
            changed = False

            def replace(match: re.Match[str]) -> str:
                nonlocal changed
                value = object_configs.get(match.group(1))
                if value is None:
                    return match.group(0)
                changed = True
                return value.strip()[1:-1] if value.strip().startswith("{") else value

            expanded = re.sub(r"\.\.\.\s*([A-Za-z_$][\w$]*)", replace, expanded)
            if not changed:
                break
        return expanded

    def asset_references(self, text: str, base_url: str, *, source_file: str = "unknown") -> List[Dict[str, Any]]:
        refs: List[Dict[str, Any]] = []
        line_at = _line_number_lookup(text)
        seen: set[Tuple[str, str]] = set()
        values = self._constant_values(text)

        def add(expression: str, kind: str, match: re.Match[str]) -> None:
            value = self._static_value(expression, values) or expression.strip("'\"` ")
            if not value or "${" in value:
                return
            url = urllib.parse.urljoin(base_url, value)
            if not urllib.parse.urlsplit(url).scheme in {"http", "https"}:
                return
            if kind == "fetch_asset":
                path = urllib.parse.urlsplit(url).path.lower()
                is_code = path.endswith((".js", ".mjs", ".cjs"))
                is_json = path.endswith(".json")
                is_runtime = self.runtime_config.is_runtime_config_url(url)
                if not (is_code or is_json or is_runtime):
                    return
                kind = "runtime_config" if is_runtime else ("manifest" if path.endswith("manifest.json") else "javascript")
            key = (url, kind)
            if key in seen:
                return
            seen.add(key)
            refs.append({
                "url": url, "asset_type": kind, "source_file": source_file,
                "source_line": line_at(match.start()),
                "context": _snippet(text, match.start(), match.end(), self.redactor),
            })

        patterns = (
            (r"\bimport\s*\(\s*(['\"`])([^'\"`]+)\1", "dynamic_chunk", 2),
            (rf"\bimport\s+(?:[^;\n]+?\s+from\s+)?(['\"`])([^'\"`]+)\1", "module", 2),
            (r"\brequire\s*\(\s*(['\"`])([^'\"`]+)\1", "module", 2),
            (r"\bnew\s+Worker\s*\(\s*(['\"`])([^'\"`]+)\1", "web_worker", 2),
            (r"navigator\.serviceWorker\.register\s*\(\s*(['\"`])([^'\"`]+)\1", "service_worker", 2),
            (r"\b(?:importScripts|workbox\.precaching)\s*\(\s*(['\"`])([^'\"`]+)\1", "worker_asset", 2),
            (r"\bfetch\s*\(\s*(['\"`])([^'\"`]+)\1", "fetch_asset", 2),
        )
        for pattern, kind, group in patterns:
            for match in re.finditer(pattern, text or "", re.IGNORECASE):
                add(match.group(group), kind, match)
        return refs

    def html_references(self, html: str, base_url: str, *, source_file: str = "document") -> List[Dict[str, Any]]:
        refs: List[Dict[str, Any]] = []
        line_at = _line_number_lookup(html)
        attr_re = re.compile(
            r"<script\b[^>]*\bsrc\s*=\s*(['\"])([^'\"]+)\1[^>]*>|"
            r"<link\b[^>]*\brel\s*=\s*(['\"])([^'\"]+)\3[^>]*\bhref\s*=\s*(['\"])([^'\"]+)\5[^>]*>|"
            r"<link\b[^>]*\bhref\s*=\s*(['\"])([^'\"]+)\7[^>]*\brel\s*=\s*(['\"])([^'\"]+)\9[^>]*>",
            re.IGNORECASE,
        )
        for match in attr_re.finditer(html or ""):
            groups = match.groups()
            if groups[1]:
                value, kind = groups[1], "javascript"
            elif groups[5]:
                value, rel, kind = groups[5], (groups[3] or "").lower(), "preload"
                if "modulepreload" in rel:
                    kind = "modulepreload"
                elif "manifest" in rel:
                    kind = "manifest"
            elif groups[7]:
                value, rel, kind = groups[7], (groups[9] or "").lower(), "preload"
                if "modulepreload" in rel:
                    kind = "modulepreload"
                elif "manifest" in rel:
                    kind = "manifest"
            else:
                continue
            url = urllib.parse.urljoin(base_url, value)
            if urllib.parse.urlsplit(url).scheme not in {"http", "https"}:
                continue
            refs.append({
                "url": url, "asset_type": kind, "source_file": source_file,
                "source_line": line_at(match.start()),
                "context": _snippet(html, match.start(), match.end(), self.redactor),
            })
        # Next's build/data manifests and common framework assets are often
        # embedded in inline JSON or preload hints rather than a script tag.
        for match in re.finditer(r"(['\"])(/_(?:next|nuxt)/[^'\"]+|/_astro/[^'\"]+|/assets/[^'\"]+\.js)['\"]", html or "", re.IGNORECASE):
            url = urllib.parse.urljoin(base_url, match.group(2))
            refs.append({"url": url, "asset_type": "framework_asset", "source_file": source_file,
                         "source_line": line_at(match.start()),
                         "context": _snippet(html, match.start(), match.end(), self.redactor)})
        return refs

    def frontend_routes(self, text: str) -> List[str]:
        """Extract internal UI routes for optional, scope-gated route crawl."""
        routes: set[str] = set()
        for match in self.FRONTEND_ROUTE_RE.finditer(text or ""):
            route = match.group(2)
            if route.startswith(("/api/", "/_next/", "/_nuxt/", "/_astro/", "/assets/")):
                continue
            routes.add(route)
        return sorted(routes)

    @staticmethod
    def _resolve_url(value: Optional[str], base_url: str, variables: Dict[str, str]) -> Optional[str]:
        if not value:
            return None
        value = value.strip()
        if value in variables:
            value = variables[value]
        if value[:1] in "'\"`":
            value, _ = _read_quoted(value, 0)
        # A request wrapper such as ``fetch(path, init)`` is not an endpoint
        # until the caller's value is reconstructed. Treating the unresolved
        # identifier as a literal relative path manufactures URLs like
        # ``/assets/path`` and later makes the evidence ledger claim a request
        # that was never sent.
        if (value not in variables and not value.startswith(("/", "http://", "https://", "ws://", "wss://"))
                and "${" not in value):
            return None
        if not value or "${" in value:
            return None
        return urllib.parse.urljoin(base_url, value)

    def _header_info(self, config: str, text: str, start: int) -> Tuple[Dict[str, Any], Optional[str], bool]:
        headers: Dict[str, Any] = {}
        auth_source: Optional[str] = None
        auth_required = False
        header_match = re.search(r"['\"]?headers['\"]?\s*:\s*\{", config, re.IGNORECASE)
        header_body = config[header_match.end():] if header_match else config
        if header_match:
            header_body, _ = _read_balanced(config, header_match.end() - 1)
        matches = list(self.GENERIC_HEADER_RE.finditer(header_body)) if header_match else []
        for match in matches:
            key = match.group("key")
            expression = match.group("value").strip()
            expression = expression.rstrip("} ")
            kind = "literal" if expression[:1] in "'\"`" else ("function_result" if "(" in expression else "variable_reference")
            is_auth_header = (key.lower() in SecretRedactor.HEADER_NAMES
                              or "authorization" in key.lower() or "token" in key.lower()
                              or "api" in key.lower() or "csrf" in key.lower())
            if is_auth_header:
                auth_required = True
                auth_source = self.redactor.redact_auth_reference(expression)[:200]
            headers[key] = {"kind": kind, "reference": self.redactor.redact_auth_reference(expression)[:200]
                            if is_auth_header
                            else self.redactor.redact_text(expression)[:200]}
        return headers, auth_source, auth_required

    def _body_shape(self, config: str) -> Dict[str, Any]:
        fields: List[str] = []
        json_match = re.search(r"JSON\.stringify\s*\(\s*\{", config, re.IGNORECASE)
        if json_match:
            body, _ = _read_balanced(config, json_match.end() - 1)
        else:
            body_match = re.search(r"\bbody\s*:\s*", config, re.IGNORECASE)
            # Header/options objects are not request bodies.  Limiting this
            # pass to the observed ``body`` property prevents fields such as
            # ``Accept`` and ``headers`` from becoming fake attacker inputs.
            if not body_match:
                return {}
            body = config[body_match.end():]
        for match in re.finditer(r"(?:^|[,\s])(['\"]?)([A-Za-z_$][\w$-]*)\1\s*:", body):
            fields.append(match.group(2))
        # Object shorthand is common in minified/source code:
        # JSON.stringify({email, password}).  Only inspect the extracted body
        # object, never runtime values.
        if json_match:
            for match in re.finditer(r"(?:\{|,)\s*([A-Za-z_$][\w$]*)\s*(?=,|$|})", body):
                fields.append(match.group(1))
        if not fields:
            return {}
        return {"fields": sorted(set(fields)), "field_count": len(set(fields)), "values_retained": False}

    def _append_endpoint(self, endpoints: List[EndpointRecord], *, url: Optional[str], method: str,
                         source_file: str, source_url: str, source_map: Optional[str],
                         line: int, request_type: str, headers: Optional[Dict[str, Any]] = None,
                         body_shape: Optional[Dict[str, Any]] = None, auth_source: Optional[str] = None,
                         auth_required: Optional[bool] = None, framework: Optional[str] = None,
                         parent_asset: Optional[str] = None, context: str = "", confidence: float = .7) -> None:
        if not url or urllib.parse.urlsplit(url).scheme not in {"http", "https", "ws", "wss"}:
            return
        url = self.redactor.redact_url(url)
        endpoints.append(EndpointRecord(
            url=url, method=method.upper(), source_file=source_file, source_line=line,
            request_type=request_type, headers=headers or {}, body_shape=body_shape or {},
            auth_required=auth_required, auth_source=auth_source, confidence=confidence,
            source_map=source_map, framework=framework, parent_asset=parent_asset,
            evidence=[{"source_file": source_file, "source_line": line,
                        "context": self.redactor.redact_text(context)[:600]}],
        ))

    def extract_endpoints(self, text: str, *, source_file: str, source_url: str,
                          source_map: Optional[str] = None, framework: Optional[str] = None,
                          parent_asset: Optional[str] = None) -> List[EndpointRecord]:
        endpoints: List[EndpointRecord] = []
        line_at = _line_number_lookup(text)
        variables = self._constant_values(text)
        object_configs = self._object_configs(text)

        # fetch() — parse actual first argument and bounded config object.
        for match in re.finditer(r"\bfetch\s*\(", text or "", re.IGNORECASE):
            url_expr, cursor = _read_expression(text, match.end())
            config = ""
            if cursor < len(text) and text[cursor] == ",":
                cursor += 1
                while cursor < len(text) and text[cursor].isspace():
                    cursor += 1
                if cursor < len(text) and text[cursor] == "{":
                    config, _ = _read_balanced(text, cursor)
                else:
                    options_expr, _ = _read_expression(text, cursor, stops=")")
                    config = object_configs.get(options_expr.strip(), "")
            config = self._expand_object_spreads(config, object_configs)
            url = self._resolve_url(url_expr, source_url, variables)
            method_match = re.search(r"\bmethod\s*:\s*(['\"])([A-Za-z]+)\1", config, re.IGNORECASE)
            method = method_match.group(2) if method_match else "GET"
            headers, auth_source, auth_required = self._header_info(config, text, match.start())
            self._append_endpoint(endpoints, url=url, method=method, source_file=source_file, source_url=source_url,
                                  source_map=source_map, line=line_at(match.start()), request_type="REST",
                                  headers=headers, body_shape=self._body_shape(config), auth_source=auth_source,
                                  auth_required=auth_required if headers else None, framework=framework,
                                  parent_asset=parent_asset, context=text[match.start(): min(len(text), match.start() + 1800)], confidence=.92)

        # axios.<method>(url, ...) and common request-client aliases.
        for match in re.finditer(r"\b(?P<client>axios|api|client|http|request)\.(?P<method>get|post|put|patch|delete|head|options)\s*\(", text or "", re.IGNORECASE):
            url_expr, _ = _read_expression(text, match.end())
            url = self._resolve_url(url_expr, source_url, variables)
            tail = text[match.start(): min(len(text), match.start() + 1800)]
            headers, auth_source, auth_required = self._header_info(tail, text, match.start())
            self._append_endpoint(endpoints, url=url, method=match.group("method"), source_file=source_file,
                                  source_url=source_url, source_map=source_map, line=line_at(match.start()),
                                  request_type="REST", headers=headers, body_shape=self._body_shape(tail),
                                  auth_source=auth_source, auth_required=auth_required if headers else None,
                                  framework=framework, parent_asset=parent_asset, context=tail, confidence=.84)

        for match in re.finditer(r"\b(?:axios|api|client|http)\s*\(\s*\{", text or "", re.IGNORECASE):
            config, _ = _read_balanced(text, match.end() - 1)
            url_match = re.search(r"\b(?:url|baseURL|endpoint)\s*:\s*([^,}]+)", config, re.IGNORECASE)
            method_match = re.search(r"\bmethod\s*:\s*(['\"])([A-Za-z]+)\1", config, re.IGNORECASE)
            url = self._resolve_url(url_match.group(1) if url_match else None, source_url, variables)
            headers, auth_source, auth_required = self._header_info(config, text, match.start())
            self._append_endpoint(endpoints, url=url, method=method_match.group(2) if method_match else "GET",
                                  source_file=source_file, source_url=source_url, source_map=source_map,
                                  line=line_at(match.start()), request_type="REST", headers=headers,
                                  body_shape=self._body_shape(config), auth_source=auth_source,
                                  auth_required=auth_required if headers else None, framework=framework,
                                  parent_asset=parent_asset, context=config, confidence=.8)

        # XMLHttpRequest.open(method, url) must retain its actual method.
        for match in re.finditer(r"\.open\s*\(\s*(['\"])([A-Za-z]+)\1\s*,\s*([^,)]+)", text or "", re.IGNORECASE):
            url = self._resolve_url(match.group(3), source_url, variables)
            self._append_endpoint(endpoints, url=url, method=match.group(2), source_file=source_file,
                                  source_url=source_url, source_map=source_map, line=line_at(match.start()),
                                  request_type="REST", framework=framework, parent_asset=parent_asset,
                                  context=match.group(0), confidence=.82)

        for match in re.finditer(r"\bnew\s+WebSocket\s*\(\s*([^,)]+)", text or "", re.IGNORECASE):
            url = self._resolve_url(match.group(1), source_url, variables)
            if url and urllib.parse.urlsplit(url).scheme in {"ws", "wss"}:
                self._append_endpoint(endpoints, url=url, method="CONNECT", source_file=source_file,
                                      source_url=source_url, source_map=source_map, line=line_at(match.start()),
                                      request_type="WebSocket", framework=framework, parent_asset=parent_asset,
                                      context=match.group(0), confidence=.94)
        # Socket.IO uses an HTTP(S) origin during the initial handshake but is
        # still a WebSocket-style realtime surface.  Keep it distinct from a
        # normal REST call and never send a connection as part of static scan.
        for match in re.finditer(r"\b(?:io|socket\.io)\s*\(\s*([^,)]+)", text or "", re.IGNORECASE):
            url = self._resolve_url(match.group(1), source_url, variables)
            self._append_endpoint(endpoints, url=url, method="CONNECT", source_file=source_file,
                                  source_url=source_url, source_map=source_map, line=line_at(match.start()),
                                  request_type="Socket.IO", framework=framework, parent_asset=parent_asset,
                                  context=match.group(0), confidence=.86)
        for match in re.finditer(r"\b(?:new\s+)?EventSource\s*\(\s*([^,)]+)", text or "", re.IGNORECASE):
            url = self._resolve_url(match.group(1), source_url, variables)
            self._append_endpoint(endpoints, url=url, method="GET", source_file=source_file,
                                  source_url=source_url, source_map=source_map, line=line_at(match.start()),
                                  request_type="SSE", framework=framework, parent_asset=parent_asset,
                                  context=match.group(0), confidence=.9)
        for match in re.finditer(r"\b(?:uri|url|endpoint|httpEndpoint|uriTemplate)\s*:\s*(['\"])([^'\"]+)\1", text or "", re.IGNORECASE):
            url = self._resolve_url(match.group(2), source_url, variables)
            if "graphql" in match.group(2).lower() or re.search(r"ApolloClient|urql|graphql-request|Relay", text, re.IGNORECASE):
                request_type = "GraphQL"
            else:
                request_type = "REST"
            self._append_endpoint(endpoints, url=url, method="POST" if request_type == "GraphQL" else "GET",
                                  source_file=source_file, source_url=source_url, source_map=source_map,
                                  line=line_at(match.start()), request_type=request_type,
                                  framework=framework, parent_asset=parent_asset, context=match.group(0), confidence=.75)

        # Add relevant literal routes not attached to a recognized call.  This
        # is discovery only; no route name implies authorization or impact.
        call_spans = [(item.start(), item.end()) for item in re.finditer(r"\b(?:fetch|axios|WebSocket|EventSource)\b", text or "", re.IGNORECASE)]
        for match in self.ENDPOINT_PATH_RE.finditer(text or ""):
            value = self._static_value(match.group("value"), variables) or match.group("value")
            parsed = urllib.parse.urlsplit(urllib.parse.urljoin(source_url, value))
            lowered = value.lower()
            relevant = (parsed.path.startswith(("/api", "/graphql", "/rpc", "/auth", "/oauth", "/admin", "/internal", "/private", "/debug", "/upload", "/download", "/export", "/webhook", "/rest/v", "/_next/data/")))
            relevant = relevant or parsed.scheme in {"ws", "wss"} or "supabase.co" in parsed.netloc or "firebaseio.com" in parsed.netloc
            if not relevant:
                continue
            if any(start <= match.start() <= end + 1500 for start, end in call_spans):
                continue
            literal_url = urllib.parse.urljoin(source_url, value)
            endpoint_type = "NextData" if parsed.path.startswith("/_next/data/") else ("GraphQL" if "graphql" in lowered else "REST")
            self._append_endpoint(endpoints, url=literal_url, method="GET",
                                  source_file=source_file, source_url=source_url, source_map=source_map,
                                  line=line_at(match.start()), request_type=endpoint_type,
                                  framework=framework, parent_asset=parent_asset,
                                  context=match.group(0), confidence=.58)
        return endpoints

    def _credential_observations(self, text: str, source_file: str, source_url: str,
                                 source_map: Optional[str] = None) -> List[Dict[str, Any]]:
        line_at = _line_number_lookup(text)
        values = self._constant_values(text)
        observations: List[Dict[str, Any]] = []
        seen: set[Tuple[str, int]] = set()
        assignment_names: Dict[str, Tuple[str, int]] = {}
        for match in re.finditer(rf"\b(?:const|let|var)\s+({_IDENTIFIER})\s*=\s*([^;\n]+)", text or ""):
            value = self._static_value(match.group(2), values)
            if value:
                assignment_names[value] = (match.group(1), line_at(match.start()))
        for match in _STRING_RE.finditer(text or ""):
            raw = self._decode_static(match.group("value"))
            if len(raw) < 6:
                continue
            context = text[max(0, match.start() - 180): min(len(text), match.end() + 260)]
            local_context = text[max(0, match.start() - 90): min(len(text), match.end() + 110)]
            variable_name, assignment_line = assignment_names.get(raw, (None, None))
            named_candidate = bool(variable_name and re.search(
                r"(?:key|token|secret|credential|password|authorization|apikey)", variable_name, re.IGNORECASE
            ))
            direct_header_value = bool(re.search(
                r"(?:authorization|x-api-key|api[-_]?key|apikey|x-auth-token|x-access-token)\s*:\s*['\"`]$",
                local_context[: max(0, local_context.find(match.group(0)))], re.IGNORECASE
            ))
            is_candidate = bool(self.redactor.TOKEN_RE.search(raw)) or named_candidate or direct_header_value
            if not is_candidate:
                continue
            classified = self.redactor.safe_credential(raw, context=context, variable_name=variable_name)
            key = (classified["sha256"], line_at(match.start()))
            if key in seen:
                continue
            seen.add(key)
            classified.update({
                "source_url": source_url, "source_file": source_file,
                "source_line": assignment_line or line_at(match.start()),
                "variable_name": variable_name, "source_map": source_map,
                "context": self.redactor.redact_text(context)[:600],
            })
            observations.append(classified)
        # Bearer strings can be assembled in template literals and may not be
        # present as a standalone string token.
        for match in re.finditer(r"\bBearer\s+([A-Za-z0-9._~+/=-]{16,})", text or "", re.IGNORECASE):
            raw = "Bearer " + match.group(1)
            classified = self.redactor.safe_credential(raw, context=text[max(0, match.start() - 120):match.end() + 120])
            key = (classified["sha256"], line_at(match.start()))
            if key not in seen:
                seen.add(key)
                classified.update({"source_url": source_url, "source_file": source_file,
                                   "source_line": line_at(match.start()),
                                   "context": self.redactor.redact_text(text[max(0, match.start() - 120):match.end() + 120])[:600],
                                   "source_map": source_map})
                observations.append(classified)
        return observations

    def analyze(self, text: str, *, source_file: str = "unknown", source_url: str = "https://target.invalid/",
                source_map: Optional[str] = None, framework: Optional[str] = None) -> Dict[str, Any]:
        text = text or ""
        detected_frameworks = self.detect_frameworks(text)
        chosen_framework = framework or (detected_frameworks[0] if detected_frameworks else None)
        flow = self.data_flow.analyze(text, source_file=source_file, source_url=source_url)
        endpoint_records = self.extract_endpoints(text, source_file=source_file, source_url=source_url,
                                                  source_map=source_map, framework=chosen_framework,
                                                  parent_asset=source_url)
        config_refs = self.runtime_config.extract_env_references(text, source_file=source_file, source_url=source_url)
        asset_refs = self.asset_references(text, source_url, source_file=source_file)
        credential_observations = self._credential_observations(text, source_file, source_url, source_map)
        frontend_routes = self.frontend_routes(text)
        response_fields = sorted(set(self.RESPONSE_FIELD_RE.findall(text)))
        auth_observations = {
            "response_token_fields": response_fields,
            "storage_keys": sorted({match.group("key") for match in LightDataFlowAnalyzer.STORAGE_SET_RE.finditer(text)}),
            "storage_reads": sorted({match.group("key") for match in LightDataFlowAnalyzer.STORAGE_GET_RE.finditer(text)}),
            "header_names": sorted({match.group("key") for match in self.AUTH_HEADER_RE.finditer(text)}, key=str.lower),
            "auth_endpoints": [record.url for record in endpoint_records if any(token in record.url.lower() for token in ("login", "signin", "auth", "oauth", "token", "refresh", "logout"))],
        }
        source_map_url = None
        map_match = re.search(r"(?:\/\/[#@]|\/\*[@#])\s*sourceMappingURL\s*=\s*([^\s*'\"]+)", text)
        if map_match:
            source_map_url = urllib.parse.urljoin(source_url, map_match.group(1))
        return {
            "frameworks": detected_frameworks,
            "framework": chosen_framework,
            "asset_references": asset_refs,
            "endpoints": endpoint_records,
            "config_references": config_refs,
            "credential_observations": credential_observations,
            "frontend_routes": frontend_routes,
            "framework_signals": {
                "next_rsc_or_flight": bool(re.search(r"next-flight|(?:^|[^a-z])rsc(?:[^a-z]|$)|Next-Router-State-Tree", text, re.IGNORECASE)),
                "next_server_actions": bool(re.search(r"use server|server action|\$ACTION_", text, re.IGNORECASE)),
                "service_worker": bool(re.search(r"serviceWorker\.register", text, re.IGNORECASE)),
            },
            "auth_observations": auth_observations,
            "data_flow": flow,
            "source_map_url": source_map_url,
            "source_file": source_file,
            "source_url": source_url,
        }

    analyze_script = analyze


__all__ = ["JSDeepAnalyzer", "LightDataFlowAnalyzer"]
