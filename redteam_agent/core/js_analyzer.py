"""
Deep Modern JavaScript Bundle & API Tracing Engine.
Extracts script bundles, unpacks sourcemaps (.map), extracts hidden API/GraphQL routes,
mines hidden parameters, harvests credentials/Bearer tokens, and live-probes discovered routes.
"""

import re
import json
import base64
import hashlib
import urllib.parse
from typing import List, Dict, Any, Set, Optional
from redteam_agent.core.config import (API_CALL_PATTERNS, DEFAULT_HEADERS, GREP_PATTERNS,
                                        ROUTE_PATTERNS, SECRET_PATTERNS)
from redteam_agent.core.http_verifier import HTTPVerifier
from redteam_agent.core.scope_manager import ScopeManager, normalize_url, URLPolicyError

class JSAnalyzer:
    def __init__(self, timeout: float = 8.0, verifier: Optional[HTTPVerifier] = None,
                 scope_manager: Optional[ScopeManager] = None):
        self.timeout = timeout
        self.scope = scope_manager
        self.verifier = verifier or HTTPVerifier(timeout=timeout, scope_manager=scope_manager, module="js_analyzer")
        self._cache: Dict[str, Dict[str, Any]] = {}
        self.failures: List[Dict[str, Any]] = []

    def fetch_url(self, url: str) -> Optional[Dict[str, Any]]:
        """Fetch once per normalized static URL; failures remain explicit and unobserved."""
        try:
            key = normalize_url(url)
        except URLPolicyError:
            return None
        if key in self._cache:
            return self._cache[key]
        response = self.verifier.send_http_request(url, headers=DEFAULT_HEADERS, priority="normal")
        result = {
            "status": response.get("status_code", 0), "headers": response.get("headers", {}),
            "body": response.get("body", ""), "success": response.get("success", False),
            "failure": response.get("failure"), "content_hash": hashlib.sha256(response.get("body", "").encode()).hexdigest()
                if response.get("body") else None,
        }
        if result.get("failure"):
            self.failures.append({"tool": "js_fetch", "url": url, **result["failure"]})
        self._cache[key] = result
        return result

    def discover_js_links(self, base_url: str, html_content: str) -> List[str]:
        """Discovers all external script links from HTML content."""
        js_links: Set[str] = set()

        # Regex for <script ... src="..." ...> (classic and module scripts)
        script_pattern = r'<script[^>]+src=["\']([^"\']+)["\']'
        matches = re.findall(script_pattern, html_content, re.IGNORECASE)
        for match in matches:
            full_url = urllib.parse.urljoin(base_url, match)
            if full_url.endswith(".js") or ".js?" in full_url or "/chunks/" in full_url:
                js_links.add(full_url)

        # <link rel="modulepreload"> / rel="preload" as="script"
        preload_pattern = r'<link[^>]+rel=["\'](?:modulepreload|preload)["\'][^>]+href=["\']([^"\']+)["\']' \
            r'|<link[^>]+href=["\']([^"\']+)["\'][^>]+rel=["\'](?:modulepreload|preload)["\']'
        for group in re.findall(preload_pattern, html_content, re.IGNORECASE):
            href = next((g for g in group if g), None)
            if href and (".js" in href or "/chunks/" in href):
                js_links.add(urllib.parse.urljoin(base_url, href))

        # Dynamic import("./chunk.js") inside inline scripts
        dynamic_pattern = r'import\s*\(\s*["\']([^"\']+\.js)["\']\s*\)'
        for match in re.findall(dynamic_pattern, html_content):
            js_links.add(urllib.parse.urljoin(base_url, match))

        # Next.js / Webpack / Vite statically-referenced assets
        for pattern in (r'["\'](/_next/static/chunks/[^"\']+\.js)["\']',
                        r'["\'](/assets/[^"\']+\.js)["\']',
                        r'["\'](/static/js/[^"\']+\.js)["\']',
                        r'["\'](/_nuxt/[^"\']+\.js)["\']'):
            for match in re.findall(pattern, html_content):
                js_links.add(urllib.parse.urljoin(base_url, match))

        return sorted(list(js_links))

    def unpack_sourcemap(self, js_url: str, js_content: str) -> Dict[str, Any]:
        """
        Attempts to detect and unpack .map sourcemaps associated with the JS bundle.
        Recovers original source file paths and code.
        """
        sourcemap_url = None
        # Check //# sourceMappingURL=...
        sm_match = re.search(r'//[#@]\s*sourceMappingURL=([^\s"\']+)', js_content)
        if sm_match:
            sourcemap_url = urllib.parse.urljoin(js_url, sm_match.group(1).strip())
        else:
            # Try convention: file.js.map
            sourcemap_url = js_url + ".map"

        result = {
            "has_sourcemap": False,
            "sourcemap_url": sourcemap_url,
            "sources": [],
            "extracted_files_count": 0,
            "unpacked_sources_sample": [],
            "sources_content": []
        }

        if not sourcemap_url:
            return result

        map_resp = self.fetch_url(sourcemap_url)
        if map_resp and map_resp["status"] == 200:
            try:
                map_json = json.loads(map_resp["body"])
                sources = map_json.get("sources", [])
                sources_content = map_json.get("sourcesContent", [])
                
                result["has_sourcemap"] = True
                result["sources"] = sources
                result["sources_content"] = sources_content
                result["extracted_files_count"] = len(sources)
                
                # Sample up to 5 source files
                for idx, src_name in enumerate(sources[:5]):
                    code_snippet = sources_content[idx][:300] if idx < len(sources_content) and sources_content[idx] else ""
                    result["unpacked_sources_sample"].append({
                        "filename": src_name,
                        "snippet": code_snippet
                    })
            except Exception:
                pass

        return result

    @staticmethod
    def _jwt_claims(token: str) -> Optional[dict]:
        try:
            part = token.split(".")[1]
            part += "=" * ((4 - len(part) % 4) % 4)
            return json.loads(base64.urlsafe_b64decode(part).decode("utf-8"))
        except Exception:
            return None

    def extract_secrets(self, content: str, source_label: str) -> List[Dict[str, Any]]:
        """Scans JavaScript content against secret regex patterns."""
        discovered_secrets = []
        for sec_name, pattern in SECRET_PATTERNS.items():
            matches = re.finditer(pattern, content)
            seen_tokens = set()
            for m in matches:
                matched_val = m.group(0).strip()
                if matched_val in seen_tokens or len(matched_val) < 6:
                    continue
                seen_tokens.add(matched_val)
                
                # Full token display for offensive research (not redacted)
                display_val = matched_val

                claims = self._jwt_claims(matched_val) if "jwt" in sec_name or "supabase" in sec_name else None
                role = (claims or {}).get("role")
                classification = "STRUCTURALLY_VALID" if claims or sec_name.endswith("_url") else "PATTERN_MATCH"
                privilege = "HIGH_PRIVILEGE" if role == "service_role" or sec_name in {
                    "aws_access_key", "stripe_secret_key", "github_token", "sendgrid_key"
                } else classification
                expected_frontend = sec_name in {"supabase_anon_key", "firebase_api_key", "stripe_publishable"}
                discovered_secrets.append({
                    "secret_type": sec_name,
                    "value": display_val,
                    "_raw_value": matched_val,
                    "display_value": display_val,
                    "source": source_label,
                    "classification": privilege,
                    "structurally_valid": bool(claims) or classification == "STRUCTURALLY_VALID",
                    "live_validated": False,
                    "jwt_claims": claims,
                    "expected_in_frontend": expected_frontend,
                    "fingerprint": hashlib.sha256(matched_val.encode()).hexdigest()[:16],
                    "severity": "Critical" if privilege == "HIGH_PRIVILEGE" else ("Info" if expected_frontend else "Medium")
                })

        # Custom auth header/field values: "campaign-token": "..." etc.
        # Vendor-specific auth keys are not covered by SECRET_PATTERNS.
        auth_value_re = re.compile(
            r'["\']([a-zA-Z0-9_-]*(?:token|secret|api[_-]?key|authorization|session)[a-zA-Z0-9_-]*)["\']'
            r'\s*[:=]\s*["\']([^"\']{8,})["\']',
            re.IGNORECASE,
        )
        seen_auth = set()
        for m in auth_value_re.finditer(content):
            key_name, value = m.group(1), m.group(2)
            if value in seen_auth or value.lower() in {"undefined", "null", "true", "false"}:
                continue
            seen_auth.add(value)
            start = max(0, m.start() - 60)
            context = content[start:m.end() + 60].replace("\n", " ")
            discovered_secrets.append({
                "secret_type": "custom_auth_value",
                "value": value,
                "_raw_value": value,
                "display_value": value,
                "source": source_label,
                "classification": "PATTERN_MATCH",
                "structurally_valid": False,
                "live_validated": False,
                "jwt_claims": None,
                "expected_in_frontend": False,
                "fingerprint": hashlib.sha256(value.encode()).hexdigest()[:16],
                "severity": "Medium",
                "auth_key": key_name,
                "context": context[:200],
            })
        return discovered_secrets

    def extract_routes(self, content: str) -> List[str]:
        """Extracts REST and GraphQL route paths from JavaScript content.

        Uses the hardcoded ROUTE_PATTERNS (kept for compatibility) PLUS a
        generic path-literal matcher so vendor-specific prefixes such as
        ``/rs/...`` (REI Vendor Portal) are not missed. Template literals
        with ``${param}`` placeholders are captured too.
        """
        routes: Set[str] = set()
        for pattern in ROUTE_PATTERNS:
            matches = re.findall(pattern, content)
            for r in matches:
                clean_r = r.strip()
                if clean_r and len(clean_r) > 2 and not clean_r.endswith(".png") and not clean_r.endswith(".jpg"):
                    routes.add(clean_r)

        # Generic path literals: "/a/b" or "/a/b/c" — any prefix, 2+ segments.
        # Covers single-quote, double-quote and backtick (template) strings.
        generic_re = re.compile(
            r'["\'`](/[a-zA-Z0-9_\-./{}:${}]+(?:/[a-zA-Z0-9_\-./{}:${}]+)+)["\'`]')
        static_markers = ("/assets/", "/vendor/", "/static/", "/node_modules/",
                          "/webpack/", "/_next/static/", "/dist/", "/build/",
                          "/images/", "/img/", "/fonts/", "/favicon")
        for m in generic_re.finditer(content):
            route = m.group(1).strip()
            if len(route) <= 2 or route in routes:
                continue
            if any(marker in route for marker in static_markers):
                continue
            last_seg = route.rsplit("/", 1)[-1].lower()
            if re.search(r"\.(?:js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|json|xml|html?)$", last_seg):
                continue
            routes.add(route)
        return sorted(list(routes))

    def extract_hidden_parameters(self, content: str) -> List[str]:
        """Extracts hidden query and body parameter names from JS AST logic."""
        params: Set[str] = set()
        
        # Patterns for params: .get("param"), params["param"], { param: value }
        param_patterns = [
            r'params\.(?:get|has)\(["\']([a-zA-Z0-9_\-]+)["\']\)',
            r'searchParams\.(?:get|has)\(["\']([a-zA-Z0-9_\-]+)["\']\)',
            r'query:\s*\{\s*["\']?([a-zA-Z0-9_\-]+)["\']?\s*:',
            r'body:\s*JSON\.stringify\(\s*\{\s*["\']?([a-zA-Z0-9_\-]+)["\']?\s*:',
            r'JSON\.stringify\(\s*\{\s*["\']?([a-zA-Z0-9_\-]+)["\']?\s*:',
            r'\{\s*["\']?([a-zA-Z0-9_\-]+)["\']?\s*:\s*["\']?[a-zA-Z0-9_\-]+["\']?\s*\}'
        ]
        
        for pat in param_patterns:
            for m in re.finditer(pat, content):
                param_name = m.group(1).strip()
                if len(param_name) > 1 and param_name not in ["true", "false", "null", "undefined", "return"]:
                    params.add(param_name)

        return sorted(list(params))

    def grep_content(self, content: str, source_label: str, max_per_pattern: int = 25) -> List[Dict[str, Any]]:
        """Applies the extended regex patterns set to any content (HTML, JS, sourcemap).
        Returns distinct matches with source label and surrounding context."""
        matches: List[Dict[str, Any]] = []
        for pattern_name, pattern in GREP_PATTERNS.items():
            found = 0
            seen = set()
            for m in re.finditer(pattern, content):
                value = m.group(0).strip()
                if not value or len(value) < 4 or value in seen:
                    continue
                seen.add(value)
                start = max(0, m.start() - 60)
                context = content[start:m.end() + 60].replace("\n", " ")
                matches.append({
                    "pattern": pattern_name,
                    "value": value[:160],
                    "source": source_label,
                    "context": context[:200],
                    "observed": True,
                })
                found += 1
                if found >= max_per_pattern:
                    break
        return matches

    def extract_api_calls(self, content: str, source_label: str) -> List[Dict[str, Any]]:
        """Finds concrete API call sites (fetch/axios/XHR/WebSocket) in JS content
        and traces the method + URL each call uses. Template literals with
        ``${param}`` placeholders are captured as parameterized routes."""
        calls: List[Dict[str, Any]] = []
        seen = set()
        for call_type, pattern in API_CALL_PATTERNS:
            for m in re.finditer(pattern, content):
                groups = [g for g in m.groups() if g]
                if not groups:
                    continue
                url = groups[-1]
                setting = groups[0] if len(groups) > 1 and call_type in ("xhr", "xhr_short") else ""
                key = (call_type, url)
                if key in seen:
                    continue
                seen.add(key)
                start = max(0, m.start() - 80)
                context = content[start:m.end() + 80].replace("\n", " ")
                route_only = url if url.startswith("/") else urllib.parse.urlsplit(url).path or url
                calls.append({
                    "call_type": call_type,
                    "method": (setting or "GET").upper(),
                    "url": url[:200],
                    "route": route_only[:200],
                    "source": source_label,
                    "context": context[:200],
                    "observed": True,
                })

        # Template-literal call sites: fetch(`/rs/asset/${id}`) etc.
        tpl_patterns = [
            ("fetch_tpl", r'fetch\s*\(\s*`([^`]+)`'),
            ("axios_tpl", r'axios\.(?:get|post|put|patch|delete|options|head|request)\s*\(\s*`([^`]+)`'),
            ("xhr_tpl", r'\.open\s*\(\s*["\']([A-Z]+)["\'],\s*`([^`]+)`'),
        ]
        for call_type, pattern in tpl_patterns:
            for m in re.finditer(pattern, content):
                groups = [g for g in m.groups() if g]
                if not groups:
                    continue
                url = groups[-1]
                setting = groups[0] if len(groups) > 1 else ""
                key = (call_type, url)
                if key in seen:
                    continue
                seen.add(key)
                start = max(0, m.start() - 80)
                context = content[start:m.end() + 80].replace("\n", " ")
                route_only = url if url.startswith("/") else urllib.parse.urlsplit(url).path or url
                calls.append({
                    "call_type": call_type,
                    "method": (setting or "GET").upper(),
                    "url": url[:200],
                    "route": route_only[:200],
                    "source": source_label,
                    "context": context[:200],
                    "observed": True,
                    "parameterized": "${" in url,
                })
        return calls

    def extract_idor_candidates(self, content: str, source_label: str) -> List[Dict[str, Any]]:
        """Flags routes with dynamic parameters that are classic IDOR/BOLA shapes.

        Shapes flagged:
        - template literal parameter: ``/rs/asset/${id}``
        - colon parameter: ``/rs/campaign/entries/:id``
        - owner-scoped query param: ``?email=``, ``?userId=``, ``?file=`` ...
        """
        candidates: List[Dict[str, Any]] = []
        seen = set()
        shapes = [
            ("template_param", r'`(/[^`]*\$\{[^`]+\}[^`]*)`'),
            ("template_param_rel", r'`([a-zA-Z][a-zA-Z0-9_\-/]*\$\{[^`]+\}[^`]*)`'),
            ("colon_param", r'["\'](/[^"\']*:[a-zA-Z][a-zA-Z0-9_-]*[^"\']*)["\']'),
            ("query_owner_param",
             r'["\'`](/[^"\'`]*\?[^"\'`]*(?:email|user(?:id)?|account|owner|file|document|order|invoice|id|key|token)[^"\'`]*=)["\'`]'),
        ]
        for shape, pattern in shapes:
            for m in re.finditer(pattern, content):
                route = m.group(1).strip()
                if len(route) <= 2 or route in seen:
                    continue
                # Skip Vue/React router regex shapes: /:catchAll(.*), /:ids+
                if re.search(r"[()*+?\[\]|]", route):
                    continue
                # Skip CSS BEM class templates: cdr-button--icon-only-${t.size}
                if "--" in route or "/" not in route:
                    continue
                seen.add(route)
                start = max(0, m.start() - 60)
                context = content[start:m.end() + 60].replace("\n", " ")
                candidates.append({
                    "route": route[:200],
                    "shape": shape,
                    "source": source_label,
                    "context": context[:200],
                    "observed": True,
                    "hypothesis": "IDOR/BOLA candidate — parameterized object reference without visible ownership check",
                })
        return candidates

    def probe_route(self, base_url: str, route_path: str) -> Dict[str, Any]:
        """Sends a live non-destructive GET / OPTIONS probe to test route status & CORS."""
        full_url = urllib.parse.urljoin(base_url, route_path)
        result = {
            "route": route_path,
            "url": full_url,
            "status": 0,
            "live": False,
            "cors_wildcard": False,
            "auth_required": False,
            "source": "js_bundle",
            "observed": False,
            "scope": self.scope.check_url(full_url, active=False) if self.scope else None,
        }

        if self.scope and not self.scope.check_url(full_url, active=True).get("allowed"):
            result["active_verification_skipped"] = "outside_scope"
            return result

        resp = self.fetch_url(full_url)
        if resp:
            result["status"] = resp["status"]
            result["live"] = resp["status"] in [200, 201, 204, 301, 302, 307, 308, 400, 401, 403, 405]
            result["observed"] = bool(resp["status"])
            result["auth_required"] = resp["status"] in [401, 403]
            cors = resp["headers"].get("Access-Control-Allow-Origin", "")
            if cors == "*" or "null" in cors:
                result["cors_wildcard"] = True
        return result

    def analyze_target(self, target_url: str, html_content: Optional[str] = None) -> Dict[str, Any]:
        """
        Executes full JS bundle analysis for a target URL:
        Discovers scripts, unpacks maps, mines secrets, extracts routes, and probes endpoints.
        """
        if not html_content:
            page_resp = self.fetch_url(target_url)
            html_content = page_resp["body"] if page_resp else ""

        js_links = self.discover_js_links(target_url, html_content)
        
        all_routes: Set[str] = set()
        all_secrets: List[Dict[str, Any]] = []
        all_params: Set[str] = set()
        all_grep: List[Dict[str, Any]] = []
        all_api_calls: List[Dict[str, Any]] = []
        all_idor_candidates: List[Dict[str, Any]] = []
        js_assets_info = []
        external_discoveries = []

        # Analyze inline scripts in HTML
        inline_secrets = self.extract_secrets(html_content, "inline_html")
        all_secrets.extend(inline_secrets)
        for r in self.extract_routes(html_content):
            all_routes.add(r)
        all_grep.extend(self.grep_content(html_content, "inline_html"))
        all_api_calls.extend(self.extract_api_calls(html_content, "inline_html"))
        all_idor_candidates.extend(self.extract_idor_candidates(html_content, "inline_html"))

        # Process each discovered external JS file (up to top 15 to balance speed & depth)
        for js_url in js_links[:15]:
            if self.scope and not self.scope.check_url(js_url, active=True).get("allowed"):
                external_discoveries.append({"value": js_url, "source": "html_script", "observed": True,
                                             "active_verification_skipped": "outside_scope"})
                continue
            js_resp = self.fetch_url(js_url)
            if not js_resp or js_resp["status"] != 200:
                continue

            js_code = js_resp["body"]
            sourcemap_info = self.unpack_sourcemap(js_url, js_code)
            
            # Extract from JS bundle code
            bundle_label = js_url.split("/")[-1]
            secrets = self.extract_secrets(js_code, bundle_label)
            routes = self.extract_routes(js_code)
            params = self.extract_hidden_parameters(js_code)

            all_secrets.extend(secrets)
            for r in routes:
                all_routes.add(r)
            for p in params:
                all_params.add(p)
            all_grep.extend(self.grep_content(js_code, bundle_label))
            all_api_calls.extend(self.extract_api_calls(js_code, bundle_label))
            all_idor_candidates.extend(self.extract_idor_candidates(js_code, bundle_label))

            # Reprocess original sources, not merely a display sample.
            source_routes: Set[str] = set()
            source_params: Set[str] = set()
            source_secret_count = 0
            for idx, source_code in enumerate(sourcemap_info.get("sources_content", [])):
                if not source_code:
                    continue
                source_name = sourcemap_info.get("sources", [])[idx] if idx < len(sourcemap_info.get("sources", [])) else f"source_{idx}"
                extracted = self.extract_secrets(source_code, f"sourcemap:{source_name}")
                all_secrets.extend(extracted)
                source_secret_count += len(extracted)
                for route in self.extract_routes(source_code):
                    source_routes.add(route)
                    all_routes.add(route)
                for hidden in self.extract_hidden_parameters(source_code):
                    source_params.add(hidden)
                    all_params.add(hidden)
                source_label = f"sourcemap:{source_name}"
                all_grep.extend(self.grep_content(source_code, source_label))
                all_api_calls.extend(self.extract_api_calls(source_code, source_label))
                all_idor_candidates.extend(self.extract_idor_candidates(source_code, source_label))

            js_assets_info.append({
                "url": js_url,
                "filename": js_url.split("/")[-1].split("?")[0],
                "size_kb": round(len(js_code) / 1024, 1),
                "has_sourcemap": sourcemap_info["has_sourcemap"],
                "sourcemap_url": sourcemap_info["sourcemap_url"],
                "extracted_sources_count": sourcemap_info["extracted_files_count"],
                "routes_found": len(set(routes) | source_routes),
                "secrets_found": len(secrets) + source_secret_count,
                "sourcemap_routes_found": len(source_routes),
                "sourcemap_params_found": len(source_params),
                "content_hash": js_resp.get("content_hash"),
                "source": "html_script",
                "observed": True,
            })

        # Probe discovered routes (up to top 15 routes)
        probed_routes = []
        for r in sorted(list(all_routes))[:15]:
            probe_res = self.probe_route(target_url, r)
            probed_routes.append(probe_res)

        return {
            "js_links_found": len(js_links),
            "js_assets": js_assets_info,
            "routes": sorted(list(all_routes)),
            "probed_routes": probed_routes,
            "secrets": all_secrets,
            "hidden_params": sorted(list(all_params)),
            "grep_matches": all_grep,
            "api_trace": all_api_calls,
            "idor_candidates": all_idor_candidates,
            "external_discoveries": external_discoveries,
            "cache_entries": len(self._cache),
            "failures": list(self.failures),
        }
