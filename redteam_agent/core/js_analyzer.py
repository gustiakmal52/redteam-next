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
from bisect import bisect_right
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any, Set, Optional
from redteam_agent.core.config import (API_CALL_PATTERNS, DEFAULT_HEADERS, GREP_PATTERNS,
                                        ROUTE_PATTERNS, SECRET_PATTERNS)
from redteam_agent.core.http_verifier import HTTPVerifier
from redteam_agent.core.scope_manager import ScopeManager, normalize_url, URLPolicyError
from redteam_agent.discovery.redaction import SecretRedactor

class JSAnalyzer:
    EVM_ADDRESS_RE = re.compile(r"(?<![0-9A-Fa-f])0x[0-9A-Fa-f]{40}(?![0-9A-Fa-f])")
    RPC_PATTERNS = (
        re.compile(r"\b(?:rpc(?:url|_url|endpoint|_endpoint)|provider(?:url|_url))\b\s*[:=]\s*['\"`]([^'\"`]+)['\"`]", re.I),
        re.compile(r"\b(?:JsonRpcProvider|StaticJsonRpcProvider|HttpProvider|WebsocketProvider|Connection)\s*\(\s*['\"`]([^'\"`]+)['\"`]", re.I),
        re.compile(r"\btransport\s*:\s*(?:http|webSocket)\s*\(\s*['\"`]([^'\"`]+)['\"`]", re.I),
    )
    SOLANA_PROGRAM_RE = re.compile(
        r"\b(?:programId|programID|program_id)\b\s*[:=]\s*(?:new\s+PublicKey\s*\(\s*)?['\"`]([1-9A-HJ-NP-Za-km-z]{32,44})['\"`]",
    )
    SOLANA_PUBLIC_KEY_RE = re.compile(r"\bnew\s+PublicKey\s*\(\s*['\"`]([1-9A-HJ-NP-Za-km-z]{32,44})['\"`]\s*\)")
    CHAIN_ID_RE = re.compile(r"\b(?:chainId|chain_id)\b\s*[:=]\s*['\"`]?(0x[0-9A-Fa-f]+|\d+)")
    HUMAN_ABI_RE = re.compile(r"['\"`]\s*(function\s+[A-Za-z_$][\w$]*\s*\([^'\"`)]*\)[^'\"`]*)['\"`]")
    EIP1967_IMPLEMENTATION_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
    SECURITY_FUNCTION_MARKERS = (
        "initialize", "upgrade", "admin", "owner", "mint", "burn", "permit", "execute",
        "withdraw", "claim", "swap", "borrow", "liquidate", "transfer",
    )

    def __init__(self, timeout: float = 8.0, verifier: Optional[HTTPVerifier] = None,
                 scope_manager: Optional[ScopeManager] = None):
        self.timeout = timeout
        self.scope = scope_manager
        self.verifier = verifier or HTTPVerifier(timeout=timeout, scope_manager=scope_manager, module="js_analyzer")
        self._cache: Dict[str, Dict[str, Any]] = {}
        self.failures: List[Dict[str, Any]] = []
        self.redactor = SecretRedactor()

    @staticmethod
    def _solana_key_valid(value: str) -> bool:
        alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        number = 0
        try:
            for char in value:
                number = number * 58 + alphabet.index(char)
        except ValueError:
            return False
        payload = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
        return len(b"\0" * (len(value) - len(value.lstrip("1"))) + payload) == 32

    def _safe_rpc_url(self, url: str) -> str:
        """Keep RPC provenance useful without exporting provider credentials."""
        try:
            parsed = urllib.parse.urlsplit(url)
            segments = [
                self.redactor.mask_secret(segment)
                if len(segment) >= 16 and re.fullmatch(r"[A-Za-z0-9._~-]+", segment) else segment
                for segment in parsed.path.split("/")
            ]
            query = urllib.parse.urlencode([
                (key, self.redactor.mask_secret(value) if value else "")
                for key, value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
            ])
            return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "/".join(segments), query, ""))
        except (TypeError, ValueError):
            return self.redactor.redact_text(url)

    def _web3_context(self, content: str, start: int, end: int) -> str:
        context = content[max(0, start - 80):min(len(content), end + 100)].replace("\n", " ")[:300]
        for url in re.findall(r"(?:https?|wss?)://[^\s'\"`]+", context):
            context = context.replace(url, self._safe_rpc_url(url))
        return context

    def extract_web3_artifacts(self, content: str, source_label: str,
                               base_url: str) -> Dict[str, List[Dict[str, Any]]]:
        """Extract Web3 evidence from one observed document/bundle/source map."""
        source_label = (self._safe_rpc_url(source_label) if source_label.startswith(
            ("http://", "https://", "ws://", "wss://")) else self.redactor.redact_text(source_label))
        artifacts: Dict[str, List[Dict[str, Any]]] = {
            "contracts": [], "solana_accounts": [], "rpc_endpoints": [],
            "chain_ids": [], "abi_functions": [], "integrations": [],
        }
        line_starts = [0]
        line_starts.extend(match.end() for match in re.finditer("\n", content or ""))

        def evidence(match: re.Match) -> Dict[str, Any]:
            return {
                "source": source_label,
                "line": bisect_right(line_starts, match.start()),
                "context": self.redactor.redact_text(self._web3_context(content, match.start(), match.end())),
                "observed": True,
            }

        seen_addresses: Set[str] = set()
        for match in self.EVM_ADDRESS_RE.finditer(content or ""):
            address = match.group(0)
            if address.lower() == "0x" + "0" * 40 or address.lower() in seen_addresses:
                continue
            seen_addresses.add(address.lower())
            artifacts["contracts"].append({
                "address": address, "format": "evm_address", "status": "CANDIDATE",
                **evidence(match),
            })

        seen_rpc: Set[str] = set()
        for pattern in self.RPC_PATTERNS:
            for match in pattern.finditer(content or ""):
                candidate = match.group(1).strip()
                if not candidate or "${" in candidate:
                    continue
                raw_url = urllib.parse.urljoin(base_url, candidate) if candidate.startswith("/") else candidate
                if not raw_url.startswith(("http://", "https://", "ws://", "wss://")) or raw_url in seen_rpc:
                    continue
                seen_rpc.add(raw_url)
                scope_url = raw_url.replace("wss://", "https://", 1).replace("ws://", "http://", 1)
                scope = self.scope.check_url(scope_url, active=False) if self.scope else None
                safe_url = self._safe_rpc_url(raw_url)
                item = evidence(match)
                item["context"] = item["context"].replace(raw_url, safe_url)
                artifacts["rpc_endpoints"].append({
                    "url": safe_url, "_raw_url": raw_url, "transport": urllib.parse.urlsplit(raw_url).scheme,
                    "status": "CANDIDATE", "in_scope": scope.get("in_scope") if scope else None,
                    **item,
                })

        for match in self.CHAIN_ID_RE.finditer(content or ""):
            raw = match.group(1)
            try:
                chain_id = int(raw, 16 if raw.lower().startswith("0x") else 10)
            except ValueError:
                continue
            artifacts["chain_ids"].append({
                "chain_id": chain_id, "status": "STATIC_OBSERVED", **evidence(match),
            })

        solana_seen: Set[str] = set()
        for pattern, kind in ((self.SOLANA_PROGRAM_RE, "program_id"),
                              (self.SOLANA_PUBLIC_KEY_RE, "public_key")):
            for match in pattern.finditer(content or ""):
                address = match.group(1)
                if address in solana_seen or not self._solana_key_valid(address):
                    continue
                solana_seen.add(address)
                artifacts["solana_accounts"].append({
                    "address": address, "kind": kind, "status": "CANDIDATE", **evidence(match),
                })

        abi_seen: Set[str] = set()
        for match in self.HUMAN_ABI_RE.finditer(content or ""):
            signature = re.sub(r"\s+", " ", match.group(1).strip())
            if signature in abi_seen:
                continue
            abi_seen.add(signature)
            name_match = re.match(r"function\s+([A-Za-z_$][\w$]*)", signature)
            name = name_match.group(1) if name_match else "unknown"
            tags = [tag for tag in self.SECURITY_FUNCTION_MARKERS if tag in name.lower()]
            artifacts["abi_functions"].append({
                "name": name, "signature": signature, "surface_tags": tags, **evidence(match),
            })

        for match in re.finditer(r"['\"]type['\"]\s*:\s*['\"]function['\"]", content or "", re.I):
            window = content[max(0, match.start() - 600):min(len(content), match.end() + 600)]
            names = list(re.finditer(r"['\"]name['\"]\s*:\s*['\"]([A-Za-z_$][\w$]*)['\"]", window))
            if not names:
                continue
            name_match = min(names, key=lambda item: abs(item.start() - min(600, match.start())))
            name = name_match.group(1)
            inputs_match = re.search(r"['\"]inputs['\"]\s*:\s*\[(.*?)\]", window, re.S)
            input_types = re.findall(r"['\"]type['\"]\s*:\s*['\"]([^'\"]+)['\"]",
                                     inputs_match.group(1)) if inputs_match else []
            signature = f"function {name}({','.join(input_types)})"
            if signature in abi_seen:
                continue
            abi_seen.add(signature)
            artifacts["abi_functions"].append({
                "name": name, "signature": signature, "surface_tags": [
                    tag for tag in self.SECURITY_FUNCTION_MARKERS if tag in name.lower()
                ], **evidence(match),
            })

        if source_label.lower().endswith(".sol") or ".sol" in source_label.lower():
            for match in re.finditer(r"\bfunction\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)", content or ""):
                signature = f"function {match.group(1)}({re.sub(r'\s+', ' ', match.group(2).strip())})"
                if signature in abi_seen:
                    continue
                abi_seen.add(signature)
                artifacts["abi_functions"].append({
                    "name": match.group(1), "signature": signature,
                    "surface_tags": [tag for tag in self.SECURITY_FUNCTION_MARKERS
                                     if tag in match.group(1).lower()], **evidence(match),
                })

        for name, pattern in (
            ("EIP-1193", r"\bwindow\.ethereum\b|\beth_requestAccounts\b"),
            ("ethers", r"\bethers(?:\.|['\"]\s*from\s*['\"]ethers)"),
            ("viem", r"\bcreatePublicClient\b|['\"]viem['\"]"),
            ("wagmi", r"\bwagmi\b|@wagmi/"),
            ("WalletConnect", r"\bWalletConnect\b|@walletconnect/"),
            ("Solana web3", r"@solana/web3\.js|\bPublicKey\s*\("),
        ):
            match = re.search(pattern, content or "", re.I)
            if match:
                artifacts["integrations"].append({"name": name, **evidence(match)})
        return artifacts

    def _rpc_call(self, url: str, method: str, params: List[Any]) -> tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
        traffic = getattr(self.verifier, "traffic", None)
        if traffic is not None:
            stats = traffic.stats()
            remaining = stats.get("requests_remaining")
            if remaining is not None and remaining <= stats.get("verification_reserve", 0):
                return None, {"status_code": 0, "_budget_skipped": True, "failure": {
                    "status": "skipped", "reason": "normal recon budget exhausted; verification reserve preserved",
                }}
        response = self.verifier.send_http_request(
            url, method="POST", headers={"Content-Type": "application/json", "Accept": "application/json"},
            body=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}),
            priority="normal", follow_redirects=True,
        )
        try:
            payload = json.loads(response.get("body") or "")
        except (TypeError, ValueError):
            payload = None
        return (payload if isinstance(payload, dict) else None), response

    def correlate_web3_artifacts(self, chunks: List[Dict[str, List[Dict[str, Any]]]]) -> Dict[str, Any]:
        """Deduplicate and scope-gate live JSON-RPC proof for extracted artifacts."""
        merged = {key: [] for key in ("contracts", "solana_accounts", "rpc_endpoints", "chain_ids",
                                      "abi_functions", "integrations")}
        for chunk in chunks:
            for key in merged:
                merged[key].extend(chunk.get(key, []))

        def dedupe(items: List[Dict[str, Any]], key_name: str) -> List[Dict[str, Any]]:
            output: Dict[str, Dict[str, Any]] = {}
            for item in items:
                value = str(item.get(key_name) or "")
                if not value:
                    continue
                identity = value.lower() if key_name in {"address", "url"} else value
                existing = output.get(identity)
                if existing is None:
                    output[identity] = dict(item, sources=[item.get("source")], evidence=[{
                        "source": item.get("source"), "line": item.get("line"), "context": item.get("context"),
                    }])
                else:
                    if item.get("source") not in existing["sources"]:
                        existing["sources"].append(item.get("source"))
                    existing["evidence"].append({
                        "source": item.get("source"), "line": item.get("line"), "context": item.get("context"),
                    })
            return list(output.values())

        contracts = dedupe(merged["contracts"], "address")
        solana_accounts = dedupe(merged["solana_accounts"], "address")
        rpc_endpoints = dedupe(merged["rpc_endpoints"], "url")
        abi_functions = dedupe(merged["abi_functions"], "signature")
        integrations = dedupe(merged["integrations"], "name")
        requests_used = 0
        raw_urls = {item["url"]: item.pop("_raw_url") for item in rpc_endpoints if item.get("_raw_url")}

        for rpc in rpc_endpoints:
            raw_url = raw_urls.get(rpc["url"])
            if rpc.get("transport") not in {"http", "https"}:
                rpc.update(status="SKIPPED", verification="unsupported WebSocket transport")
                continue
            if not raw_url or (self.scope and not self.scope.check_url(raw_url, active=True).get("allowed")):
                rpc.update(status="SKIPPED_OUT_OF_SCOPE", verification="active JSON-RPC request not permitted by scope")
                continue
            payload, response = self._rpc_call(raw_url, "eth_chainId", [])
            requests_used += int(not response.get("_budget_skipped"))
            if response.get("_budget_skipped"):
                rpc.update(status="SKIPPED_BUDGET", verification=response["failure"]["reason"])
                continue
            chain = payload.get("result") if payload else None
            if response.get("status_code") == 200 and isinstance(chain, str) and re.fullmatch(r"0x[0-9A-Fa-f]+", chain):
                rpc.update(status="VERIFIED", protocol="EVM", chain_id=int(chain, 16),
                           status_code=200, response_time_sec=response.get("response_time_sec"))
                continue
            payload, response = self._rpc_call(raw_url, "getVersion", [])
            requests_used += int(not response.get("_budget_skipped"))
            version = payload.get("result") if payload else None
            if response.get("status_code") == 200 and isinstance(version, dict) and version.get("solana-core"):
                rpc.update(status="VERIFIED", protocol="SOLANA", node_version=version.get("solana-core"),
                           feature_set=version.get("feature-set"), status_code=200,
                           response_time_sec=response.get("response_time_sec"))
            else:
                rpc.update(status="UNVERIFIED", status_code=response.get("status_code"),
                           verification="endpoint did not return a valid EVM or Solana identity response")

        verified_evm = [item for item in rpc_endpoints if item.get("status") == "VERIFIED" and item.get("protocol") == "EVM"]
        for contract in contracts:
            matching = [rpc for rpc in verified_evm if set(contract.get("sources", [])) & set(rpc.get("sources", []))]
            if not matching and len(verified_evm) == 1:
                matching = verified_evm
            if not matching:
                contract["verification"] = "no uniquely correlated in-scope EVM RPC"
                continue
            rpc = matching[0]
            raw_url = raw_urls.get(rpc["url"])
            payload, response = self._rpc_call(raw_url, "eth_getCode", [contract["address"], "latest"])
            requests_used += int(not response.get("_budget_skipped"))
            if response.get("_budget_skipped"):
                contract["verification"] = response["failure"]["reason"]
                continue
            code = payload.get("result") if payload else None
            if (response.get("status_code") != 200 or not isinstance(code, str)
                    or not re.fullmatch(r"0x(?:[0-9A-Fa-f]{2})*", code)):
                contract.update(status="UNVERIFIED", verification="eth_getCode did not return valid bytecode")
                continue
            contract.update(rpc=rpc["url"], chain_id=rpc.get("chain_id"), bytecode_size=max(0, (len(code) - 2) // 2))
            if code == "0x":
                contract.update(status="OBSERVED_NO_CODE", deployment_verified=False)
                continue
            contract.update(status="VERIFIED_CONTRACT", deployment_verified=True,
                            bytecode_sha256=hashlib.sha256(bytes.fromhex(code[2:])).hexdigest())
            payload, storage_response = self._rpc_call(
                raw_url, "eth_getStorageAt", [contract["address"], self.EIP1967_IMPLEMENTATION_SLOT, "latest"])
            requests_used += int(not storage_response.get("_budget_skipped"))
            storage = payload.get("result") if payload else None
            if (storage_response.get("status_code") == 200 and isinstance(storage, str)
                    and re.fullmatch(r"0x[0-9A-Fa-f]{64}", storage) and int(storage, 16)):
                implementation = "0x" + storage[-40:]
                impl_payload, impl_response = self._rpc_call(raw_url, "eth_getCode", [implementation, "latest"])
                requests_used += int(not impl_response.get("_budget_skipped"))
                impl_code = impl_payload.get("result") if impl_payload else None
                implementation_verified = bool(
                    impl_response.get("status_code") == 200 and isinstance(impl_code, str)
                    and re.fullmatch(r"0x(?:[0-9A-Fa-f]{2})+", impl_code)
                )
                contract["proxy"] = {
                    "status": "VERIFIED_EIP1967_PROXY" if implementation_verified else "EIP1967_SLOT_OBSERVED",
                    "implementation": implementation,
                    "implementation_code_verified": implementation_verified,
                    "implementation_bytecode_size": max(0, (len(impl_code) - 2) // 2) if isinstance(impl_code, str) else 0,
                    "slot": self.EIP1967_IMPLEMENTATION_SLOT,
                }

        verified_solana = [item for item in rpc_endpoints if item.get("status") == "VERIFIED" and item.get("protocol") == "SOLANA"]
        for account in solana_accounts:
            matching = [rpc for rpc in verified_solana if set(account.get("sources", [])) & set(rpc.get("sources", []))]
            if not matching and len(verified_solana) == 1:
                matching = verified_solana
            if not matching:
                account["verification"] = "no uniquely correlated in-scope Solana RPC"
                continue
            rpc = matching[0]
            payload, response = self._rpc_call(raw_urls[rpc["url"]], "getAccountInfo",
                                               [account["address"], {"encoding": "base64"}])
            requests_used += int(not response.get("_budget_skipped"))
            if response.get("_budget_skipped"):
                account["verification"] = response["failure"]["reason"]
                continue
            value = (payload.get("result") or {}).get("value") if payload else None
            if response.get("status_code") == 200 and isinstance(value, dict):
                executable = bool(value.get("executable"))
                account.update(status="VERIFIED_PROGRAM" if executable else "VERIFIED_ACCOUNT",
                               account_verified=True, executable=executable, owner=value.get("owner"),
                               lamports=value.get("lamports"), rpc=rpc["url"])
            else:
                account.update(status="UNVERIFIED", account_verified=False,
                               verification="getAccountInfo did not return an observed account")

        static_chain_ids = dedupe(merged["chain_ids"], "chain_id")
        for rpc in verified_evm:
            if not any(item.get("chain_id") == rpc.get("chain_id") for item in static_chain_ids):
                static_chain_ids.append({"chain_id": rpc.get("chain_id"), "status": "RPC_VERIFIED",
                                         "source": rpc["url"], "sources": [rpc["url"]], "evidence": []})
        result = {
            "detected": bool(contracts or solana_accounts or rpc_endpoints or abi_functions or integrations),
            "contracts": contracts, "solana_accounts": solana_accounts, "rpc_endpoints": rpc_endpoints,
            "chain_ids": static_chain_ids, "abi_functions": abi_functions, "integrations": integrations,
        }
        result["stats"] = {
            "rpc_candidates": len(rpc_endpoints),
            "rpc_verified": sum(item.get("status") == "VERIFIED" for item in rpc_endpoints),
            "contract_candidates": len(contracts),
            "contracts_verified": sum(item.get("status") == "VERIFIED_CONTRACT" for item in contracts),
            "proxies_verified": sum((item.get("proxy") or {}).get("status") == "VERIFIED_EIP1967_PROXY"
                                    for item in contracts),
            "solana_accounts": len(solana_accounts),
            "solana_programs_verified": sum(item.get("status") == "VERIFIED_PROGRAM" for item in solana_accounts),
            "abi_functions": len(abi_functions), "verification_requests": requests_used,
        }
        return result

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
            self.failures.append({"tool": "js_fetch", "url": self._safe_rpc_url(url), **result["failure"]})
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
        web3_chunks: List[Dict[str, List[Dict[str, Any]]]] = []
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
        web3_chunks.append(self.extract_web3_artifacts(html_content, "inline_html", target_url))

        # Analyze every in-scope bundle that fits the shared request budget.
        # Each bundle may also consume one request for its source map.
        in_scope_js = []
        for js_url in js_links:
            if self.scope and not self.scope.check_url(js_url, active=True).get("allowed"):
                external_discoveries.append({"value": self._safe_rpc_url(js_url), "source": "html_script", "observed": True,
                                             "active_verification_skipped": "outside_scope"})
                continue
            in_scope_js.append(js_url)
        traffic = getattr(self.verifier, "traffic", None)
        js_candidates = in_scope_js
        if traffic is not None:
            budget = traffic.stats()
            remaining = budget.get("requests_remaining")
            if remaining is not None:
                normal_requests = max(0, int(remaining) - int(budget.get("verification_reserve", 0)))
                js_candidates = js_candidates[:normal_requests // 2]

        for js_url in js_candidates:
            js_resp = self.fetch_url(js_url)
            if not js_resp or js_resp["status"] != 200:
                continue

            js_code = js_resp["body"]
            sourcemap_info = self.unpack_sourcemap(js_url, js_code)
            
            # Extract from JS bundle code
            bundle_label = urllib.parse.urlsplit(js_url).path.rsplit("/", 1)[-1] or "bundle.js"
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
            web3_chunks.append(self.extract_web3_artifacts(js_code, bundle_label, js_url))

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
                web3_chunks.append(self.extract_web3_artifacts(source_code, source_label, js_url))

            js_assets_info.append({
                "url": self._safe_rpc_url(js_url),
                "filename": bundle_label,
                "size_kb": round(len(js_code) / 1024, 1),
                "has_sourcemap": sourcemap_info["has_sourcemap"],
                "sourcemap_url": self._safe_rpc_url(sourcemap_info["sourcemap_url"]),
                "extracted_sources_count": sourcemap_info["extracted_files_count"],
                "routes_found": len(set(routes) | source_routes),
                "secrets_found": len(secrets) + source_secret_count,
                "sourcemap_routes_found": len(source_routes),
                "sourcemap_params_found": len(source_params),
                "content_hash": js_resp.get("content_hash"),
                "source": "html_script",
                "observed": True,
            })

        # Probe every observed route that still fits the shared normal budget.
        probed_routes = []
        route_candidates = sorted(all_routes)
        if traffic is not None:
            budget = traffic.stats()
            remaining = budget.get("requests_remaining")
            if remaining is not None:
                route_candidates = route_candidates[:max(
                    0, int(remaining) - int(budget.get("verification_reserve", 0)))]
        if route_candidates:
            workers = 1
            if traffic is not None:
                config = traffic.config if hasattr(traffic, "config") else {}
                try:
                    workers = max(1, min(int(config.get("per_host_concurrency", 4) or 4),
                                         int(config.get("global_concurrency", 8) or 8)))
                except (TypeError, ValueError):
                    workers = 4
            workers = min(workers, len(route_candidates))
            if workers > 1:
                with ThreadPoolExecutor(max_workers=workers) as pool:
                    probed_routes = list(pool.map(lambda r: self.probe_route(target_url, r), route_candidates))
            else:
                probed_routes = [self.probe_route(target_url, r) for r in route_candidates]

        web3 = self.correlate_web3_artifacts(web3_chunks)
        return {
            "js_links_found": len(js_links),
            "js_assets": js_assets_info,
            "js_assets_budget_skipped": len(in_scope_js) - len(js_candidates),
            "routes": sorted(list(all_routes)),
            "probed_routes": probed_routes,
            "routes_budget_skipped": len(all_routes) - len(route_candidates),
            "secrets": all_secrets,
            "hidden_params": sorted(list(all_params)),
            "grep_matches": all_grep,
            "api_trace": all_api_calls,
            "idor_candidates": all_idor_candidates,
            "web3": web3,
            "external_discoveries": external_discoveries,
            "cache_entries": len(self._cache),
            "failures": list(self.failures),
        }
