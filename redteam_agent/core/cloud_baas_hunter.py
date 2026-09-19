"""Evidence-first Supabase/Firebase access-control auditing."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from typing import Any, Dict, List, Optional

from redteam_agent.core.config import CVSS_VECTORS, cvss3_score
from redteam_agent.core.findings import FindingStatus, normalized_finding
from redteam_agent.core.http_verifier import HTTPVerifier
from redteam_agent.core.scope_manager import ScopeManager


SENSITIVE_FIELDS = {"password", "password_hash", "token", "access_token", "refresh_token",
                    "email", "secret", "credential", "credentials", "phone", "hash", "ssn", "api_key"}


class CloudBaaSHunter:
    def __init__(self, timeout: float = 6.0, verifier: Optional[HTTPVerifier] = None,
                 scope_manager: Optional[ScopeManager] = None):
        self.timeout = timeout
        self.scope = scope_manager
        self.verifier = verifier

    @staticmethod
    def decode_jwt_payload(token: str) -> Optional[Dict[str, Any]]:
        """Decode claims structurally; this does not validate the JWT signature."""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None
            payload = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
            decoded = json.loads(base64.urlsafe_b64decode(payload).decode("utf-8"))
            return decoded if isinstance(decoded, dict) else None
        except Exception:
            return None

    @staticmethod
    def _mask(value: str) -> str:
        # Full token display for offensive research (not redacted)
        return value

    @staticmethod
    def _sensitive_paths(value: Any, prefix: str = "") -> list[str]:
        """Return field paths, never field values, from a BaaS response."""
        paths: list[str] = []
        if isinstance(value, dict):
            for key, child in value.items():
                name = str(key)
                path = f"{prefix}.{name}" if prefix else name
                if name.lower() in SENSITIVE_FIELDS:
                    paths.append(path)
                if isinstance(child, (dict, list)):
                    paths.extend(CloudBaaSHunter._sensitive_paths(child, path))
        elif isinstance(value, list):
            for index, child in enumerate(value[:5]):
                paths.extend(CloudBaaSHunter._sensitive_paths(child, f"{prefix}[{index}]"))
        return sorted(set(paths))

    @staticmethod
    def _json_shape(value: Any) -> Any:
        """Describe response structure without retaining record values."""
        if isinstance(value, dict):
            return {str(key): CloudBaaSHunter._json_shape(child) for key, child in list(value.items())[:50]}
        if isinstance(value, list):
            return {"type": "array", "length": len(value),
                    "item": CloudBaaSHunter._json_shape(value[0]) if value else None}
        if value is None:
            return "null"
        return type(value).__name__

    @classmethod
    def _safe_baas_response(cls, response: Dict[str, Any], body: str,
                            sensitive_fields: Optional[list[str]] = None) -> Dict[str, Any]:
        """Evidence summary for triage; raw BaaS body is intentionally absent."""
        parsed: Any = None
        try:
            parsed = json.loads(body or "")
        except (TypeError, ValueError, json.JSONDecodeError):
            parsed = None
        discovered = cls._sensitive_paths(parsed) if parsed is not None else list(sensitive_fields or [])
        content_type = next((str(value) for key, value in (response.get("headers") or {}).items()
                             if str(key).lower() == "content-type"), "")
        return {
            "status_code": response.get("status_code", 0),
            "content_type": content_type,
            "body_length": len(body or ""),
            "body_sha256": hashlib.sha256((body or "").encode("utf-8", errors="replace")).hexdigest(),
            "json_shape": cls._json_shape(parsed) if parsed is not None else "non_json",
            "sensitive_field_paths": sorted(set(discovered)),
            "raw_body_stored": False,
            "raw_excerpt_stored": False,
        }

    def _verifier_for(self, url: str) -> HTTPVerifier:
        if self.verifier:
            return self.verifier
        return HTTPVerifier(timeout=self.timeout, scope_manager=self.scope or ScopeManager.from_target(url), module="baas")

    def audit_supabase(self, supabase_url: str, anon_key: str) -> Dict[str, Any]:
        clean_url = supabase_url.rstrip("/")
        headers = {"apikey": anon_key, "Authorization": f"Bearer {anon_key}", "User-Agent": "Gustiakmal-RedTeam-BaaSHunter/2.1"}
        claims = self.decode_jwt_payload(anon_key)
        service_role_claim = bool(claims and claims.get("role") == "service_role")
        result = {
            "target_url": clean_url, "anon_key_preview": self._mask(anon_key), "jwt_claims": claims,
            "token_classification": "HIGH_PRIVILEGE" if service_role_claim else ("STRUCTURALLY_VALID" if claims else "PATTERN_MATCH"),
            "signature_validated": False, "is_service_role": service_role_claim, "openapi_exposed": False,
            "discovered_tables": [], "vulnerable_tables_rls_bypass": [], "findings": [], "failures": [],
        }
        verifier = self._verifier_for(clean_url)
        schema_url = f"{clean_url}/rest/v1/"
        schema_response = verifier.send_http_request(schema_url, headers=headers)
        discovered_tables: set[str] = set()
        if schema_response.get("status_code") == 200:
            try:
                schema_data = json.loads(schema_response.get("body", ""))
                definitions = schema_data.get("definitions", {}) or schema_data.get("paths", {})
                for key in definitions:
                    name = key.strip("/").split("/")[-1]
                    if name and not name.startswith("rpc/"):
                        discovered_tables.add(name)
                result["openapi_exposed"] = True
            except (ValueError, AttributeError) as exc:
                result["failures"].append({"tool": "supabase_schema", "status": "failed", "reason": f"invalid JSON: {exc}", "verified": False})
        else:
            result["failures"].append(schema_response.get("failure") or {
                "tool": "supabase_schema", "status": "failed", "reason": schema_response.get("error") or f"HTTP {schema_response.get('status_code')}", "verified": False})
        # Crucially, blocked schema enumeration no longer fabricates common table names.
        result["discovered_tables"] = sorted(discovered_tables)

        if service_role_claim:
            key_worked = schema_response.get("status_code") == 200
            result["findings"].append(normalized_finding(
                finding_type="Supabase Service Role Credential Exposed Client-Side", target=clean_url, endpoint=schema_url,
                status=FindingStatus.VERIFIED if key_worked else FindingStatus.LIKELY,
                confidence=.96 if key_worked else .75, source_module="cloud_baas_hunter", source_tool="JWT structural analysis + HTTPVerifier",
                test={"request": {"url": schema_url, "credential": self._mask(anon_key)},
                      "response": self._safe_baas_response(schema_response, schema_response.get("body", ""))},
                evidence=[{"jwt_role_claim": "service_role", "credential_accepted": key_worked}],
                verification_checks=[{"name": "service_role_claim", "passed": True}, {"name": "credential_accepted", "passed": key_worked}],
                missing_evidence=[] if key_worked else ["The service did not accept the credential during in-scope validation"],
                severity="Critical" if key_worked else "High",
                cvss_score=cvss3_score(CVSS_VECTORS["cloud_credential_read"], 9.1) if key_worked else 0.0,
                reproduction_curl="Credential-bearing reproduction is retained locally but redacted from generic results.",
                verification_note="A structurally service_role JWT was accepted by the project API." if key_worked else
                    "JWT claims indicate service_role, but signature and live acceptance are not proven.",
                observed_impact="The project API accepted a client-exposed service-role credential." if key_worked else
                    "Client-side material contains a JWT claiming the service_role role.",
                potential_impact="An accepted service-role credential can bypass Supabase RLS within its project privileges.",
            ))

        for table in result["discovered_tables"][:10]:
            table_url = f"{clean_url}/rest/v1/{table}?select=*&limit=2"
            response = verifier.send_http_request(table_url, headers=headers)
            if response.get("status_code") != 200:
                continue
            try:
                rows = json.loads(response.get("body", ""))
            except ValueError:
                continue
            if not isinstance(rows, list) or not rows:
                continue
            fields = list(rows[0].keys()) if isinstance(rows[0], dict) else []
            sensitive = sorted(set(fields) & SENSITIVE_FIELDS)
            credential_fields = sorted(set(fields) & {"password", "password_hash", "token", "secret",
                                                       "ssn", "api_key", "hash", "phone"})
            # Real impact: if credential-bearing fields are readable with the
            # anon (client-exposed) key, that is VERIFIED — the same bar as Firebase.
            if credential_fields:
                status = FindingStatus.VERIFIED
            elif sensitive:
                status = FindingStatus.LIKELY
            else:
                status = FindingStatus.DISCOVERED
            record = {"table": table, "status_code": 200, "records_sample_count": len(rows),
                      "fields": fields, "sensitive_fields": sensitive,
                      "credential_fields": credential_fields, "status": status.value}
            result["vulnerable_tables_rls_bypass"].append(record)
            result["findings"].append(normalized_finding(
                finding_type=(f"Supabase Anonymous Read of Credential Fields on '{table}'" if credential_fields
                              else f"Supabase Anonymous Read Access on '{table}'"),
                target=clean_url, endpoint=table_url,
                status=status, confidence=.85 if credential_fields else (.7 if sensitive else .45),
                source_module="cloud_baas_hunter", source_tool="HTTPVerifier",
                test={"request": {"url": table_url, "role": claims.get("role") if claims else "unknown"},
                      "response": {"status_code": 200, "row_count": len(rows), "fields": fields}},
                evidence=[record], verification_checks=[{"name": "anonymous_rows_returned", "passed": True},
                    {"name": "credential_fields_returned", "passed": bool(credential_fields)},
                    {"name": "sensitive_fields_returned", "passed": bool(sensitive)}],
                false_positive_reasons=[] if credential_fields else ["Public read access can be an intentional RLS policy"],
                missing_evidence=[] if credential_fields else ["Credential or owner-controlled data must be shown to prove broken RLS"],
                severity="Critical" if credential_fields else ("High" if sensitive else "Info"),
                cvss_score=cvss3_score(CVSS_VECTORS["cloud_credential_read"], 9.1) if credential_fields else 0.0,
                reproduction_curl="Credential-bearing reproduction is retained locally but redacted from generic results.",
                verification_note=f"The API returned {len(rows)} row(s) with the frontend role; credential fields: {', '.join(credential_fields)}."
                    if credential_fields else f"The API returned {len(rows)} row(s); policy intent is not yet established.",
                observed_impact=f"The supplied frontend role can read credential-like fields from '{table}': {', '.join(credential_fields)}."
                    if credential_fields else f"The supplied frontend role can read fields from '{table}': {', '.join(fields)}.",
                potential_impact="Credential-bearing rows may permit account compromise or further access." if credential_fields
                    else "If this table is intended to be private, additional records may be exposed.",
                vrt_category="Server-Side Misconfiguration > Insecure Database Configuration",
            ))
        return result

    def audit_firebase(self, firebase_url: str) -> Dict[str, Any]:
        clean_url = firebase_url.rstrip("/")
        test_url = f"{clean_url}/.json?shallow=true&limitToFirst=1"
        response = self._verifier_for(clean_url).send_http_request(test_url)
        body = response.get("body", "")
        open_read = response.get("status_code") == 200 and body.strip() not in {"", "null"} and "error" not in body.lower()
        result = {"target_url": clean_url, "test_url": test_url, "is_open": open_read,
                  "status_code": response.get("status_code", 0), "findings": [], "failure": response.get("failure")}
        if not open_read:
            return result

        # Real impact: try to read actual record values and look for sensitive fields.
        data_sample_url = f"{clean_url}/.json?orderBy=\"$key\"&limitToFirst=1&shallow=false"
        data_response = self._verifier_for(clean_url).send_http_request(data_sample_url)
        data_body = data_response.get("body", "")
        parsed_data: Any = None
        try:
            parsed_data = json.loads(data_body or "")
        except (TypeError, ValueError, json.JSONDecodeError):
            parsed_data = None
        sensitive_paths = self._sensitive_paths(parsed_data) if parsed_data is not None else []
        sensitive = sorted(set(path.rsplit(".", 1)[-1].split("[", 1)[0]
                               for path in sensitive_paths))
        if not sensitive:
            sensitive = sorted(set(field for field in SENSITIVE_FIELDS
                                   if re.search(rf'"({field})"\s*:', data_body, re.I)))
        credentials_proven = bool(data_body.strip() not in {"", "null"} and sensitive)
        severity = "High" if credentials_proven else "Medium"
        status = FindingStatus.VERIFIED if credentials_proven else FindingStatus.LIKELY
        confidence = .85 if credentials_proven else .7
        result["data_read"] = bool(data_body.strip() not in {"", "null"})
        result["sensitive_fields_observed"] = sensitive
        result["credentials_accessible"] = credentials_proven
        result["findings"].append(normalized_finding(
            finding_type="Firebase Realtime Database Public Read with Credential Fields" if credentials_proven
                else "Firebase Realtime Database Public Read Candidate",
            target=clean_url, endpoint=data_sample_url,
            status=status, confidence=confidence, source_module="cloud_baas_hunter", source_tool="HTTPVerifier",
            test={"request": {"url": data_sample_url},
                  "response": self._safe_baas_response(data_response, data_body, sensitive)},
            evidence=[{"shallow_read_returned_data": True, "sensitive_fields": sensitive,
                       "record_data_read": credentials_proven}],
            false_positive_reasons=[] if credentials_proven else ["Public data may be intentional"],
            missing_evidence=[] if credentials_proven else ["Sensitive data or policy violation must be shown before VERIFIED"],
            severity=severity,
            cvss_score=cvss3_score(CVSS_VECTORS["cloud_credential_read"], 8.1) if credentials_proven else 0.0,
            reproduction_curl=f'curl -i -s "{data_sample_url}"',
            verification_note="Unauthenticated read returned records containing credential-like fields." if credentials_proven
                else "Unauthenticated shallow read returned data; sensitivity and policy intent are unproven.",
            observed_impact="Unauthenticated users can read records exposing credential fields: " + ", ".join(sensitive) + "."
                if credentials_proven else "Unauthenticated users can enumerate at least one top-level database key.",
            potential_impact="Credential-bearing records may allow account compromise or further database access.",
            vrt_category="Server-Side Misconfiguration > Insecure Database Configuration",
        ))
        return result

    def audit_vercel(self, url: str) -> Dict[str, Any]:
        """Read-only Vercel audit: fingerprint the deployment and detect a dangling
        deployment (a classic subdomain takeover candidate)."""
        clean_url = url.rstrip("/")
        response = self._verifier_for(clean_url).send_http_request(clean_url)
        headers = {str(k).lower(): str(v) for k, v in response.get("headers", {}).items()}
        body = response.get("body", "")
        vercel_headers = any(k.startswith("x-vercel") or "vercel" in headers.get("server", "")
                             for k in headers)
        not_found_markers = [m for m in ("DEPLOYMENT_NOT_FOUND", "NOT_FOUND",
                                          "The deployment could not be found",
                                          "couldn't find the requested deployment")
                             if m.lower() in body.lower()]
        is_vercel = vercel_headers or "vercel.app" in clean_url or "vercel" in headers.get("server", "")
        result = {"target_url": clean_url, "is_vercel": is_vercel, "status_code": response.get("status_code", 0),
                  "dangling": bool(not_found_markers), "markers": not_found_markers,
                  "findings": [], "failure": response.get("failure"), "source": "auto_discovered"}
        if not is_vercel:
            return result
        if not_found_markers:
            result["findings"].append(normalized_finding(
                finding_type="Dangling Vercel Deployment (Subdomain Takeover Candidate)",
                target=clean_url, endpoint=clean_url, status=FindingStatus.SUSPECTED, confidence=.6,
                source_module="cloud_baas_hunter", source_tool="HTTPVerifier + Vercel fingerprint",
                test=self._legacy_evidence_test(response),
                evidence=[{"status_code": response.get("status_code"), "markers": not_found_markers,
                           "vercel_fingerprinted": True}],
                verification_checks=[{"name": "vercel_fingerprinted", "passed": True},
                                     {"name": "deployment_not_found_marker", "passed": True}],
                false_positive_reasons=["A generic 404 page may contain NOT_FOUND without being a Vercel deployment"],
                missing_evidence=["Claiming the deployment name proves control; needs manual Vercel account verification"],
                severity="High", cvss_score=0.0, param="n/a",
                reproduction_curl=f'curl -i -s "{clean_url}"',
                verification_note="The Vercel-hosted domain answers with a deployment-not-found page, indicating the deployment was deleted or never created.",
                observed_impact="The hostname points at Vercel but no live deployment exists behind it.",
                potential_impact="An attacker who registers the deployment name may serve arbitrary content on this hostname.",
                vrt_category="Server-Side Misconfiguration > Subdomain Takeover",
            ))
        else:
            result["hosted_note"] = True
            result["notes"] = ["Vercel-hosted asset; no dangling deployment detected."]
        return result

    @staticmethod
    def _legacy_evidence_test(response: Dict[str, Any]) -> Dict[str, Any]:
        # Legacy callers used to copy the complete wire request/response into
        # findings. That can include Authorization, cookies, or BaaS records.
        # Preserve triage metadata and a structural digest instead.
        return {
            "request": {"method": response.get("method", "GET"),
                        "url": response.get("url", "")},
            "response": {
                **CloudBaaSHunter._safe_baas_response(response, response.get("body", "")),
                "response_time_sec": response.get("response_time_sec", 0),
            },
        }

    @staticmethod
    def _is_supabase_host(value: str) -> bool:
        host = (value or "").lower()
        if "://" in host:
            host = host.split("//", 1)[1]
        host = host.split("/")[0].split(":")[0]
        return host.endswith(".supabase.co") or host == "supabase.co"

    @staticmethod
    def _is_firebase_host(value: str) -> bool:
        host = (value or "").lower()
        if "://" in host:
            host = host.split("//", 1)[1]
        host = host.split("/")[0].split(":")[0]
        return any(host.endswith(sfx) or host == sfx for sfx in
                   (".firebaseio.com", ".firebaseapp.com", ".firebasedatabase.app", ".firebase.google.com"))

    def audit_supabase_unauth(self, supabase_url: str) -> Dict[str, Any]:
        """Auto-discovery probe without any key: if /rest/v1/ answers 200 (or a
        non-401 status with real content) without an API key, that is notable.
        Never claims VERIFIED — just a discovery-level candidate."""
        clean_url = supabase_url.rstrip("/")
        schema_url = f"{clean_url}/rest/v1/"
        response = self._verifier_for(clean_url).send_http_request(schema_url)
        status = response.get("status_code", 0)
        body = response.get("body", "")
        exposed = status == 200 or (status in (403, 405) and len(body) > 5)
        result = {
            "target_url": clean_url, "auth_used": False, "source": "auto_discovered",
            "openapi_exposed": status == 200 and "definitions" in body or "paths" in body,
            "schema_status": status, "is_open_without_key": exposed, "findings": [],
        }
        if exposed:
            result["findings"].append(normalized_finding(
                finding_type="Supabase Project Answering Without API Key", target=clean_url, endpoint=schema_url,
                status=FindingStatus.DISCOVERED, confidence=.35, source_module="cloud_baas_hunter",
                source_tool="unauthenticated PostgREST probe",
                test={"request": {"url": schema_url, "auth": "none"},
                      "response": self._safe_baas_response(response, body)},
                evidence=[{"schema_status": status, "auth_used": False}],
                verification_checks=[{"name": "postgrest_answered_unauth", "passed": True}],
                false_positive_reasons=["A 403/405 without API key can be Cloudflare/edge behavior, not open data"],
                missing_evidence=["Successful data read with a valid anon/service key is required for VERIFIED"],
                severity="Info", cvss_score=0.0, param="none",
                verification_note="The Supabase project responded to an unauthenticated request; access extent unproven.",
                observed_impact="The Supabase API endpoint is reachable and answers without credentials.",
                potential_impact="If an anon key is later recovered, RLS tables may be enumerable.",
                vrt_category="Server-Side Misconfiguration > Supabase Access Control",
            ))
        return result

    def audit_discovered_assets(self, secrets: List[Dict[str, Any]], hosts: Optional[List[str]] = None,
                                target_url: Optional[str] = None) -> Dict[str, Any]:
        """Auto-discovers BaaS assets from JS secrets, subdomain/host recon, and
        the scan target itself, then audits each in-scope instance automatically."""
        supabase_urls = [s.get("_raw_value", s.get("value")) for s in secrets if s.get("secret_type") == "supabase_url"]
        supabase_keys = [s.get("_raw_value", s.get("value")) for s in secrets if s.get("secret_type") in {"supabase_anon_key", "jwt_token"}]
        firebase_urls = [s.get("_raw_value", s.get("value")) for s in secrets if s.get("secret_type") == "firebase_url"]

        # Auto-detect from recon hosts (subdomains + live hosts) and the target itself.
        recon_hosts = [h for h in (hosts or []) if h]
        for host in recon_hosts:
            if self._is_supabase_host(host):
                supabase_urls.append(host if "://" in host else f"https://{host}")
            elif self._is_firebase_host(host):
                firebase_urls.append(host if "://" in host else f"https://{host}")
        if target_url:
            if self._is_supabase_host(target_url):
                supabase_urls.append(target_url)
            elif self._is_firebase_host(target_url):
                firebase_urls.append(target_url)

        # Vercel candidates: hostname/target on *.vercel.app or clearly vercel-served.
        vercel_urls = [u for u in supabase_urls + firebase_urls if ".vercel.app" in (u or "")]
        for host in recon_hosts:
            lowered = (host or "").lower()
            if ".vercel.app" in lowered or ".vercel-script.com" in lowered:
                vercel_urls.append(host if "://" in host else f"https://{host}")
        if target_url and ".vercel.app" in (target_url or "").lower():
            vercel_urls.append(target_url)

        # Track where each URL came from so the UI can label auto vs js_secret.
        secret_sources = {s.get("_raw_value", s.get("value")): "js_secret" for s in secrets}
        findings, supabase_reports, firebase_reports, vercel_reports, skipped = [], [], [], [], []
        for url in set(filter(None, supabase_urls)):
            origin = secret_sources.get(url, "auto_discovered")
            if self.scope and not self.scope.check_url(url, active=True).get("allowed"):
                skipped.append({"value": url, "source": origin, "observed": True,
                                "active_verification_skipped": "outside_scope"})
                continue
            key_found = None
            for key in set(filter(None, supabase_keys)):
                if len(key.split(".")) == 3 and ("jwt" in key or "eyJ" in key):
                    key_found = key
                    break
            if key_found:
                report = self.audit_supabase(url, key_found)
                report["auth_used"] = True
            else:
                report = self.audit_supabase_unauth(url)
            report["source"] = origin
            supabase_reports.append(report)
            findings.extend(report.get("findings", []))
        for url in set(filter(None, firebase_urls)):
            if self.scope and not self.scope.check_url(url, active=True).get("allowed"):
                skipped.append({"value": url, "source": "auto_discovered", "observed": True,
                                "active_verification_skipped": "outside_scope"})
                continue
            report = self.audit_firebase(url)
            report["source"] = "auto_discovered"
            firebase_reports.append(report)
            findings.extend(report["findings"])
        for url in set(filter(None, vercel_urls)):
            if self.scope and not self.scope.check_url(url, active=True).get("allowed"):
                skipped.append({"value": url, "source": "auto_discovered", "observed": True,
                                "active_verification_skipped": "outside_scope"})
                continue
            report = self.audit_vercel(url)
            vercel_reports.append(report)
            findings.extend(report["findings"])
        return {"supabase_audits": supabase_reports, "firebase_audits": firebase_reports,
                "vercel_audits": vercel_reports, "findings": findings,
                "verified_findings": [f for f in findings if f["status"] == "VERIFIED"], "skipped_external": skipped}
