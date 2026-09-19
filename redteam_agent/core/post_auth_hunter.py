"""Post-Auth Surface Hunter — behavioral, context-specific, adaptive.

Modern approach: instead of signature matching (nuclei templates, known
payloads that WAFs block and every scanner replays), this engine compares
actual application behavior across auth states and object identifiers:

  1. differential_auth      — same endpoint with session vs without session.
     A 200 with data on the no-auth path is an unauthenticated access
     finding (the pattern that produced the NASA cross-provider read).
  2. bola_sequential_auth   — with a session, walk sequential object IDs and
     compare bodies; distinct 200s on other objects are BOLA candidates.
  3. excessive_data_exposure — inspect JSON response keys for sensitive
     fields (email/phone/token/api_key/...) returned to the caller.
  4. mass_assignment        — POST extra privileged fields (role/admin/...);
     acceptance is a mass-assignment candidate.

Discipline: every finding carries the tuple
PRODUCT-CONTROL -> STATE-CHANGE -> POST-CHANGE-CALL -> EFFECT where the
evidence allows it; otherwise it stays a candidate with missing_evidence.
"""

from __future__ import annotations

import json
import re
import urllib.parse
from typing import Any, Dict, List, Optional

from redteam_agent.core.findings import FindingStatus, normalized_finding
from redteam_agent.core.http_verifier import HTTPVerifier

_SENSITIVE_JSON_KEYS = (
    "email", "phone", "phone_number", "mobile", "ssn", "social_security",
    "passport", "credit_card", "card_number", "cvv", "bank_account",
    "api_key", "apikey", "access_token", "refresh_token", "id_token",
    "secret", "password", "passwd", "private_key", "authorization",
    "dob", "date_of_birth", "address", "home_address", "salary", "balance",
)

_PRIVILEGED_FIELDS = ("role", "is_admin", "admin", "is_staff", "permissions",
                      "is_verified", "is_premium", "account_type", "plan",
                      "status", "active", "approved")

_ID_IN_PATH_RE = re.compile(r"(.*[/_-])([A-Za-z0-9]{1,32})$")
_ID_IN_QUERY_RE = re.compile(r"(?:^|[?&])(?:id|object_id|user_id|account_id|doc_id|file_id|record_id|item_id|resource_id)=([A-Za-z0-9]{1,32})(?:&|$)", re.I)


class PostAuthHunter:
    """Behavioral post-auth surface analysis with a session-capable verifier."""

    def __init__(self, verifier: HTTPVerifier, anonymous_verifier: Optional[HTTPVerifier] = None):
        self.verifier = verifier
        # Anonymous verifier shares the same scope but has NO session auth,
        # so differential auth tests compare like-for-like.
        self.anonymous_verifier = anonymous_verifier or self._clone_without_auth(verifier)

    @staticmethod
    def _clone_without_auth(verifier: HTTPVerifier) -> HTTPVerifier:
        clone = HTTPVerifier(
            timeout=verifier.timeout,
            traffic_controller=verifier.traffic,
            scope_manager=verifier.scope,
            module="post_auth_hunter_anonymous",
        )
        return clone

    # ------------------------------------------------------------------
    # 1. Differential auth — the unauthenticated-access detector
    # ------------------------------------------------------------------
    def differential_auth(self, endpoint: str) -> Optional[Dict[str, Any]]:
        """Same endpoint with session vs without session.

        A 200 with a non-trivial body on the anonymous path while the
        authenticated path also returns 200 is an unauthenticated access
        candidate.  A 401/403 on the anonymous path is the expected control.
        """
        authed = self.verifier.send_http_request(endpoint)
        anon = self.anonymous_verifier.send_http_request(endpoint)
        authed_status = authed.get("status_code", 0)
        anon_status = anon.get("status_code", 0)
        anon_body = str(anon.get("body", "") or "")
        authed_body = str(authed.get("body", "") or "")
        if anon_status not in (200, 201):
            return None
        if len(anon_body.strip()) < 40:
            return None  # empty/placeholder body is not evidence of data access
        if anon_status == authed_status and anon_body == authed_body:
            # Identical responses on both paths: the endpoint is simply public.
            return None
        return normalized_finding(
            finding_type="Unauthenticated Access (Differential Auth)", target=endpoint,
            endpoint=endpoint, status=FindingStatus.LIKELY, confidence=.7,
            source_module="post_auth_hunter", source_tool="HTTPVerifier",
            baseline=self._evidence(anon), test=self._evidence(authed),
            evidence=[{"anonymous_status": anon_status, "authenticated_status": authed_status,
                       "anonymous_body_bytes": len(anon_body.encode("utf-8")),
                       "authenticated_body_bytes": len(authed_body.encode("utf-8"))}],
            verification_checks=[{"name": "anonymous_request_succeeded", "passed": True},
                                 {"name": "anonymous_body_non_trivial", "passed": True},
                                 {"name": "responses_differ_between_auth_states", "passed": True}],
            false_positive_reasons=["Endpoint may be intentionally public",
                                    "Anonymous response may be a cached or generic page"],
            missing_evidence=["Owner-vs-other authenticated A/B comparison",
                              "Confirmation that anonymous data is non-public (e.g. 0 hits in search API)"],
            severity="High", cvss_score=7.5, param="",
            reproduction_curl=f'curl -i -s "{endpoint}"',
            verification_note=f"Anonymous request returned HTTP {anon_status} with {len(anon_body)} bytes of content.",
            observed_impact="Data reachable without any session credentials.",
            potential_impact="If the data is non-public, other users or unauthenticated parties can read it.",
            raw_request=anon.get("raw_request", ""), raw_response=anon.get("raw_response", "")[:1500],
            vrt_category="Broken Access Control > Unauthenticated Access",
        )

    # ------------------------------------------------------------------
    # 2. BOLA with a session — sequential object walk
    # ------------------------------------------------------------------
    def bola_sequential_auth(self, endpoint: str, max_walk: int = 3) -> Optional[Dict[str, Any]]:
        """With a session, walk sequential object IDs and compare bodies.

        Distinct 200 bodies on other objects are BOLA candidates.  This is
        stronger than the anonymous variant because the session proves the
        caller is authenticated yet still reaches foreign objects.
        """
        parsed = urllib.parse.urlparse(endpoint)
        path_match = _ID_IN_PATH_RE.search(parsed.path.rstrip("/"))
        query_match = _ID_IN_QUERY_RE.search(endpoint)
        if not path_match and not query_match:
            return None
        if path_match:
            prefix, first_id = path_match.group(1), path_match.group(2)
            base = f"{parsed.scheme}://{parsed.netloc}{prefix}"
            ids = [first_id]
            if first_id.isdigit():
                ids += [str(int(first_id) + offset) for offset in range(1, max_walk + 1)]
            urls = [f"{base}{i}" for i in ids]
        else:
            param = query_match.group(1)
            first_id = query_match.group(2)
            base = endpoint
            ids = [first_id]
            if first_id.isdigit():
                ids += [str(int(first_id) + offset) for offset in range(1, max_walk + 1)]
            urls = [re.sub(rf"({param}=)[A-Za-z0-9]{{1,32}}", rf"\g<1>{i}", base) for i in ids]
        responses = [self.verifier.send_http_request(u) for u in urls]
        statuses = [r.get("status_code", 0) for r in responses]
        if not all(s == 200 for s in statuses):
            return None
        bodies = [str(r.get("body", "") or "") for r in responses]
        distinct = len({b for b in bodies}) > 1 and any(
            abs(len(bodies[0]) - len(b)) > 10 for b in bodies[1:])
        if not distinct:
            return None
        return normalized_finding(
            finding_type="Broken Object Level Authorization (BOLA) Candidate", target=endpoint,
            endpoint=urls[0], status=FindingStatus.LIKELY, confidence=.65,
            source_module="post_auth_hunter", source_tool="HTTPVerifier",
            baseline=self._evidence(responses[0]), test=self._evidence(responses[1]),
            evidence=[{"object_ids_tested": ids, "statuses": statuses,
                       "body_bytes": [len(b.encode("utf-8")) for b in bodies]}],
            verification_checks=[{"name": "authenticated_session_used", "passed": True},
                                 {"name": "foreign_object_accessible", "passed": True},
                                 {"name": "distinct_responses", "passed": True}],
            false_positive_reasons=["Sequential IDs may be intentional design",
                                    "Distinct bodies may reflect non-sensitive per-object data"],
            missing_evidence=["Owner-vs-other A/B with two identities and owner marker",
                              "Confirmation the foreign object belongs to another user"],
            severity="High", cvss_score=8.1, param="object_id",
            reproduction_curl=" && ".join(f'curl -i -s "{u}"' for u in urls[:2]),
            verification_note=f"Authenticated session reached {len(ids)} sequential object IDs with distinct 200 bodies.",
            observed_impact="Foreign object identifiers are enumerable with a valid session.",
            potential_impact="Other users' objects may be readable if authorization is missing.",
            raw_request=responses[0].get("raw_request", ""),
            raw_response=responses[1].get("raw_response", "")[:1500],
            vrt_category="Server-Side Injection > Broken Object Level Authorization",
        )

    # ------------------------------------------------------------------
    # 3. Excessive data exposure — sensitive JSON keys
    # ------------------------------------------------------------------
    def excessive_data_exposure(self, endpoint: str) -> Optional[Dict[str, Any]]:
        """Inspect JSON response keys for sensitive fields returned to the caller."""
        response = self.verifier.send_http_request(endpoint)
        if response.get("status_code") not in (200, 201):
            return None
        body = str(response.get("body", "") or "")
        try:
            data = json.loads(body)
        except (TypeError, ValueError):
            return None
        sensitive = self._find_sensitive_keys(data)
        if not sensitive:
            return None
        return normalized_finding(
            finding_type="Excessive Data Exposure", target=endpoint,
            endpoint=endpoint, status=FindingStatus.LIKELY, confidence=.6,
            source_module="post_auth_hunter", source_tool="HTTPVerifier",
            baseline=self._evidence(response), test={},
            evidence=[{"sensitive_keys": sensitive, "body_bytes": len(body.encode("utf-8"))}],
            verification_checks=[{"name": "json_response", "passed": True},
                                 {"name": "sensitive_keys_present", "passed": True}],
            false_positive_reasons=["Keys may be masked/empty in the response",
                                    "Endpoint may legitimately return the caller's own data"],
            missing_evidence=["Non-empty sensitive values", "Data belongs to another user"],
            severity="Medium", cvss_score=5.3, param="",
            reproduction_curl=f'curl -i -s "{endpoint}"',
            verification_note=f"Response exposes sensitive JSON keys: {', '.join(sensitive[:8])}.",
            observed_impact="Sensitive field names present in API response.",
            potential_impact="If values are populated, PII or credentials may be disclosed.",
            raw_request=response.get("raw_request", ""),
            raw_response=response.get("raw_response", "")[:1500],
            vrt_category="Broken Access Control > Excessive Data Exposure",
        )

    # ------------------------------------------------------------------
    # 4. Mass assignment — privileged field acceptance
    # ------------------------------------------------------------------
    def mass_assignment(self, endpoint: str) -> Optional[Dict[str, Any]]:
        """POST extra privileged fields; acceptance is a mass-assignment candidate."""
        for field in _PRIVILEGED_FIELDS:
            payload = json.dumps({field: True, "name": "probe"})
            response = self.verifier.send_http_request(
                endpoint, method="POST",
                headers={"Content-Type": "application/json", "Accept": "application/json"},
                body=payload)
            status = response.get("status_code", 0)
            if status in (200, 201, 202):
                return normalized_finding(
                    finding_type="Mass Assignment Candidate", target=endpoint,
                    endpoint=endpoint, status=FindingStatus.LIKELY, confidence=.5,
                    source_module="post_auth_hunter", source_tool="HTTPVerifier",
                    baseline=self._evidence(response), test={},
                    evidence=[{"field_tested": field, "status_code": status}],
                    verification_checks=[{"name": "privileged_field_accepted", "passed": True}],
                    false_positive_reasons=["Field may be ignored silently",
                                            "200 may be a generic success without state change"],
                    missing_evidence=["State change confirmed (POST-CHANGE-CALL)",
                                      "Privileged field actually persisted"],
                    severity="Medium", cvss_score=6.5, param=field,
                    reproduction_curl=f'curl -i -s -X POST "{endpoint}" -H "Content-Type: application/json" -d \'{payload}\'',
                    verification_note=f"POST with privileged field '{field}' returned HTTP {status}.",
                    observed_impact="Server accepted a privileged field in the request body.",
                    potential_impact="If persisted, an attacker may escalate privileges.",
                    raw_request=response.get("raw_request", ""),
                    raw_response=response.get("raw_response", "")[:1500],
                    vrt_category="Server-Side Injection > Mass Assignment",
                )
        return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _find_sensitive_keys(data: Any, depth: int = 0) -> List[str]:
        if depth > 4 or data is None:
            return []
        found: List[str] = []
        if isinstance(data, dict):
            for key, value in data.items():
                lowered = str(key).lower()
                if any(s in lowered for s in _SENSITIVE_JSON_KEYS):
                    found.append(str(key))
                found.extend(PostAuthHunter._find_sensitive_keys(value, depth + 1))
        elif isinstance(data, list):
            for item in data[:20]:
                found.extend(PostAuthHunter._find_sensitive_keys(item, depth + 1))
        return list(dict.fromkeys(found))

    @staticmethod
    def _evidence(response: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "status_code": response.get("status_code", 0),
            "body_bytes": len(str(response.get("body", "") or "").encode("utf-8")),
            "headers": {k: v for k, v in (response.get("headers") or {}).items()
                        if k.lower() not in {"set-cookie", "authorization"}},
        }