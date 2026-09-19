"""Local-only secret handling for the discovery layer.

Raw credential material is a transient analysis input.  The public discovery
model contains a mask and a SHA-256 fingerprint for deduplication only.  This
module intentionally has no network client and does not send values to
reference, logging, browser, or reporting components.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import urllib.parse
from typing import Any, Dict, Iterable, Optional


PLACEHOLDER_RE = re.compile(
    r"^(?:your[_-]?(?:api[_-]?)?key|api[_-]?key|secret|token|password|"
    r"changeme|change[_-]?me|placeholder|dummy|example|sample|test(?:ing)?|"
    r"xxx+|none|null|undefined|default|replace[_-]?me|<[^>]+>)$",
    re.IGNORECASE,
)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: Dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    size = float(len(value))
    return -sum((count / size) * math.log2(count / size) for count in counts.values())


def decode_jwt_claims(value: str) -> Optional[Dict[str, Any]]:
    """Decode JWT claims structurally, never verify or execute a token."""
    try:
        parts = value.split(".")
        if len(parts) != 3 or not all(parts):
            return None
        payload = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
        decoded = base64.urlsafe_b64decode(payload.encode("ascii"))
        claims = json.loads(decoded.decode("utf-8"))
        return claims if isinstance(claims, dict) else None
    except (ValueError, TypeError, UnicodeError, json.JSONDecodeError):
        return None


class SecretRedactor:
    """Mask and classify candidate values without persisting their plaintext."""

    PUBLIC_PREFIXES = {
        "AIza": "Firebase/Google",
        "pk_live_": "Stripe",
        "pk_test_": "Stripe",
    }
    SECRET_PREFIXES = {
        "AKIA": "AWS",
        "ASIA": "AWS",
        "A3T": "AWS",
        "AGPA": "AWS",
        "AIDA": "AWS",
        "AROA": "AWS",
        "AIPA": "AWS",
        "ANPA": "AWS",
        "ANVA": "AWS",
        "ghp_": "GitHub",
        "gho_": "GitHub",
        "ghs_": "GitHub",
        "ghu_": "GitHub",
        "ghr_": "GitHub",
        "sk_live_": "Stripe",
        "sk_test_": "Stripe",
        "rk_live_": "Stripe",
        "SG.": "SendGrid",
        "xoxb-": "Slack",
        "xoxp-": "Slack",
        "xoxa-": "Slack",
    }

    # Obvious token forms used for static analysis.  They are deliberately
    # paired with context/entropy checks below; a regex hit is not a finding.
    TOKEN_RE = re.compile(
        r"(?P<bearer>Bearer\s+[A-Za-z0-9._~+/=-]{16,})|"
        r"(?P<jwt>eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9._~+/=-]{8,})|"
        r"(?P<aws>\b(?:AKIA|ASIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}\b)|"
        r"(?P<github>\bgh[opsur]_[A-Za-z0-9]{20,255}\b)|"
        r"(?P<stripe>\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b)|"
        r"(?P<firebase>\bAIza[A-Za-z0-9_-]{30,}\b)|"
        r"(?P<sendgrid>\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b)|"
        r"(?P<slack>\bxox[baprs]-[A-Za-z0-9-]{20,}\b)",
        re.IGNORECASE,
    )

    # scheme://user:password@host — strip credentials, keep URL shape
    URL_CRED_RE = re.compile(
        r"(\b[a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@",
        re.IGNORECASE,
    )

    HEADER_NAMES = {
        "authorization", "x-api-key", "api-key", "apikey", "x-auth-token",
        "x-access-token", "x-csrf-token", "x-xsrf-token", "proxy-authorization",
    }

    def __init__(self, mask_prefix: int = 6, mask_suffix: int = 4):
        self.mask_prefix = max(2, int(mask_prefix))
        self.mask_suffix = max(2, int(mask_suffix))

    @staticmethod
    def is_placeholder(value: str) -> bool:
        normalized = (value or "").strip().strip("\"'").strip()
        if not normalized:
            return True
        if PLACEHOLDER_RE.fullmatch(normalized):
            return True
        # Provider prefixes can hide fixture values such as
        # ``sk_test_example`` from the exact-match rule above.  Reject only
        # explicit placeholder suffixes; a real ``sk_test_...`` key is not
        # rejected merely because Stripe uses the word ``test`` in its prefix.
        if re.search(r"(?:^|[_-])(example|placeholder|changeme|change[_-]?me|dummy|sample|xxx+)(?:$|[_-])",
                     normalized.lower()):
            return True
        compact = re.sub(r"[^a-z0-9]", "", normalized.lower())
        if compact and (len(set(compact)) == 1 or compact in {"abc123", "123456", "qwerty"}):
            return True
        return False

    def fingerprint(self, value: str) -> str:
        return hashlib.sha256((value or "").encode("utf-8", errors="replace")).hexdigest()

    def mask_secret(self, value: str) -> str:
        """Mask a secret value, keeping only a short prefix/suffix for correlation."""
        raw = str(value or "")
        if not raw:
            return ""
        if len(raw) <= self.mask_prefix + self.mask_suffix + 3:
            return "[REDACTED]"
        return f"{raw[:self.mask_prefix]}...{raw[-self.mask_suffix:]}"

    def redact_text(self, text: str, known_values: Optional[Iterable[str]] = None) -> str:
        """Redact credential-shaped values from free text."""
        if not text:
            return str(text or "")
        result = str(text)
        for match in self.TOKEN_RE.finditer(result):
            result = result.replace(match.group(0), "[REDACTED]")
        result = self.URL_CRED_RE.sub(r"\1[REDACTED]@", result)
        if known_values:
            for value in known_values:
                if value and len(str(value)) >= 8:
                    result = result.replace(str(value), "[REDACTED]")
        return result

    def redact_headers(self, headers: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Redact sensitive header values; keep benign headers readable."""
        result: Dict[str, Any] = {}
        for key, value in (headers or {}).items():
            str_key = str(key)
            if str_key.lower() in self.HEADER_NAMES:
                result[str_key] = "[REDACTED]"
            else:
                result[str_key] = self.redact_text(str(value))
        return result

    def redact_auth_reference(self, expression: str) -> str:
        """Redact credential material inside an auth expression."""
        return self.redact_text(str(expression or ""))

    def redact_url(self, url: str) -> str:
        """Redact sensitive query values from a URL, keeping the shape."""
        raw = str(url or "")
        if not raw:
            return raw
        try:
            parsed = urllib.parse.urlsplit(raw)
            query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
            safe_query = "&".join(
                f"{key}={self.mask_secret(value) if key.lower() in {
                    'token', 'secret', 'password', 'api_key', 'apikey',
                    'access_token', 'refresh_token', 'key', 'sig', 'signature',
                } else value}"
                for key, value in query
            )
            return urllib.parse.urlunsplit(
                (parsed.scheme, parsed.netloc, parsed.path, safe_query, parsed.fragment))
        except Exception:  # noqa: BLE001 - never fail on malformed URL
            return self.redact_text(raw)

    def redact_json(self, value: Any, _key: str = "") -> Any:
        """Recursively redact sensitive values inside JSON-like structures.

        Two-pass: first collect every value stored under a sensitive key
        (e.g. ``_raw_value``), then redact the whole tree so sibling
        ``context`` fields that embed the same raw value are scrubbed too.
        """
        known = self._collect_sensitive_values(value)
        return self._redact_json_inner(value, _key=_key, _known=known)

    def _collect_sensitive_values(self, value: Any) -> set:
        found = set()
        if isinstance(value, dict):
            for key, item in value.items():
                if self._sensitive_name(str(key)) and isinstance(item, str) and len(item) >= 8:
                    found.add(item)
                found |= self._collect_sensitive_values(item)
        elif isinstance(value, list):
            for item in value:
                found |= self._collect_sensitive_values(item)
        return found

    def _redact_json_inner(self, value: Any, _key: str = "", _known: Optional[set] = None) -> Any:
        if isinstance(value, dict):
            return {str(key): self._redact_json_inner(item, _key=str(key), _known=_known)
                    for key, item in value.items()}
        if isinstance(value, list):
            return [self._redact_json_inner(item, _key=_key, _known=_known) for item in value]
        if isinstance(value, str):
            if self._sensitive_name(_key):
                return "[REDACTED]"
            return self.redact_text(value, known_values=_known)
        return value

    @staticmethod
    def _sensitive_name(name: str) -> bool:
        lowered = name.lower().replace("-", "_")
        return any(marker in lowered for marker in (
            "password", "secret", "api_key", "apikey", "access_key",
            "access_token", "refresh_token", "private_key",
            "raw_value", "raw_key",
        ))

    @staticmethod
    def _provider_from_prefix(value: str) -> Optional[str]:
        for prefix, provider in SecretRedactor.SECRET_PREFIXES.items():
            if value.startswith(prefix):
                return provider
        for prefix, provider in SecretRedactor.PUBLIC_PREFIXES.items():
            if value.startswith(prefix):
                return provider
        return None

    @staticmethod
    def _context_score(context: str, variable_name: Optional[str] = None,
                       usage: Optional[Iterable[Dict[str, Any]]] = None) -> float:
        haystack = f"{context} {variable_name or ''} " + " ".join(
            str(item) for item in (usage or [])
        )
        lowered = haystack.lower()
        score = 0.0
        for marker, weight in (
            ("authorization", .20), ("bearer", .20), ("x-api-key", .18),
            ("apikey", .15), ("service_role", .25), ("private", .20),
            ("secret", .10), ("password", .10), ("createclient", .10),
            ("supabase", .08), ("firebase", .05), ("api_key", .12),
            ("access_token", .20), ("accesstoken", .20), ("refresh_token", .20),
            ("refreshtoken", .20), ("id_token", .15), ("idtoken", .15),
            ("oauth", .15), ("session", .10),
        ):
            if marker in lowered:
                score += weight
        return min(1.0, score)

    def classify_value(self, value: str, *, context: str = "", provider_hint: Optional[str] = None,
                       variable_name: Optional[str] = None,
                       usage: Optional[Iterable[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """Classify a value using provider format plus surrounding code context.

        ``status`` describes static evidence.  It is never ``VERIFIED`` solely
        because a string matches a pattern; live verification must be explicit
        and tied to a linked target/project.
        """
        raw = str(value or "").strip().strip("\"'")
        result: Dict[str, Any] = {
            "credential_type": "UNKNOWN_TOKEN", "provider": provider_hint,
            "status": "CANDIDATE", "masked_value": self.mask_secret(raw),
            "sha256": self.fingerprint(raw), "prefix": raw[:8], "length": len(raw),
            "public": False, "confidence": 0.0, "reason": "",
            "jwt_claims": None,
        }
        if not raw or self.is_placeholder(raw):
            result.update(status="REJECTED", confidence=0.0, reason="empty or placeholder value")
            return result

        claims = decode_jwt_claims(raw) if raw.count(".") == 2 and raw.startswith("eyJ") else None
        context_score = self._context_score(context, variable_name, usage)
        provider = provider_hint or self._provider_from_prefix(raw)
        result["provider"] = provider
        result["jwt_claims"] = self._safe_claims(claims)

        if raw.lower().startswith("bearer "):
            result["credential_type"] = "BEARER_REFERENCE"
            bearer_value = raw.split(None, 1)[1]
            nested = self.classify_value(bearer_value, context=f"{context} bearer", provider_hint=provider_hint,
                                          variable_name=variable_name, usage=usage)
            result["provider"] = nested.get("provider")
            result["public"] = bool(nested.get("public"))
            result["confidence"] = min(1.0, .65 + context_score)
            result["status"] = "LIKELY" if len(bearer_value) >= 20 else "CANDIDATE"
            result["reason"] = "literal bearer credential reference"
            return result

        if claims is not None:
            role = str(claims.get("role") or "").lower()
            issuer = str(claims.get("iss") or "").lower()
            result["credential_type"] = "JWT"
            if "supabase.co" in issuer or claims.get("ref") or role in {"anon", "service_role"}:
                result["provider"] = "Supabase"
                result["credential_type"] = "BAAS_KEY"
                if role == "anon":
                    result["public"] = True
                    result["reason"] = "structurally valid Supabase anon/publishable key"
                    result["confidence"] = min(1.0, .88 + context_score / 2)
                    result["status"] = "LIKELY"
                elif role == "service_role":
                    result["credential_type"] = "POTENTIAL_SECRET"
                    result["reason"] = "JWT role claims service_role; project acceptance is not yet proven"
                    result["confidence"] = min(1.0, .90 + context_score / 4)
                    result["status"] = "LIKELY"
                else:
                    result["reason"] = "JWT is correlated with a Supabase-like issuer/claims"
                    result["confidence"] = min(1.0, .75 + context_score / 2)
                    result["status"] = "LIKELY"
            else:
                result["reason"] = "structurally valid JWT; issuer/privilege not established"
                result["confidence"] = min(1.0, .70 + context_score / 2)
                result["status"] = "LIKELY"
            return result

        if provider == "Firebase/Google" and raw.startswith("AIza"):
            result.update(credential_type="PUBLIC_CLIENT_KEY", public=True, status="LIKELY",
                          confidence=min(1.0, .82 + context_score / 3),
                          reason="Firebase/Google browser API key format; API-key visibility is not secret proof")
            return result
        if provider == "Stripe" and raw.startswith(("pk_live_", "pk_test_")):
            result.update(credential_type="PUBLIC_CLIENT_KEY", public=True, status="LIKELY",
                          confidence=min(1.0, .85 + context_score / 4),
                          reason="Stripe publishable key format")
            return result
        if provider == "Stripe" and raw.startswith(("sk_live_", "sk_test_", "rk_live_")):
            result.update(credential_type="POTENTIAL_SECRET", status="LIKELY",
                          confidence=min(1.0, .86 + context_score / 3),
                          reason="Stripe secret/restricted-key format; target acceptance is not yet proven")
            return result
        if provider in {"AWS", "GitHub", "SendGrid", "Slack"}:
            result.update(credential_type="POTENTIAL_SECRET", status="LIKELY",
                          confidence=min(1.0, .86 + context_score / 3),
                          reason=f"{provider} credential format with contextual static evidence")
            return result

        # Prefer the defining property/variable name over a broad source
        # window.  A bundle commonly contains login-token code next to an
        # unrelated API key; letting that surrounding text win would turn the
        # API key into an OAuth reference and corrupt the data-flow graph.
        semantic_name = str(variable_name or "").lower().replace("-", "_")
        if re.search(r"(?:api[_]?key|x_api_key|apikey)", semantic_name) and not re.search(
            r"(?:client_secret|private[_]?key|access[_]?key|secret|oauth|access[_]?token|"
            r"refresh[_]?token|id[_]?token|session)", semantic_name
        ):
            if len(raw) >= 16 and shannon_entropy(raw) >= 3.0:
                result.update(credential_type="API_KEY", status="LIKELY",
                              confidence=min(1.0, .50 + context_score + min(.25, len(raw) / 200)),
                              reason="high-entropy value assigned to an API-key field")
                return result

        semantic_context = f"{variable_name or ''} {context}".lower().replace("-", "_")
        if re.search(r"(?:client_secret|private[_]?key|access[_]?key|secret)", semantic_context):
            if len(raw) >= 16 and shannon_entropy(raw) >= 2.5:
                result.update(credential_type="POTENTIAL_SECRET", status="LIKELY",
                              confidence=min(1.0, .68 + context_score / 2),
                              reason="high-entropy value appears in a secret-bearing configuration field")
                return result
        if re.search(r"(?:oauth|access[_]?token|refresh[_]?token|id[_]?token)", semantic_context):
            result.update(credential_type="OAUTH_TOKEN_REFERENCE", status="LIKELY" if len(raw) >= 20 else "CANDIDATE",
                          confidence=min(1.0, .62 + context_score / 2),
                          reason="token-shaped value is used in an OAuth/token response context")
            return result
        if re.search(r"(?:session[_]?token|session[_]?id|session)", semantic_context):
            result.update(credential_type="SESSION_REFERENCE", status="LIKELY" if len(raw) >= 20 else "CANDIDATE",
                          confidence=min(1.0, .58 + context_score / 2),
                          reason="value is used as a session reference; target acceptance is not yet proven")
            return result

        # Generic values need both reasonable entropy and use-site context.
        if len(raw) >= 16 and shannon_entropy(raw) >= 3.0 and context_score >= .12:
            result.update(credential_type="API_KEY", status="LIKELY",
                          confidence=min(1.0, .45 + context_score + min(.25, len(raw) / 200)),
                          reason="high-entropy value used in an authentication/header context")
        else:
            result.update(credential_type="UNKNOWN_TOKEN", status="CANDIDATE",
                          confidence=min(.35, context_score),
                          reason="format or context is insufficient for a credential claim")
        return result

    @staticmethod
    def _safe_claims(claims: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not claims:
            return None
        allowed = {"iss", "ref", "role", "exp", "iat", "aud", "sub"}
        return {key: claims[key] for key in allowed if key in claims and isinstance(claims[key], (str, int, float, bool))}

    def safe_credential(self, value: str, **kwargs: Any) -> Dict[str, Any]:
        """Return a report-safe representation; the input is not retained."""
        result = self.classify_value(value, **kwargs)
        result.pop("jwt_claims", None)
        return result

    def safe_config_value(self, value: str, *, name: str = "") -> Dict[str, Any]:
        """Keep non-secret configuration identifiers useful for triage.

        A runtime API URL, OAuth client ID, tenant ID, pool ID, realm, or
        region is not credential material.  Masking those values makes an
        otherwise valid report impossible to correlate to the affected
        project.  Secret-shaped config fields still use the normal
        credential classifier, and URLs are canonicalized with sensitive
        query values removed.
        """
        raw = str(value or "").strip()
        lowered = re.sub(r"[^a-z0-9]", "", str(name or "").lower())
        public_markers = (
            "url", "uri", "endpoint", "domain", "issuer", "authority", "projectid", "projectref", "poolid",
            "tenantid", "userid", "userpoolid", "identitypoolid", "clientid", "appid",
            "applicationid", "region", "realm", "bucket", "redirecturi", "audience",
            "messagingsenderid",
        )
        secret_markers = ("secret", "password", "private", "accesstoken", "refreshtoken", "session", "credential")
        if raw and any(marker in lowered for marker in public_markers) and not any(marker in lowered for marker in secret_markers):
            safe_value = self.redact_url(raw) if raw.startswith(("http://", "https://")) else raw
            return {
                "value": safe_value, "public_identifier": True, "sensitive": False,
                "length": len(raw), "sha256": self.fingerprint(raw),
            }
        return self.safe_credential(raw, context=name, variable_name=name)


__all__ = ["SecretRedactor", "decode_jwt_claims", "shannon_entropy"]
