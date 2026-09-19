"""Provider-aware BaaS correlation and bounded, linked-project validation."""

from __future__ import annotations

import re
import urllib.parse
from typing import Any, Dict, Iterable, List, Optional

from redteam_agent.discovery.js_deep import JSDeepAnalyzer, _line_number, _read_balanced, _read_expression
from redteam_agent.discovery.models import BaaSProject, CredentialRecord, EndpointRecord
from redteam_agent.discovery.redaction import SecretRedactor, decode_jwt_claims


class BaaSCorrelationEngine:
    """Correlate a URL and its key at the same code boundary.

    In particular, this class never picks the first key found in a bundle and
    tries it against every project.  Each project is created from an observed
    constructor/config object or an equally strong local relationship.
    """

    SUPABASE_URL_RE = re.compile(r"https?://[A-Za-z0-9-]+\.supabase\.co(?:/[A-Za-z0-9_./-]*)?", re.IGNORECASE)
    FIREBASE_URL_RE = re.compile(
        r"https?://[A-Za-z0-9-]+\.(?:firebaseio\.com|firebasedatabase\.app|firebaseapp\.com)"
        r"(?:/[A-Za-z0-9_./-]*)?", re.IGNORECASE
    )
    CONFIG_FIELDS = ("apiKey", "authDomain", "projectId", "databaseURL", "storageBucket", "messagingSenderId", "appId")
    FIREBASE_FIELD_RE = re.compile(
        r"['\"]?(apiKey|authDomain|projectId|databaseURL|storageBucket|messagingSenderId|appId)"
        r"['\"]?\s*:\s*([^,}\n]+)"
    )
    GENERIC_URL_RE = re.compile(r"https?://[^'\"`\s<>]{3,300}", re.IGNORECASE)
    CLOUD_MARKERS = {
        "AWS Cognito": ("cognito-idp.", "cognitoidentity", "userpoolid", "identitypoolid", "amazoncognito.com"),
        "Auth0": ("auth0.com", "auth0client", "auth0-spa-js", "auth0"),
        "Clerk": ("clerk.com", "clerk.publishable", "clerkfrontendapi", "@clerk/", "clerk"),
        "Okta": (".okta.com", "okta.com", "oktaauth", "@okta/"),
        "Azure AD": ("login.microsoftonline.com", "msal", "azuread", "tenantid"),
        "Keycloak": ("keycloak", "/realms/", "keycloak-js"),
        "Appwrite": ("cloud.appwrite.io", "appwrite", "setendpoint"),
        "PocketBase": ("pocketbase", "/api/collections/"),
        "AWS Frontend": ("execute-api.", "s3.amazonaws.com", "apigateway", "aws-sdk"),
        "OIDC/OAuth": ("authorization_endpoint", "token_endpoint", "jwks_uri", "openid-configuration"),
    }
    # These fields are public correlation evidence.  Keeping them visible is
    # important for a triager: a client ID, pool ID, tenant, realm, or issuer
    # identifies the exact project without granting access by itself.  Secret
    # fields (client_secret, access_token, private keys, API credentials) are
    # deliberately absent from this allowlist and are handled by the
    # credential/redaction pipeline instead.
    PUBLIC_IDENTIFIER_FIELDS = {
        "AWS Cognito": ("userPoolId", "identityPoolId", "userPoolWebClientId", "poolId", "clientId", "region", "endpoint"),
        "Auth0": ("domain", "clientId", "client_id", "audience", "issuer", "authorization_endpoint", "token_endpoint", "jwks_uri", "redirect_uri"),
        "Clerk": ("frontendApi", "domain", "instanceId", "clientId"),
        "Okta": ("issuer", "clientId", "client_id", "orgUrl", "domain"),
        "Azure AD": ("tenantId", "clientId", "client_id", "authority", "redirectUri", "redirect_uri"),
        "Keycloak": ("url", "realm", "clientId", "client_id", "issuer"),
        "Appwrite": ("endpoint", "projectId", "project_id", "projectRef", "databaseId"),
        "PocketBase": ("url", "endpoint", "baseUrl", "projectRef"),
        "AWS Frontend": ("region", "clientId", "client_id", "apiUrl", "apiGatewayUrl", "bucket", "bucketName", "s3Bucket", "endpoint"),
        "OIDC/OAuth": ("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri", "client_id", "redirect_uri", "scope"),
    }
    PUBLIC_IDENTIFIER_RE = re.compile(
        r"(?P<key>['\"]?(?:userPoolId|identityPoolId|userPoolWebClientId|poolId|clientId|client_id|"
        r"region|endpoint|domain|audience|issuer|authorization_endpoint|token_endpoint|jwks_uri|"
        r"redirectUri|redirect_uri|frontendApi|instanceId|orgUrl|tenantId|authority|url|realm|"
        r"projectId|project_id|projectRef|databaseId|baseUrl|scope|apiUrl|apiGatewayUrl|bucket|bucketName|"
        r"s3Bucket)['\"]?)\s*(?::|=)\s*"
        r"(?P<expr>[^,}\n]+)", re.IGNORECASE
    )

    def __init__(self, *, redactor: Optional[SecretRedactor] = None, cloud_hunter: Any = None):
        self.redactor = redactor or SecretRedactor()
        self.cloud_hunter = cloud_hunter
        self.js_helper = JSDeepAnalyzer(redactor=self.redactor)

    @staticmethod
    def _project_ref(url: Optional[str], claims: Optional[Dict[str, Any]] = None) -> Optional[str]:
        if claims and claims.get("ref"):
            return str(claims["ref"])
        host = urllib.parse.urlsplit(url or "").hostname or ""
        return host.split(".", 1)[0] if host.endswith(".supabase.co") else None

    def _find_credential(self, value: Optional[str], credentials: Iterable[CredentialRecord]) -> Optional[CredentialRecord]:
        if not value:
            return None
        fingerprint = self.redactor.fingerprint(value)
        for record in credentials:
            if record.sha256 == fingerprint:
                return record
        return None

    def _resolved_argument(self, expression: str, variables: Dict[str, str]) -> Optional[str]:
        """Resolve only a proven static constructor argument.

        An unresolved identifier such as ``SUPABASE_ANON_KEY`` is a reference,
        not a credential value.  Treating the identifier text as the key would
        create a false URL/key pairing and could later send that identifier to
        a verifier.  Runtime config values are intentionally left unresolved;
        the browser/auth-context path is the only place allowed to observe
        them.
        """
        expression = (expression or "").strip()
        value = self.js_helper._static_value(expression, variables)
        if value is not None:
            return value
        if expression[:1] in "'\"`":
            literal, _ = _read_expression(expression, 0, stops="")
            return self.js_helper._decode_static(literal[1:-1] if len(literal) >= 2 else "")
        return None

    @staticmethod
    def _key_type(key: Optional[str], credential: Optional[CredentialRecord] = None) -> tuple[Optional[str], Optional[Dict[str, Any]], float]:
        if not key:
            return None, None, .35
        claims = decode_jwt_claims(key)
        role = str((claims or {}).get("role") or "").lower()
        issuer = str((claims or {}).get("iss") or "").lower()
        if role == "service_role":
            return "service_role-like", claims, .98
        if role == "anon":
            return "anon", claims, .98
        if issuer and "supabase" in issuer:
            return "unknown", claims, .82
        if credential and credential.credential_type == "BAAS_KEY":
            return "unknown", claims, max(.65, credential.confidence)
        return "unknown", claims, .45

    @staticmethod
    def _services_from_text(text: str, provider: str) -> List[str]:
        lowered = (text or "").lower()
        if provider == "Supabase":
            mapping = (("/auth/v1", "Auth"), ("/rest/v1", "PostgREST"), ("/storage/v1", "Storage"), (".rpc(", "RPC"), ("realtime", "Realtime"))
        else:
            mapping = (("signinanonymously", "Authentication"), ("getauth", "Authentication"), ("firebaseauth", "Authentication"),
                       ("firestore", "Firestore"), ("firebaseio.com", "Realtime Database"), ("getdatabase", "Realtime Database"),
                       ("getstorage", "Storage"), ("storagebucket", "Storage"), ("functions", "Functions"), ("hosting", "Hosting"))
        return sorted({label for marker, label in mapping if marker in lowered})

    def _supabase_call_projects(self, text: str, source: Dict[str, Any], credentials: List[CredentialRecord]) -> List[BaaSProject]:
        projects: List[BaaSProject] = []
        variables = self.js_helper._constant_values(text)
        for match in re.finditer(r"\bcreateClient\s*\(", text or "", re.IGNORECASE):
            first, cursor = _read_expression(text, match.end())
            if cursor >= len(text) or text[cursor] != ",":
                continue
            second, _ = _read_expression(text, cursor + 1)
            url = self._resolved_argument(first, variables)
            key = self._resolved_argument(second, variables)
            if not (url and ("supabase.co" in url.lower() or "supabase" in text[max(0, match.start() - 100):match.end() + 100].lower())):
                continue
            if not urllib.parse.urlsplit(url).scheme:
                url = urllib.parse.urljoin(source.get("source_url") or "", url)
            credential = self._find_credential(key, credentials)
            key_type, claims, confidence = self._key_type(key, credential)
            project = BaaSProject(
                provider="Supabase", project_ref=self._project_ref(url, claims), url=url.rstrip("/"),
                key_type=key_type, key_fingerprint=self.redactor.fingerprint(key) if key else None,
                key_source=source.get("source_file"), services=self._services_from_text(text, "Supabase"),
                public_identifiers={"project_ref": self._project_ref(url, claims)} if self._project_ref(url, claims) else {},
                confidence=confidence, _raw_key=key if key else None,
                evidence=[{"source_file": source.get("source_file"), "source_line": _line_number(text, match.start()),
                           "relationship": "createClient(url, key)",
                           "source_map": source.get("source_map")}],
            )
            if claims:
                project.auth["jwt_claims"] = {key: claims[key] for key in ("iss", "ref", "role", "exp", "iat", "aud") if key in claims}
            project.auth["key_public_configuration"] = key_type == "anon"
            project.postgrest["observed"] = "/rest/v1" in text
            project.storage["observed"] = "/storage/v1" in text
            project.rpc["observed"] = ".rpc(" in text
            projects.append(project)
        return projects

    def _supabase_config_projects(self, text: str, source: Dict[str, Any], credentials: List[CredentialRecord]) -> List[BaaSProject]:
        """Pair Supabase URL/key fields inside one config boundary.

        Runtime JSON and framework config files often expose the values as
        ``SUPABASE_URL``/``SUPABASE_ANON_KEY`` without a visible
        ``createClient`` call.  Pairing is limited to one object or to
        explicitly suffixed sibling assignments; unrelated keys in the same
        bundle are never tried against every observed project.
        """
        field_re = re.compile(
            r"['\"]?(?P<name>[A-Za-z_$][\w$.-]*)['\"]?\s*:\s*(?P<expr>[^,}\n]+)"
        )
        assignments_re = re.compile(
            r"\b(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)\s*=\s*(?P<expr>[^;\n]+)"
        )
        variables = self.js_helper._constant_values(text)
        structures: List[tuple[str, str, str, int]] = []

        def static_value(expression: str) -> Optional[str]:
            value = self.js_helper._static_value(expression.strip(), variables)
            if value is None and expression.strip()[:1] in "'\"`":
                literal, _ = _read_expression(expression.strip(), 0, stops="")
                value = self.js_helper._decode_static(literal[1:-1] if len(literal) >= 2 else "")
            return str(value).strip().strip("'\"`") if value is not None else None

        def key_field(name: str) -> bool:
            lowered = re.sub(r"[^a-z0-9]", "", name.lower())
            return lowered in {"key", "apikey", "anonkey", "publishablekey", "servicerolekey", "servicekey"} \
                or ("supabase" in lowered and any(marker in lowered for marker in ("key", "token", "secret")))

        def add_pair(url_name: str, url: str, key_name: str, key: str, line: int) -> BaaSProject:
            if not urllib.parse.urlsplit(url).scheme:
                url = urllib.parse.urljoin(source.get("source_url") or "", url)
            credential = self._find_credential(key, credentials)
            key_type, claims, confidence = self._key_type(key, credential)
            project_ref = self._project_ref(url, claims)
            project = BaaSProject(
                provider="Supabase", project_ref=project_ref, url=url.rstrip("/"),
                key_type=key_type, key_fingerprint=self.redactor.fingerprint(key) if key else None,
                key_source=source.get("source_file"), services=self._services_from_text(text, "Supabase"),
                public_identifiers={"project_ref": project_ref} if project_ref else {},
                confidence=confidence, _raw_key=key or None,
                evidence=[{"source_file": source.get("source_file"), "source_line": line,
                           "relationship": "Supabase URL/key fields in one config boundary",
                           "url_field": url_name, "key_field": key_name,
                           "source_map": source.get("source_map")}],
            )
            if claims:
                project.auth["jwt_claims"] = {claim: claims[claim] for claim in ("iss", "ref", "role", "exp", "iat", "aud") if claim in claims}
            project.auth["key_public_configuration"] = key_type == "anon"
            project.postgrest["observed"] = "/rest/v1" in text
            project.storage["observed"] = "/storage/v1" in text
            project.rpc["observed"] = ".rpc(" in text
            return project

        # Object/config boundary pairing is the primary path.  For multiple
        # projects in one object, only an identical suffix (for example A)
        # makes a pair deterministic; otherwise the object is left unpaired.
        for start in (match.start() for match in re.finditer(r"\{", text or "")):
            block, end = _read_balanced(text, start)
            if not block or end <= start:
                continue
            fields: List[tuple[str, str, int]] = []
            for match in field_re.finditer(block):
                value = static_value(match.group("expr"))
                if value:
                    fields.append((match.group("name"), value, _line_number(text, start + match.start())))
            urls = [(name, value, line) for name, value, line in fields if "supabase.co" in value.lower()]
            keys = [(name, value, line) for name, value, line in fields if key_field(name)]
            if not urls or not keys:
                continue
            pairs: List[tuple[tuple[str, str, int], tuple[str, str, int]]] = []
            if len(urls) == 1 and len(keys) == 1:
                pairs = [(urls[0], keys[0])]
            else:
                def suffix(name: str) -> str:
                    match = re.search(r"(?:^|[_-])([a-z0-9]+)$", name.lower())
                    return match.group(1) if match else ""
                for url_item in urls:
                    matches = [key_item for key_item in keys if suffix(url_item[0]) and suffix(url_item[0]) == suffix(key_item[0])]
                    if len(matches) == 1:
                        pairs.append((url_item, matches[0]))
            for url_item, key_item in pairs:
                structures.append((url_item[0], url_item[1], key_item[0], key_item[1], url_item[2]))

        # A small sibling-assignment fallback supports Vite/Next runtime
        # variables while still requiring the shared SUPABASE naming boundary
        # and a close, unambiguous URL/key pair.
        assignments = []
        for match in assignments_re.finditer(text or ""):
            value = static_value(match.group("expr"))
            if value:
                assignments.append((match.group("name"), value, _line_number(text, match.start()), match.start()))
        url_assignments = [item for item in assignments if "supabase.co" in item[1].lower()]
        key_assignments = [item for item in assignments if key_field(item[0])]
        for url_item in url_assignments:
            nearby = [item for item in key_assignments if "supabase" in item[0].lower()
                      and abs(item[3] - url_item[3]) <= 900]
            if len(nearby) != 1:
                continue
            key_item = nearby[0]
            if not any(item[1] == url_item[1] and item[3] == key_item[1] for item in structures):
                structures.append((url_item[0], url_item[1], key_item[0], key_item[1], url_item[2]))

        return [add_pair(url_name, url, key_name, key, line) for url_name, url, key_name, key, line in structures]

    def _supabase_fallbacks(self, text: str, source: Dict[str, Any], credentials: List[CredentialRecord], existing_urls: set[str]) -> List[BaaSProject]:
        """Record unpaired Supabase URLs, never inventing a key pairing."""
        projects: List[BaaSProject] = []
        for match in self.SUPABASE_URL_RE.finditer(text or ""):
            url = match.group(0).rstrip("/")
            if url in existing_urls:
                continue
            nearby = text[max(0, match.start() - 240): min(len(text), match.end() + 240)]
            projects.append(BaaSProject(
                provider="Supabase", project_ref=self._project_ref(url), url=url,
                key_type=None, key_source=None, services=self._services_from_text(nearby, "Supabase"),
                public_identifiers={"project_ref": self._project_ref(url)} if self._project_ref(url) else {},
                confidence=.62, evidence=[{"source_file": source.get("source_file"),
                                           "source_line": _line_number(text, match.start()),
                                           "relationship": "Supabase URL observed without a constructor key"}],
            ))
        return projects

    def _firebase_projects(self, text: str, source: Dict[str, Any], credentials: List[CredentialRecord]) -> List[BaaSProject]:
        projects: List[BaaSProject] = []
        # Prefer the object assigned to firebaseConfig/config; its fields form
        # one project rather than seven unrelated observations.
        starts = list(re.finditer(r"\b(?:firebaseConfig|firebase_config|firebaseOptions|config)\s*=\s*\{", text or "", re.IGNORECASE))
        # Runtime JSON and inline config may have no assignment at all.  Add
        # only objects that contain Firebase's characteristic config fields so
        # unrelated request objects are not treated as projects.
        seen_starts = {match.end() - 1 for match in starts}
        structural_starts: List[int] = []
        for object_start in (match.start() for match in re.finditer(r"\{", text or "")):
            if object_start in seen_starts:
                continue
            block, _ = _read_balanced(text, object_start)
            if re.search(r"['\"]?apiKey['\"]?\s*:", block, re.IGNORECASE) and re.search(
                r"['\"]?(?:projectId|authDomain|databaseURL|storageBucket)['\"]?\s*:", block, re.IGNORECASE
            ):
                structural_starts.append(object_start)
                seen_starts.add(object_start)
        for start in starts:
            object_start = start.end() - 1
            block, _ = _read_balanced(text, object_start)
            fields: Dict[str, str] = {}
            for match in self.FIREBASE_FIELD_RE.finditer(block):
                value = match.group(2).strip()
                resolved = self.js_helper._static_value(value, self.js_helper._constant_values(text))
                fields[match.group(1)] = resolved or value.strip("'\"` ")
            if not ({"apiKey", "projectId"} & set(fields)):
                continue
            api_key = fields.get("apiKey")
            credential = self._find_credential(api_key, credentials)
            project = BaaSProject(
                provider="Firebase", project_ref=fields.get("projectId"), url=fields.get("databaseURL"),
                key_type="public-client-key" if api_key else None,
                key_fingerprint=self.redactor.fingerprint(api_key) if api_key else None,
                key_source=source.get("source_file"), services=self._services_from_text(text, "Firebase"),
                public_identifiers={key: fields[key] for key in ("projectId", "authDomain", "databaseURL", "storageBucket",
                                                                  "messagingSenderId", "appId") if fields.get(key)},
                confidence=.92 if fields.get("projectId") and api_key else .78,
                evidence=[{"source_file": source.get("source_file"), "source_line": _line_number(text, start.start()),
                           "relationship": "Firebase config object", "fields": sorted(fields)}],
            )
            project.auth["auth_domain"] = fields.get("authDomain")
            project.auth["api_key_masked"] = self.redactor.mask_secret(api_key) if api_key else None
            project.postgrest["database_url"] = fields.get("databaseURL")
            project.storage["bucket"] = fields.get("storageBucket")
            project.auth["public_key_expected"] = True
            projects.append(project)
        if structural_starts:
            for object_start in sorted(structural_starts):
                block, _ = _read_balanced(text, object_start)
                fields: Dict[str, str] = {}
                for match in self.FIREBASE_FIELD_RE.finditer(block):
                    value = match.group(2).strip()
                    resolved = self.js_helper._static_value(value, self.js_helper._constant_values(text))
                    fields[match.group(1)] = resolved or value.strip("'\"` ")
                api_key = fields.get("apiKey")
                if not ({"apiKey", "projectId"} & set(fields)):
                    continue
                project = BaaSProject(
                    provider="Firebase", project_ref=fields.get("projectId"), url=fields.get("databaseURL"),
                    key_type="public-client-key" if api_key else None,
                    key_fingerprint=self.redactor.fingerprint(api_key) if api_key else None,
                    key_source=source.get("source_file"), services=self._services_from_text(text, "Firebase"),
                    public_identifiers={key: fields[key] for key in ("projectId", "authDomain", "databaseURL", "storageBucket",
                                                                      "messagingSenderId", "appId") if fields.get(key)},
                    confidence=.92 if fields.get("projectId") and api_key else .78,
                    evidence=[{"source_file": source.get("source_file"), "source_line": _line_number(text, object_start),
                               "relationship": "Firebase config object", "fields": sorted(fields)}],
                )
                project.auth["auth_domain"] = fields.get("authDomain")
                project.auth["api_key_masked"] = self.redactor.mask_secret(api_key) if api_key else None
                project.postgrest["database_url"] = fields.get("databaseURL")
                project.storage["bucket"] = fields.get("storageBucket")
                project.auth["public_key_expected"] = True
                projects.append(project)
        if not starts and not structural_starts:
            for match in self.FIREBASE_URL_RE.finditer(text or ""):
                url = match.group(0).rstrip("/")
                projects.append(BaaSProject(provider="Firebase", url=url, project_ref=(urllib.parse.urlsplit(url).hostname or "").split(".", 1)[0],
                                            public_identifiers={"project_ref": (urllib.parse.urlsplit(url).hostname or "").split(".", 1)[0]},
                                            confidence=.6, evidence=[{"source_file": source.get("source_file"),
                                                                       "source_line": _line_number(text, match.start()),
                                                                       "relationship": "Firebase database URL observed"}]))
        return projects

    def _public_identifiers(self, text: str, provider: str) -> Dict[str, str]:
        """Extract provider allowlisted identifiers for actionable evidence.

        This is intentionally not a generic ``key/value`` dump.  Only fields
        known to be public identifiers for the detected provider are retained;
        values are still bounded and URL query material is redacted.  The
        result is safe to show in a triage report and lets a reviewer tie a
        finding to the exact tenant/project/pool.
        """
        allowed = {item.lower(): item for item in self.PUBLIC_IDENTIFIER_FIELDS.get(provider, ())}
        if not allowed:
            return {}
        identifiers: Dict[str, str] = {}

        def extract(fragment: str) -> None:
            variables = self.js_helper._constant_values(fragment)
            for match in self.PUBLIC_IDENTIFIER_RE.finditer(fragment or ""):
                key_text = match.group("key").strip("'\" ")
                canonical = allowed.get(key_text.lower())
                if not canonical:
                    continue
                expression = match.group("expr").strip()
                value = self.js_helper._static_value(expression, variables)
                if value is None:
                    continue
                value = str(value).strip().strip("'\"`")
                if not value or len(value) > 512 or self.redactor.is_placeholder(value):
                    continue
                if "//" in value or value.startswith(("http:", "https:")):
                    value = self.redactor.redact_url(value)
                identifiers.setdefault(canonical, value)

        # First use the smallest structural boundary available.  Scanning the
        # entire bundle would pair the first clientId in an application with a
        # later, unrelated Auth0/Cognito object—the same class of error this
        # engine avoids for Supabase URL/key pairing.
        for start in (match.start() for match in re.finditer(r"\{", text or "")):
            block, end = _read_balanced(text, start)
            if not block or end <= start:
                continue
            prefix = text[max(0, start - 160):start]
            boundary = prefix + block
            if any(marker.lower() in boundary.lower() for marker in self.CLOUD_MARKERS.get(provider, ())):
                extract(block)

        # Some SDKs expose flat constants rather than an object.  Keep the
        # fallback local to the marker occurrence; it is not a bundle-wide
        # key/value harvest.
        if not identifiers:
            markers = self.CLOUD_MARKERS.get(provider, ())
            for marker in markers:
                for occurrence in re.finditer(re.escape(marker), text or "", re.IGNORECASE):
                    extract(text[max(0, occurrence.start() - 180): occurrence.end() + 220])
        return identifiers

    def _generic_cloud_projects(self, text: str, source: Dict[str, Any]) -> List[BaaSProject]:
        """Record public auth/cloud configuration as correlated technology.

        These identifiers are discovery metadata, not credentials.  The method
        intentionally stores marker names and a provider URL, never arbitrary
        config values or client secrets.  Impact verification belongs to the
        provider-specific, in-scope workflow.
        """
        lowered = (text or "").lower()
        urls = [match.group(0).rstrip(".,)") for match in self.GENERIC_URL_RE.finditer(text or "")]
        projects: List[BaaSProject] = []
        for provider, markers in self.CLOUD_MARKERS.items():
            matched = sorted({marker for marker in markers if marker.lower() in lowered})
            if not matched:
                continue
            provider_urls = [self.redactor.redact_url(url) for url in urls
                             if any(marker.rstrip(".").lower() in url.lower() for marker in markers)]
            url = provider_urls[0] if provider_urls else None
            identifiers = self._public_identifiers(text, provider)
            ref_match = None
            if provider == "AWS Cognito":
                ref_match = re.search(r"\b(?:userPoolId|identityPoolId|poolId)\s*:\s*['\"]([^'\"]+)", text, re.IGNORECASE)
            elif provider == "Azure AD":
                ref_match = re.search(r"\btenantId\s*:\s*['\"]([^'\"]+)", text, re.IGNORECASE)
            elif provider == "Keycloak":
                ref_match = re.search(r"\brealm\s*:\s*['\"]([^'\"]+)", text, re.IGNORECASE)
            elif provider == "Auth0":
                ref_match = re.search(r"\bdomain\s*:\s*['\"]([^'\"]*auth0[^'\"]*)", text, re.IGNORECASE)
            project_ref = ref_match.group(1) if ref_match else None
            if not project_ref:
                project_ref = (identifiers.get("userPoolId") or identifiers.get("identityPoolId")
                               or identifiers.get("poolId") or identifiers.get("projectRef")
                               or identifiers.get("tenantId") or identifiers.get("projectId")
                               or identifiers.get("domain") or identifiers.get("realm")
                               or identifiers.get("issuer"))
            if not project_ref and url:
                project_ref = urllib.parse.urlsplit(url).hostname
            if not project_ref:
                project_ref = f"{source.get('source_file') or 'source'}:{_line_number(text, text.lower().find(matched[0].lower()))}"
            if not url:
                candidate_url = next((value for value in identifiers.values()
                                      if value.startswith(("http://", "https://"))), None)
                url = candidate_url
            services = ["Authentication"]
            if provider == "Appwrite" and any(item in matched for item in ("cloud.appwrite.io", "appwrite")):
                services.append("Appwrite API")
            if provider == "PocketBase":
                services.append("PocketBase API")
            if provider == "AWS Frontend":
                if any("execute-api." in item.lower() or "apigateway" in item.lower() for item in matched):
                    services.append("API Gateway")
                if any("s3.amazonaws.com" in item.lower() for item in matched):
                    services.append("S3/Storage")
            projects.append(BaaSProject(
                provider=provider, project_ref=project_ref, url=url,
                key_type="public-config", services=services, confidence=.76,
                public_identifiers=identifiers,
                evidence=[{"source_file": source.get("source_file"),
                           "source_line": _line_number(text, text.lower().find(matched[0].lower())),
                           "relationship": "provider configuration markers", "markers": matched,
                           "public_identifier_fields": sorted(identifiers),
                           "values_retained": False}],
                auth={"config_markers": matched, "public_identifiers_only": True,
                      "public_identifiers": identifiers},
            ))
        return projects

    def correlate(self, sources: Iterable[Dict[str, Any]], credentials: Optional[List[CredentialRecord]] = None,
                  endpoints: Optional[List[EndpointRecord]] = None, config_refs: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        credentials = list(credentials or [])
        projects: List[BaaSProject] = []
        relationships: List[Dict[str, Any]] = []
        for source in sources or []:
            text = str(source.get("text") or source.get("source_code") or "")
            if not text:
                continue
            supabase = self._supabase_call_projects(text, source, credentials)
            supabase.extend(self._supabase_config_projects(text, source, credentials))
            urls = {project.url for project in supabase if project.url}
            supabase.extend(self._supabase_fallbacks(text, source, credentials, urls))
            firebase = self._firebase_projects(text, source, credentials)
            generic = self._generic_cloud_projects(text, source)
            for project in supabase + firebase + generic:
                projects.append(project)
                if project.key_fingerprint:
                    relationships.append({"relationship_type": "credential_to_baas_project",
                                          "from": f"credential:{project.key_fingerprint}",
                                          "to": f"baas:{project.provider}:{project.project_ref or project.url}",
                                          "source": source.get("source_file"),
                                          "evidence": project.evidence[-1] if project.evidence else {}})

        # Merge only identical provider/project identities.  Two Supabase refs
        # remain distinct even when they share a source file.
        merged: Dict[tuple[str, str], BaaSProject] = {}
        for project in projects:
            key = (project.provider, project.project_ref or project.url or "unknown")
            existing = merged.get(key)
            if existing is None:
                merged[key] = project
                continue
            existing.services = sorted(set(existing.services) | set(project.services))
            existing.evidence.extend(item for item in project.evidence if item not in existing.evidence)
            existing.confidence = max(existing.confidence, project.confidence)
            existing.key_fingerprint = existing.key_fingerprint or project.key_fingerprint
            existing._raw_key = existing._raw_key or project._raw_key
            existing.key_type = existing.key_type or project.key_type
            existing.key_source = existing.key_source or project.key_source
            existing.public_identifiers.update({key: value for key, value in project.public_identifiers.items()
                                                if key not in existing.public_identifiers})
        return {"projects": list(merged.values()), "relationships": relationships,
                "supabase": [project for project in merged.values() if project.provider == "Supabase"],
                "firebase": [project for project in merged.values() if project.provider == "Firebase"]}

    def verify_supabase(self, project: BaaSProject, verifier: Any, scope_manager: Any,
                        *, authorized: bool = False, request_limit: int = 2) -> Dict[str, Any]:
        """Validate only the linked project/key, with at most two requests."""
        limit = min(2, max(0, int(request_limit)))
        if not authorized:
            return {"verified": False, "status": "NOT_RUN", "reason": "explicit authorized validation is required", "requests_used": 0}
        if not project.url or not project._raw_key:
            return {"verified": False, "status": "NOT_RUN", "reason": "no URL/key pair was correlated", "requests_used": 0}
        if scope_manager and not scope_manager.check_url(project.url, active=True).get("allowed"):
            return {"verified": False, "status": "OUT_OF_SCOPE", "reason": "linked project is outside active scope", "requests_used": 0}
        headers = {"apikey": project._raw_key, "Authorization": f"Bearer {project._raw_key}"}
        checks: List[Dict[str, Any]] = []
        for suffix in ("/rest/v1/?limit=2", "/auth/v1/settings")[:limit]:
            response = verifier.send_http_request(project.url.rstrip("/") + suffix, headers=headers, priority="verification")
            status = int(response.get("status_code") or 0)
            accepted = 200 <= status < 400
            checks.append({"endpoint": suffix, "status_code": status,
                           "body_length": len(str(response.get("body") or "")),
                           # A 404/5xx is not evidence that the credential was
                           # accepted.  Only a successful redirect/response is
                           # a bounded project-association signal.
                           "accepted": accepted})
            if accepted:
                break
        accepted = any(item["accepted"] for item in checks)
        project.verification = {"verified": bool(accepted), "status": "VERIFIED" if accepted else "NOT_CONFIRMED",
                                "credential_accepted": bool(accepted), "checks": checks,
                                "requests_used": len(checks), "impact_proven": False,
                                "note": "Acceptance proves project association only; row-level impact requires a target-specific data marker."}
        return project.verification

    def verify_firebase(self, project: BaaSProject, verifier: Any, scope_manager: Any,
                        *, authorized: bool = False, request_limit: int = 1) -> Dict[str, Any]:
        if not authorized:
            return {"verified": False, "status": "NOT_RUN", "reason": "explicit authorized validation is required", "requests_used": 0}
        url = project.url
        if not url:
            return {"verified": False, "status": "NOT_RUN", "reason": "no linked Firebase database surface was observed", "requests_used": 0}
        if scope_manager and not scope_manager.check_url(url, active=True).get("allowed"):
            return {"verified": False, "status": "OUT_OF_SCOPE", "reason": "linked Firebase surface is outside active scope", "requests_used": 0}
        response = verifier.send_http_request(url.rstrip("/") + "/.json?shallow=true&limitToFirst=1", priority="verification")
        status = int(response.get("status_code") or 0)
        project.verification = {"verified": status == 200, "status": "VERIFIED" if status == 200 else "NOT_CONFIRMED",
                                "status_code": status, "requests_used": 1, "impact_proven": False,
                                "note": "Firebase API-key visibility is public configuration; rules/data impact needs a specific proof."}
        return project.verification


__all__ = ["BaaSCorrelationEngine"]
