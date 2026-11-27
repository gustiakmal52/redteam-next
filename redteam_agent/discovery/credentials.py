"""Context-aware static credential discovery and explicit validation."""

from __future__ import annotations

import inspect
import re
from typing import Any, Dict, Iterable, List, Optional

from redteam_agent.discovery.js_deep import JSDeepAnalyzer, _line_number_lookup, _read_quoted
from redteam_agent.discovery.models import CredentialRecord
from redteam_agent.discovery.redaction import SecretRedactor


class CredentialDiscoveryEngine:
    """Find credential references without turning pattern matches into bugs."""

    ASSIGNMENT_RE = re.compile(
        r"\b(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)\s*=\s*(?P<expr>[^;\n]+)"
    )
    HEADER_USE_RE = re.compile(
        r"['\"]?(?P<header>authorization|x-api-key|api[-_]?key|apikey|x-auth-token|x-access-token|"
        r"x-csrf-token|x-xsrf-token|[A-Za-z][A-Za-z0-9_-]*(?:key|token|secret|auth|credential)[A-Za-z0-9_-]*)"
        r"['\"]?\s*:\s*(?P<expr>[^,}\n]+)", re.IGNORECASE
    )
    RESPONSE_USE_RE = re.compile(
        r"(?P<variable>[A-Za-z_$][\w$]*)\s*=\s*(?P<source>[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*))"
    )
    PROPERTY_CREDENTIAL_RE = re.compile(
        r"['\"]?(?P<name>(?:api[_-]?key|x-api-key|authorization|bearer|access[_-]?token|"
        r"refresh[_-]?token|id[_-]?token|session[_-]?token|client[_-]?secret|secret|"
        r"private[_-]?key|access[_-]?key|credential|password))['\"]?\s*:\s*"
        r"(?P<quote>['\"])(?P<value>(?:\\.|(?!\2).)*?)(?P=quote)", re.IGNORECASE | re.DOTALL
    )

    def __init__(self, redactor: Optional[SecretRedactor] = None):
        self.redactor = redactor or SecretRedactor()
        self.records: Dict[str, CredentialRecord] = {}

    @staticmethod
    def _context(text: str, start: int, end: int) -> str:
        return text[max(0, start - 220): min(len(text), end + 320)]

    def _record_from_raw(self, raw: str, *, text: str, source_url: str, source_file: str,
                         source_line: int, variable_name: Optional[str] = None,
                         source_map: Optional[str] = None, context: str = "") -> Optional[CredentialRecord]:
        classification = self.redactor.classify_value(raw, context=context, variable_name=variable_name)
        if classification["status"] == "REJECTED":
            return None
        record = CredentialRecord(
            credential_type=classification["credential_type"], provider=classification.get("provider"),
            status=classification["status"], masked_value=classification["masked_value"],
            sha256=classification["sha256"], prefix=classification["prefix"], length=classification["length"],
            source_url=source_url, source_file=source_file, source_line=source_line,
            context=self.redactor.redact_text(context, [raw])[:600], variable_name=variable_name,
            public=bool(classification.get("public")), confidence=float(classification.get("confidence", 0.0)),
            reason=classification.get("reason", ""), _raw_value=raw,
            evidence=[{"source_url": source_url, "source_file": source_file, "source_line": source_line,
                       "source_map": source_map, "context": self.redactor.redact_text(context, [raw])[:600]}],
        )
        claims = classification.get("jwt_claims")
        if claims:
            record.evidence[0]["jwt_claims"] = claims
        return record

    def _merge(self, record: CredentialRecord) -> CredentialRecord:
        existing = self.records.get(record.sha256)
        if existing is None:
            self.records[record.sha256] = record
            return record
        existing.confidence = max(existing.confidence, record.confidence)
        if existing.status != "VERIFIED" and record.status == "VERIFIED":
            existing.status = "VERIFIED"
        elif existing.status == "CANDIDATE" and record.status == "LIKELY":
            existing.status = "LIKELY"
        existing.public = existing.public or record.public
        existing.provider = existing.provider or record.provider
        existing.credential_type = existing.credential_type if existing.credential_type != "UNKNOWN_TOKEN" else record.credential_type
        existing.evidence.extend(item for item in record.evidence if item not in existing.evidence)
        if record.variable_name and record.variable_name not in {existing.variable_name, *[item.get("variable_name") for item in existing.usage]}:
            existing.usage.append({"type": "variable_definition", "variable_name": record.variable_name,
                                   "source_file": record.source_file, "source_line": record.source_line})
        return existing

    def discover(self, text: str, *, source_url: str = "", source_file: str = "unknown",
                 source_map: Optional[str] = None) -> List[CredentialRecord]:
        text = text or ""
        line_at = _line_number_lookup(text)
        values: Dict[str, str] = {}
        # Resolve only literal/constant assignments.  No eval and no function execution.
        helper = JSDeepAnalyzer(redactor=self.redactor)
        values.update(helper._constant_values(text))
        local: List[CredentialRecord] = []
        assignment_by_value: Dict[str, tuple[str, int]] = {}
        for match in self.ASSIGNMENT_RE.finditer(text):
            expression = match.group("expr").strip()
            value = helper._static_value(expression, values)
            if value:
                assignment_by_value[value] = (match.group("name"), line_at(match.start()))

        for match in re.finditer(r"(?P<quote>['\"`])(?P<value>(?:\\.|(?!\1).)*?)(?P=quote)", text, re.DOTALL):
            raw = helper._decode_static(match.group("value"))
            variable_name, assignment_line = assignment_by_value.get(raw, (None, None))
            context = self._context(text, match.start(), match.end())
            local_context = text[max(0, match.start() - 90): min(len(text), match.end() + 110)]
            # A nearby `password` field or `X-API-Key` property is not enough:
            # it frequently surrounds ordinary URL/header literals.  Generic
            # candidates require a credential-like assignment name, or a
            # literal value directly occupying an auth header value.
            likely_name = bool(variable_name and re.search(
                r"(?:key|token|secret|credential|password|authorization|apikey|bearer)",
                variable_name, re.IGNORECASE
            ))
            direct_header_value = bool(re.search(
                r"(?:authorization|x-api-key|api[-_]?key|apikey|x-auth-token|x-access-token|"
                r"[A-Za-z][A-Za-z0-9_-]*(?:key|token|secret|auth|credential)[A-Za-z0-9_-]*)\s*:\s*['\"`]$",
                local_context[: max(0, local_context.find(match.group(0)))], re.IGNORECASE
            ))
            format_hit = bool(self.redactor.TOKEN_RE.search(raw))
            if not (format_hit or likely_name or direct_header_value):
                continue
            record = self._record_from_raw(
                raw, text=text, source_url=source_url, source_file=source_file,
                source_line=assignment_line or line_at(match.start()),
                variable_name=variable_name, source_map=source_map, context=context,
            )
            if record:
                local.append(self._merge(record))

        # Bare Authorization: Bearer constructed in a template/string can
        # straddle tokenization boundaries.
        for match in re.finditer(r"\bBearer\s+([A-Za-z0-9._~+/=-]{16,})", text, re.IGNORECASE):
            raw = f"Bearer {match.group(1)}"
            record = self._record_from_raw(raw, text=text, source_url=source_url, source_file=source_file,
                                           source_line=line_at(match.start()), source_map=source_map,
                                           context=self._context(text, match.start(), match.end()))
            if record:
                local.append(self._merge(record))

        # Runtime JSON/config objects do not have JavaScript assignments.  A
        # property name is a stronger usage-site signal than a nearby string,
        # so inspect only credential-shaped property names and keep the same
        # format/placeholder/entropy gate.
        for match in self.PROPERTY_CREDENTIAL_RE.finditer(text):
            raw = helper._decode_static(match.group("value"))
            context = self._context(text, match.start(), match.end())
            record = self._record_from_raw(
                raw, text=text, source_url=source_url, source_file=source_file,
                source_line=line_at(match.start()), variable_name=match.group("name"),
                source_map=source_map, context=context,
            )
            if record:
                local.append(self._merge(record))

        self._attach_usages(text, source_file, line_at)
        return list(dict((record.sha256, record) for record in local).values())

    # Alias used by integrations that call all analyzers with scan().
    scan = discover

    def add_observations(self, observations: Iterable[Dict[str, Any]]) -> List[CredentialRecord]:
        """Merge already-redacted observations from another static pass."""
        output: List[CredentialRecord] = []
        for item in observations or []:
            fingerprint = str(item.get("sha256") or item.get("fingerprint") or "")
            if not fingerprint:
                continue
            record = CredentialRecord(
                credential_type=str(item.get("credential_type") or item.get("secret_type") or "UNKNOWN_TOKEN"),
                provider=item.get("provider"), status=str(item.get("status") or "CANDIDATE"),
                masked_value=str(item.get("masked_value") or item.get("display_value") or item.get("value") or ""),
                sha256=fingerprint, prefix=str(item.get("prefix") or ""), length=int(item.get("length") or 0),
                source_url=item.get("source_url"), source_file=str(item.get("source_file") or item.get("source") or "unknown"),
                source_line=item.get("source_line"), context=str(item.get("context") or ""),
                variable_name=item.get("variable_name"), public=bool(item.get("public")),
                confidence=float(item.get("confidence") or 0.0), reason=str(item.get("reason") or ""),
                evidence=[{key: value for key, value in item.items() if key not in {"_raw_value", "value"}}],
            )
            output.append(self._merge(record))
        return output

    def _attach_usages(self, text: str, source_file: str, line_at: Any) -> None:
        for match in self.HEADER_USE_RE.finditer(text or ""):
            header, expression = match.group("header"), match.group("expr").strip().rstrip("}")
            variable = expression.strip("`'\" ").split("${")[-1].rstrip("}")
            for record in self.records.values():
                if record.variable_name and (record.variable_name == expression or record.variable_name in expression or record.variable_name == variable):
                    usage = {"type": "header", "header": header, "reference": variable or self.redactor.redact_text(expression),
                             "source_file": source_file, "source_line": line_at(match.start())}
                    if usage not in record.usage:
                        record.usage.append(usage)
                    record.evidence.append({"usage": {"header": header, "reference": variable or "literal"},
                                            "source_file": source_file, "source_line": line_at(match.start())})

    def link_endpoint(self, endpoint: Any) -> None:
        endpoint_url = getattr(endpoint, "url", None) or (endpoint.get("url") if isinstance(endpoint, dict) else None)
        if not endpoint_url:
            return
        headers = getattr(endpoint, "headers", {}) or (endpoint.get("headers", {}) if isinstance(endpoint, dict) else {})
        auth_source = getattr(endpoint, "auth_source", None) or (endpoint.get("auth_source") if isinstance(endpoint, dict) else None)
        for record in self.records.values():
            refs = [str(item.get("reference", "")) for item in (record.usage or [])]
            if (record.variable_name and (record.variable_name in str(headers) or record.variable_name in str(auth_source))) or any(
                record.masked_value and record.masked_value in str(headers)
                for _ in [0]
            ):
                if endpoint_url not in record.linked_endpoints:
                    record.linked_endpoints.append(endpoint_url)
                record.evidence.append({"linked_endpoint": endpoint_url, "usage_references": refs})

    def validate(self, record_or_fingerprint: CredentialRecord | str, validator: Any, *, authorized: bool,
                 in_scope: bool, reason: str = "") -> Dict[str, Any]:
        """Run an explicit provider/endpoint validator using the raw value in memory only."""
        record = record_or_fingerprint if isinstance(record_or_fingerprint, CredentialRecord) else self.records.get(record_or_fingerprint)
        if record is None:
            return {"verified": False, "status": "UNKNOWN", "reason": "credential record not found"}
        if not authorized or not in_scope:
            return {"verified": False, "status": "NOT_RUN", "reason": "authorized in-scope validation is required"}
        if record._raw_value is None:
            return {"verified": False, "status": "NOT_RUN", "reason": "raw value is unavailable in this process"}
        try:
            outcome = validator(record._raw_value, record)
            if inspect.isawaitable(outcome):
                raise RuntimeError("async validators must be awaited by the integration layer")
        except Exception as exc:
            record.verification = {"verified": False, "status": "ERROR", "reason": str(exc)[:300]}
            return record.verification
        if not isinstance(outcome, dict):
            outcome = {"verified": bool(outcome)}
        verified = bool(outcome.get("verified"))
        record.verification = {
            key: self.redactor.redact_json(value)
            for key, value in outcome.items()
            if key not in {"raw_value", "token", "secret", "credential"}
        }
        record.verification.setdefault("authorized", True)
        record.verification.setdefault("in_scope", True)
        if reason:
            record.verification["operator_reason"] = reason[:300]
        if verified:
            record.status = "VERIFIED"
        return {"verified": verified, **record.verification}

    def purge_raw_values(self) -> int:
        """Release validator-only plaintext values from this scan object."""
        purged = 0
        for record in self.records.values():
            if record._raw_value is not None:
                record._raw_value = None
                purged += 1
        return purged

    close = purge_raw_values

    def report(self) -> List[Dict[str, Any]]:
        return [record.to_dict() for record in self.records.values()]


__all__ = ["CredentialDiscoveryEngine"]
