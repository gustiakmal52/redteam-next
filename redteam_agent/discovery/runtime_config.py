"""Runtime and build-time configuration discovery."""

from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
from typing import Any, Dict, Iterable, List, Optional

from redteam_agent.discovery.models import RuntimeConfigRecord
from redteam_agent.discovery.redaction import SecretRedactor


class RuntimeConfigAnalyzer:
    """Extract config references and values while preserving name/value meaning."""

    CONFIG_NAMES = (
        "config.js", "env.js", "runtime-config.js", "runtime_config.js", "settings.js",
        "environment.js", "app-config.js", "app_config.js", "config.json", "env.json",
        "settings.json", "manifest.json", "runtime.json",
    )
    ENV_NAME_RE = re.compile(
        r"\b(?:NEXT_PUBLIC_[A-Z0-9_]+|VITE_[A-Z0-9_]+|REACT_APP_[A-Z0-9_]+|"
        r"NUXT_PUBLIC_[A-Z0-9_]+|PUBLIC_[A-Z0-9_]+)\b"
        r"|\bprocess\.env\.([A-Za-z_$][\w$]*)\b"
        r"|\bimport\.meta\.env\.([A-Za-z_$][\w$]*)\b"
        r"|\bimport\.meta\.env\b"
        r"|\b(?:window|globalThis)\.(?:__ENV__|__CONFIG__|config)\b",
        re.IGNORECASE,
    )
    ENV_ASSIGN_RE = re.compile(
        r"\b(?P<name>(?:NEXT_PUBLIC_|VITE_|REACT_APP_|NUXT_PUBLIC_|PUBLIC_)[A-Z0-9_]+)\s*=\s*"
        r"(?P<value>['\"])(?P<literal>.*?)(?P=value)", re.IGNORECASE
    )
    INLINE_CONFIG_RE = re.compile(
        r"\b(?:window|globalThis)\.(?:__ENV__|__CONFIG__|config)\s*=\s*\{(?P<body>[^{}]{0,50000})\}",
        re.IGNORECASE | re.DOTALL,
    )
    INLINE_FIELD_RE = re.compile(
        r"(?P<key>['\"]?[A-Za-z_$][\w$.-]*['\"]?)\s*:\s*"
        r"(?P<quote>['\"])(?P<value>(?:\\.|(?!\2).)*?)(?P=quote)", re.DOTALL
    )

    def __init__(self, redactor: Optional[SecretRedactor] = None):
        self.redactor = redactor or SecretRedactor()

    def is_runtime_config_url(self, url: str) -> bool:
        path = urllib.parse.urlsplit(url or "").path.lower().rstrip("/")
        filename = path.rsplit("/", 1)[-1]
        return filename in {name.lower() for name in self.CONFIG_NAMES}

    def find_references(self, text: str, base_url: str, source_file: str = "unknown") -> List[Dict[str, Any]]:
        """Find explicit frontend references to config resources."""
        references: List[Dict[str, Any]] = []
        patterns = (
            r"(?:fetch|import|axios\.get|XMLHttpRequest[^;]{0,120}\.open)\s*\(\s*['\"]([^'\"]+)['\"]",
            r"(?:src|href|url|configUrl|runtimeConfig)\s*[:=]\s*['\"]([^'\"]+)['\"]",
        )
        seen: set[str] = set()
        for pattern in patterns:
            for match in re.finditer(pattern, text or "", re.IGNORECASE):
                candidate = match.group(1)
                resolved = urllib.parse.urljoin(base_url, candidate)
                if not self.is_runtime_config_url(resolved):
                    continue
                if resolved in seen:
                    continue
                seen.add(resolved)
                references.append({
                    "url": resolved,
                    "source_file": source_file,
                    "source_line": (text[:match.start()].count("\n") + 1),
                    "context": self.redactor.redact_text(text[max(0, match.start() - 80): match.end() + 120])[:400],
                })
        return references

    def extract_env_references(self, text: str, *, source_file: str = "unknown",
                                source_url: Optional[str] = None) -> List[Dict[str, Any]]:
        records: List[Dict[str, Any]] = []
        seen: set[tuple[str, int]] = set()
        for match in self.ENV_NAME_RE.finditer(text or ""):
            raw = match.group(0)
            if raw.lower().startswith("process.env."):
                name = raw.split(".", 2)[-1]
                kind = "environment variable NAME"
            elif raw.lower().startswith("import.meta.env."):
                name = raw.split(".", 2)[-1]
                kind = "environment variable NAME"
            elif raw.lower() == "import.meta.env":
                name = raw
                kind = "runtime config object"
            elif raw.lower() in {"window.__env__", "window.__config__", "window.config",
                                 "globalthis.__env__", "globalthis.__config__", "globalthis.config"}:
                name = raw
                kind = "runtime config object"
            else:
                name = raw
                kind = "environment variable NAME"
            line = text[:match.start()].count("\n") + 1
            key = (name, line)
            if key in seen:
                continue
            seen.add(key)
            records.append({
                "name": name, "kind": kind, "source_file": source_file,
                "source_url": source_url, "source_line": line,
                "context": self.redactor.redact_text(text[max(0, match.start() - 100):match.end() + 160])[:500],
            })
        for match in self.ENV_ASSIGN_RE.finditer(text or ""):
            records.append({
                "name": match.group("name"), "kind": "environment variable VALUE",
                "value": self.redactor.safe_config_value(match.group("literal"), name=match.group("name")),
                "source_file": source_file, "source_url": source_url,
                "source_line": text[:match.start()].count("\n") + 1,
                "context": self.redactor.redact_text(text[max(0, match.start() - 80):match.end() + 120])[:500],
            })
        return records

    def extract_inline_config_values(self, text: str, *, source_file: str = "unknown",
                                     source_url: Optional[str] = None) -> List[Dict[str, Any]]:
        """Extract shallow literal fields from browser runtime config objects.

        The parser is deliberately structural and bounded.  It does not
        execute JavaScript or recursively evaluate arbitrary expressions, but
        it keeps public URLs/identifiers available for triage and routes
        credential-shaped values through the normal redactor.
        """
        records: List[Dict[str, Any]] = []
        for object_match in self.INLINE_CONFIG_RE.finditer(text or ""):
            body = object_match.group("body") or ""
            for field_match in self.INLINE_FIELD_RE.finditer(body):
                name = field_match.group("key").strip("'\"")
                value = field_match.group("value")
                line = text[:object_match.start() + field_match.start()].count("\n") + 1
                records.append({
                    "name": name, "kind": "runtime config VALUE",
                    "value": self.redactor.safe_config_value(value, name=name),
                    "source_file": source_file, "source_url": source_url,
                    "source_line": line,
                })
        return records

    @staticmethod
    def _flatten(value: Any, prefix: str = "") -> Iterable[tuple[str, Any]]:
        if isinstance(value, dict):
            for key, item in value.items():
                child = f"{prefix}.{key}" if prefix else str(key)
                yield from RuntimeConfigAnalyzer._flatten(item, child)
        elif isinstance(value, list):
            yield prefix, f"array[{len(value)}]"
        else:
            yield prefix, value

    def parse(self, url: str, body: str, *, content_type: Optional[str] = None,
              source_file: Optional[str] = None, references: Optional[List[Dict[str, Any]]] = None) -> RuntimeConfigRecord:
        body = body or ""
        record = RuntimeConfigRecord(
            url=url, content_type=content_type, source_file=source_file,
            body_hash=hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest(),
            references=list(references or []),
        )
        parsed: Any = None
        if "json" in (content_type or "").lower() or url.lower().endswith(".json"):
            try:
                parsed = json.loads(body)
            except (TypeError, ValueError, json.JSONDecodeError):
                parsed = None
        if isinstance(parsed, dict):
            for key, value in self._flatten(parsed):
                record.keys.append(key)
                if isinstance(value, str):
                    safe = self.redactor.safe_config_value(value, name=key)
                    safe["name"] = key
                    record.values.append(safe)
                else:
                    record.values.append({"name": key, "value_type": type(value).__name__, "value": value})
            record.status = "PARSED_JSON"
        else:
            env_refs = self.extract_env_references(body, source_file=source_file or url, source_url=url)
            inline_refs = self.extract_inline_config_values(body, source_file=source_file or url, source_url=url)
            combined = env_refs + inline_refs
            record.keys = sorted({item["name"] for item in combined if item.get("name")})
            record.values = [item["value"] | {"name": item["name"]}
                             for item in combined if item.get("value")]
            record.status = "PARSED_INLINE_OBJECT" if inline_refs else ("PARSED_TEXT" if env_refs else "UNPARSED")
        return record


__all__ = ["RuntimeConfigAnalyzer"]
