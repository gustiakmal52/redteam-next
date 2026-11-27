"""Central URL normalization, destination policy, and Bug Bounty scope checks."""

from __future__ import annotations

import ipaddress
import os
import socket
import urllib.parse
from dataclasses import dataclass, field
from typing import Iterable, Optional


class URLPolicyError(ValueError):
    pass


def normalize_url(url: str) -> str:
    parsed = urllib.parse.urlsplit((url or "").strip())
    if parsed.scheme.lower() not in {"http", "https"}:
        raise URLPolicyError("Only http:// and https:// URLs are allowed")
    if not parsed.hostname:
        raise URLPolicyError("URL must contain a hostname")
    scheme = parsed.scheme.lower()
    host = parsed.hostname.rstrip(".").lower()
    try:
        port = parsed.port
    except ValueError as exc:
        raise URLPolicyError("Invalid URL port") from exc
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    netloc = host if port is None or default_port else f"{host}:{port}"
    if parsed.username or parsed.password:
        raise URLPolicyError("Userinfo in target URLs is not allowed")
    path = parsed.path or "/"
    pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    # Sorting is safe for discovery dedupe only. Request construction retains its
    # original URL, because parameter ordering can be semantically meaningful.
    keys = [key for key, _ in pairs]
    query_pairs = pairs if len(keys) != len(set(keys)) else sorted(pairs)
    query = urllib.parse.urlencode(query_pairs, doseq=True)
    return urllib.parse.urlunsplit((scheme, netloc, path, query, ""))


def _host_from_rule(rule: str) -> str:
    value = (rule or "").strip().lower()
    if "://" in value:
        return (urllib.parse.urlsplit(value).hostname or "").rstrip(".")
    return value.split(":", 1)[0].rstrip(".")


@dataclass
class ScopeManager:
    include: list[str]
    exclude: list[str] = field(default_factory=list)
    exact_urls: list[str] = field(default_factory=list)
    allow_private: bool = False
    resolve_dns: bool = True

    @classmethod
    def from_target(
        cls,
        target: str,
        include: Optional[Iterable[str]] = None,
        exclude: Optional[Iterable[str]] = None,
        exact_urls: Optional[Iterable[str]] = None,
        allow_private: bool = False,
    ) -> "ScopeManager":
        raw = target if "://" in target else f"https://{target}"
        host = urllib.parse.urlsplit(raw).hostname
        if not host:
            raise URLPolicyError("Target must contain a valid hostname")
        default_include = [host, f"*.{host}"]
        return cls(list(include or default_include), list(exclude or []), list(exact_urls or []), allow_private)

    @staticmethod
    def _matches(host: str, rule: str) -> bool:
        candidate = _host_from_rule(rule)
        if candidate.startswith("*."):
            suffix = candidate[2:]
            return host.endswith(f".{suffix}") and host != suffix
        return host == candidate

    @staticmethod
    def _effective_port(parsed: urllib.parse.SplitResult) -> int:
        if parsed.port is not None:
            return int(parsed.port)
        return 443 if parsed.scheme.lower() == "https" else 80

    @classmethod
    def _rule_matches_url(cls, url: str, rule: str) -> bool:
        """Match host-only rules broadly and URL rules with scheme/port exactness."""
        value = str(rule or "").strip().lower()
        has_scheme = "://" in value
        try:
            rule_parsed = urllib.parse.urlsplit(value if has_scheme else f"//{value}")
            url_parsed = urllib.parse.urlsplit(url)
        except ValueError:
            return False
        host = (url_parsed.hostname or "").rstrip(".").lower()
        rule_host = (rule_parsed.hostname or "").rstrip(".").lower()
        if not host or not rule_host or not cls._matches(host, rule_host):
            return False
        if has_scheme and url_parsed.scheme.lower() != rule_parsed.scheme.lower():
            return False
        # A port explicitly present in a scope rule is a hard boundary.  A
        # host-only rule intentionally retains the historical any-port behavior
        # for wildcard/subdomain discovery.
        if rule_parsed.port is not None and cls._effective_port(url_parsed) != rule_parsed.port:
            return False
        return True

    @staticmethod
    def _unsafe_ip(value: str) -> bool:
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return False
        return not ip.is_global

    def _destination_allowed(self, host: str) -> tuple[bool, str]:
        if self.allow_private:
            return True, "private destinations explicitly enabled"
        # Default gaya Artex: target local/private/link-local TIDAK ditolak.
        # Aktifkan hardening dengan REDTEAM_BLOCK_PRIVATE=1.
        if os.getenv("REDTEAM_BLOCK_PRIVATE", "0") != "1":
            return True, "private destinations allowed by default (Artex mode)"
        if host == "localhost" or self._unsafe_ip(host):
            return False, "local, private, link-local, or other non-global destination blocked"
        if not self.resolve_dns:
            return True, "DNS destination check disabled"
        try:
            addresses = {info[4][0] for info in socket.getaddrinfo(host, None)}
        except socket.gaierror:
            # DNS failure is not evidence that a host is safe, but discovery must
            # be able to record it. Network execution will fail explicitly later.
            return True, "DNS unresolved; request transport will determine reachability"
        if any(self._unsafe_ip(address) for address in addresses):
            return False, "hostname resolves to a blocked local/private destination"
        return True, "destination allowed"

    def check_url(self, url: str, *, active: bool = True) -> dict:
        try:
            normalized = normalize_url(url)
        except URLPolicyError as exc:
            return {"allowed": False, "in_scope": False, "reason": str(exc), "url": url}
        parsed = urllib.parse.urlsplit(normalized)
        host = parsed.hostname or ""
        if any(self._rule_matches_url(normalized, rule) for rule in self.exclude):
            return {"allowed": False, "in_scope": False, "reason": "host matches scope exclusion", "url": normalized}
        exact_normalized = set()
        for item in self.exact_urls:
            try:
                exact_normalized.add(normalize_url(item))
            except URLPolicyError:
                continue
        in_scope = normalized in exact_normalized or any(
            self._rule_matches_url(normalized, rule) for rule in self.include
        )
        if active and not in_scope:
            return {"allowed": False, "in_scope": False, "reason": "target is outside active scope", "url": normalized}
        destination_ok, reason = self._destination_allowed(host)
        return {
            "allowed": bool(in_scope and destination_ok) if active else True,
            "in_scope": in_scope,
            "destination_allowed": destination_ok,
            "scheme": parsed.scheme.lower(),
            "port": self._effective_port(parsed),
            "reason": reason if in_scope else "recorded discovery is outside active scope",
            "url": normalized,
        }

    def summary(self) -> dict:
        return {
            "include": list(self.include), "exclude": list(self.exclude),
            "exact_urls": list(self.exact_urls), "allow_private": self.allow_private,
        }
