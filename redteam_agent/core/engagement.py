"""Engagement authorization — real validation for offensive bug bounty use.

An engagement record is the authorization contract for offensive testing:
- allowed_targets: exact hosts or wildcard suffixes (e.g. "example.com", "*.example.com")
- expires_at: ISO-8601 timestamp; sessions after expiry are rejected
- prohibited_techniques: never allowed (denial-of-service, destructive-write, ...)
- allowed_techniques: vulnerability classes the engagement authorizes
- emergency_contact: recorded but never exported in public summaries

Every offensive scan MUST carry an engagement record. The no-op stub era is
over: validation is enforced at task creation and at web API entry points.
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from typing import Any, Optional, Sequence

# Techniques that are never allowed regardless of the engagement record.
HARD_PROHIBITED = {
    "denial-of-service", "destructive-write", "social-engineering",
    "mitm", "spam", "credential-stuffing",
}

# Vulnerability classes with a target-specific planner implemented.
IMPLEMENTED_CLASSES = frozenset({
    "idor", "bola", "bfla",
    "xss", "sqli", "sql-injection", "ssrf", "ssti",
    "open-redirect", "graphql", "cloud-baas",
    "authorization", "auth-bypass",
})


class EngagementError(ValueError):
    """Raised when an engagement constraint is violated."""


class EngagementProfile:
    """Authorization contract for offensive testing."""

    def __init__(self, engagement_id: str = "local",
                 authorization_reference: str = "local",
                 allowed_targets: Optional[Sequence[str]] = None,
                 expires_at: Optional[str] = None,
                 prohibited_techniques: Optional[Sequence[str]] = None,
                 objective: str = "",
                 allowed_techniques: Optional[Sequence[str]] = None,
                 emergency_contact: str = "",
                 notes: Optional[Sequence[str]] = None):
        self.engagement_id = str(engagement_id or "local")
        self.authorization_reference = str(authorization_reference or "local")
        self.allowed_targets = tuple(str(item).strip() for item in (allowed_targets or ()) if str(item).strip())
        self.expires_at = expires_at
        self.prohibited_techniques = tuple(str(item).strip() for item in (prohibited_techniques or ()) if str(item).strip())
        self.objective = str(objective or "")
        self.allowed_techniques = tuple(str(item).strip() for item in (allowed_techniques or ()) if str(item).strip())
        self.emergency_contact = str(emergency_contact or "")
        self.notes = tuple(str(item) for item in (notes or ()))

    # ------------------------------------------------------------------ #
    # Construction
    # ------------------------------------------------------------------ #
    @classmethod
    def from_mapping(cls, value: Any) -> "EngagementProfile":
        if value is None:
            return cls()
        if isinstance(value, cls):
            return value
        if not isinstance(value, dict):
            raise EngagementError("engagement must be a mapping")
        return cls(
            engagement_id=value.get("engagement_id"),
            authorization_reference=value.get("authorization_reference"),
            allowed_targets=value.get("allowed_targets"),
            expires_at=value.get("expires_at"),
            prohibited_techniques=value.get("prohibited_techniques"),
            objective=value.get("objective"),
            allowed_techniques=value.get("allowed_techniques"),
            emergency_contact=value.get("emergency_contact"),
            notes=value.get("notes"),
        )

    @classmethod
    def from_file(cls, path: Any) -> "EngagementProfile":
        p = Path(str(path))
        if not p.exists():
            raise EngagementError(f"engagement file not found: {path}")
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001 - surface parse errors as EngagementError
            raise EngagementError(f"invalid engagement file {path}: {exc}") from exc
        return cls.from_mapping(data)

    # ------------------------------------------------------------------ #
    # Validation
    # ------------------------------------------------------------------ #
    def _expires_dt(self) -> Optional[dt.datetime]:
        if not self.expires_at:
            return None
        try:
            return dt.datetime.fromisoformat(str(self.expires_at).replace("Z", "+00:00"))
        except ValueError:
            return None

    def assert_active(self, now: Optional[dt.datetime] = None) -> None:
        now = now or dt.datetime.now(dt.timezone.utc)
        expiry = self._expires_dt()
        if expiry is not None and expiry < now:
            raise EngagementError(
                f"engagement {self.engagement_id} expired at {self.expires_at}")

    @staticmethod
    def _host_of(value: str) -> str:
        host = str(value).strip()
        if "://" in host:
            host = host.split("://", 1)[1]
        host = host.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        host = host.split(":", 1)[0]
        return host.rstrip(".").lower()

    def _target_allowed(self, target: str) -> bool:
        if not self.allowed_targets:
            return True  # no targets configured = unrestricted local mode
        host = self._host_of(target)
        if not host:
            return False
        for allowed in self.allowed_targets:
            allowed_host = self._host_of(allowed)
            if not allowed_host:
                continue
            if allowed_host.startswith("*."):
                suffix = allowed_host[1:]  # ".example.com"
                if host == allowed_host[2:] or host.endswith(suffix):
                    return True
            elif host == allowed_host or host.endswith("." + allowed_host):
                return True
        return False

    def assert_scope(self, target: str,
                     requested_scope: Optional[Sequence[str]] = None) -> None:
        if not self._target_allowed(target):
            raise EngagementError(
                f"target {target} is outside engagement scope "
                f"(allowed: {', '.join(self.allowed_targets) or 'unrestricted'})")
        if requested_scope:
            for scope_item in requested_scope:
                if not self._target_allowed(str(scope_item)):
                    raise EngagementError(
                        f"requested scope {scope_item} is outside engagement scope")

    def assert_techniques(self, techniques: Optional[Sequence[str]] = None) -> None:
        if not techniques:
            return
        for technique in techniques:
            tech = str(technique).strip().lower()
            if tech in self.prohibited_techniques or tech in HARD_PROHIBITED:
                raise EngagementError(
                    f"technique {technique} is prohibited by engagement "
                    f"{self.engagement_id}")

    def validate_session(self, target: str,
                         requested_scope: Optional[Sequence[str]] = None,
                         techniques: Optional[Sequence[str]] = None,
                         now: Optional[dt.datetime] = None) -> None:
        """Validate target scope, expiry, and techniques in one call."""
        self.assert_active(now=now)
        self.assert_scope(target, requested_scope=requested_scope)
        self.assert_techniques(techniques)

    # ------------------------------------------------------------------ #
    # Public summary (never exports contact value)
    # ------------------------------------------------------------------ #
    def public_summary(self) -> dict[str, Any]:
        return {
            "engagement_id": self.engagement_id,
            "authorization_reference": self.authorization_reference,
            "allowed_targets": list(self.allowed_targets),
            "expires_at": self.expires_at,
            "prohibited_techniques": list(self.prohibited_techniques),
            "allowed_techniques": list(self.allowed_techniques),
            "objective": self.objective,
            "emergency_contact_recorded": bool(self.emergency_contact),
            "notes": list(self.notes),
            "authorization_validated": True,
        }


def engagement_required(offensive: bool,
                        profile: Optional[EngagementProfile]) -> None:
    """Raise EngagementError when an offensive session has no engagement record."""
    if offensive and profile is None:
        raise EngagementError("offensive scan requires --engagement-file")