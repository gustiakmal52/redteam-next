"""Portable, redacted, integrity-checkable evidence bundles."""

from __future__ import annotations

import datetime as dt
import hashlib
import io
import json
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Mapping

from redteam_agent.core.report_builder import ReportBuilder
from redteam_agent.discovery.redaction import SecretRedactor


class EvidenceBundleBuilder:
    """Build an evidence archive without exporting auth/session secrets."""

    def __init__(self) -> None:
        self.redactor = SecretRedactor()
        self.report_builder = ReportBuilder()

    @staticmethod
    def _digest(value: bytes) -> str:
        return hashlib.sha256(value).hexdigest()

    def files(self, results: Mapping[str, Any]) -> dict[str, bytes]:
        sanitized = self.redactor.redact_json(dict(results))
        result_bytes = (
            json.dumps(sanitized, indent=2, sort_keys=True, ensure_ascii=False, default=str)
            + "\n"
        ).encode("utf-8")
        report = self.report_builder.generate_full_audit_report(sanitized)
        report_bytes = self.redactor.redact_text(report).encode("utf-8")
        generated_at = dt.datetime.now(dt.timezone.utc).isoformat()
        entries = {
            "results.json": {
                "sha256": self._digest(result_bytes), "bytes": len(result_bytes),
                "purpose": "redacted machine-readable scan result",
            },
            "report.md": {
                "sha256": self._digest(report_bytes), "bytes": len(report_bytes),
                "purpose": "human-readable evidence-first report",
            },
        }
        manifest = {
            "format": "gustiakmal-redteam-evidence-bundle/v1",
            "generated_at": generated_at,
            "target": sanitized.get("target"),
            "scan_status": sanitized.get("status"),
            "engagement": sanitized.get("engagement", {}),
            "hunt_focus": sanitized.get("hunt_focus", {}),
            "scope": sanitized.get("scope", {}),
            "files": entries,
            "integrity_note": "Verify each listed SHA-256 before relying on an extracted artifact.",
            "secret_handling": "Authentication material is process-memory-only and is excluded from this archive.",
        }
        manifest_bytes = (
            json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False, default=str)
            + "\n"
        ).encode("utf-8")
        return {
            "manifest.json": manifest_bytes,
            "results.json": result_bytes,
            "report.md": report_bytes,
        }

    def build_zip(self, results: Mapping[str, Any]) -> bytes:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, content in self.files(results).items():
                archive.writestr(name, content)
        return buffer.getvalue()

    def write_directory(self, results: Mapping[str, Any], output_dir: str | Path) -> Path:
        destination = Path(output_dir).expanduser().resolve()
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists() or destination.is_symlink():
            raise FileExistsError(f"evidence bundle directory already exists: {destination}")
        staging = Path(tempfile.mkdtemp(prefix=".evidence-", dir=destination.parent))
        try:
            for name, content in self.files(results).items():
                (staging / name).write_bytes(content)
            staging.rename(destination)
        finally:
            shutil.rmtree(staging, ignore_errors=True)
        return destination
