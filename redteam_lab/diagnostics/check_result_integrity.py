"""Offline diagnostics: exercise reporting with synthetic data, never scan."""
import contextlib
import io
import json
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from redteam_lab import observe_test as observer
from redteam_agent.core.fp_killer import kill_pass


def run_observer(scan):
    class FakeLab:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            pass

        def stop(self):
            pass

        def observed_requests(self):
            return [{"method": "GET", "path": "/", "query": "", "status": 200}]

    def control_response(url):
        return {"status": 200 if url == "http://127.0.0.1:12345/" else 404,
                "headers": {"content-type": "text/html", "content-security-policy": "default-src 'none'",
                            "x-frame-options": "DENY", "x-content-type-options": "nosniff"}, "body": ""}

    with tempfile.TemporaryDirectory() as directory:
        argv = ["observe_test", "--port", "12345", "--outdir", directory]
        output = io.StringIO()
        with patch.object(sys, "argv", argv), patch.object(observer, "Lab", FakeLab), \
             patch.object(observer, "http_get", control_response), \
             patch.object(observer.subprocess, "run", return_value=SimpleNamespace(
                 returncode=0, stdout=json.dumps(scan), stderr="")), contextlib.redirect_stdout(output):
            code = observer.main()
        text = output.getvalue()
        return {"exit_code": code, "verdict": next((line.strip() for line in text.splitlines() if "VERDICT:" in line), "missing"),
                "unbacked_claim_warning": "CLAIMED BUT NEVER REQUESTED" in text,
                "summary_written": bool(list(Path(directory).rglob("summary.txt")))}


def main():
    base = "http://127.0.0.1:12345"
    results = {
        "empty_findings_unobserved_claim": run_observer({"findings": [], "vulnerabilities": [], "request": {"method": "GET", "url": base + "/never-requested"}}),
        "verified_with_empty_findings": run_observer({"findings": [], "vulnerabilities": [{"status": "VERIFIED", "endpoint": base + "/"}]}),
        "investigate_exit_status": run_observer({"findings": [{"status": "VERIFIED", "endpoint": base + "/"}], "vulnerabilities": [{"status": "VERIFIED", "endpoint": base + "/"}]}),
        "method_query_mismatch": run_observer({"findings": [{"status": "SUSPECTED", "method": "POST", "endpoint": base + "/?unobserved=value"}], "vulnerabilities": []}),
    }
    for name, overrides in {
        "nan_confidence": {"confidence": float("nan")},
        "whitespace_review": {"status": "REJECTED", "human_review": {"action": "MARK_VERIFIED", "reason": "   "}},
        "malformed_confidence": {"confidence": "invalid"},
    }.items():
        finding = {"status": "VERIFIED", "type": "Synthetic review record", "confidence": .9,
                   "vrt_triage": {"is_approved": True}, **overrides}
        try:
            result = kill_pass([finding])
            results[name] = {"submission_ready": len(result["submission_ready"]), "quarantined": len(result["quarantined"])}
        except Exception as exc:
            results[name] = {"error_type": type(exc).__name__, "message": str(exc)}
    destination = ROOT / "redteam_lab" / "diagnostics" / "result_integrity.json"
    destination.write_text(json.dumps(results, indent=2, ensure_ascii=False) + "\n")
    print(destination)
    print(json.dumps(results, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
