"""Modern Behavioral Engine tests — boolean oracle SQLi, SSTI arithmetic,
median command timing, cache poisoning, security headers, DOM XSS.

Discipline: SSTI arithmetic with two semantically-different results is the
only VERIFIED class here; everything else stays LIKELY with missing_evidence.
"""
import json
import time
import urllib.parse

from redteam_agent.core.http_verifier import HTTPVerifier
from redteam_agent.core.modern_engine import ModernEngine
from redteam_agent.core.scope_manager import ScopeManager


def _verifier():
    return HTTPVerifier(scope_manager=ScopeManager(["example.com"], resolve_dns=False))


def _resp(status=200, body="", headers=None, elapsed=0.02):
    return {
        "success": 200 <= status < 400, "status_code": status,
        "headers": headers or {}, "body": body,
        "response_time_sec": elapsed, "raw_request": "", "raw_response": "",
        "redirects": [],
    }


# ---------------------------------------------------------------------------
# 1. SQLi boolean oracle
# ---------------------------------------------------------------------------
def test_sqli_boolean_oracle_detected():
    verifier = _verifier()

    def fake(url, *a, **k):
        decoded = urllib.parse.unquote(url)
        if "1=2" in decoded or "1'='2" in decoded or '1"="2' in decoded:
            return _resp(200, json.dumps({"count": 0}))
        return _resp(200, json.dumps({"count": 42}))

    verifier.send_http_request = fake
    engine = ModernEngine(verifier)
    finding = engine.sqli_boolean_differential("https://example.com/api/search?id=1", "id")
    assert finding is not None
    assert "Boolean Oracle" in finding["type"]
    assert finding["status"] == "LIKELY"
    assert finding["evidence"][0]["oracle_pairs"]


def test_sqli_boolean_oracle_absent_returns_none():
    verifier = _verifier()
    verifier.send_http_request = lambda *a, **k: _resp(200, json.dumps({"count": 42}))
    engine = ModernEngine(verifier)
    assert engine.sqli_boolean_differential("https://example.com/api/search?id=1", "id") is None


def test_sqli_boolean_no_param_returns_none():
    engine = ModernEngine(_verifier())
    assert engine.sqli_boolean_differential("https://example.com/api/search", "id") is None


def test_sqli_boolean_no_fp_on_search_literal():
    """Search endpoint yang hasilnya bergantung pada literal query (bukan SQL)
    TIDAK boleh dianggap oracle: payload true mengubah hasil vs baseline."""
    verifier = _verifier()

    def fake(url, *a, **k):
        decoded = urllib.parse.unquote(url)
        # hasil pencarian = literal query itu sendiri (search teks biasa)
        q = decoded.split("q=", 1)[1] if "q=" in decoded else ""
        return _resp(200, json.dumps({"results": [q]}))

    verifier.send_http_request = fake
    engine = ModernEngine(verifier)
    finding = engine.sqli_boolean_differential("https://example.com/api/search?q=lab", "q")
    assert finding is None, "search literal yang mengubah hasil = BUKAN oracle SQL"


def test_sqli_boolean_no_fp_on_query_reflection():
    """Aplikasi yang merefleksikan query string ke body (bukan SQLi) tidak
    boleh dianggap oracle: true-payload mengubah body vs baseline."""
    verifier = _verifier()

    def fake(url, *a, **k):
        decoded = urllib.parse.unquote(url)
        q = decoded.split("q=", 1)[1] if "q=" in decoded else ""
        return _resp(200, f"<p>Searching for: {q}</p>")

    verifier.send_http_request = fake
    engine = ModernEngine(verifier)
    finding = engine.sqli_boolean_differential("https://example.com/api/search?q=lab", "q")
    assert finding is None, "refleksi query string = BUKAN oracle SQL"


# ---------------------------------------------------------------------------
# 2. SSTI arithmetic
# ---------------------------------------------------------------------------
def test_ssti_arithmetic_verified():
    verifier = _verifier()

    def fake(url, *a, **k):
        decoded = urllib.parse.unquote(url)
        if "7*8" in decoded:
            return _resp(200, "<html>result: 56</html>")
        if "7*7" in decoded:
            return _resp(200, "<html>result: 49</html>")
        return _resp(200, "<html>ok</html>")

    verifier.send_http_request = fake
    engine = ModernEngine(verifier)
    finding = engine.ssti_arithmetic_multi_engine("https://example.com/page?q=x", "q")
    assert finding is not None
    assert finding["status"] == "VERIFIED"
    assert "SSTI" in finding["type"]
    assert finding["evidence"][0]["result_49_present"] is True


def test_ssti_arithmetic_not_evaluated_returns_none():
    verifier = _verifier()
    verifier.send_http_request = lambda *a, **k: _resp(200, "<html>ok</html>")
    engine = ModernEngine(verifier)
    assert engine.ssti_arithmetic_multi_engine("https://example.com/page?q=x", "q") is None


# ---------------------------------------------------------------------------
# 3. Command injection — median timing
# ---------------------------------------------------------------------------
def test_cmd_time_based_median_detected():
    verifier = _verifier()

    def fake(url, *a, **k):
        decoded = urllib.parse.unquote(url)
        if "sleep 5" in decoded:
            return _resp(200, "ok", elapsed=5.2)
        if "sleep 1" in decoded:
            return _resp(200, "ok", elapsed=1.2)
        return _resp(200, "ok", elapsed=0.1)

    verifier.send_http_request = fake
    engine = ModernEngine(verifier)
    finding = engine.cmd_time_based_median("https://example.com/api/ping?host=1", "host", samples=2)
    assert finding is not None
    assert "Command Injection" in finding["type"]
    assert finding["status"] == "LIKELY"
    assert finding["evidence"][0]["median_sleep5_s"] >= 2.0


def test_cmd_time_based_no_shift_returns_none():
    verifier = _verifier()
    verifier.send_http_request = lambda *a, **k: _resp(200, "ok", elapsed=0.1)
    engine = ModernEngine(verifier)
    assert engine.cmd_time_based_median("https://example.com/api/ping?host=1", "host", samples=2) is None


# ---------------------------------------------------------------------------
# 4. Cache poisoning
# ---------------------------------------------------------------------------
def test_cache_poisoning_detected():
    verifier = _verifier()

    def fake(url, *a, headers=None, **k):
        if headers and "attacker.example" in str(headers):
            return _resp(200, "<html>host: attacker.example</html>",
                         {"Age": "12", "X-Cache": "HIT"})
        return _resp(200, "<html>host: example.com</html>", {"Age": "12"})

    verifier.send_http_request = fake
    engine = ModernEngine(verifier)
    finding = engine.cache_poisoning("https://example.com/")
    assert finding is not None
    assert "Cache Poisoning" in finding["type"]
    assert finding["evidence"][0]["reflected"] is True


def test_cache_poisoning_no_reflection_returns_none():
    verifier = _verifier()
    verifier.send_http_request = lambda *a, **k: _resp(200, "<html>ok</html>", {"Age": "12"})
    engine = ModernEngine(verifier)
    assert engine.cache_poisoning("https://example.com/") is None


# ---------------------------------------------------------------------------
# 5. Security headers
# ---------------------------------------------------------------------------
def test_security_headers_missing_detected():
    verifier = _verifier()
    verifier.send_http_request = lambda *a, **k: _resp(200, "<html>ok</html>", {"Server": "nginx"})
    engine = ModernEngine(verifier)
    finding = engine.security_headers_audit("https://example.com/")
    assert finding is not None
    assert "Security Headers" in finding["type"]
    assert len(finding["evidence"][0]["missing_headers"]) >= 5


def test_security_headers_complete_returns_none():
    verifier = _verifier()
    verifier.send_http_request = lambda *a, **k: _resp(200, "<html>ok</html>", {
        "Content-Security-Policy": "default-src 'none'",
        "Strict-Transport-Security": "max-age=31536000",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-origin",
        "Referrer-Policy": "no-referrer",
    })
    engine = ModernEngine(verifier)
    assert engine.security_headers_audit("https://example.com/") is None


# ---------------------------------------------------------------------------
# 6. DOM XSS
# ---------------------------------------------------------------------------
def test_dom_xss_sink_source_detected():
    engine = ModernEngine(_verifier())
    assets = [{
        "url": "https://example.com/app.js",
        "content": "const q = location.hash; document.getElementById('x').innerHTML = q;",
    }]
    findings = engine.dom_xss_analysis(assets)
    assert len(findings) == 1
    assert "DOM XSS" in findings[0]["finding_type"]
    assert findings[0]["status"] == "SUSPECTED"
    assert findings[0]["missing_evidence"]


def test_dom_xss_sink_only_returns_empty():
    engine = ModernEngine(_verifier())
    assets = [{"url": "https://example.com/app.js",
               "content": "document.getElementById('x').innerHTML = 'static';"}]
    assert engine.dom_xss_analysis(assets) == []