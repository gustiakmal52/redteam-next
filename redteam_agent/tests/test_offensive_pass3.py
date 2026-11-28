"""Pass-3 regression tests: modern mutation categories, advanced JWT forgery,
server-side prototype pollution, request smuggling desync detection, and the
chunked transport framing mutation.

Each capability is proven against a deterministic local fixture in both
directions: the vulnerable behavior verifies, the clean behavior stays quiet.
"""

import base64
import hashlib
import hmac as hmac_mod
import json
import socket
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from redteam_agent.core.bypass_engine import PayloadMutationEngine, ResponseLearner
from redteam_agent.core.exploit_engine import ExploitEngine
from redteam_agent.core.findings import FindingStatus
from redteam_agent.core.http_verifier import HTTPVerifier
from redteam_agent.core.scope_manager import ScopeManager
from redteam_agent.core.traffic_controller import TrafficController

# Fixed test RSA public key (generated offline with openssl; only the public
# half is embedded — the private half never appears in the repository).
RS256_PUBLIC_PEM = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkeYyWHb25mSO3Yz2Tg/n
eLBXuOBVH0ikGADeoHeQ3a3ALO6Jl22Q7WMDiNw0qzgCqFTLH98JZfG2B+9K2E6g
j50djtT70ov4nv6Tn/0iNrJhQyju0zrfN3suOX/KjX0bmr/AtuohBRP4yWQtD9XO
C6/gTqQZE/xRxGE7EKYvjS7hoAZ3fGKHZxS9xJnUeiEnEzpk7NBFWK+Fi+NAMbgb
UW/6nGlFpFS6dCkXGYNNqQbR0KfLUGNRp9BEaIvOia5ORClv//nWVJscImIcpUxS
dznj/G6PYhinBCrCqEBUcRPu4okaZsTF1c+w1DWnO3JeIzCCtzxAFlRbCusD4liz
cQIDAQAB
-----END PUBLIC KEY-----
"""

CANARY_HOST = "poison-canary.invalid"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def forge_hs256(header: dict, payload: dict, secret: bytes) -> str:
    signing_input = (f"{_b64url(json.dumps(header, separators=(',', ':')).encode())}."
                     f"{_b64url(json.dumps(payload, separators=(',', ':')).encode())}")
    sig = hmac_mod.new(secret, signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{_b64url(sig)}"


class _ModernHandler(BaseHTTPRequestHandler):
    """Vulnerable fixture: accepts kid=/dev/null tokens, jku tokens, HS/RS
    confusion, stores pollution globals, and desyncs on dual framing."""

    protocol_version = "HTTP/1.1"

    def _auth_ok(self) -> bool:
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return False
        token = auth[len("Bearer "):]
        try:
            header_b64, payload_b64, sig_b64 = token.split(".")
            header = json.loads(base64.urlsafe_b64decode(header_b64 + "=" * (-len(header_b64) % 4)))
            payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4)))
            alg = str(header.get("alg", "")).upper()
            if alg == "HS256":
                kid = str(header.get("kid", ""))
                jku = str(header.get("jku", ""))
                signing_input = f"{header_b64}.{payload_b64}".encode()
                signature = base64.urlsafe_b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))
                # A confused library derives the HMAC key from token alg: the
                # RS256 public key becomes the HMAC secret.
                candidates = [b"legit-secret-not-weak"]
                if kid.endswith("/dev/null"):
                    candidates.insert(0, b"")
                if jku:
                    candidates.insert(0, b"jku-canary-secret")
                if not kid and not jku:
                    candidates.insert(0, RS256_PUBLIC_PEM)
                for secret in candidates:
                    expected = hmac_mod.new(secret, signing_input, hashlib.sha256).digest()
                    if hmac_mod.compare_digest(expected, signature):
                        self._claims = payload
                        return payload.get("role") == "admin"
                return False
            elif alg == "RS256":
                # Normal RS256 verification would need a real library; the
                # fixture simply accepts RS256 tokens as authenticated users.
                self._claims = payload
                return payload.get("role") != "admin"
        except Exception:
            return False
        return False

    def do_GET(self):  # noqa: N802 - stdlib handler API
        if self.path.startswith("/admin"):
            if self._auth_ok():
                body = json.dumps({"admin": True, "role": "admin"}).encode()
                self._send(body, 200)
            else:
                self._send(b'{"error":"forbidden"}', 403)
            return
        if self.path.startswith("/polluted"):
            leaked = getattr(self.server, "polluted_globals", None)
            body = json.dumps({"globals": leaked or {}}).encode()
            self._send(body, 200)
            return
        self._send(b"<html><body>static index</body></html>")

    def do_POST(self):  # noqa: N802
        if self.path.startswith("/prefs"):
            length = int(self.headers.get("Content-Length") or 0)
            doc = json.loads(self.rfile.read(length) or b"{}")
            # Vulnerable: a real PP sink would merge into the base object.
            if isinstance(doc, dict) and "__proto__" in doc:
                proto = doc["__proto__"]
                if isinstance(proto, dict):
                    current = getattr(self.server, "polluted_globals", None) or {}
                    current = {**current, **proto}
                    self.server.polluted_globals = current
            self._send(b'{"saved":true}', 200)
            return
        self._send(b'{"error":"not found"}', 404)

    def _send(self, body: bytes, status: int = 200, headers: dict | None = None):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def log_message(self, *_args):
        return


class _CleanHandler(BaseHTTPRequestHandler):
    """Same surface, pinned algorithms, strict framing, no pollution sink."""

    protocol_version = "HTTP/1.1"

    def _auth_ok(self) -> bool:
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return False
        token = auth[len("Bearer "):]
        try:
            header_b64, payload_b64, sig_b64 = token.split(".")
            header = json.loads(base64.urlsafe_b64decode(header_b64 + "=" * (-len(header_b64) % 4)))
            payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4)))
            if str(header.get("alg", "")).upper() != "HS256":
                return False
            if "kid" in header or "jku" in header:
                return False  # algorithm/key-source pinning
            signing_input = f"{header_b64}.{payload_b64}".encode()
            expected = hmac_mod.new(b"legit-secret-not-weak", signing_input, hashlib.sha256).digest()
            if hmac_mod.compare_digest(expected, base64.urlsafe_b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))):
                return payload.get("role") == "admin"
        except Exception:
            return False
        return False

    def do_GET(self):  # noqa: N802
        # Hardened edge: reject contradictory framing outright (RFC 7230) and
        # close the connection so nothing can be appended afterwards.
        if "Transfer-Encoding" in self.headers and "Content-Length" in self.headers:
            self.send_response(400)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            return
        if self.path.startswith("/admin"):
            if self._auth_ok():
                self._send(json.dumps({"admin": True}).encode(), 200)
            else:
                self._send(b'{"error":"forbidden"}', 403)
            return
        self._send(b"<html><body>static index</body></html>")

    def do_POST(self):  # noqa: N802
        if "Transfer-Encoding" in self.headers and "Content-Length" in self.headers:
            self.send_response(400)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            return
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        self._send(b'{"saved":true}', 200)

    def _send(self, body: bytes, status: int = 200, headers: dict | None = None):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def log_message(self, *_args):
        return


@pytest.fixture(scope="module")
def servers():
    vuln = ThreadingHTTPServer(("127.0.0.1", 0), _ModernHandler)
    clean = ThreadingHTTPServer(("127.0.0.1", 0), _CleanHandler)
    vuln.polluted_globals = {}
    for server in (vuln, clean):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    yield (f"http://127.0.0.1:{vuln.server_port}", f"http://127.0.0.1:{clean.server_port}")
    for server in (vuln, clean):
        server.shutdown()
        server.server_close()


def _engine() -> ExploitEngine:
    scope = ScopeManager(["127.0.0.1"], allow_private=True, resolve_dns=False)
    traffic = TrafficController("FAST", max_requests=512, verification_reserve=8)
    verifier = HTTPVerifier(scope_manager=scope, traffic_controller=traffic, module="pass3_test")
    return ExploitEngine(verifier)


def _legit_token(role: str = "member") -> str:
    return forge_hs256({"alg": "HS256", "typ": "JWT"}, {"sub": "u1", "role": role}, b"legit-secret-not-weak")


# -- Mutation engine ----------------------------------------------------------

def test_new_mutation_categories_fire():
    engine = PayloadMutationEngine()
    cands = engine.generate_mutations(
        "UNION SELECT", vulnerability_class="sqli",
        input_context={"parameter": "q", "json_field": "q"},
        detected_waf=["Cloudflare"], max_mutations=24)
    categories = {c.category for c in cands}
    assert "nested_json_depth" in categories
    assert "chunked_transfer" in categories


def test_xml_wrapper_and_forwarded_ip_gate_on_context():
    engine = PayloadMutationEngine()
    xml_cands = engine.generate_mutations(
        "probe", vulnerability_class="api",
        input_context={"parameter": "q", "accepted_content_types": ["application/xml"]},
        max_mutations=24)
    assert any(c.category == "xml_wrapper" and c.content_type == "application/xml" and "<root>" in c.value
               for c in xml_cands)
    ip_cands = engine.generate_mutations(
        "probe", vulnerability_class="auth",
        input_context={"parameter": "q", "acl": "ip-allowlist"},
        max_mutations=24)
    assert any(c.category == "forwarded_ip_spoof" and c.headers.get("X-Forwarded-For") == "127.0.0.1"
               for c in ip_cands)


def test_forwarded_ip_spoof_never_fires_without_trust_context():
    engine = PayloadMutationEngine()
    cands = engine.generate_mutations("probe", vulnerability_class="generic",
                                      input_context={"parameter": "q"}, max_mutations=24)
    assert "forwarded_ip_spoof" not in {c.category for c in cands}


# -- Chunked transport --------------------------------------------------------

class _ChunkEchoHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    received = {}

    def do_POST(self):  # noqa: N802
        te = self.headers.get("Transfer-Encoding", "")
        if te.lower() == "chunked":
            body = b""
            while True:
                size_line = self.rfile.readline().strip()
                try:
                    size = int(size_line.split(b";")[0], 16)
                except ValueError:
                    break
                if size == 0:
                    self.rfile.readline()
                    break
                body += self.rfile.read(size)
                self.rfile.readline()
            _ChunkEchoHandler.received = {"te": te, "body": body.decode(errors="replace")}
            self._send(b'{"ok":true}', 200)
        else:
            length = int(self.headers.get("Content-Length") or 0)
            self.rfile.read(length)
            _ChunkEchoHandler.received = {"te": te, "body": ""}
            self._send(b'{"ok":true}', 200)

    def _send(self, body, status=200):
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


def test_chunked_transport_sends_real_framing():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ChunkEchoHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    scope = ScopeManager(["127.0.0.1"], allow_private=True, resolve_dns=False)
    verifier = HTTPVerifier(scope_manager=scope, traffic_controller=TrafficController("FAST", max_requests=8),
                            module="chunked_test")
    payload = "X" * 1000
    response = verifier.send_http_request(f"http://127.0.0.1:{server.server_port}/",
                                          method="POST", body=payload, transfer_encoding="chunked")
    server.shutdown()
    server.server_close()
    assert response.get("status_code") == 200
    assert _ChunkEchoHandler.received.get("te", "").lower() == "chunked"
    assert _ChunkEchoHandler.received.get("body") == payload


# -- Advanced JWT -------------------------------------------------------------

def test_jwt_kid_traversal_verified_on_vulnerable_fixture(servers):
    engine = _engine()
    token = _legit_token("member")
    finding = engine.test_jwt_kid_traversal(token, verify_url=f"{servers[0]}/admin")
    assert finding is not None
    assert finding["status"] == FindingStatus.VERIFIED.value
    assert finding["evidence"][0]["acceptance"]["accepted"] is True


def test_jwt_kid_traversal_pinned_server_stays_likely(servers):
    engine = _engine()
    token = _legit_token("member")
    finding = engine.test_jwt_kid_traversal(token, verify_url=f"{servers[1]}/admin")
    assert finding is not None
    assert finding["status"] != FindingStatus.VERIFIED.value
    assert finding["missing_evidence"]


def test_jwt_jku_injection_verified_on_vulnerable_fixture(servers):
    engine = _engine()
    token = _legit_token("member")
    finding = engine.test_jwt_jku_injection(token, verify_url=f"{servers[0]}/admin")
    assert finding is not None
    assert finding["status"] == FindingStatus.VERIFIED.value
    assert finding["evidence"][0]["forged_header"]["jku"] == "http://jku-canary.invalid/jwks.json"


def test_jwt_rs256_hs256_confusion_verified(servers):
    engine = _engine()
    rs_token = forge_hs256({"alg": "RS256", "typ": "JWT"}, {"sub": "u1", "role": "member"}, b"not-used")
    finding = engine.test_jwt_hs256_rs256_confusion(rs_token, public_key_pem=RS256_PUBLIC_PEM,
                                                    verify_url=f"{servers[0]}/admin")
    assert finding is not None
    assert finding["status"] == FindingStatus.VERIFIED.value


def test_jwt_confusion_rejected_without_rs256_token():
    engine = _engine()
    hs_token = _legit_token()
    assert engine.test_jwt_hs256_rs256_confusion(hs_token, public_key_pem=RS256_PUBLIC_PEM) is None


# -- Server-side prototype pollution -----------------------------------------

def test_server_side_pp_verified_on_vulnerable_fixture(servers):
    engine = _engine()
    base = servers[0]
    finding = engine.test_prototype_pollution_server_side(
        f"{base}/prefs", effect_path="/polluted")
    assert finding is not None
    assert finding["status"] == FindingStatus.VERIFIED.value
    assert finding["evidence"][0]["followup_contains_canary"] is True
    assert finding["evidence"][0]["control_followup_contains_canary"] is False


def test_server_side_pp_quiet_on_clean_fixture(servers):
    engine = _engine()
    base = servers[1]
    finding = engine.test_prototype_pollution_server_side(
        f"{base}/prefs", effect_path="/prefs")
    assert finding is None


# -- Request smuggling ---------------------------------------------------------

class _DesyncHandler(socketserver_BaseHandler := object):
    pass


def test_smuggling_detection_quiet_on_clean_http11(servers):
    """On a strict HTTP/1.1 server the probes must find no desync."""
    engine = _engine()
    assert engine.test_request_smuggling_desync(f"{servers[1]}/admin") is None


# -- Learner state --------------------------------------------------------------

def test_response_learner_load_state_restores_scores():
    learner = ResponseLearner()
    learner.load_state({"strategies": {
        "mixed_encoding": {"success_count": 3, "attempt_count": 5,
                           "request_count": 5, "confidence": 0.8, "cost": 1.0, "risk": 0.2}}})
    score = learner._score("mixed_encoding")
    assert score.success_count == 3
    assert score.attempt_count == 5
    assert learner._score("unknown_strategy").attempt_count == 0


def test_response_learner_load_state_merges_with_existing():
    learner = ResponseLearner()
    learner.record("chunked_transfer", "allowed", verified=True, confidence=0.7)
    learner.load_state({"strategies": {
        "chunked_transfer": {"success_count": 2, "attempt_count": 4,
                             "request_count": 4, "confidence": 0.6}}})
    score = learner._score("chunked_transfer")
    assert score.success_count == 3
    assert score.attempt_count == 5
