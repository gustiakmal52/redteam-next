"""Evidence-first HTTP verification with scope, URL policy, and traffic controls."""

from __future__ import annotations

import html
import gzip
import http.client
from functools import lru_cache
import json
import os
import re
import ssl
import socket
import statistics
import threading
from difflib import SequenceMatcher
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from typing import Any, Dict, Optional

try:
    import brotli as _brotli
except ImportError:  # pragma: no cover - depends on the deployment image
    _brotli = None

from redteam_agent.core.findings import FindingStatus
from redteam_agent.core.scope_manager import ScopeManager
from redteam_agent.core.sql_strategies import (candidate_dialects, error_marker,
                                                strategy_for)
from redteam_agent.core.traffic_controller import RequestBudgetExceeded, TrafficController, TrafficStopped


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_TEXT_COMPARE_LIMIT = 8192
_UUID_RE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f-]{27,}\b", re.I)
_DYNAMIC_NUMBER_RE = re.compile(r"\b\d{4,}\b")
_STATIC_PATH_RE = re.compile(
    r"(?:/_next/static/|/assets/|\.(?:js|css|map|png|jpe?g|gif|svg|woff2?|ttf)(?:\?|$))", re.I)


@lru_cache(maxsize=256)
def _numeric_token_pattern(expected: str) -> "re.Pattern[str]":
    return re.compile(rf"(?<![0-9]){re.escape(expected)}(?![0-9])")


def _eval_context_similarity(responses: Any, probes: Any) -> float:
    """Compare truncated SSTI response bodies after masking evaluated tokens."""
    bodies = []
    for (_, expected), response in zip(probes, responses):
        text = str(response.get("body", "") or "")[:_TEXT_COMPARE_LIMIT]
        bodies.append(_numeric_token_pattern(str(expected)).sub("<EVAL_TOKEN>", text, count=1))
    if len(bodies) < 2:
        return 0.0
    if bodies[0] == bodies[1]:
        return 1.0
    return SequenceMatcher(None, bodies[0], bodies[1]).ratio()


def _close_quietly(connection: Any) -> None:
    try:
        connection.close()
    except Exception:
        pass


class _KeepAlivePool:
    """Thread-safe pool of idle keep-alive connections.

    A scan issues hundreds of requests to the same handful of hosts.  urllib
    deliberately forces ``Connection: close`` and closes the socket after every
    single request, so each one paid a fresh TCP handshake (plus a full TLS
    handshake over HTTPS) before the first byte of the request was even sent.
    Reusing sockets removes that per-request cost and — just as importantly for
    a bug-bounty engagement — stops opening hundreds of short-lived connections
    to a production target.

    Only idempotent requests are pooled (see ``_PooledOpenMixin.do_open``): a
    pooled socket that the peer closed between requests must never cause a
    silent replay of a state-changing request.
    """

    def __init__(self, max_idle_total: int = 16, max_idle_per_key: int = 4,
                 idle_timeout: float = 30.0):
        self.max_idle_total = max(1, int(max_idle_total))
        self.max_idle_per_key = max(1, int(max_idle_per_key))
        self.idle_timeout = max(1.0, float(idle_timeout))
        self._idle: Dict[tuple, list] = {}
        self._lock = threading.Lock()
        self._idle_count = 0
        self.connections_created = 0
        self.connections_reused = 0

    def acquire(self, key: tuple, factory) -> tuple:
        """Return ``(connection, reused)``; prefers a live idle socket."""
        with self._lock:
            bucket = self._idle.get(key)
            while bucket:
                connection, stamp = bucket.pop()
                self._idle_count -= 1
                if (time.monotonic() - stamp <= self.idle_timeout
                        and getattr(connection, "sock", None) is not None):
                    self.connections_reused += 1
                    return connection, True
                _close_quietly(connection)
            self.connections_created += 1
        return factory(), False

    def release(self, key: tuple, connection) -> None:
        with self._lock:
            bucket = self._idle.setdefault(key, [])
            if self._idle_count < self.max_idle_total and len(bucket) < self.max_idle_per_key:
                bucket.append((connection, time.monotonic()))
                self._idle_count += 1
                return
        _close_quietly(connection)

    def stats(self) -> Dict[str, int]:
        with self._lock:
            idle = sum(1 for bucket in self._idle.values() for connection, _ in bucket
                       if getattr(connection, "sock", None) is not None)
        return {"connections_created": self.connections_created,
                "connections_reused": self.connections_reused,
                "connections_idle": idle}

    def close(self) -> None:
        with self._lock:
            idle = [connection for bucket in self._idle.values() for connection, _ in bucket]
            self._idle = {}
            self._idle_count = 0
        for connection in idle:
            _close_quietly(connection)


class _KeepAliveResponse:
    """urllib-compatible view of an http.client response that recycles its socket.

    urllib's own response wrapper closes the socket when the object goes away,
    which is exactly what makes persistent connections impossible.  This view
    returns the connection to the pool once the body has been read in full, and
    discards it on every other path (partial reads, errors, ``Connection:
    close``), because a half-read response cannot be reused safely.
    """

    def __init__(self, raw, pool: _KeepAlivePool, key: tuple, connection, url: str):
        self._raw = raw
        self._pool = pool
        self._key = key
        self._connection = connection
        self._finished = False
        self.url = url
        self.msg = raw.reason
        self.code = raw.status
        self.status = raw.status
        self.headers = raw.headers

    def info(self):
        return self._raw.headers

    def geturl(self) -> str:
        return self.url

    def getcode(self) -> int:
        return self._raw.status

    def fileno(self) -> int:
        return self._raw.fileno()

    def read(self, amt=None):
        data = self._raw.read(amt)
        if amt is None:
            self._recycle()
        return data

    def readline(self, *args):
        return self._raw.readline(*args)

    def readlines(self, *args):
        return self._raw.readlines(*args)

    def __iter__(self):
        return iter(self._raw)

    def close(self) -> None:
        try:
            self._raw.close()
        except Exception:
            pass
        self._finished = True
        _close_quietly(self._connection)

    def _recycle(self) -> None:
        if self._finished:
            return
        self._finished = True
        reusable = False
        if not getattr(self._raw, "will_close", True):
            try:
                reusable = (self._raw.isclosed()
                            and getattr(self._connection, "sock", None) is not None)
            except Exception:
                reusable = False
        if reusable:
            self._pool.release(self._key, self._connection)
        else:
            _close_quietly(self._connection)


class _PooledOpenMixin:
    """Replaces ``AbstractHTTPHandler.do_open`` with a keep-alive transport.

    Everything else (scope checks, redirect handling, error processing, raw
    request/response capture) is untouched: the returned object still satisfies
    ``urllib.error.HTTPError`` construction, so non-2xx handling is unchanged.
    """

    _pool: _KeepAlivePool
    _IDEMPOTENT = frozenset({"GET", "HEAD", "OPTIONS"})

    @staticmethod
    def _tune_socket(connection, timeout) -> None:
        """Disable Nagle and apply the per-request timeout to an open socket.

        Back-to-back requests over one persistent socket otherwise stall on
        delayed ACK (~40 ms) for every request after the first, which would make
        connection reuse look slower than reopening sockets.
        """
        sock = getattr(connection, "sock", None)
        if sock is None:
            return
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        if isinstance(timeout, (int, float)):
            try:
                sock.settimeout(timeout)
            except OSError:
                pass

    def do_open(self, http_class, req, **http_conn_args):
        host = req.host
        if not host:
            raise urllib.error.URLError("no host given")
        parsed = urllib.parse.urlsplit(req.full_url)
        method = req.get_method()
        # Proxied/tunnelled requests and state-changing methods keep the stdlib
        # behaviour (fresh connection, Connection: close).  Pooling those would
        # trade a silent duplicate write for a little speed, which is never a
        # good trade in an evidence-first tool.
        if req._tunnel_host or req.host != parsed.netloc or method not in self._IDEMPOTENT:
            return super().do_open(http_class, req, **http_conn_args)

        selector = parsed.path or "/"
        if parsed.query:
            selector = f"{selector}?{parsed.query}"

        headers = dict(req.unredirected_hdrs)
        headers.update({key: value for key, value in req.headers.items() if key not in headers})
        # HTTP/1.1 is persistent by default; dropping urllib's forced
        # "Connection: close" is what makes reuse possible at all.
        headers = {name.title(): value for name, value in headers.items()
                   if str(name).lower() != "connection"}

        key = (parsed.scheme, host, id(http_conn_args.get("context")))

        def factory():
            connection = http_class(host, timeout=req.timeout, **http_conn_args)
            connection.set_debuglevel(getattr(self, "_debuglevel", 0))
            try:
                connection.connect()
            except OSError as exc:
                _close_quietly(connection)
                raise urllib.error.URLError(exc)
            self._tune_socket(connection, req.timeout)
            return connection

        for attempt in range(2):
            connection, reused = self._pool.acquire(key, factory)
            if isinstance(req.timeout, (int, float)):
                connection.timeout = req.timeout
            self._tune_socket(connection, req.timeout)
            try:
                connection.request(method, selector, req.data, headers,
                                   encode_chunked=req.has_header("Transfer-encoding"))
                raw = connection.getresponse()
            except (OSError, http.client.HTTPException) as exc:
                _close_quietly(connection)
                # An idle socket the peer had already closed is retried once on a
                # fresh connection; only idempotent methods reach this branch.
                if reused and attempt == 0:
                    continue
                if isinstance(exc, OSError):
                    raise urllib.error.URLError(exc)
                raise
            return _KeepAliveResponse(raw, self._pool, key, connection, req.get_full_url())

        raise urllib.error.URLError("no reusable connection available")


class _PooledHTTPHandler(_PooledOpenMixin, urllib.request.HTTPHandler):
    def __init__(self, pool: _KeepAlivePool):
        super().__init__()
        self._pool = pool


class _PooledHTTPSHandler(_PooledOpenMixin, urllib.request.HTTPSHandler):
    def __init__(self, pool: _KeepAlivePool, **kwargs):
        super().__init__(**kwargs)
        self._pool = pool


# Header names whose values must never appear in raw evidence.  Kept inline
# here (not imported from bypass_engine) to avoid a circular import.
_SENSITIVE_HEADERS = {
    "authorization", "cookie", "set-cookie", "proxy-authorization",
    "x-api-key", "api-key", "x-auth-token", "x-access-token",
    "x-csrf-token", "x-xsrf-token", "x-amz-security-token",
}


class HTTPVerifier:
    def __init__(self, timeout: float = 10.0, traffic_controller: Optional[TrafficController] = None,
                 scope_manager: Optional[ScopeManager] = None, module: str = "verifier",
                 verify_tls: bool = True, pool: Optional[_KeepAlivePool] = None,
                 ssl_context: Optional[ssl.SSLContext] = None):
        self.timeout = timeout
        self.traffic = traffic_controller or TrafficController()
        self.scope = scope_manager
        self.module = module
        self.verify_tls = bool(verify_tls)
        request_purpose = os.environ.get("REDTEAM_REQUEST_PURPOSE", "").strip()
        bugcrowd_ninja = os.environ.get("REDTEAM_BUGCROWD_NINJA", "").strip()
        if any("\r" in value or "\n" in value for value in (request_purpose, bugcrowd_ninja)):
            raise ValueError("request header environment values must not contain newlines")
        self.required_headers = {
            key: value for key, value in {
                "X-Request-Purpose": request_purpose,
                "X-Bugcrowd-Ninja": bugcrowd_ninja,
            }.items() if value
        }
        # Program-specific researcher identification headers (e.g. Bitso's
        # "X-Bug-Bounty: Bugcrowd-<user>"). Supplied as a JSON object via env;
        # merged here so program headers ride every engine request uniformly.
        extra_headers_raw = os.environ.get("REDTEAM_EXTRA_HEADERS", "").strip()
        if extra_headers_raw:
            extra_headers = json.loads(extra_headers_raw)
            if not isinstance(extra_headers, dict):
                raise ValueError("REDTEAM_EXTRA_HEADERS must be a JSON object")
            for header_key, header_value in extra_headers.items():
                if "\r" in str(header_value) or "\n" in str(header_value):
                    raise ValueError("request header environment values must not contain newlines")
                self.required_headers[str(header_key)] = str(header_value)
        # TLS verification is part of evidence integrity.  The insecure mode
        # remains an explicit opt-in for a researcher-controlled lab with a
        # self-signed certificate; it is never the default.
        self.ssl_context = ssl_context or (ssl.create_default_context() if self.verify_tls
                                           else ssl._create_unverified_context())
        self._pool = pool or _KeepAlivePool()
        self._opener = urllib.request.build_opener(
            _NoRedirect(),
            _PooledHTTPSHandler(self._pool, context=self.ssl_context),
            _PooledHTTPHandler(self._pool),
        )
        # Session authentication state.  Auth headers are replayed ONLY to the
        # exact netloc they were obtained from; they never leak to other hosts
        # or redirect targets, and they never override headers a caller set
        # explicitly (e.g. AuthorizationBypassEngine identity comparison).
        self._auth_headers: Dict[str, str] = {}
        self._auth_netloc: Optional[str] = None
        self._auth_cookies: Dict[str, str] = {}
        self._auth_origin: Optional[str] = None

    def connection_stats(self) -> Dict[str, int]:
        """Connection-reuse counters for evidence: fewer sockets, less load."""
        return self._pool.stats()

    def close(self) -> None:
        """Release every idle keep-alive socket held by this verifier."""
        self._pool.close()

    def _sleep_before_retry(self, attempt: int, headers: Any) -> None:
        """Sleep once per retry, honoring Retry-After when the policy allows it."""
        delay = self.traffic.retry_delay(attempt)
        if self.traffic.config.get("respect_retry_after", True):
            retry_after = next((v for k, v in (headers or {}).items()
                                if str(k).lower() == "retry-after"), None)
            if retry_after is not None:
                try:
                    parser = getattr(self.traffic, "_retry_after_seconds", None)
                    parsed = float(parser(retry_after)) if parser else float(retry_after)
                except (TypeError, ValueError):
                    parsed = 0.0
                delay = max(delay, min(30.0, max(0.0, parsed)))
        time.sleep(delay)

    @staticmethod
    def _error_result(url: str, method: str, headers: dict, body: Optional[str], reason: str,
                      error_type: str = "request_failed") -> Dict[str, Any]:
        return {
            "success": False, "verified": False, "status_code": 0, "headers": {}, "body": "",
            "response_time_sec": 0.0, "raw_request": HTTPVerifier._format_raw_request(method, url, headers, body),
            "raw_response": f"HTTP REQUEST NOT EXECUTED: {reason}", "error": reason,
            "failure": {"status": "failed", "reason": reason, "type": error_type, "verified": False},
        }

    @staticmethod
    def _decode_response_body(data: bytes | str, headers: Any) -> str:
        """Decode the encodings negotiated by the shared HTTP client.

        Asset discovery intentionally uses this verifier instead of creating a
        second downloader.  Modern CDNs commonly return Brotli or gzip for
        JavaScript, JSON, and source maps; parsing the compressed bytes as
        UTF-8 would otherwise silently produce false negatives.  Multiple
        content encodings are decoded in reverse application order, while an
        unavailable Brotli decoder remains an explicit, readable fallback.
        """
        if isinstance(data, str):
            return data
        payload = data or b""
        encoding = ""
        for key, value in (headers or {}).items():
            if str(key).lower() == "content-encoding":
                encoding = str(value or "")
                break
        encodings = [part.strip().lower() for part in encoding.split(",") if part.strip()]
        for item in reversed(encodings):
            try:
                if item in {"gzip", "x-gzip"}:
                    payload = gzip.decompress(payload)
                elif item == "br":
                    if _brotli is None:
                        return payload.decode("utf-8", errors="replace")
                    payload = _brotli.decompress(payload)
                elif item == "deflate":
                    try:
                        payload = zlib.decompress(payload)
                    except zlib.error:
                        # Some servers send a raw DEFLATE stream despite the
                        # RFC wrapper being the usual representation.
                        payload = zlib.decompress(payload, -zlib.MAX_WBITS)
                else:
                    # Unknown encodings are left visible as a decoding error;
                    # silently guessing would make evidence less trustworthy.
                    continue
            except Exception:
                # Decoder-specific exceptions differ between the stdlib and
                # optional Brotli implementations.  A malformed compressed
                # response must remain observable as text, not abort the
                # shared discovery pipeline.
                return payload.decode("utf-8", errors="replace")
        return payload.decode("utf-8", errors="replace")

    def send_http_request(self, url: str, method: str = "GET", headers: Optional[Dict[str, str]] = None,
                          body: Optional[str] = None, *, priority: str = "verification",
                          follow_redirects: bool = True, max_redirects: int = 5) -> Dict[str, Any]:
        """Execute a real request; never synthesize status, body, or technology evidence."""
        merged_headers = {"User-Agent": "Gustiakmal-RedTeam-Verifier/2.1"}
        merged_headers.update(headers or {})
        merged_headers.update(self.required_headers)
        headers = merged_headers
        # Session auth is replayed only to the exact netloc it was obtained
        # from, and only when the caller did not already set that header
        # explicitly (identity-comparison engines must stay in control).
        if self._auth_headers and self._auth_netloc:
            request_netloc = urllib.parse.urlparse(url).netloc
            if request_netloc == self._auth_netloc:
                for auth_key, auth_value in self._auth_headers.items():
                    if not any(str(key).lower() == auth_key.lower() for key in headers):
                        headers[auth_key] = auth_value
        if not any(str(key).lower() == "accept-encoding" for key in headers):
            headers["Accept-Encoding"] = "gzip, br" if _brotli is not None else "gzip"
        method = method.upper()
        active_scope = self.scope
        if active_scope is None:
            try:
                active_scope = ScopeManager.from_target(url)
            except Exception as exc:
                return self._error_result(url, method, headers, body, str(exc), "url_policy")
        current_url = url
        redirects: list[dict] = []
        retry_attempt = 0
        retry_limit = int(self.traffic.config.get("retry_limit", 0))

        for _ in range(max_redirects + 1 + (max_redirects + 1) * retry_limit):
            decision = active_scope.check_url(current_url, active=True)
            if not decision.get("allowed"):
                reason = decision.get("reason", "URL rejected by scope policy")
                result = self._error_result(current_url, method, headers, body, reason, "scope_or_url_policy")
                result["scope"] = decision
                result["redirects"] = redirects
                return result
            data_bytes = body.encode("utf-8") if body is not None else None
            request_url = current_url
            start = None
            try:
                with self.traffic.request_slot(request_url, module=self.module, priority=priority) as slot:
                    req = urllib.request.Request(request_url, data=data_bytes, headers=headers, method=method)
                    start = time.monotonic()
                    try:
                        response = self._opener.open(req, timeout=self.timeout)
                        status_code = response.status
                        resp_headers = dict(response.headers)
                        resp_body = self._decode_response_body(response.read(), resp_headers)
                        success = 200 <= status_code < 400
                        error = None
                    except urllib.error.HTTPError as exc:
                        status_code = exc.code
                        resp_headers = dict(exc.headers or {})
                        resp_body = self._decode_response_body(exc.read(), resp_headers)
                        success = False
                        error = str(exc)
                    elapsed = time.monotonic() - start
                self.traffic.observe_response(request_url, status_code, resp_headers, elapsed, error)
            except (RequestBudgetExceeded, TrafficStopped) as exc:
                result = self._error_result(request_url, method, headers, body, str(exc), "traffic_policy")
                result["scope"] = decision
                result["redirects"] = redirects
                return result
            except Exception as exc:
                elapsed = time.monotonic() - start if start is not None else 0.0
                self.traffic.observe_response(request_url, 0, {}, elapsed, str(exc))
                if retry_attempt < retry_limit:
                    retry_attempt += 1
                    self._sleep_before_retry(retry_attempt, {})
                    continue
                return {
                    **self._error_result(request_url, method, headers, body, str(exc), "transport"),
                    "response_time_sec": elapsed, "scope": decision, "redirects": redirects,
                }

            if status_code in {429, 503} and retry_attempt < retry_limit:
                retry_attempt += 1
                self._sleep_before_retry(retry_attempt, resp_headers)
                continue
            location = next((v for k, v in resp_headers.items() if k.lower() == "location"), None)
            if status_code in {301, 302, 303, 307, 308} and location and follow_redirects:
                next_url = urllib.parse.urljoin(request_url, location)
                next_decision = active_scope.check_url(next_url, active=True)
                redirects.append({"status_code": status_code, "from": request_url, "to": next_url,
                                  "scope": next_decision})
                if not next_decision.get("allowed"):
                    return {
                        "success": False, "verified": False, "status_code": status_code,
                        "headers": resp_headers, "body": resp_body, "response_time_sec": elapsed,
                        "raw_request": self._format_raw_request(method, request_url, headers, body),
                        "raw_response": self._format_raw_response(status_code, resp_headers, resp_body),
                        "error": "Redirect target rejected by scope policy",
                        "failure": {"status": "blocked", "reason": next_decision.get("reason"), "verified": False},
                        "scope": decision, "redirects": redirects, "request_number": slot["request_number"],
                    }
                current_url = next_url
                if status_code == 303:
                    method, body = "GET", None
                continue

            return {
                "success": success, "status_code": status_code, "headers": resp_headers, "body": resp_body,
                "response_time_sec": elapsed,
                "raw_request": self._format_raw_request(method, request_url, headers, body),
                "raw_response": self._format_raw_response(status_code, resp_headers, resp_body),
                "error": error, "scope": decision, "redirects": redirects,
                "request_number": slot["request_number"], "traffic_profile": self.traffic.preset,
            }

        return self._error_result(current_url, method, headers, body, "Too many redirects", "redirect_limit")

    @staticmethod
    def _url_with_param(target_url: str, param_name: str, value: str) -> str:
        parsed = urllib.parse.urlparse(target_url)
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        query[param_name] = [value]
        return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(query, doseq=True), fragment=""))

    @staticmethod
    def classify_reflection(body: str, payload: str, content_type: str) -> dict:
        reflected = payload in body
        lowered_type = (content_type or "").lower()
        if not reflected:
            return {"classification": "NOT_REFLECTED", "context": "none", "executable": False}
        if "application/json" in lowered_type or "+json" in lowered_type:
            return {"classification": "REFLECTED_INPUT", "context": "JSON", "executable": False}
        if "text/plain" in lowered_type:
            return {"classification": "REFLECTED_INPUT", "context": "plain_text", "executable": False}
        html_like = "text/html" in lowered_type or "application/xhtml" in lowered_type or bool(
            re.search(r"<!doctype\s+html|<html\b|<body\b", body, re.I))
        if not html_like:
            return {"classification": "REFLECTED_INPUT", "context": "unknown_non_html", "executable": False}
        index = body.find(payload)
        before, after = body[max(0, index - 160):index], body[index + len(payload):index + len(payload) + 160]
        if re.search(r"<!--(?:(?!-->).)*$", before, re.S):
            context = "HTML_comment"
        elif re.search(r"<textarea\b[^>]*>[^<]*$", before, re.I | re.S):
            context = "textarea"
        elif re.search(r"<script\b[^>]*>[^<]*$", before, re.I | re.S):
            context = "JavaScript"
        elif before.rfind("<") > before.rfind(">"):
            context = "HTML_attribute_or_tag"
        else:
            context = "HTML_text"
        # This canary is deterministically executable only when parsed as HTML
        # text that creates a new script element. A literal script tag inside an
        # attribute or an existing JS string is not sufficient proof.
        executable = context == "HTML_text" and payload.lower().startswith("<script")
        return {"classification": "VERIFIED_XSS" if executable else "POSSIBLE_XSS",
                "context": context, "executable": executable, "excerpt": before[-80:] + payload + after[:80]}

    def verify_xss(self, target_url: str, param_name: str, canary_token: str = "AGY_XSS_9981") -> Dict[str, Any]:
        payload = f"<script>alert('{canary_token}')</script>"
        test_url = self._url_with_param(target_url, param_name, payload)
        result = self.send_http_request(test_url)
        content_type = next((v for k, v in result.get("headers", {}).items() if k.lower() == "content-type"), "")
        context = self.classify_reflection(result.get("body", ""), payload, content_type)
        escaped = html.escape(payload, quote=True) in result.get("body", "") or "&lt;script" in result.get("body", "").lower()
        # Static response analysis can establish unescaped reflection in an
        # HTML context, not actual browser execution.  A browser adapter must
        # add an explicit canary proof before this becomes VERIFIED.
        reflection_proven = bool(result.get("success") and context["executable"] and not escaped)
        # ``verified`` is retained as a legacy response-level observation flag
        # for callers that consume HTTPVerifier directly.  It is explicitly
        # not browser proof; higher layers must use ``browser_execution`` and
        # the shared finding disposition gate before submission.
        verified = reflection_proven
        return {
            "verified": verified,
            "browser_verified": False,
            "status": FindingStatus.LIKELY.value if reflection_proven else FindingStatus.SUSPECTED.value,
            "reflection_only": reflection_proven,
            "browser_execution": False,
            "classification": context["classification"], "vuln_type": "Reflected XSS", "test_url": test_url,
            "payload_used": payload, "evidence": {**context, "is_escaped": escaped,
                "status_code": result.get("status_code"), "content_type": content_type},
            "raw_request": result.get("raw_request", ""), "raw_response": result.get("raw_response", ""),
            "request": result,
            "verification_note": (
                "Unescaped script markup reflected in an HTML context; browser execution was not demonstrated."
                if reflection_proven else
                f"Reflection is absent, escaped, or non-executable ({context['context']}); not verified as XSS."
            ),
        }

    @staticmethod
    def exact_numeric_token(body: str, expected: str) -> bool:
        return bool(_numeric_token_pattern(str(expected)).search(body or ""))

    def verify_ssti(self, target_url: str, param_name: str) -> Dict[str, Any]:
        probes = [("{{7*77}}", "539"), ("{{8*83}}", "664")]
        baseline = self.send_http_request(target_url)
        responses = [self.send_http_request(self._url_with_param(target_url, param_name, payload)) for payload, _ in probes]
        checks = []
        baseline_body = baseline.get("body", "")
        for (payload, expected), response in zip(probes, responses):
            exact = self.exact_numeric_token(response.get("body", ""), expected)
            checks.append({"payload": payload, "expected": expected, "exact_token": exact,
                           "payload_not_reflected": payload not in response.get("body", ""),
                           "absent_from_baseline": not self.exact_numeric_token(baseline_body, expected),
                           "request_success": response.get("success", False)})
        static_path = bool(_STATIC_PATH_RE.search(target_url))
        context_similarity = _eval_context_similarity(responses, probes)
        equivalent_context = context_similarity >= .8
        deterministic = (all(c["exact_token"] and c["payload_not_reflected"] and c["absent_from_baseline"]
                             and c["request_success"] for c in checks) and equivalent_context)
        verified = deterministic and not static_path
        both_tokens = all(c["exact_token"] for c in checks)
        status = FindingStatus.VERIFIED if verified else (FindingStatus.LIKELY if both_tokens and not static_path else FindingStatus.SUSPECTED)
        confidence = .96 if verified else (.7 if both_tokens else (.35 if any(c["exact_token"] for c in checks) else .15))
        false_positives = ["Static asset is not a credible server-side template evaluation surface"] if static_path else []
        return {
            "verified": verified, "status": status.value,
            "confidence": confidence, "vuln_type": "Server-Side Template Injection (SSTI)",
            "baseline": baseline, "probes": responses, "verification_checks": checks + [
                {"name": "equivalent_response_context", "passed": equivalent_context,
                 "similarity": round(context_similarity, 3)}],
            "false_positive_reasons": false_positives,
            "missing_evidence": [] if verified else ["Two consistent differential arithmetic evaluations are required"],
            "verification_note": "Two distinct arithmetic expressions produced exact, baseline-absent results." if verified
                else "Differential arithmetic evaluation was not deterministically proven.",
        }

    def verify_sqli_time_based(self, target_url: str, param_name: str, delay_sec: int = 5, samples: int = 3) -> Dict[str, Any]:
        control_payload = "1' AND 1=1-- "
        delay_payload = f"1' AND (SELECT 1 FROM (SELECT(SLEEP({delay_sec})))AGY)-- "
        control_url = self._url_with_param(target_url, param_name, control_payload)
        test_url = self._url_with_param(target_url, param_name, delay_payload)
        baselines = [self.send_http_request(target_url) for _ in range(samples)]
        controls = [self.send_http_request(control_url) for _ in range(samples)]
        delayed = [self.send_http_request(test_url) for _ in range(samples)]
        bt = [r.get("response_time_sec", 0.0) for r in baselines if r.get("status_code")]
        ct = [r.get("response_time_sec", 0.0) for r in controls if r.get("status_code")]
        pt = [r.get("response_time_sec", 0.0) for r in delayed if r.get("status_code")]
        enough = len(bt) == len(ct) == len(pt) == samples
        bm = statistics.median(bt) if bt else 0.0
        cm = statistics.median(ct) if ct else 0.0
        pm = statistics.median(pt) if pt else 0.0
        delta = pm - max(bm, cm)
        threshold = max(1.0, delay_sec - 1.0)
        repeats = sum(1 for value in pt if value - max(bm, cm) >= threshold)
        control_stable = abs(cm - bm) < max(1.0, delay_sec * .3)
        verified = enough and control_stable and delta >= threshold and repeats >= max(2, samples - 1)
        return {
            "verified": verified, "status": FindingStatus.VERIFIED.value if verified else FindingStatus.SUSPECTED.value,
            "confidence": .95 if verified else (.55 if delta >= threshold else .2),
            "vuln_type": "Time-Based Blind SQL Injection", "test_url": test_url, "payload_used": delay_payload,
            "baseline": baselines, "control": controls, "test": delayed,
            "evidence": {"baseline_samples": bt, "control_samples": ct, "payload_samples": pt,
                "baseline_median_sec": round(bm, 3), "control_median_sec": round(cm, 3),
                "payload_median_sec": round(pm, 3), "timing_delta_sec": round(delta, 3),
                "number_of_samples": samples, "repeatable_delays": repeats, "control_stable": control_stable},
            "verification_note": "Repeatable median timing differential matched the requested database delay." if verified
                else "Timing differential was absent, unstable, or not repeatable; not verified.",
        }

    # -- JSON body injection surface --------------------------------------
    # Modern APIs take their input in POST JSON bodies; query-parameter-only
    # probing leaves that whole surface untested. These verifiers reuse the
    # exact deterministic criteria of the GET variants so an injection inside
    # a JSON body can only VERIFY on the same repeatable, baseline-absent
    # evidence.

    @staticmethod
    def _json_post_headers() -> Dict[str, str]:
        return {"Content-Type": "application/json", "Accept": "application/json",
                "User-Agent": "Gustiakmal-RedTeam-Verifier/2.1"}

    def verify_sqli_time_based_json(self, target_url: str, field: str = "q",
                                    delay_sec: int = 5, samples: int = 3) -> Dict[str, Any]:
        """Time-based blind SQLi delivered inside a JSON POST body."""
        headers = self._json_post_headers()

        def post(payload: dict) -> Dict[str, Any]:
            return self.send_http_request(target_url, method="POST", headers=dict(headers),
                                          body=json.dumps(payload), priority="verification")

        delay_payload = f"1' AND (SELECT 1 FROM (SELECT(SLEEP({delay_sec})))AGY)-- "
        baselines = [post({field: "0"}) for _ in range(samples)]
        controls = [post({field: "1"}) for _ in range(samples)]
        delayed = [post({field: delay_payload}) for _ in range(samples)]
        bt = [r.get("response_time_sec", 0.0) for r in baselines if r.get("status_code")]
        ct = [r.get("response_time_sec", 0.0) for r in controls if r.get("status_code")]
        pt = [r.get("response_time_sec", 0.0) for r in delayed if r.get("status_code")]
        enough = len(bt) == len(ct) == len(pt) == samples
        bm = statistics.median(bt) if bt else 0.0
        cm = statistics.median(ct) if ct else 0.0
        pm = statistics.median(pt) if pt else 0.0
        delta = pm - max(bm, cm)
        threshold = max(1.0, delay_sec - 1.0)
        repeats = sum(1 for value in pt if value - max(bm, cm) >= threshold)
        control_stable = abs(cm - bm) < max(1.0, delay_sec * .3)
        verified = enough and control_stable and delta >= threshold and repeats >= max(2, samples - 1)
        return {
            "verified": verified, "status": FindingStatus.VERIFIED.value if verified else FindingStatus.SUSPECTED.value,
            "confidence": .95 if verified else (.55 if delta >= threshold else .2),
            "vuln_type": "Time-Based Blind SQL Injection (JSON body)", "test_url": target_url,
            "payload_used": json.dumps({field: delay_payload}), "json_field": field,
            "baseline": baselines, "control": controls, "test": delayed,
            "evidence": {"baseline_samples": bt, "control_samples": ct, "payload_samples": pt,
                "baseline_median_sec": round(bm, 3), "control_median_sec": round(cm, 3),
                "payload_median_sec": round(pm, 3), "timing_delta_sec": round(delta, 3),
                "number_of_samples": samples, "repeatable_delays": repeats, "control_stable": control_stable,
                "injection_surface": "json_body"},
            "verification_note": "Repeatable median timing differential matched the requested database delay inside a JSON body." if verified
                else "Timing differential in the JSON body was absent, unstable, or not repeatable; not verified.",
        }

    @staticmethod
    def _sql_request_with_value(target_url: str, field: str, value: str, *,
                                method: str = "GET", headers: Optional[Dict[str, str]] = None,
                                body: Optional[str] = None,
                                input_location: str = "query") -> Dict[str, Any]:
        """Replace only the observed input location for a modern API request."""
        selected_headers = dict(headers or {})
        selected_method = str(method or "GET").upper()
        location = str(input_location or "query").lower()
        selected_body = body
        request_url = target_url
        if location in {"query", "url", "parameter"}:
            request_url = HTTPVerifier._url_with_param(target_url, field, value)
        elif location in {"json", "json_body"}:
            try:
                parsed = json.loads(body or "{}")
            except (TypeError, ValueError, json.JSONDecodeError):
                parsed = {}
            if not isinstance(parsed, dict):
                parsed = {}
            parsed[field] = value
            selected_body = json.dumps(parsed, ensure_ascii=False, separators=(",", ":"))
            selected_headers.setdefault("Content-Type", "application/json")
            selected_headers.setdefault("Accept", "application/json")
        elif location in {"form", "form_body", "urlencoded"}:
            try:
                parsed = urllib.parse.parse_qs(body or "", keep_blank_values=True)
            except (TypeError, ValueError):
                parsed = {}
            parsed[field] = [value]
            selected_body = urllib.parse.urlencode(parsed, doseq=True)
            selected_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        elif location in {"header", "headers"}:
            selected_headers[field] = value
        else:
            # Unknown contexts must not be silently rewritten into a query
            # parameter. The observed request is preserved and the value is
            # carried in a JSON body only when the caller explicitly supplied
            # one of the supported locations above.
            return {"url": target_url, "method": selected_method,
                    "headers": selected_headers, "body": selected_body}
        return {"url": request_url, "method": selected_method,
                "headers": selected_headers, "body": selected_body}

    @staticmethod
    def _sql_body_similarity(first: Dict[str, Any], second: Dict[str, Any]) -> float:
        """Compare truncated response bodies while ignoring dynamic identifiers."""
        def raw(value: Any) -> str:
            return str((value or {}).get("body", "") if isinstance(value, dict) else value or "")

        first_raw = raw(first)
        second_raw = raw(second)
        if first_raw == second_raw:
            return 1.0

        def normalise(text: str) -> str:
            text = text[:_TEXT_COMPARE_LIMIT]
            return _DYNAMIC_NUMBER_RE.sub("<NUMBER>", _UUID_RE.sub("<UUID>", text))

        first_text = normalise(first_raw)
        second_text = normalise(second_raw)
        if first_text == second_text:
            return 1.0
        return SequenceMatcher(None, first_text, second_text).ratio()

    @staticmethod
    def _sql_response_ok(response: Dict[str, Any]) -> bool:
        return bool(response.get("status_code") and response.get("status_code") < 600)

    def verify_sqli_adaptive(
        self, target_url: str, field: str, *, dialect: str = "auto",
        method: str = "GET", headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None, input_location: str = "query",
        delay_sec: int = 4, samples: int = 3, request_budget: int = 16,
        backend_evidence: Optional[Sequence[str]] = None,
        true_marker: Optional[str] = None, false_marker: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Verify SQLi on the observed transport using ranked semantic probes.

        Modern applications frequently put filters in JSON, form bodies, or
        headers and route them through an ORM. This verifier therefore tests
        the discovered input location, uses a short dialect-ranked list, and
        prefers a repeatable boolean differential before a dialect-specific
        timing probe. It never treats a 200 response, a WAF change, or a single
        latency spike as proof.
        """
        budget = max(0, int(request_budget))
        samples = max(1, min(3, int(samples)))
        sent = 0
        attempts: list[dict[str, Any]] = []

        def send(value: str) -> Optional[Dict[str, Any]]:
            nonlocal sent
            if sent >= budget:
                return None
            request = self._sql_request_with_value(
                target_url, field, value, method=method, headers=headers,
                body=body, input_location=input_location)
            response = self.send_http_request(
                request["url"], method=request["method"], headers=request["headers"],
                body=request["body"], priority="verification")
            sent += 1
            attempts.append({"request": request, "response": response})
            return response

        # The control uses the discovered transport and field, not an invented
        # q/id parameter. It also gives auto-detection real response evidence.
        controls = [item for item in (send("0"), send("0")) if item is not None]
        if not controls:
            return {
                "verified": False, "status": FindingStatus.SUSPECTED.value,
                "confidence": .05, "dialect": "generic", "proof_mode": "none",
                "requests_used": sent, "attempts": attempts,
                "missing_evidence": ["A reachable observed input location is required"],
            }
        evidence_text = list(backend_evidence or []) + [str(item.get("body", "")) for item in controls]
        dialects = candidate_dialects(dialect if str(dialect).lower() != "auto" else "generic", evidence_text)
        best: Optional[Dict[str, Any]] = None

        for selected_dialect in dialects:
            strategy = strategy_for(selected_dialect)
            if sent + 4 > budget:
                break
            true_payload = strategy.render("boolean_true", input_context=input_location)
            false_payload = strategy.render("boolean_false", input_context=input_location)
            true_responses = [item for item in (send(true_payload), send(true_payload)) if item is not None]
            false_responses = [item for item in (send(false_payload), send(false_payload)) if item is not None]
            if not true_responses or not false_responses:
                break
            baseline = controls[-1]
            true_stable = len(true_responses) < 2 or self._sql_body_similarity(true_responses[0], true_responses[1]) >= .85
            false_stable = len(false_responses) < 2 or self._sql_body_similarity(false_responses[0], false_responses[1]) >= .85
            # Short JSON responses can score deceptively high with a raw
            # character similarity (e.g. ``{"rows":[...]}`` vs
            # ``{"rows":[]}``). Use a stricter boundary so a changed result
            # set is a real semantic differential, not a one-character drift.
            true_false_different = self._sql_body_similarity(true_responses[0], false_responses[0]) < .85
            true_baseline_match = self._sql_body_similarity(true_responses[0], baseline) >= .72
            true_marker_seen = bool(true_marker and any(str(true_marker) in str(item.get("body", "")) for item in true_responses))
            false_marker_seen = bool(false_marker and any(str(false_marker) in str(item.get("body", "")) for item in false_responses))
            payload_echoed = any(
                payload and payload in str(item.get("body", ""))
                for payload in (true_payload, false_payload)
                for item in true_responses + false_responses
            )
            boolean_verified = bool(
                true_stable and false_stable and true_false_different and not payload_echoed
                and (true_baseline_match or (true_marker_seen and false_marker_seen))
            )
            candidate = {
                "dialect": selected_dialect, "proof_mode": "boolean_differential",
                "boolean_verified": boolean_verified,
                "true_payload": true_payload, "false_payload": false_payload,
                "true_stable": true_stable, "false_stable": false_stable,
                "true_false_different": true_false_different,
                "true_baseline_match": true_baseline_match,
                "true_marker_seen": true_marker_seen, "false_marker_seen": false_marker_seen,
                "payload_echoed": payload_echoed,
                "control": controls, "true": true_responses, "false": false_responses,
            }
            best = candidate
            if boolean_verified:
                return {
                    "verified": True, "status": FindingStatus.VERIFIED.value,
                    "confidence": .94, "dialect": selected_dialect,
                    "proof_mode": "boolean_differential", "requests_used": sent,
                    "attempts": attempts, "evidence": candidate,
                    "payload_used": true_payload,
                    "verification_note": "Repeatable dialect-aware true/false responses differed while the true branch matched the observed control response.",
                    "missing_evidence": [],
                }

            # An explicit provider error is useful evidence, but it is not
            # promoted to VERIFIED without a behavior differential.
            quote_payload = strategy.render("quote_probe", input_context=input_location)
            quote_response = send(quote_payload)
            marker = error_marker(str((quote_response or {}).get("body", "")), selected_dialect)
            control_marker = error_marker(str(baseline.get("body", "")), selected_dialect)
            if quote_response and marker and not control_marker:
                best = {**candidate, "proof_mode": "provider_error", "error_marker": marker,
                        "quote_payload": quote_payload, "quote_response": quote_response}

            if strategy.supports_timing and sent + 4 <= budget:
                time_payload = strategy.render("time_true", delay_sec=delay_sec,
                                               input_context=input_location)
                if time_payload:
                    timing_controls = [item for item in (send(true_payload), send(true_payload)) if item is not None]
                    timing_delayed = [item for item in (send(time_payload), send(time_payload)) if item is not None]
                    control_times = [float(item.get("response_time_sec", 0.0) or 0.0) for item in timing_controls]
                    delayed_times = [float(item.get("response_time_sec", 0.0) or 0.0) for item in timing_delayed]
                    control_median = statistics.median(control_times) if control_times else 0.0
                    delayed_median = statistics.median(delayed_times) if delayed_times else 0.0
                    threshold = max(1.0, int(delay_sec) - 1.0)
                    repeats = sum(1 for value in delayed_times if value - control_median >= threshold)
                    timing_verified = bool(
                        len(timing_controls) >= 2 and len(timing_delayed) >= 2
                        and abs(control_median - statistics.median([float(item.get("response_time_sec", 0.0) or 0.0) for item in controls])) < max(1.0, delay_sec * .35)
                        and delayed_median - control_median >= threshold and repeats >= 1
                    )
                    timing_candidate = {
                        **(best or candidate), "proof_mode": "repeatable_timing",
                        "time_payload": time_payload, "control_median_sec": round(control_median, 3),
                        "delayed_median_sec": round(delayed_median, 3),
                        "timing_delta_sec": round(delayed_median - control_median, 3),
                        "repeatable_delays": repeats, "timing_verified": timing_verified,
                    }
                    if timing_verified:
                        return {
                            "verified": True, "status": FindingStatus.VERIFIED.value,
                            "confidence": .96, "dialect": selected_dialect,
                            "proof_mode": "repeatable_timing", "requests_used": sent,
                            "attempts": attempts, "evidence": timing_candidate,
                            "payload_used": time_payload,
                            "verification_note": "A dialect-specific time condition produced a repeatable median delay over the semantic control.",
                            "missing_evidence": [],
                        }
                    best = timing_candidate

        if best and best.get("proof_mode") == "provider_error":
            return {
                "verified": False, "status": FindingStatus.LIKELY.value,
                "confidence": .72, "dialect": best.get("dialect", "generic"),
                "proof_mode": "provider_error", "requests_used": sent,
                "attempts": attempts, "evidence": best,
                "payload_used": best.get("quote_payload", ""),
                "verification_note": "A provider-specific SQL error appeared only after the controlled quote probe; execution/data impact is not yet proven.",
                "missing_evidence": ["Repeatable boolean or timing behavior is required for VERIFIED SQL injection"],
            }
        return {
            "verified": False, "status": FindingStatus.SUSPECTED.value,
            "confidence": .28, "dialect": (best or {}).get("dialect", dialect),
            "proof_mode": (best or {}).get("proof_mode", "differential_not_proven"),
            "requests_used": sent, "attempts": attempts, "evidence": best or {},
            "payload_used": (best or {}).get("true_payload", ""),
            "verification_note": "Dialect-aware SQL probes produced no repeatable, application-relevant differential.",
            "missing_evidence": ["Repeatable boolean/timing behavior or a verified backend data effect is required"],
        }

    def verify_ssti_json(self, target_url: str, field: str = "q") -> Dict[str, Any]:
        """SSTI arithmetic evaluation delivered inside a JSON POST body."""
        headers = self._json_post_headers()

        def post(payload: dict) -> Dict[str, Any]:
            return self.send_http_request(target_url, method="POST", headers=dict(headers),
                                          body=json.dumps(payload), priority="verification")

        probes = [("{{7*77}}", "539"), ("{{8*83}}", "664")]
        baseline = post({field: "x"})
        responses = [post({field: payload}) for payload, _ in probes]
        checks = []
        baseline_body = baseline.get("body", "")
        for (payload, expected), response in zip(probes, responses):
            exact = self.exact_numeric_token(response.get("body", ""), expected)
            checks.append({"payload": payload, "expected": expected, "exact_token": exact,
                           "payload_not_reflected": payload not in response.get("body", ""),
                           "absent_from_baseline": not self.exact_numeric_token(baseline_body, expected),
                           "request_success": response.get("success", False)})
        context_similarity = _eval_context_similarity(responses, probes)
        equivalent_context = context_similarity >= .8
        deterministic = (all(c["exact_token"] and c["payload_not_reflected"] and c["absent_from_baseline"]
                             and c["request_success"] for c in checks) and equivalent_context)
        verified = deterministic
        both_tokens = all(c["exact_token"] for c in checks)
        status = FindingStatus.VERIFIED if verified else (FindingStatus.LIKELY if both_tokens else FindingStatus.SUSPECTED)
        return {
            "verified": verified, "status": status.value,
            "confidence": .96 if verified else (.7 if both_tokens else .15),
            "vuln_type": "Server-Side Template Injection (SSTI, JSON body)",
            "baseline": baseline, "probes": responses, "verification_checks": checks + [
                {"name": "equivalent_response_context", "passed": equivalent_context,
                 "similarity": round(context_similarity, 3)},
                {"name": "injection_surface", "passed": True}],
            "false_positive_reasons": [],
            "missing_evidence": [] if verified else ["Two consistent differential arithmetic evaluations are required"],
            "verification_note": "Two distinct arithmetic expressions in JSON bodies produced exact, baseline-absent results." if verified
                else "Differential arithmetic evaluation inside a JSON body was not deterministically proven.",
        }

    ERROR_DISCLOSURE_MARKERS = [
        "Traceback (most recent call last)", "File \"", "line, in ", "at com.",
        "org.springframework.", "javax.servlet.", "java.lang.",
        "System.Data.SqlClient", "Microsoft.Data.SqlClient", "Npgsql.", "MySqlConnector",
        "psycopg2.errors", "sqlalchemy.exc.", "django.db.utils", "MySQLdb._exceptions",
        "PHP Fatal error", "Fatal error: Uncaught", "Stack trace:", ".php on line",
        "You have an error in your SQL syntax", "syntax error at or near",
        "pg_query()", "mysqli_query()", "Traceback", "KeyError: ", "TypeError: ",
        "NameError: ", "AttributeError: ", "ValueError: ", "IndexError: ", "Unhandled exception",
        "Express", "at async ", "_http_outgoing", "SyntaxError: Unexpected token",
    ]

    ERROR_DISCLOSURE_PAYLOADS = [
        "{\"q\":",                              # truncated / malformed JSON
        "{\"q\": {\"nested\": true}}",        # object where scalar expected
        "{\"q\": [1, 2, \"x\"]}",            # array where scalar expected
        "{\"q\": 123, \"q\": \"dup\"}",      # duplicate keys
    ]

    def probe_error_disclosure(self, target_url: str) -> Dict[str, Any]:
        """Sends malformed/type-confused JSON bodies and looks for canonical
        framework/database stack markers. VERIFIED only when a real stack marker
        appears and the response was not merely echoing our sent payload."""
        headers = self._json_post_headers()
        observed = []
        for payload in self.ERROR_DISCLOSURE_PAYLOADS:
            response = self.send_http_request(target_url, method="POST", headers=dict(headers),
                                              body=payload, priority="verification")
            body = response.get("body", "") or ""
            status = response.get("status_code")
            lowered = body.lower()
            marker = next((m for m in self.ERROR_DISCLOSURE_MARKERS if m.lower() in lowered), None)
            # A response that just echoes our literal payload back is not a leak.
            echoed = bool(payload and payload in body)
            if marker and not echoed and status in (400, 500):
                observed.append({"payload_sent": payload, "status_code": status, "marker": marker,
                                 "response_preview": body[:400]})
        verified = bool(observed)
        return {
            "verified": verified,
            "status": FindingStatus.VERIFIED.value if verified else FindingStatus.SUSPECTED.value,
            "confidence": .92 if verified else .1,
            "vuln_type": "Error/Stack-Trace Disclosure on Malformed Input", "test_url": target_url,
            "evidence": {"observed_leaks": observed, "payloads_sent": self.ERROR_DISCLOSURE_PAYLOADS,
                         "leak_count": len(observed)},
            "verification_note": "Malformed JSON input made the server leak a canonical stack/database error marker." if verified
                else "Malformed-input responses did not expose stack or database error markers.",
        }

    def verify_idor(self, target_url: str, unauthorized_headers: Optional[Dict[str, str]] = None,
                    owner_response: Optional[dict] = None, expected_owner_id: Optional[str] = None) -> Dict[str, Any]:
        test = self.send_http_request(target_url, headers=unauthorized_headers)
        comparable = bool(owner_response and expected_owner_id)
        owner_marker = bool(expected_owner_id and expected_owner_id in test.get("body", ""))
        verified = bool(comparable and test.get("status_code") == 200 and owner_marker)
        return {
            "verified": verified, "status": FindingStatus.VERIFIED.value if verified else FindingStatus.SUSPECTED.value,
            "vuln_type": "IDOR / Broken Object Level Authorization", "test_url": target_url,
            "evidence": {"status_code": test.get("status_code"), "owner_context_compared": comparable,
                         "expected_owner_marker_observed": owner_marker},
            "missing_evidence": [] if verified else ["Owner-controlled A/B object comparison is required"],
            "raw_request": test.get("raw_request", ""), "raw_response": test.get("raw_response", ""),
            "verification_note": "Unauthorized context returned the other owner's controlled object." if verified
                else "Changing an object identifier or receiving HTTP 200 alone does not prove IDOR.",
        }

    @staticmethod
    def _format_raw_request(method: str, url: str, headers: Dict[str, str], body: Optional[str]) -> str:
        parsed = urllib.parse.urlparse(url)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        lines = [f"{method.upper()} {path} HTTP/1.1", f"Host: {parsed.netloc}"]
        for key, value in headers.items():
            if str(key).lower() in _SENSITIVE_HEADERS:
                lines.append(f"{key}: [REDACTED]")
            else:
                lines.append(f"{key}: {value}")
        lines.append("")
        if body:
            lines.append(body)
        return "\n".join(lines)

    def set_session_auth(self, headers: Dict[str, str], netloc: Optional[str] = None,
                         cookies: Optional[Dict[str, str]] = None,
                         origin: Optional[str] = None) -> None:
        """Store auth headers replayed only to the same netloc.

        The token stays in process memory; it is never written to evidence,
        reports, or the dashboard.  Callers that need identity comparison
        (AuthorizationBypassEngine) keep passing explicit headers, which
        always take precedence over session auth.
        """
        self._auth_headers = dict(headers or {})
        self._auth_netloc = netloc
        self._auth_cookies = dict(cookies or {})
        self._auth_origin = origin

    def has_session_auth(self) -> bool:
        """Return True if session authentication is active."""
        return bool(self._auth_headers) and bool(self._auth_netloc)

    def login_session(self, auth_url: str, username: str, password: str,
                      username_field: str = "username", password_field: str = "password",
                      extra_fields: Optional[Dict[str, str]] = None,
                      token_paths: Optional[List[str]] = None,
                      token_header: str = "Authorization",
                      token_prefix: str = "Bearer ") -> Dict[str, Any]:
        """Login once via the scoped verifier and store the session token.

        Supported token sources (checked in order):
          1. JSON response body at one of token_paths (defaults to common
             token/access_token/data.token/result.token paths)
          2. Authorization response header
          3. Set-Cookie response header (stored as Cookie for replay)

        The extracted token is replayed only to the auth_url netloc.
        Returns a summary dict; the token itself is never returned.
        """
        parsed = urllib.parse.urlparse(auth_url)
        netloc = parsed.netloc
        if not netloc:
            return {"success": False, "error": "invalid auth URL"}
        payload: Dict[str, str] = {username_field: username, password_field: password}
        for key, value in (extra_fields or {}).items():
            payload[key] = value
        response = self.send_http_request(
            auth_url, method="POST",
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            body=json.dumps(payload),
        )
        status = response.get("status_code", 0)
        if status not in (200, 201):
            return {"success": False, "status_code": status,
                    "error": response.get("body", "")[:200] or response.get("error", "login failed")}
        resp_headers = response.get("headers", {}) or {}
        resp_body = response.get("body", "") or ""
        token: Optional[str] = None
        source = ""
        # 1. JSON body token paths
        try:
            data = json.loads(resp_body)
        except (TypeError, ValueError):
            data = None
        if data is not None:
            for path in (token_paths or ["token", "access_token", "accessToken",
                                         "data.token", "data.accessToken", "result.token",
                                         "data.access_token", "session.token"]):
                node = data
                ok = True
                for part in path.split("."):
                    if isinstance(node, dict) and part in node:
                        node = node[part]
                    else:
                        ok = False
                        break
                if ok and isinstance(node, str) and node.strip():
                    token = node.strip()
                    source = f"json:{path}"
                    break
        # 2. Authorization response header
        if not token:
            for key, value in resp_headers.items():
                if str(key).lower() == "authorization" and str(value).strip():
                    token = str(value).strip()
                    source = "header:authorization"
                    break
        # 3. Set-Cookie
        cookies: Dict[str, str] = {}
        if not token:
            for key, value in resp_headers.items():
                if str(key).lower() == "set-cookie":
                    cookie_name = str(value).split("=", 1)[0].strip()
                    cookie_value = str(value).split("=", 1)[1].split(";", 1)[0].strip()
                    cookies[cookie_name] = cookie_value
            if cookies:
                source = "cookie"
        if not token and not cookies:
            return {"success": False, "status_code": status,
                    "error": "no token found in login response"}
        auth_headers: Dict[str, str] = {}
        if token:
            if token_header.lower() == "authorization" and not token.lower().startswith(("bearer ", "basic ")):
                auth_headers[token_header] = token_prefix + token
            else:
                auth_headers[token_header] = token
        if cookies:
            auth_headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
        self.set_session_auth(auth_headers, netloc=netloc, cookies=cookies, origin=auth_url)
        return {"success": True, "status_code": status, "token_source": source,
                "auth_netloc": netloc, "auth_headers": list(auth_headers.keys())}

    @staticmethod
    def _format_raw_response(status_code: int, headers: Dict[str, str], body: str) -> str:
        lines = [f"HTTP/1.1 {status_code}"]
        lines.extend(f"{k}: {v}" for k, v in headers.items())
        text = body or ""
        lines.extend(["", text[:1500] + ("\n... [truncated]" if len(text) > 1500 else "")])
        return "\n".join(lines)
