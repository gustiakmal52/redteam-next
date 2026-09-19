"""Fresh-context browser verification for XSS and browser-readable CORS proof."""

from __future__ import annotations

import os
import shutil
import threading
import time
import urllib.parse
from typing import Any, Mapping, Optional

from redteam_agent.core.scope_manager import ScopeManager
from redteam_agent.core.traffic_controller import RequestBudgetExceeded, TrafficController, TrafficStopped

try:  # Optional at import time so static/HTTP-only scans remain lightweight.
    from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
    from playwright.sync_api import sync_playwright
except ImportError:  # pragma: no cover - depends on deployment extras
    PlaywrightTimeoutError = TimeoutError
    sync_playwright = None


class BrowserVerificationUnavailable(RuntimeError):
    pass


class BrowserVerifier:
    """Run one-off proofs in a fresh, isolated browser context.

    No ambient profile, cookies, storage, response bodies, or credential values
    are read. Optional headers are caller-supplied researcher context and are
    never returned in proof records.
    """

    def __init__(self, *, scope_manager: Optional[ScopeManager] = None,
                 traffic_controller: Optional[TrafficController] = None,
                 timeout_ms: int = 7000, executable_path: Optional[str] = None):
        self.scope = scope_manager
        self.traffic = traffic_controller
        self.timeout_ms = max(1000, int(timeout_ms))
        self.executable_path = executable_path or shutil.which("chromium") or shutil.which("google-chrome")
        self._browser = None
        self._stop_requested = threading.Event()
        self._auxiliary_origin = ""

    @staticmethod
    def available() -> bool:
        return sync_playwright is not None

    @staticmethod
    def _driver_ready() -> bool:
        if sync_playwright is None:
            return False
        try:
            from playwright._impl._transport import compute_driver_executable
            _node, driver = compute_driver_executable()
            return bool(driver and os.path.isfile(driver))
        except Exception:
            # A future Playwright packaging layout may not expose the internal
            # helper; the launch probe below remains the final authority.
            return True

    @classmethod
    def runtime_available(cls, executable_path: Optional[str] = None) -> bool:
        """Return true only when the Python driver and Chromium can launch.

        Some Linux distributions ship the Python bindings without the matching
        Playwright Node driver. Import success alone would then create a false
        impression that browser execution proof is available.
        """
        if sync_playwright is None or not cls._driver_ready():
            return False
        executable = executable_path or shutil.which("chromium") or shutil.which("google-chrome")
        if not executable:
            return False
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True, executable_path=executable)
                browser.close()
            return True
        except Exception:
            return False

    def _route_handler(self, route: Any) -> None:
        request = route.request
        url = str(request.url)
        if self._stop_requested.is_set():
            route.abort()
            return
        if self._auxiliary_origin:
            parsed = urllib.parse.urlsplit(url)
            request_origin = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
            if request_origin == self._auxiliary_origin:
                # The researcher origin is a browser-only synthetic page. It
                # is fulfilled locally and is never fetched or added to target
                # scope; only the subsequent target request is active.
                route.fulfill(status=200, content_type="text/html",
                              body="<!doctype html><html><body>cors probe</body></html>")
                return
        if self.scope is not None:
            decision = self.scope.check_url(url, active=True)
            if not decision.get("allowed"):
                route.abort()
                return
        try:
            if self.traffic is not None:
                with self.traffic.request_slot(url, module="browser_verify", priority="verification"):
                    # ``route.fetch`` + ``fulfill`` is required for a browser
                    # page whose researcher origin is fulfilled in-memory;
                    # plain ``continue_`` can leave that cross-origin fetch in
                    # an unobservable pending state in Chromium. The target
                    # request still traverses the browser and the same budget.
                    response = route.fetch()
                    route.fulfill(response=response)
            else:
                response = route.fetch()
                route.fulfill(response=response)
        except (RequestBudgetExceeded, TrafficStopped):
            route.abort()
        except Exception:
            route.abort()

    def _response_observer(self, response: Any) -> None:
        if self.traffic is None:
            return
        try:
            self.traffic.observe_response(str(response.url), int(response.status), dict(response.headers))
        except Exception:
            # Browser proof must not fail because a provider exposes unusual
            # response metadata. The request budget was already accounted for.
            return

    def verify_reflected_xss(self, target_url: str, param: str, payload: str, *,
                             canary: str = "AGY_XSS_9981",
                             headers: Optional[Mapping[str, str]] = None) -> dict[str, Any]:
        """Navigate to the exact reflected payload and require execution."""
        if sync_playwright is None or not self._driver_ready():
            return {"verified": False, "available": False, "browser_execution": False,
                    "reason": "Playwright browser driver is not installed or is incomplete"}
        if self._stop_requested.is_set():
            return {"verified": False, "available": True, "browser_execution": False,
                    "reason": "browser verification stopped by kill switch"}
        if self.scope is not None and not self.scope.check_url(target_url, active=True).get("allowed"):
            return {"verified": False, "available": True, "browser_execution": False,
                    "reason": "target URL rejected by scope policy"}
        from redteam_agent.core.http_verifier import HTTPVerifier
        test_url = HTTPVerifier._url_with_param(target_url, param, payload)
        if self.scope is not None and not self.scope.check_url(test_url, active=True).get("allowed"):
            return {"verified": False, "available": True, "browser_execution": False,
                    "reason": "payload URL rejected by scope policy"}
        executed = {"value": False}
        response_status = 0
        started = time.monotonic()
        try:
            with sync_playwright() as playwright:
                launch_options = {"headless": True}
                if self.executable_path:
                    launch_options["executable_path"] = self.executable_path
                browser = playwright.chromium.launch(**launch_options)
                self._browser = browser
                context = browser.new_context(
                    ignore_https_errors=False,
                    extra_http_headers={str(k): str(v) for k, v in (headers or {}).items()},
                )
                context.route("**/*", self._route_handler)
                page = context.new_page()
                page.on("response", self._response_observer)

                def on_dialog(dialog: Any) -> None:
                    if str(dialog.message) == str(canary):
                        executed["value"] = True
                    dialog.dismiss()

                page.on("dialog", on_dialog)
                response = page.goto(test_url, wait_until="domcontentloaded", timeout=self.timeout_ms)
                response_status = int(response.status) if response is not None else 0
                try:
                    page.wait_for_timeout(250)
                    property_hit = bool(page.evaluate(
                        "Boolean(window.__AGY_XSS_CANARY__ || window.__AGY_XSS_CANARY_EXECUTED__)"))
                    executed["value"] = bool(executed["value"] or property_hit)
                except Exception:
                    pass
                context.close()
                browser.close()
                self._browser = None
        except (PlaywrightTimeoutError, RequestBudgetExceeded, TrafficStopped) as exc:
            return {"verified": False, "available": True, "browser_execution": False,
                    "status_code": response_status, "reason": str(exc)[:300],
                    "elapsed_sec": round(time.monotonic() - started, 3)}
        except Exception as exc:
            return {"verified": False, "available": True, "browser_execution": False,
                    "status_code": response_status, "reason": str(exc)[:300],
                    "elapsed_sec": round(time.monotonic() - started, 3)}
        return {
            "verified": bool(executed["value"]), "available": True,
            "browser_execution": bool(executed["value"]),
            "canary": str(canary), "status_code": response_status,
            "elapsed_sec": round(time.monotonic() - started, 3),
            "context": "fresh_isolated_context", "credentials_retained": False,
        }

    def verify_cors_read(self, target_url: str, *, researcher_origin: str,
                         headers: Optional[Mapping[str, str]] = None,
                         expected_marker: str = "") -> dict[str, Any]:
        """Prove that a synthetic researcher origin can read the target.

        The auxiliary origin is fulfilled inside the browser route handler, so
        this method never expands network scope to a third-party origin. The
        target request itself is still subject to ScopeManager and the shared
        TrafficController. Response bodies remain inside the page and are
        reduced to length/content-type/marker metadata before returning.
        """
        if sync_playwright is None or not self._driver_ready():
            return {"verified": False, "available": False,
                    "read_authenticated_response": False,
                    "reason": "Playwright browser driver is not installed or is incomplete"}
        if self._stop_requested.is_set():
            return {"verified": False, "available": True,
                    "read_authenticated_response": False,
                    "reason": "browser verification stopped by kill switch"}
        if self.scope is not None and not self.scope.check_url(target_url, active=True).get("allowed"):
            return {"verified": False, "available": True,
                    "read_authenticated_response": False,
                    "reason": "target URL rejected by scope policy"}
        parsed_origin = urllib.parse.urlsplit(str(researcher_origin or ""))
        if parsed_origin.scheme.lower() not in {"http", "https"} or not parsed_origin.netloc \
                or parsed_origin.username or parsed_origin.password:
            return {"verified": False, "available": True,
                    "read_authenticated_response": False,
                    "reason": "researcher_origin must be an absolute http(s) origin without userinfo"}
        origin = f"{parsed_origin.scheme.lower()}://{parsed_origin.netloc.lower()}"
        probe_url = origin + "/__agy_cors_probe__"
        browser_headers = {
            str(key): str(value) for key, value in (headers or {}).items()
            if str(key).lower() not in {"origin", "host", "content-length"}
        }
        started = time.monotonic()
        response_metadata: dict[str, Any] = {}
        self._auxiliary_origin = origin
        try:
            with sync_playwright() as playwright:
                launch_options = {"headless": True}
                if self.executable_path:
                    launch_options["executable_path"] = self.executable_path
                browser = playwright.chromium.launch(**launch_options)
                self._browser = browser
                context = browser.new_context(ignore_https_errors=False,
                                              extra_http_headers=browser_headers)
                context.route("**/*", self._route_handler)
                page = context.new_page()
                page.on("response", self._response_observer)
                page.goto(probe_url, wait_until="domcontentloaded", timeout=self.timeout_ms)
                response_metadata = page.evaluate(
                    """async ({target, marker}) => {
                        try {
                            const response = await fetch(target, {credentials: 'include'});
                            const contentType = response.headers.get('content-type') || '';
                            const text = await response.text();
                            return {
                                readable: true,
                                status: response.status,
                                content_type: contentType,
                                body_length: text.length,
                                marker_found: Boolean(marker && text.includes(marker))
                            };
                        } catch (error) {
                            return {readable: false, error: String(error).slice(0, 240)};
                        }
                    }""",
                    {"target": str(target_url), "marker": str(expected_marker or "")},
                ) or {}
                context.close()
                browser.close()
                self._browser = None
        except (PlaywrightTimeoutError, RequestBudgetExceeded, TrafficStopped) as exc:
            return {"verified": False, "available": True,
                    "read_authenticated_response": False,
                    "reason": str(exc)[:300],
                    "elapsed_sec": round(time.monotonic() - started, 3)}
        except Exception as exc:
            return {"verified": False, "available": True,
                    "read_authenticated_response": False,
                    "reason": str(exc)[:300],
                    "elapsed_sec": round(time.monotonic() - started, 3)}
        finally:
            self._auxiliary_origin = ""
        readable = bool(response_metadata.get("readable"))
        marker_found = bool(response_metadata.get("marker_found"))
        return {
            "verified": readable and (not expected_marker or marker_found),
            "available": True,
            "read_authenticated_response": readable and (not expected_marker or marker_found),
            "response_status": response_metadata.get("status", 0),
            "content_type": str(response_metadata.get("content_type", "")),
            "body_length": int(response_metadata.get("body_length", 0) or 0),
            "marker_found": marker_found,
            "error": str(response_metadata.get("error", ""))[:240],
            "origin": origin,
            "elapsed_sec": round(time.monotonic() - started, 3),
            "context": "fresh_isolated_context",
            "credentials_retained": False,
        }

    def stop(self) -> None:
        """Best-effort kill-switch hook for an active browser proof."""
        self._stop_requested.set()
        browser = self._browser
        if browser is not None:
            try:
                browser.close()
            except Exception:
                pass
            self._browser = None
        self._auxiliary_origin = ""


__all__ = ["BrowserVerificationUnavailable", "BrowserVerifier"]
