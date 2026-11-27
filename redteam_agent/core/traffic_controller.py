"""Central request pacing, concurrency, retry/backoff, and budget accounting."""

from __future__ import annotations

import random
import threading
import time
import urllib.parse
from collections import Counter, defaultdict, deque
from contextlib import contextmanager
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from typing import Callable, Optional

from redteam_agent.core.config import DEFAULT_REQUEST_BUDGET, DEFAULT_TRAFFIC_PRESET, DEFAULT_VERIFICATION_RESERVE, get_traffic_profile


class RequestBudgetExceeded(RuntimeError):
    pass


class TrafficStopped(RuntimeError):
    pass


@dataclass
class HostState:
    current_rps: float
    next_allowed: float = 0.0
    backoff_until: float = 0.0
    pressure_events: int = 0
    stable_responses: int = 0
    latency_ema: Optional[float] = None


class TrafficController:
    def __init__(self, preset: str = DEFAULT_TRAFFIC_PRESET, max_requests: Optional[int] = DEFAULT_REQUEST_BUDGET,
                 verification_reserve: int = DEFAULT_VERIFICATION_RESERVE, event_callback: Optional[Callable[[str], None]] = None):
        self.preset = preset.upper()
        self.config = get_traffic_profile(self.preset)
        self.max_requests = max_requests
        self.verification_reserve = max(0, verification_reserve)
        if max_requests is not None:
            self.verification_reserve = min(self.verification_reserve, max(1, max_requests // 5))
        self.event_callback = event_callback
        self._lock = threading.RLock()
        self._global_sem = threading.BoundedSemaphore(self.config["global_concurrency"])
        self._host_sems: dict[str, threading.BoundedSemaphore] = {}
        self._hosts: dict[str, HostState] = {}
        self._global_next = 0.0
        self._stopped = False
        self.requests_sent = 0
        self.requests_by_host = Counter()
        self.requests_by_module = Counter()
        self.status_counts = Counter()
        self.events = deque(maxlen=200)

    def _event(self, message: str) -> None:
        stamped = f"[TRAFFIC] {message}"
        self.events.append(stamped)
        if self.event_callback:
            self.event_callback(stamped)

    def kill(self) -> None:
        with self._lock:
            self._stopped = True
            self._event("kill switch activated")

    def _host(self, url: str) -> str:
        return (urllib.parse.urlsplit(url).hostname or "unknown").lower()

    def _host_state(self, host: str) -> HostState:
        if host not in self._hosts:
            self._hosts[host] = HostState(float(self.config["per_host_rps"]))
            self._host_sems[host] = threading.BoundedSemaphore(self.config["per_host_concurrency"])
        return self._hosts[host]

    def _claim_budget(self, host: str, module: str, priority: str) -> int:
        if self._stopped:
            raise TrafficStopped("Traffic controller kill switch is active")
        if self.max_requests is not None:
            remaining = self.max_requests - self.requests_sent
            if remaining <= 0:
                raise RequestBudgetExceeded("Request budget exhausted")
            if priority != "verification" and remaining <= self.verification_reserve:
                raise RequestBudgetExceeded("Remaining request budget is reserved for verification")
        self.requests_sent += 1
        self.requests_by_host[host] += 1
        self.requests_by_module[module] += 1
        return self.requests_sent

    @contextmanager
    def request_slot(self, url: str, module: str = "http", priority: str = "normal"):
        host = self._host(url)
        with self._lock:
            state = self._host_state(host)
            request_number = self._claim_budget(host, module, priority)
            # Claim this request's start time under the lock, then sleep for it
            # *outside* every semaphore.  Sleeping while holding a concurrency
            # slot made the pacing wait head-of-line block the whole pool: with
            # per_host_rps of 3 the slot was occupied for up to 333 ms doing
            # nothing, so throughput collapsed well below the configured limits.
            now = time.monotonic()
            wait_until = max(self._global_next, state.next_allowed, state.backoff_until)
            global_interval = 1.0 / max(float(self.config["global_rps"]), 0.01)
            host_interval = 1.0 / max(state.current_rps, 0.01)
            self._global_next = max(now, wait_until) + global_interval
            state.next_allowed = max(now, wait_until) + host_interval
        delay = wait_until - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        self._global_sem.acquire()
        try:
            self._host_sems[host].acquire()
            try:
                yield {"request_number": request_number, "host": host}
            finally:
                self._host_sems[host].release()
        finally:
            self._global_sem.release()

    @staticmethod
    def _retry_after_seconds(value: Optional[str]) -> float:
        if not value:
            return 0.0
        try:
            return max(0.0, float(value))
        except ValueError:
            try:
                return max(0.0, parsedate_to_datetime(value).timestamp() - time.time())
            except Exception:
                return 0.0

    def observe_response(self, url: str, status_code: int, headers: Optional[dict] = None,
                         latency: Optional[float] = None, error: Optional[str] = None) -> None:
        host = self._host(url)
        headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
        with self._lock:
            state = self._host_state(host)
            if status_code:
                self.status_counts[str(status_code)] += 1
            previous_ema = state.latency_ema
            if latency is not None:
                state.latency_ema = latency if previous_ema is None else (previous_ema * .8 + latency * .2)
            latency_spike = previous_ema is not None and latency is not None and latency > max(previous_ema * 3, previous_ema + 2)
            reset = bool(error and any(token in error.lower() for token in ("reset", "broken pipe", "disconnect")))
            pressured = status_code in {429, 503} or "retry-after" in headers or latency_spike or reset
            if pressured and self.config["adaptive_backoff"]:
                old = state.current_rps
                state.pressure_events += 1
                state.stable_responses = 0
                state.current_rps = max(1.0, old - 1.0) if old > 1 else max(0.5, old / 2)
                retry_after = self._retry_after_seconds(headers.get("retry-after")) if self.config["respect_retry_after"] else 0
                exponential = min(30.0, (2 ** min(state.pressure_events, 5)) + random.uniform(0, .25))
                state.backoff_until = max(state.backoff_until, time.monotonic() + max(retry_after, exponential))
                self._event(f"{status_code or 'connection pressure'} detected on {host}; reducing host limit: {old:g} RPS -> {state.current_rps:g} RPS")
                if retry_after:
                    self._event(f"Retry-After on {host}: {retry_after:g} seconds")
            elif not pressured:
                state.stable_responses += 1
                if state.stable_responses >= 10 and state.current_rps < self.config["per_host_rps"]:
                    old = state.current_rps
                    state.current_rps = min(float(self.config["per_host_rps"]), old + 1.0)
                    state.pressure_events = max(0, state.pressure_events - 1)
                    state.stable_responses = 0
                    self._event(f"host {host} recovered; increasing to {state.current_rps:g} RPS")

    def retry_delay(self, attempt: int, headers: Optional[dict] = None) -> float:
        """Single global backoff definition, shared with the HTTP verifier."""
        cap = 30.0
        backoff = min(cap, (2 ** max(0, min(int(attempt), 5))) + random.uniform(0, .25))
        if headers and self.config.get("respect_retry_after"):
            lowered = {str(k).lower(): str(v) for k, v in headers.items()}
            retry_after = self._retry_after_seconds(lowered.get("retry-after"))
            if retry_after:
                return min(cap, max(backoff, retry_after))
        return backoff

    def stats(self) -> dict:
        with self._lock:
            remaining = None if self.max_requests is None else max(0, self.max_requests - self.requests_sent)
            return {
                "preset": self.preset, **self.config,
                "max_requests": self.max_requests, "verification_reserve": self.verification_reserve,
                "requests_sent": self.requests_sent, "requests_remaining": remaining,
                "requests_by_host": dict(self.requests_by_host), "requests_by_module": dict(self.requests_by_module),
                "429_count": self.status_counts.get("429", 0), "503_count": self.status_counts.get("503", 0),
                "current_throttle_state": {host: round(state.current_rps, 2) for host, state in self._hosts.items()},
                "kill_switch": self._stopped, "events": list(self.events),
            }
