"""Offline throughput benchmark for the shared HTTP request path.

Runs a throwaway threaded HTTP/1.1 server on loopback, drives HTTPVerifier
through it with a fixed worker count, and reports wall time, throughput,
latency percentiles and — most importantly — how many TCP connections the
verifier actually opened.  A tool that forces ``Connection: close`` opens one
connection per request; a keep-alive transport opens roughly one per worker.

Nothing here touches a real target: the server is local, in-process, and it is
shut down before the script exits.

Usage:
    python3 redteam_lab/bench_request_path.py                       # no pacing
    python3 redteam_lab/bench_request_path.py --preset NORMAL       # real pacing
    python3 redteam_lab/bench_request_path.py --handshake-cost 0.06 # simulate WAN
"""

from __future__ import annotations

import argparse
import socket
import statistics
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from redteam_agent.core.http_verifier import HTTPVerifier  # noqa: E402
from redteam_agent.core.scope_manager import ScopeManager  # noqa: E402
from redteam_agent.core.traffic_controller import TrafficController  # noqa: E402


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # keep-alive capable; requires Content-Length
    server_version = "BenchLab/1.0"

    def _respond(self) -> None:
        body = b'{"ok":true,"bench":1}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = do_HEAD = do_POST = do_PUT = _respond

    def log_message(self, *args) -> None:  # keep the console clean
        pass


class _BenchServer(ThreadingHTTPServer):
    """Threaded server that counts accepted TCP connections."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, handler, handshake_cost: float = 0.0):
        super().__init__(addr, handler)
        self.handshake_cost = max(0.0, handshake_cost)
        self.connections = 0
        self._counter_lock = threading.Lock()

    def get_request(self):
        sock, addr = super().get_request()
        # Real servers (nginx, CDNs) disable Nagle; socketserver does not, and
        # leaving it on makes the harness itself add ~40 ms delayed-ACK stalls
        # that would be misread as request-path latency.
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        with self._counter_lock:
            self.connections += 1
        if self.handshake_cost:
            # Simulates the per-connection cost of a WAN round trip (TCP + TLS
            # handshake) that keep-alive amortises and Connection: close cannot.
            time.sleep(self.handshake_cost)
        return sock, addr


def _pct(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, int(round(q * (len(ordered) - 1))))
    return ordered[idx]


def run_phase(name: str, base_url: str, verifier: HTTPVerifier, server: _BenchServer,
              total: int, workers: int) -> dict:
    results: list[dict] = []
    lock = threading.Lock()

    def one(index: int) -> None:
        response = verifier.send_http_request(f"{base_url}/bench/{index}", priority="normal")
        with lock:
            results.append(response)

    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(one, range(total)))
    wall = time.perf_counter() - started

    ok = [r for r in results if r.get("status_code") == 200]
    latencies = [float(r.get("response_time_sec") or 0.0) for r in ok]
    failures = len(results) - len(ok)
    stats = {
        "phase": name,
        "requests": total,
        "workers": workers,
        "wall_sec": round(wall, 3),
        "rps": round(total / wall, 2) if wall else 0.0,
        "ok": len(ok),
        "failed": failures,
        "p50_ms": round(_pct(latencies, 0.50) * 1000, 2),
        "p95_ms": round(_pct(latencies, 0.95) * 1000, 2),
        "conns_opened": server.connections,
        "conns_per_request": round(server.connections / total, 3) if total else 0.0,
    }
    if latencies:
        stats["mean_ms"] = round(statistics.fmean(latencies) * 1000, 2)
    return stats


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline request-path throughput benchmark")
    parser.add_argument("--requests", type=int, default=120)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--preset", default=None,
                        help="Traffic preset to honour (NORMAL/FAST/STEALTH). Omit for unpaced transport cost.")
    parser.add_argument("--handshake-cost", type=float, default=0.0,
                        help="Seconds of simulated per-connection cost (WAN handshake model)")
    parser.add_argument("--label", default="", help="Free-form label printed with the result")
    args = parser.parse_args()

    server = _BenchServer(("127.0.0.1", 0), _Handler, handshake_cost=args.handshake_cost)
    port = server.server_address[1]
    base_url = f"http://127.0.0.1:{port}"
    threading.Thread(target=server.serve_forever, daemon=True).start()

    try:
        if args.preset:
            controller = TrafficController(preset=args.preset, max_requests=None)
            controller.config = {**controller.config,
                                 "global_concurrency": max(args.workers, controller.config["global_concurrency"]),
                                 "per_host_concurrency": max(args.workers, controller.config["per_host_concurrency"])}
        else:
            # No pacing: isolates transport cost (connection setup, headers, body).
            controller = TrafficController(preset="FAST", max_requests=None)
            controller.config = {**controller.config, "global_rps": 10000.0, "per_host_rps": 10000.0,
                                 "global_concurrency": args.workers, "per_host_concurrency": args.workers}

        scope = ScopeManager.from_target(base_url, allow_private=True)
        verifier = HTTPVerifier(timeout=15.0, traffic_controller=controller, scope_manager=scope,
                                module="bench")

        # Warm the path once so import/first-connection noise stays out of the numbers.
        verifier.send_http_request(f"{base_url}/warmup", priority="normal")
        server.connections = 0

        stats = run_phase("measured", base_url, verifier, server, args.requests, args.workers)
    finally:
        server.shutdown()
        server.server_close()

    print(f"--- request-path benchmark {('[' + args.label + '] ') if args.label else ''}---")
    print(f"python      : {sys.version.split()[0]}")
    print(f"requests    : {stats['requests']}  workers: {stats['workers']}  "
          f"pacing: {args.preset or 'OFF'}  simulated handshake: {args.handshake_cost}s")
    for key in ("wall_sec", "rps", "ok", "failed", "p50_ms", "mean_ms", "p95_ms",
                "conns_opened", "conns_per_request"):
        if key in stats:
            print(f"{key:12}: {stats[key]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
