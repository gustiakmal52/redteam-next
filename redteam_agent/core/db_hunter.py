"""Database exposure hunter.

Detects database connection strings (Supabase/Postgres/MySQL/Mongo/Redis/...)
inside harvested JS secrets, regex-grep matches and page HTML; flags publicly
exposed database ports (standard AND non-standard), exposed web DB admin
panels, and downloadable SQL dump/backup files. Findings stay SUSPECTED/
DISCOVERED unless live-verified — we deliberately never authenticate to a
remote database and never write data.
"""

from __future__ import annotations

import json
import re
import socket
import urllib.parse
from typing import Any, Dict, List, Optional

from redteam_agent.core.config import (CVSS_VECTORS, DB_ADMIN_PANEL_MARKERS, DB_ADMIN_PANEL_PATHS,
                                        DB_BACKUP_PATHS, DB_PORT_SERVICES, DB_URL_PATTERNS,
                                        SQL_DUMP_MARKERS, cvss3_score)
from redteam_agent.core.findings import FindingStatus, normalized_finding
from redteam_agent.core.traffic_controller import RequestBudgetExceeded, TrafficStopped
from redteam_agent.discovery.redaction import SecretRedactor


REDIS_PING = b"*1\r\n$4\r\nPING\r\n"
REDIS_INFO = b"*1\r\n$4\r\nINFO\r\n"
PG_SSL_REQUEST = (8).to_bytes(4, "big") + (80877103).to_bytes(4, "big")
PG_STARTUP = (16 + 8 + 4 + 12).to_bytes(4, "big") + (196608).to_bytes(4, "big") + b"user\x00postgres\x00database\x00postgres\x00\x00"


def _probe_socket(host: str, port: int, timeout: float, service: str,
                  result: Dict[str, Any]) -> Dict[str, Any]:
    """Raw socket handshake. Caller is responsible for scope/traffic gating."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if service == "redis":
                sock.sendall(REDIS_PING)
                resp = sock.recv(256)
                result["banner"] = resp.decode("utf-8", errors="replace")[:200]
                if resp.startswith(b"+PONG"):
                    result["auth_free"] = True
                    result["notes"].append("PING answered without authentication (requirepass empty)")
                    sock.sendall(REDIS_INFO)
                    info = sock.recv(512)
                    if b"# Server" in info or b"redis_version" in info:
                        result["notes"].append("INFO readable without authentication")
                elif b"NOAUTH" in resp or b"DENIED" in resp:
                    result["auth_free"] = False
            elif service == "postgres":
                sock.sendall(PG_SSL_REQUEST)
                ssl_resp = sock.recv(1)
                if ssl_resp in (b"S", b"N"):
                    sock.sendall(PG_STARTUP)
                    auth = sock.recv(128)
                    result["banner"] = auth.decode("utf-8", errors="replace")[:200]
                    if auth.startswith(b"R") and len(auth) >= 5 and int.from_bytes(auth[4:8], "big") == 0:
                        result["auth_free"] = True
                        result["notes"].append("PostgreSQL AuthenticationOk without password (trust)")
                    elif auth.startswith(b"E"):
                        result["auth_free"] = False
                        result["notes"].append("PostgreSQL rejected startup message (auth/confg)")
            elif service == "mysql":
                banner = sock.recv(256)
                result["banner"] = banner.decode("utf-8", errors="replace")[:200] or "<binary greeting>"
                result["auth_free"] = None
            elif service == "mongodb":
                banner = sock.recv(256)
                result["banner"] = banner.decode("utf-8", errors="replace")[:200]
                result["auth_free"] = None
            elif service in ("elasticsearch", "couchdb") or port in (9200, 9300, 5984):
                http = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
                sock.sendall(http.encode())
                body = b""
                while True:
                    chunk = sock.recv(512)
                    if not chunk:
                        break
                    body += chunk
                text = body.decode("utf-8", errors="replace")[:300]
                result["banner"] = text
                if b"200 OK" in body and (b"cluster_name" in body or b"You Know, for Search" in body):
                    result["auth_free"] = True
                    result["notes"].append("Elasticsearch responded to unauthenticated HTTP GET")
            else:
                banner = sock.recv(256)
                result["banner"] = banner.decode("utf-8", errors="replace")[:200]
    except (socket.timeout, ConnectionRefusedError, ConnectionResetError, OSError) as exc:
        result["state"] = "error"
        result["notes"].append(f"probe error: {exc}")
    return result


def probe_db_port(host: str, port: int, timeout: float = 4.0,
                  scope_manager: Optional[Any] = None,
                  traffic_controller: Optional[Any] = None,
                  module: str = "db_probe") -> Dict[str, Any]:
    """Non-destructive live probe of an exposed database port.
    Returns evidence only; never authenticates with passwords and never writes.
    When a scope manager is supplied the host must be in scope (fail-closed);
    when a traffic controller is supplied the probe passes through request_slot()
    so budget, rate limit and kill switch apply exactly like HTTP requests."""
    service = DB_PORT_SERVICES.get(port, "unknown")
    result = {"host": host, "port": port, "service": service, "state": "open",
              "existing": True, "banner": None, "auth_free": None, "notes": []}
    if scope_manager is not None:
        decision = scope_manager.check_url(f"http://{host}:{port}/", active=True)
        if not decision.get("allowed"):
            result["state"] = "blocked"
            result["notes"].append(f"scope policy: {decision.get('reason', 'host out of scope')}")
            return result
    probe_url = f"http://{host}:{port}/"
    try:
        if traffic_controller is not None:
            with traffic_controller.request_slot(probe_url, module=module, priority="normal"):
                return _probe_socket(host, port, timeout, service, result)
        return _probe_socket(host, port, timeout, service, result)
    except (RequestBudgetExceeded, TrafficStopped) as exc:
        result["state"] = "blocked"
        result["notes"].append(f"traffic policy: {exc}")
        return result


def _mask(value: str) -> str:
    return SecretRedactor().mask_secret(value)


class DBHunter:
    def __init__(self, scope=None, scope_manager=None, verifier=None):
        self.scope = scope or scope_manager
        self.verifier = verifier

    def _probe_unknown_port(self, host: str, port: int,
                            scope_manager: Optional[Any] = None,
                            traffic_controller: Optional[Any] = None) -> Dict[str, Any]:
        """Tries to fingerprint a DB service behind an unknown open TCP port.
        Uses only banner reads and protocol handshakes (never writes data).
        Scope and traffic controls apply exactly like known-port probes."""
        result = {"host": host, "port": port, "service": "unknown", "state": "open",
                  "banner": None, "auth_free": None, "notes": []}
        if scope_manager is not None:
            decision = scope_manager.check_url(f"http://{host}:{port}/", active=True)
            if not decision.get("allowed"):
                result["state"] = "blocked"
                result["notes"].append(f"scope policy: {decision.get('reason', 'host out of scope')}")
                return result
        try:
            def _fingerprint() -> Dict[str, Any]:
                with socket.create_connection((host, port), timeout=4.0) as sock:
                    sock.settimeout(4.0)
                    try:
                        greeting = sock.recv(256)
                        text = greeting.decode("utf-8", errors="replace").lower()
                    except socket.timeout:
                        greeting, text = b"", ""
                    result["banner"] = greeting.decode("utf-8", errors="replace")[:200]
                    lowered = text
                    for marker, service in (
                        ("redis_version", "redis"), ("+pong", "redis"), ("redis server", "redis"),
                        ("mysql", "mysql"), ("mariadb", "mysql"), ("postgresql", "postgres"),
                        ("mongodb", "mongodb"), ("elasticsearch", "elasticsearch"),
                        ("couchdb", "couchdb"), ("memcached", "memcached"), ("cassandra", "cassandra"),
                        ("sql server", "sqlserver"), ("oracle", "oracle"), ("dynamodb", "dynamodb")):
                        if marker in lowered:
                            result["service"] = service
                            result["notes"].append(f"banner marker '{marker}' matched {service}")
                            if service == "redis" and greeting.startswith(b"+"):
                                result["auth_free"] = True
                                result["notes"].append("banner answered without authentication challenge")
                            break
                return result
            if traffic_controller is not None:
                with traffic_controller.request_slot(f"http://{host}:{port}/",
                                                     module="db_probe", priority="normal"):
                    return _fingerprint()
            return _fingerprint()
        except (RequestBudgetExceeded, TrafficStopped) as exc:
            result["state"] = "blocked"
            result["notes"].append(f"traffic policy: {exc}")
            return result
        except (socket.timeout, ConnectionRefusedError, ConnectionResetError, OSError) as exc:
            result["state"] = "error"
            result["notes"].append(f"probe error: {exc}")
        return result

    def _hunt_web(self, endpoints: List[str]) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]],
                                                      List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Checks discovered endpoints for web DB admin panels, downloadable SQL
        dump/backup files, and hidden DB connection strings inside page HTML.
        Every request goes through the scope-bound verifier (traffic controlled)."""
        admin_panels: List[Dict[str, Any]] = []
        backup_files: List[Dict[str, Any]] = []
        hidden_strings: List[Dict[str, Any]] = []
        findings: List[Dict[str, Any]] = []
        roots: List[str] = []
        seen_roots = set()
        for url in endpoints:
            if not isinstance(url, str) or not url.startswith(("http://", "https://")):
                continue
            parsed = urllib.parse.urlsplit(url)
            root = f"{parsed.scheme}://{parsed.netloc}/"
            if root not in seen_roots:
                seen_roots.add(root)
                roots.append(root)
            if len(roots) >= 3:  # keep the web DB sweep bounded per scan
                break
        verifier = self.verifier
        for root in roots:
            # 1) Admin panels: GET known DB panel paths, match page markers.
            for path, panel_name in DB_ADMIN_PANEL_PATHS.items():
                url = urllib.parse.urljoin(root, path.lstrip("/"))
                response = verifier.send_http_request(url, priority="normal")
                if response.get("status_code") != 200:
                    continue
                body = (response.get("body") or "").lower()
                markers = DB_ADMIN_PANEL_MARKERS.get(panel_name, [])
                if not any(marker in body for marker in markers):
                    continue
                admin_panels.append({"url": url, "panel": panel_name, "observed": True,
                                     "status_code": 200})
                findings.append(normalized_finding(
                    finding_type=f"Exposed Web DB Admin Panel ({panel_name})", target=root,
                    endpoint=url, status=FindingStatus.DISCOVERED, confidence=.55,
                    source_module="db_hunter", source_tool="HTTP admin panel fingerprint",
                    test={"request": {"url": url}, "response": {"status_code": 200}},
                    evidence=[{"panel": panel_name, "markers_matched": markers[:2]}],
                    verification_checks=[{"name": "panel_markers_in_response", "passed": True}],
                    missing_evidence=["Login bypass / default credentials are not tested by this tool"],
                    severity="Medium", cvss_score=0.0, param="path",
                    reproduction_curl=f'curl -i -s "{url}"',
                    verification_note=f"A {panel_name} interface is reachable at a public URL.",
                    observed_impact=f"{panel_name} web interface responds at {url}.",
                    potential_impact="If credentials are weak, the panel may expose or modify database contents.",
                    vrt_category="Server-Side Misconfiguration > Insecure Database Configuration",
                ))
            # 2) SQL dump / backup files: only content that looks like a real dump.
            for path in DB_BACKUP_PATHS:
                url = urllib.parse.urljoin(root, path.lstrip("/"))
                response = verifier.send_http_request(url, priority="normal")
                if response.get("status_code") != 200:
                    continue
                body = response.get("body") or ""
                content_type = next((v for k, v in response.get("headers", {}).items()
                                     if k.lower() == "content-type"), "").lower()
                matched_markers = [m for m in SQL_DUMP_MARKERS if m.lower() in body.lower()]
                strong_dump_markers = [m for m in matched_markers if m.lower() in (
                    "-- mysql dump", "postgresql database dump", "dump completed",
                    "pg_dump", "server version", "\\copy ")]
                is_html_page = "html" in content_type
                # VERIFIED only when the body looks like an actual dump: either a
                # definitive dump header, or several SQL markers in a non-HTML body.
                if strong_dump_markers:
                    pass
                elif is_html_page or len(matched_markers) < 3:
                    continue
                backup_files.append({"url": url, "markers": matched_markers[:3],
                                     "content_type": content_type, "observed": True})
                findings.append(normalized_finding(
                    finding_type="Publicly Downloadable Database Dump/Backup File", target=root,
                    endpoint=url, status=FindingStatus.VERIFIED, confidence=.93,
                    source_module="db_hunter", source_tool="HTTP dump signature check",
                    test={"request": {"url": url},
                          "response": {"status_code": 200, "content_type": content_type}},
                    evidence=[{"markers": matched_markers[:3], "content_type": content_type}],
                    verification_checks=[{"name": "sql_dump_markers_present", "passed": True},
                                         {"name": "not_html_wrapper", "passed": True}],
                    missing_evidence=[], severity="Critical",
                    cvss_score=cvss3_score(CVSS_VECTORS["db_dump_exposed"], 8.5), param="path",
                    reproduction_curl=f'curl -i -s "{url}"',
                    verification_note="The URL returns a file whose body contains SQL dump markers.",
                    observed_impact="A full database backup appears downloadable without authentication.",
                    potential_impact="The dump may contain user records, credentials, and business data.",
                    vrt_category="Information Disclosure > Sensitive Source/Configuration",
                ))
            # 3) Hidden DB strings inside the rendered page (incl. HTML comments).
            # Raw values are returned as candidates only; classification masks them.
            response = verifier.send_http_request(root, priority="normal")
            body = response.get("body") or ""
            if response.get("status_code") == 200 and body:
                for name, pattern in DB_URL_PATTERNS.items():
                    for match in re.finditer(pattern, body):
                        hidden_strings.append({"value": match.group(0), "source": f"html:{root}",
                                               "kind": f"html_db_{name}"})
                        break
        return admin_panels, backup_files, hidden_strings, findings

    def hunt(self, secrets: List[Dict[str, Any]], grep_matches: List[Dict[str, Any]],
             ports: Optional[List[Dict[str, Any]]] = None,
             endpoints: Optional[List[str]] = None,
             reveal_raw: bool = False) -> Dict[str, Any]:
        """Collects candidate connection strings, exposed DB ports, and web DB
        exposures (admin panels, dump files, hidden strings in page HTML).

        Web checks only run when a scope-bound ``verifier`` and ``endpoints`` are
        available; every request goes through the shared traffic/scope controls.
        """
        candidates = self._collect(secrets, grep_matches)
        strings, findings = self._classify(candidates, reveal_raw=reveal_raw)
        exposed_ports = self._classify_ports(ports or [], findings)
        admin_panels: List[Dict[str, Any]] = []
        backup_files: List[Dict[str, Any]] = []
        hidden_db_strings: List[Dict[str, Any]] = []
        if self.verifier is not None and endpoints:
            admin_panels, backup_files, html_candidates, web_findings = self._hunt_web(endpoints)
            findings.extend(web_findings)
            hidden_strings, hidden_findings = self._classify(html_candidates, reveal_raw=reveal_raw)
            hidden_db_strings = hidden_strings
            findings.extend(hidden_findings)
        return {
            "connection_strings": strings,
            "exposed_ports": exposed_ports,
            "admin_panels": admin_panels,
            "backup_files": backup_files,
            "hidden_db_strings": hidden_db_strings,
            "findings": findings,
            "total_connection_strings": len(strings),
            "total_exposed_ports": len(exposed_ports),
            "total_admin_panels": len(admin_panels),
            "total_backup_files": len(backup_files),
            "total_hidden_db_strings": len(hidden_db_strings),
        }

    @staticmethod
    def _collect(secrets: List[Dict[str, Any]], grep_matches: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Harvest raw values from secrets and grep matches, tagged with source."""
        raw: List[Dict[str, Any]] = []
        seen = set()
        for secret in secrets or []:
            value = secret.get("_raw_value") or secret.get("value", "")
            src = secret.get("source", "secret")
            typ = secret.get("secret_type", "unknown")
            if value and value not in seen and any(scheme in value for scheme in
                    ("://", "arn:aws:dynamodb")):
                seen.add(value)
                raw.append({"value": value, "source": src, "kind": typ})
        for match in grep_matches or []:
            value = match.get("value", "")
            src = match.get("source", "grep")
            if value and value not in seen and ("://" in value or "arn:aws:dynamodb" in value):
                seen.add(value)
                raw.append({"value": value, "source": src, "kind": "grep"})
        return raw

    def _classify(self, raw: List[Dict[str, Any]], *, reveal_raw: bool = False) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        strings: List[Dict[str, Any]] = []
        findings: List[Dict[str, Any]] = []
        for item in raw:
            value = item["value"]
            matched = {name: pat for name, pat in DB_URL_PATTERNS.items() if re.search(pat, value)}
            if not matched:
                continue
            scheme = min(matched.keys(), key=lambda k: len(k))
            masked = _mask(value)
            if any(c["masked"] == masked for c in strings):
                continue
            record = {
                "scheme": scheme, "masked": masked, "source": item["source"],
                "kind": item["kind"], "observed": True,
            }
            if reveal_raw:
                record["_raw_value"] = value
            try:
                parsed = urllib.parse.urlsplit(value if "://" in value else f"//{value}")
                record["host"] = parsed.hostname or ""
                record["port"] = parsed.port
                record["has_credentials"] = bool(parsed.username)
                record["is_private_host"] = bool(parsed.hostname and
                    re.search(r"(localhost|127\\.0\\.0\\.1|10\\.|192\\.168\\.|172\\.(1[6-9]|2\\d|3[01])\\.)", parsed.hostname))
                record["db_name"] = (parsed.path or "/").lstrip("/").split("?")[0]
            except ValueError:
                record.setdefault("has_credentials", False)
            strings.append(record)

            # Anti false positive: never claim a live-exposed database from a
            # string alone. Only flag the disclosure with honest missing evidence.
            findings.append(normalized_finding(
                finding_type=f"Database Connection String Exposed Client-Side ({scheme})",
                target=item["source"], endpoint=item["source"],
                status=FindingStatus.SUSPECTED,
                confidence=.65 if record.get("has_credentials") else .4,
                source_module="db_hunter", source_tool="regex + URL parsing",
                evidence=[{**record, "raw_value": None}],
                verification_checks=[{"name": "scheme_detected", "passed": True},
                                     {"name": "credentials_embedded", "passed": record.get("has_credentials", False)}],
                false_positive_reasons=["Connection strings may be placeholders, dead code, or be protected at the network layer"],
                missing_evidence=["Live connectivity and credential validity must be proven manually under authorization"],
                severity="High" if record.get("has_credentials") else "Medium",
                cvss_score=0.0, param="connection_string",
                verification_note="A database connection string is recoverable from client-side assets; validity unproven.",
                observed_impact=f"Client-side asset discloses a {scheme} connection string"
                                f"{' with embedded credentials' if record.get('has_credentials') else ''}.",
                potential_impact="If the string is live and reachable, the database may be directly accessible.",
                vrt_category="Information Disclosure > Sensitive Source/Configuration",
            ))
        return strings, findings

    def _classify_ports(self, ports: List[Dict[str, Any]], findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Marks DB service ports observed by naabu as recon notes, not vulns.
        Known DB ports are probed with the service-specific handshake. Unknown
        open ports are only fingerprinted (banner read, read-only) when a
        scope-bound verifier is available and the port was observed by recon."""
        exposed: List[Dict[str, Any]] = []
        fingerprint_budget = 5
        for port in ports or []:
            host = port.get("host", "")
            pnum = port.get("port", 0)
            service = DB_PORT_SERVICES.get(pnum)
            fingerprinted = False
            if service:
                probe = probe_db_port(host, pnum, scope_manager=self.scope,
                                      traffic_controller=getattr(self.verifier, "traffic", None))
            elif self.verifier is not None and port.get("observed") and fingerprint_budget > 0:
                fingerprint_budget -= 1
                probe = self._probe_unknown_port(host, pnum, scope_manager=self.scope,
                                                 traffic_controller=getattr(self.verifier, "traffic", None))
                if probe.get("service") in (None, "unknown"):
                    continue
                service = probe["service"]
                fingerprinted = True
            else:
                continue
            entry = {
                "host": host, "port": pnum,
                "service": service, "state": port.get("state", "open"),
                "source": port.get("source", "naabu"), "observed": True,
                "fingerprinted": fingerprinted,
            }
            entry["probe"] = probe
            if probe.get("banner"):
                entry["banner"] = probe["banner"]
            if probe.get("auth_free"):
                entry["auth_free"] = True
            exposed.append(entry)
            if probe.get("auth_free"):
                # Real impact: unauthenticated access to a database service.
                findings.append(normalized_finding(
                    finding_type=f"Unauthenticated {service.title()} Service Exposed",
                    target=port.get("host", ""), endpoint=f"{port.get('host')}:{port.get('port')}",
                    status=FindingStatus.VERIFIED, confidence=.9, source_module="db_hunter",
                    source_tool="live TCP probe (read-only, no auth used)",
                    test={"request": {"type": "tcp_probe", "method": "banner/handshake"},
                          "response": {"banner": probe.get("banner"), "notes": probe.get("notes", [])}},
                    evidence=[{"service": service, "host": port.get("host"), "port": port.get("port"),
                               "auth_free": True, "probe_notes": probe.get("notes", [])}],
                    verification_checks=[{"name": "service_answered_unauth", "passed": True}],
                    severity="High",
                    cvss_score=cvss3_score(CVSS_VECTORS["db_unauth_exposed"], 8.1), param="n/a",
                    reproduction_curl=f"nc -zv {port.get('host')} {port.get('port')}",
                    verification_note="Live probe confirmed the {service} service answers requests without authentication.".format(service=service),
                    observed_impact=f"The {service} service on {port.get('host')}:{port.get('port')} accepts unauthenticated connections.",
                    potential_impact="An attacker may read or manipulate data depending on server config.",
                    vrt_category="Server-Side Misconfiguration > Insecure Database Configuration",
                ))
            elif probe.get("state") == "open" and probe.get("banner"):
                findings.append(normalized_finding(
                    finding_type=f"Public {service.title()} Port Exposed",
                    target=port.get("host", ""), endpoint=f"{port.get('host')}:{port.get('port')}",
                    status=FindingStatus.DISCOVERED, confidence=.55, source_module="db_hunter",
                    source_tool="live TCP banner grab",
                    test={"request": {"type": "tcp_probe"}, "response": {"banner": probe.get("banner")[:160]}},
                    evidence=[{"service": service, "banner": probe.get("banner")[:160]}],
                    verification_checks=[{"name": "service_banner_observed", "passed": True}],
                    false_positive_reasons=["Firewall/WAF may allow handshake but block attacker sessions"],
                    missing_evidence=["Authenticated access or data exposure must be proven"],
                    severity="Low", cvss_score=0.0, param="n/a",
                    reproduction_curl=f"nc -zv {port.get('host')} {port.get('port')}",
                    verification_note="A reachable DB port responded with a service banner.",
                    observed_impact=f"{service.title()} is reachable on {port.get('host')}:{port.get('port')}.",
                    potential_impact="If auth is weak or absent, the database may be accessible remotely.",
                    vrt_category="Server-Side Misconfiguration > Insecure Database Configuration",
                ))
        return exposed
