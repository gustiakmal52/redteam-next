import asyncio
import json
import stat
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from redteam_agent.core import recon_pipeline
from redteam_agent.core.http_verifier import HTTPVerifier
from redteam_agent.core.js_analyzer import JSAnalyzer
from redteam_agent.core.report_builder import ReportBuilder
from redteam_agent.core.scope_manager import ScopeManager
from redteam_agent.core.task_manager import ScanTask
from redteam_agent.core.traffic_controller import TrafficController


def _executable(path, source):
    path.write_text("#!/usr/bin/env python3\n" + source, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return str(path)


def test_web2_and_web3_recon_keep_observed_coverage(tmp_path, monkeypatch):
    httpx = _executable(tmp_path / "httpx", '''
import json, sys
for host in sys.stdin.read().splitlines():
    print(json.dumps({"url": "https://" + host, "host": host, "status_code": 200,
                      "title": host, "tech": ["ObservedTech"], "content_length": 10}))
''')
    gau = _executable(tmp_path / "gau", '''
for index in range(120):
    print(f"https://example.com/archive/{index}?query=value")
print("https://outside.invalid/external?url=value")
''')
    katana = _executable(tmp_path / "katana", '''
import json, sys
args = sys.argv[1:]
seeds = open(args[args.index("-list") + 1], encoding="utf-8").read().splitlines()
for seed in seeds:
    seed = seed.rstrip("/")
    for index in range(3):
        response = {"status_code": 200, "technologies": ["ObservedFramework"]}
        if index == 0:
            response["forms"] = [{"method": "POST", "action": seed + "/api/search",
                                  "enctype": "application/x-www-form-urlencoded",
                                  "parameters": ["url", "query", "cmd"]}]
        print(json.dumps({"request": {"method": "GET", "endpoint": seed + f"/page/{index}?id={index}"},
                          "response": response}))
''')
    monkeypatch.setitem(recon_pipeline.TOOL_PATHS, "httpx", httpx)
    monkeypatch.setitem(recon_pipeline.TOOL_PATHS, "gau", gau)
    monkeypatch.setitem(recon_pipeline.TOOL_PATHS, "katana", katana)

    task = ScanTask("wide-recon", "example.com")
    task.scope_manager.resolve_dns = False
    pipeline = recon_pipeline.ReconPipeline(task)
    subdomains = ["example.com", *(f"host-{index}.example.com" for index in range(74))]
    live_hosts = asyncio.run(pipeline.run_http_probing(subdomains))
    endpoints = asyncio.run(pipeline.run_crawlers(live_hosts))

    assert len(live_hosts) == 75
    assert len(endpoints) >= 420  # 120 GAU + 225 Katana + 75 form actions, after dedupe.
    assert {record["url"] for record in task.results["endpoint_records"]
            if "katana_form" in record["sources"]}
    form = next(record for record in task.results["endpoint_records"]
                if record["url"] == "https://example.com/api/search")
    assert form["methods"] == ["POST"]
    assert form["body_fields"] == ["cmd", "query", "url"]
    assert {"high_value_input", "high_value_route", "state_changing_method"} <= set(form["priority_reasons"])
    assert any(item["value"].startswith("https://outside.invalid/")
               for item in task.results["external_discoveries"])
    assert not any(item.startswith("https://outside.invalid/") for item in endpoints)

    contract = "0x1111111111111111111111111111111111111111"
    implementation = "2222222222222222222222222222222222222222"
    solana_program = "11111111111111111111111111111111"
    requests = []

    class RPCHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def _send(self, status, body, content_type):
            payload = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            if self.path == "/":
                self._send(200, "".join(
                    f'<script src="/app-{index}.js"></script>' for index in range(20)), "text/html")
            elif self.path.startswith("/app-") and self.path.endswith(".js"):
                port = self.server.server_port
                index = int(self.path.removeprefix("/app-").removesuffix(".js"))
                web3_source = f'''const rpcUrl="http://127.0.0.1:{port}/evm";
	const rpcEndpoint="http://127.0.0.1:{port}/solana";
	const target="{contract}"; const chainId=1;
	const programId=new PublicKey("{solana_program}");
	const abi=["function upgradeTo(address implementation)",
	{{"inputs":[{{"name":"amount","type":"uint256"}}],"name":"withdraw","type":"function"}}];
	window.ethereum.request({{method:"eth_requestAccounts"}});''' if index == 19 else ""
                self._send(200, f'const route="/api/route-{index}";{web3_source}', "application/javascript")
            else:
                self._send(404, "not found", "text/plain")

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode()
            call = json.loads(body)
            requests.append((self.path, call["method"]))
            if self.path == "/evm":
                if call["method"] == "eth_chainId":
                    result = "0x1"
                elif call["method"] == "eth_getStorageAt":
                    result = "0x" + "0" * 24 + implementation
                elif call["method"] == "eth_getCode":
                    result = "0x6001600055"
                else:
                    result = None
                payload = {"jsonrpc": "2.0", "id": 1, "result": result}
            elif call["method"] == "eth_chainId":
                payload = {"jsonrpc": "2.0", "id": 1, "error": {"code": -32601}}
            elif call["method"] == "getVersion":
                payload = {"jsonrpc": "2.0", "id": 1,
                           "result": {"solana-core": "2.0.0", "feature-set": 123}}
            else:
                payload = {"jsonrpc": "2.0", "id": 1, "result": {"value": {
                    "executable": True, "owner": solana_program, "lamports": 1, "data": ["", "base64"]}}}
            self._send(200, json.dumps(payload), "application/json")

    server = ThreadingHTTPServer(("127.0.0.1", 0), RPCHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_port
        scope = ScopeManager(["127.0.0.1"], allow_private=True, resolve_dns=False)
        verifier = HTTPVerifier(timeout=3, traffic_controller=TrafficController("FAST", max_requests=100),
                                scope_manager=scope, module="web3_test")
        analysis = JSAnalyzer(verifier=verifier, scope_manager=scope).analyze_target(f"http://127.0.0.1:{port}/")
        web3 = analysis["web3"]
    finally:
        server.shutdown()
        thread.join(timeout=2)

    assert web3["stats"]["rpc_verified"] == 2
    assert web3["stats"]["contracts_verified"] == 1
    assert web3["stats"]["proxies_verified"] == 1
    assert web3["stats"]["solana_programs_verified"] == 1
    assert web3["stats"]["verification_requests"] == 7
    assert len(analysis["js_assets"]) == 20
    assert len(analysis["probed_routes"]) == 20
    assert analysis["js_assets_budget_skipped"] == analysis["routes_budget_skipped"] == 0
    assert len(requests) == 7
    assert requests.count(("/evm", "eth_getCode")) == 2
    assert ("/evm", "eth_getStorageAt") in requests
    assert ("/solana", "getAccountInfo") in requests
    assert {item["name"] for item in web3["abi_functions"]} >= {"upgradeTo", "withdraw"}
    assert "_raw_url" not in json.dumps(web3)
    report = ReportBuilder().generate_full_audit_report({"target": "local-fixture", "web3_recon": web3})
    assert "Web3 Recon Evidence" in report and "VERIFIED_EIP1967_PROXY" in report
