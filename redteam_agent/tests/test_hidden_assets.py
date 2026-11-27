"""Synthetic, offline coverage for the first-class hidden discovery layer.

The fixture verifier below is deliberately small: it records every attempted
URL and returns only responses explicitly placed in the fixture.  This keeps
the tests useful for scope/budget/redaction regressions without contacting a
real service or treating a static observation as a vulnerability.
"""

from __future__ import annotations

import json
import base64
import gzip
from copy import deepcopy

import pytest

from redteam_agent.core.scope_manager import ScopeManager
from redteam_agent.core.http_verifier import HTTPVerifier
from redteam_agent.discovery.baas_correlation import BaaSCorrelationEngine
from redteam_agent.discovery.credentials import CredentialDiscoveryEngine
from redteam_agent.discovery.hidden_assets import HiddenAssetEngine
from redteam_agent.discovery.js_deep import JSDeepAnalyzer
from redteam_agent.discovery.models import EndpointRecord
from redteam_agent.discovery.redaction import SecretRedactor


TARGET = "https://app.test/"


class FixtureVerifier:
    def __init__(self, responses):
        self.responses = dict(responses)
        self.calls = []

    def send_http_request(self, url, method="GET", headers=None, body=None, **kwargs):
        self.calls.append({"url": url, "method": method, "headers": headers or {}, "body": body,
                           "kwargs": kwargs})
        response = self.responses.get(url)
        if response is None:
            return {"success": False, "status_code": 404, "headers": {"Content-Type": "text/plain"},
                    "body": "not found"}
        if callable(response):
            response = response(url=url, method=method, headers=headers or {}, body=body, kwargs=kwargs)
        return deepcopy(response)


def _scope(*, include=None):
    return ScopeManager(include=include or ["app.test", "*.app.test"], allow_private=True, resolve_dns=False)


def _modern_fixture():
    generic_key = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"
    app_js = f'''\
const API_KEY = "{generic_key}";
const opts = {{ headers: {{ "X-API-Key": API_KEY }} }};
fetch("/api/private", {{ method: "POST", body: JSON.stringify({{email, password}}), ...opts }});
fetch("/api/login", {{ method: "POST", body: JSON.stringify({{email, password}}) }});
const token = response.access_token;
localStorage.setItem("auth", token);
fetch("/api/me", {{ headers: {{ Authorization: `Bearer ${{localStorage.getItem("auth")}}` }} }});
const sbA = createClient("https://aaa.supabase.co", "KEY_A");
const sbB = createClient("https://bbb.supabase.co", "KEY_B");
import("./lazy.js");
navigator.serviceWorker.register("./sw.js");
//# sourceMappingURL=app.js.map
'''
    lazy_js = 'fetch("/api/lazy", { method: "PATCH" });'
    sw_js = 'self.addEventListener("fetch", () => fetch("/api/background"));'
    source_map = {
        "version": 3,
        "file": "app.js",
        "sourceRoot": "",
        "sources": ["src/original.ts"],
        "names": ["fromMap"],
        "sourcesContent": ['fetch("/api/from-map", { method: "PATCH" });'],
    }
    html = f'''<!doctype html>
<html><head>
<link rel="modulepreload" href="/app.js">
<link rel="preload" as="script" href="/lazy.js">
</head><body>
<script id="__NEXT_DATA__" type="application/json">{{"buildId":"build-1","page":"/"}}</script>
<script type="module" src="/app.js"></script>
</body></html>'''
    responses = {
        TARGET: {"success": True, "status_code": 200, "headers": {"Content-Type": "text/html"}, "body": html},
        "https://app.test/app.js": {"success": True, "status_code": 200,
                                     "headers": {"Content-Type": "application/javascript", "ETag": "app-v1"},
                                     "body": app_js},
        "https://app.test/app.js.map": {"success": True, "status_code": 200,
                                         "headers": {"Content-Type": "application/json"},
                                         "body": json.dumps(source_map)},
        "https://app.test/lazy.js": {"success": True, "status_code": 200,
                                      "headers": {"Content-Type": "application/javascript"}, "body": lazy_js},
        "https://app.test/sw.js": {"success": True, "status_code": 200,
                                    "headers": {"Content-Type": "application/javascript"}, "body": sw_js},
        "https://app.test/_next/static/build-1/_buildManifest.js": {"success": True, "status_code": 200,
                                                                      "headers": {"Content-Type": "application/javascript"},
                                                                      "body": 'self.__BUILD_MANIFEST={"/":[]}'},
        "https://app.test/_next/static/build-1/_ssgManifest.js": {"success": True, "status_code": 200,
                                                                    "headers": {"Content-Type": "application/javascript"},
                                                                    "body": 'self.__SSG_MANIFEST=[]'},
        "https://app.test/_next/static/build-1/_middlewareManifest.json": {"success": True, "status_code": 200,
                                                                            "headers": {"Content-Type": "application/json"},
                                                                            "body": '{"middleware":{}}'},
    }
    return responses, generic_key


def _engine(responses, **kwargs):
    verifier = FixtureVerifier(responses)
    engine = HiddenAssetEngine(
        verifier=verifier,
        scope_manager=_scope(),
        request_budget=kwargs.pop("request_budget", 40),
        asset_budget=kwargs.pop("asset_budget", 30),
        source_map_budget=kwargs.pop("source_map_budget", 4),
        verification_budget=kwargs.pop("verification_budget", 4),
        **kwargs,
    )
    return engine, verifier


def test_modern_assets_source_map_recursion_method_body_and_worker_routes():
    responses, _ = _modern_fixture()
    engine, verifier = _engine(responses)
    result = engine.discover(TARGET, deep_assets=True, secret_discovery=True, auth_flow=True, source_maps=True)

    asset_urls = {item["url"] for item in result["assets"]}
    assert "https://app.test/app.js" in asset_urls
    assert "https://app.test/lazy.js" in asset_urls
    assert "https://app.test/sw.js" in asset_urls
    assert result["stats"]["source_maps"] == 1
    assert any(item["url"] == "https://app.test/src/original.ts" for item in result["assets"])

    endpoints = {(item["method"], item["url"]): item for item in result["endpoints"]}
    assert endpoints[("POST", "https://app.test/api/private")]["body_shape"]["fields"] == ["email", "password"]
    assert endpoints[("PATCH", "https://app.test/api/from-map")]["source_map"].endswith("app.js.map")
    assert endpoints[("PATCH", "https://app.test/api/lazy")]["source_file"] == "lazy.js"
    assert any(item["asset_type"] == "service_worker" for item in result["assets"])
    assert any(call["url"] == "https://app.test/app.js.map" for call in verifier.calls)


def test_raw_credentials_are_available_only_for_explicit_local_result():
    responses, generic_key = _modern_fixture()
    safe_engine, _ = _engine(responses)
    safe = safe_engine.discover(TARGET, source_maps=False)
    assert generic_key not in json.dumps(safe)
    assert all("_raw_value" not in item for item in safe["credentials"])

    raw_engine, _ = _engine(responses)
    raw = raw_engine.discover(TARGET, source_maps=False, raw_local_results=True)
    assert any(item.get("_raw_value") == generic_key for item in raw["credentials"])
    assert raw["coverage"]["redaction"]["raw_values_persisted"] is False


def test_supabase_pairing_is_constructor_local_and_unresolved_keys_are_not_values():
    text = '''
const URL_A = "https://aaa.supabase.co";
const KEY_A = "KEY_A";
const URL_B = "https://bbb.supabase.co";
const KEY_B = "KEY_B";
createClient(URL_A, KEY_A);
createClient(URL_B, KEY_B);
createClient(URL_A, RUNTIME_KEY);
'''
    redactor = SecretRedactor()
    credentials = CredentialDiscoveryEngine(redactor)
    credentials.discover(text, source_url="https://app.test/app.js", source_file="app.js")
    correlated = BaaSCorrelationEngine(redactor=redactor).correlate(
        [{"text": text, "source_url": "https://app.test/app.js", "source_file": "app.js"}],
        credentials=list(credentials.records.values()),
    )
    projects = {project.project_ref: project for project in correlated["projects"] if project.project_ref}
    assert set(projects) == {"aaa", "bbb"}
    assert projects["aaa"]._raw_key == "KEY_A"
    assert projects["bbb"]._raw_key == "KEY_B"
    # The unresolved third constructor produces no invented RUNTIME_KEY value.
    assert all(project._raw_key != "RUNTIME_KEY" for project in projects.values())
    assert "KEY_A" not in json.dumps([project.to_dict() for project in projects.values()])
    assert "KEY_B" not in json.dumps([project.to_dict() for project in projects.values()])


def test_firebase_config_is_one_public_project_and_api_key_is_not_a_secret_finding():
    firebase_key = "AIza" + "A" * 35
    text = f'''const firebaseConfig = {{
      apiKey: "{firebase_key}",
      authDomain: "demo.firebaseapp.com",
      projectId: "demo-project",
      databaseURL: "https://demo-default-rtdb.firebaseio.com",
      storageBucket: "demo.appspot.com",
      messagingSenderId: "123456789",
      appId: "1:123456789:web:abcdef"
    }};
    initializeApp(firebaseConfig); getAuth(); getDatabase(); getStorage();'''
    redactor = SecretRedactor()
    credentials = CredentialDiscoveryEngine(redactor)
    records = credentials.discover(text, source_url="https://app.test/app.js", source_file="app.js")
    correlated = BaaSCorrelationEngine(redactor=redactor).correlate(
        [{"text": text, "source_url": "https://app.test/app.js", "source_file": "app.js"}],
        credentials=records,
    )
    key_record = next(record for record in records if record.sha256 == redactor.fingerprint(firebase_key))
    assert key_record.credential_type == "PUBLIC_CLIENT_KEY"
    assert key_record.public is True
    assert key_record.status == "LIKELY"
    assert len(correlated["firebase"]) == 1
    assert correlated["firebase"][0].project_ref == "demo-project"
    assert correlated["firebase"][0].key_fingerprint == key_record.sha256


def test_baas_fast_path_keeps_indirect_config_pairs():
    source = {"source_file": "bundle.js", "source_url": TARGET,
              "text": 'const URL="https://demo.supabase.co";const KEY="demo-key";'
                      'const cfg={url:URL,key:KEY};const fb={apiKey:"public",projectId:"demo"};'}
    result = BaaSCorrelationEngine().correlate([source])
    assert any(project.project_ref == "demo" and project._raw_key == "demo-key"
               for project in result["supabase"])
    assert any(project.project_ref == "demo" for project in result["firebase"])


def test_runtime_config_is_reprocessed_for_exact_baas_pairing_and_public_ids_remain_visible():
    config = json.dumps({
        "SUPABASE_URL": "https://runtime-a.supabase.co",
        "SUPABASE_ANON_KEY": "RUNTIME_KEY_A",
        "clientId": "runtime-public-client",
        "clientSecret": "abcdefghijklmnopQRSTUV123456",
    })
    responses = {
        TARGET: {"success": True, "status_code": 200, "headers": {"Content-Type": "text/html"},
                 "body": '<script src="/runtime-config.json"></script>'},
        "https://app.test/runtime-config.json": {"success": True, "status_code": 200,
                                                   "headers": {"Content-Type": "application/json"}, "body": config},
    }
    engine, _ = _engine(responses)
    result = engine.discover(TARGET, deep_assets=True, secret_discovery=True, auth_flow=False, source_maps=False)

    project = next(item for item in result["baas_projects"] if item["provider"] == "Supabase")
    assert project["project_ref"] == "runtime-a"
    assert project["key_type"] == "unknown"
    assert project["public_identifiers"]["project_ref"] == "runtime-a"
    runtime = next(item for item in result["runtime_configs"] if item["url"].endswith("runtime-config.json"))
    public_client = next(item for item in runtime["values"] if item.get("name") == "clientId")
    assert public_client["value"] == "runtime-public-client"
    secret = next(item for item in runtime["values"] if item.get("name") == "clientSecret")
    assert secret["masked_value"] != "abcdefghijklmnopQRSTUV123456"
    assert config not in json.dumps(result)


def test_inline_runtime_config_keeps_public_identifiers_and_redacts_secret_fields():
    public_id = "inline-client-123"
    raw_secret = "abcdefghijklmnopQRSTUV123456"
    responses = {
        TARGET: {"success": True, "status_code": 200, "headers": {"Content-Type": "text/html"},
                 "body": '<script src="/app.js"></script>'},
        "https://app.test/app.js": {"success": True, "status_code": 200,
                                     "headers": {"Content-Type": "application/javascript"},
                                     "body": f'window.__ENV__ = {{ apiUrl: "https://api.app.test", clientId: "{public_id}", clientSecret: "{raw_secret}" }};'},
    }
    engine, _ = _engine(responses)
    result = engine.discover(TARGET, deep_assets=True, secret_discovery=True, auth_flow=False, source_maps=False)
    config = next(item for item in result["runtime_configs"] if item["status"] == "PARSED_INLINE_OBJECT")
    values = {item["name"]: item for item in config["values"]}
    assert values["apiUrl"]["value"] == "https://api.app.test"
    assert values["clientId"]["value"] == public_id
    assert values["clientId"]["public_identifier"] is True
    assert values["clientSecret"]["masked_value"] != raw_secret
    assert raw_secret not in json.dumps(result)


def test_linked_service_role_acceptance_becomes_verified_finding_with_redacted_evidence():
    payload = base64.urlsafe_b64encode(json.dumps({
        "iss": "https://aaa.supabase.co/auth/v1", "ref": "aaa", "role": "service_role",
        "aud": "authenticated", "iat": 1700000000, "exp": 2700000000,
    }, separators=(",", ":")).encode()).decode().rstrip("=")
    service_key = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + payload + ".signature123"
    html = '<script src="/app.js"></script>'
    app_js = f'const SERVICE_KEY = "{service_key}"; createClient("https://aaa.supabase.co", SERVICE_KEY);'
    responses = {
        TARGET: {"success": True, "status_code": 200, "headers": {"Content-Type": "text/html"}, "body": html},
        "https://app.test/app.js": {"success": True, "status_code": 200,
                                     "headers": {"Content-Type": "application/javascript"}, "body": app_js},
        "https://aaa.supabase.co/rest/v1/?limit=2": {"success": True, "status_code": 200,
                                                       "headers": {"Content-Type": "application/json"}, "body": "[]"},
        "https://aaa.supabase.co/auth/v1/settings": {"success": True, "status_code": 200,
                                                       "headers": {"Content-Type": "application/json"}, "body": "{}"},
    }
    verifier = FixtureVerifier(responses)
    engine = HiddenAssetEngine(
        verifier=verifier,
        scope_manager=_scope(include=["app.test", "aaa.supabase.co"]),
        asset_budget=8, source_map_budget=1, verification_budget=2,
    )
    result = engine.discover(TARGET, deep_assets=True, secret_discovery=True, auth_flow=False,
                             source_maps=False, verify_baas=True)
    credential = next(item for item in result["credentials"] if item["provider"] == "Supabase")
    assert credential["status"] == "VERIFIED"
    assert credential["public"] is False
    assert credential["verification"]["credential_accepted"] is True
    assert len(result["findings"]) == 1
    assert result["findings"][0]["status"] == "VERIFIED"
    assert "SUPABASE_KEY='[RESEARCHER_HELD_VALUE]'" in result["findings"][0]["reproduction_curl"]
    assert "HTTP 200" in result["findings"][0]["observed_impact"]
    assert result["findings"][0]["evidence"][0]["public_identifiers"]["project_ref"] == "aaa"
    assert service_key not in json.dumps(result)
    assert any(call["url"] == "https://aaa.supabase.co/rest/v1/?limit=2"
               and call["headers"]["Authorization"].startswith("Bearer ") for call in verifier.calls)


def test_credential_to_endpoint_graph_and_auth_flow_are_correlated_without_values():
    responses, generic_key = _modern_fixture()
    engine, _ = _engine(responses)
    result = engine.discover(TARGET, deep_assets=True, secret_discovery=True, auth_flow=True, source_maps=False)

    credential = next(item for item in result["credentials"] if item["sha256"] == SecretRedactor().fingerprint(generic_key))
    assert credential["credential_type"] == "API_KEY"
    assert "https://app.test/api/private" in credential["linked_endpoints"]
    assert any(item["relationship_type"] == "credential_to_endpoint"
               and "api/private" in item["to_node"] for item in result["relationships"])
    assert any(node["node_type"] == "Storage" and node["label"] == "localStorage.auth"
               for flow in result["auth_flows"] for node in flow["nodes"])
    assert any(node["node_type"] == "AuthorizationHeader"
               for flow in result["auth_flows"] for node in flow["nodes"])
    assert any("api/me" in node["label"] and node["node_type"] == "ProtectedEndpoint"
               for flow in result["auth_flows"] for node in flow["nodes"])
    assert any(edge["relationship"] == "read_for_authorization"
               for flow in result["auth_flows"] for edge in flow["edges"])


def test_final_result_and_standard_export_never_contain_raw_discovered_value():
    responses, generic_key = _modern_fixture()
    engine, _ = _engine(responses)
    result = engine.discover(TARGET, deep_assets=True, secret_discovery=True, auth_flow=False, source_maps=False)
    exported_again = engine.standard_export()
    assert generic_key not in json.dumps(result)
    assert generic_key not in json.dumps(exported_again)
    assert all("_raw_value" not in record for record in result["credentials"])
    assert result["coverage"]["redaction"]["raw_values_exported"] is False


def test_scope_records_external_dependency_without_fetching_it():
    html = '<script src="/app.js"></script>'
    responses = {
        TARGET: {"success": True, "status_code": 200, "headers": {"Content-Type": "text/html"}, "body": html},
        "https://app.test/app.js": {"success": True, "status_code": 200,
                                     "headers": {"Content-Type": "application/javascript"},
                                     "body": 'import("https://cdn.third-party.invalid/chunk.js");'},
    }
    engine, verifier = _engine(responses)
    result = engine.discover(TARGET, deep_assets=True, secret_discovery=False, auth_flow=False, source_maps=False)
    assert "https://cdn.third-party.invalid/chunk.js" not in {call["url"] for call in verifier.calls}
    external = next(item for item in result["assets"] if item["url"] == "https://cdn.third-party.invalid/chunk.js")
    assert external["status"] == "OUT_OF_SCOPE"
    assert result["coverage"]["out_of_scope"]


def test_runtime_observation_requires_researcher_owned_authorized_context_and_redacts_headers():
    engine, _ = _engine({TARGET: {"success": True, "status_code": 200,
                                  "headers": {"Content-Type": "text/html"}, "body": ""}})
    denied = engine.observe_runtime(
        requests=[{"url": TARGET + "api/me", "headers": {"Authorization": "Bearer raw"}}],
        authorized_session=False, browser_context="ambient",
    )
    assert denied["evidence"][0]["status"] == "NOT_RUN"
    observed = engine.observe_runtime(
        requests=[{"url": TARGET + "api/me", "method": "GET", "headers": {"Authorization": "Bearer raw"},
                   "response_token_fields": ["access_token"]}],
        storage_events=[{"storage": "localStorage", "key": "auth", "operation": "set", "value": "raw"}],
        authorized_session=True, browser_context="researcher-owned",
    )
    encoded = json.dumps(observed)
    assert "Bearer raw" not in encoded
    assert "raw" not in encoded
    assert any(node["node_type"] == "ProtectedEndpoint" for node in observed["nodes"])


def test_light_data_flow_handles_static_encoding_and_actual_methods():
    analyzer = JSDeepAnalyzer()
    text = '''
const prefix = "/api";
const route = prefix + "/v2/items";
const encoded = atob("L2FwaS9kZWNvZGVk");
fetch(route, {method: "PUT"});
new XMLHttpRequest().open("PATCH", encoded);
'''
    endpoints = analyzer.extract_endpoints(text, source_file="app.js", source_url=TARGET)
    assert ("PUT", "https://app.test/api/v2/items") in {(item.method, item.url) for item in endpoints}
    assert ("PATCH", "https://app.test/api/decoded") in {(item.method, item.url) for item in endpoints}


def test_cli_and_web_shared_engine_contract_is_deterministic():
    responses, _ = _modern_fixture()
    first, _ = _engine(responses)
    second, _ = _engine(responses)
    first_result = first.discover(TARGET, deep_assets=True, secret_discovery=True, auth_flow=True, source_maps=True)
    second_result = second.discover(TARGET, deep_assets=True, secret_discovery=True, auth_flow=True, source_maps=True)
    keys = ("assets", "endpoints", "credentials", "baas_projects", "auth_flows", "source_maps", "relationships")
    assert {key: first_result[key] for key in keys} == {key: second_result[key] for key in keys}


def test_next_build_manifest_keeps_page_to_chunk_relationship_and_queues_exact_chunk():
    html = '<script id="__NEXT_DATA__" type="application/json">{"buildId":"build-2","page":"/"}</script>'
    html += '<script src="/_next/static/build-2/_buildManifest.js"></script>'
    responses = {
        TARGET: {"success": True, "status_code": 200, "headers": {"Content-Type": "text/html"}, "body": html},
        "https://app.test/_next/static/build-2/_buildManifest.js": {
            "success": True, "status_code": 200,
            "headers": {"Content-Type": "application/javascript"},
            "body": 'self.__BUILD_MANIFEST={"/dashboard":["static/chunks/pages/dashboard-abc.js"]}',
        },
        "https://app.test/_next/static/build-2/static/chunks/pages/dashboard-abc.js": {
            "success": True, "status_code": 200,
            "headers": {"Content-Type": "application/javascript"},
            "body": 'fetch("/api/dashboard", { method: "GET" });',
        },
    }
    engine, verifier = _engine(responses, source_map_budget=0)
    result = engine.discover(TARGET, deep_assets=True, secret_discovery=False, auth_flow=False, source_maps=False)
    next_info = result["integrations"]["next"]
    assert "/dashboard" in next_info["page_routes"]
    assert "https://app.test/_next/static/build-2/static/chunks/pages/dashboard-abc.js" in next_info["manifest_assets"]
    assert any(item["source"] == "next_build_manifest" and "dashboard-abc.js" in item["url"]
               for item in result["assets"])
    assert any(call["url"].endswith("dashboard-abc.js") for call in verifier.calls)


def test_generic_cloud_auth_config_is_metadata_only_and_never_cross_pairable():
    text = '''
import { PublicClientApplication } from "@azure/msal-browser";
const azure = { clientId: "public-client", tenantId: "tenant-123", authority: "https://login.microsoftonline.com/tenant-123" };
const auth0 = { domain: "demo.auth0.com", clientId: "auth0-client", clientSecret: "secret-material" };
const cognito = { userPoolId: "us-east-1_demo", identityPoolId: "us-east-1:identity" };
const keycloak = { url: "https://id.example.test/realms/demo", realm: "demo" };
'''
    projects = BaaSCorrelationEngine().correlate(
        [{"text": text, "source_url": TARGET, "source_file": "auth-config.js"}]
    )["projects"]
    providers = {project.provider for project in projects}
    assert {"AWS Cognito", "Auth0", "Azure AD", "Keycloak"}.issubset(providers)
    encoded = json.dumps([project.to_dict() for project in projects])
    # Public identifiers are actionable triage evidence and must remain
    # visible; only secret-bearing fields are excluded from the provider model.
    assert "public-client" in encoded
    assert "auth0-client" in encoded
    assert "us-east-1:identity" in encoded
    assert "tenant-123" in encoded
    assert "secret-material" not in encoded
    assert all(project.key_type == "public-config" for project in projects)
    auth0_project = next(project for project in projects if project.provider == "Auth0")
    assert auth0_project.public_identifiers["clientId"] == "auth0-client"
    assert auth0_project.auth["public_identifiers"]["domain"] == "demo.auth0.com"


def test_shared_http_client_decodes_gzip_and_brotli_asset_responses():
    body = b'{"asset":"decoded"}'
    assert HTTPVerifier._decode_response_body(gzip.compress(body), {"Content-Encoding": "gzip"}) == body.decode()
    brotli = pytest.importorskip("brotli")
    assert HTTPVerifier._decode_response_body(brotli.compress(body), {"content-encoding": "br"}) == body.decode()


def test_unresolved_request_wrapper_argument_does_not_create_fake_endpoint():
    analyzer = JSDeepAnalyzer()
    endpoints = analyzer.extract_endpoints(
        'function request(path, init) { return fetch(path, init); }',
        source_file="wrapper.js", source_url=TARGET,
    )
    assert not any(item.url.endswith("/path") for item in endpoints)
