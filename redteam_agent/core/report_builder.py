"""Evidence-bound Bug Bounty reporting without inferred-impact fabrication."""

from __future__ import annotations

import json
import math
from typing import Any, Dict

from redteam_agent.discovery.redaction import SecretRedactor


class ReportBuilder:
    def __init__(self):
        self.redactor = SecretRedactor()

    @staticmethod
    def _confidence(finding: Dict[str, Any]) -> str:
        value = finding.get("confidence")
        try:
            number = float(value)
        except (TypeError, ValueError, OverflowError):
            return "Unknown — valid confidence was not recorded"
        if isinstance(value, bool) or not math.isfinite(number) or not 0 <= number <= 1:
            return "Unknown — confidence must be a finite number between 0 and 1"
        return f"{number:.2f}"

    @staticmethod
    def _verification_source(finding: Dict[str, Any]) -> str:
        if finding.get("status") != "VERIFIED":
            return "Not proven — finding is not marked VERIFIED"
        review = finding.get("human_review") or {}
        if review.get("action") == "MARK_VERIFIED":
            return "Human review recorded; evidence still requires final triage"
        return "Scanner-reported VERIFIED; independent validation not established by this report"

    @staticmethod
    def _unknown(reason: str) -> str:
        return f"Unknown — {reason}"

    def generate_markdown_report(self, finding: Dict[str, Any], target_info: str = "") -> str:
        status = finding.get("status", "SUSPECTED")
        finding_type = finding.get("type") or finding.get("vuln_type", "Security finding")
        severity = finding.get("severity", "Unrated")
        endpoint = finding.get("endpoint") or finding.get("target_url") or target_info or self._unknown("endpoint was not recorded")
        parameter = finding.get("param") or self._unknown("the scanner did not identify a parameter")
        reproduction = finding.get("reproduction_curl") or self._unknown("no reproduction command was captured")
        observed = finding.get("observed_impact") or finding.get("verification_note") or self._unknown("observed impact was not recorded")
        potential = finding.get("potential_impact") or self._unknown("additional impact was not established")
        raw_request = finding.get("raw_request") or self._unknown("raw request was not captured")
        raw_response = finding.get("raw_response") or self._unknown("raw response was not captured")
        checks = finding.get("verification_checks", [])
        missing = finding.get("missing_evidence", [])
        readiness = "Ready for human final triage" if status == "VERIFIED" else "Candidate only; not ready for submission"
        if status == "REJECTED":
            readiness = "Rejected; excluded from active candidates"
        return f"""# [{severity}] {finding_type} on {endpoint}

## Validation State

- **Recorded status**: `{status}`
- **Verification source**: {self._verification_source(finding)}
- **Confidence**: `{self._confidence(finding)}`
- **Disposition**: {readiness}
- **Source module**: `{finding.get('source_module') or self._unknown('source module missing')}`
- **Observed at**: `{finding.get('observed_at') or self._unknown('timestamp missing')}`

## Summary

The supplied finding records the behavior below. Authorization is not established by this report; check the official bounty program policy or audit Rules of Engagement for scope.

- **Target**: `{finding.get('target') or target_info or self._unknown('target was not recorded')}`
- **Endpoint**: `{endpoint}`
- **Method**: `{finding.get('method', 'GET')}`
- **Parameter / header**: `{parameter}`

## Observed Impact

{observed}

## Potential Impact

{potential}

Potential impact is not claimed as achieved. It requires additional evidence or human confirmation.

## Reproduction

```bash
{reproduction}
```

## Verification Checks

```json
{json.dumps(checks, indent=2, default=str)}
```

## Missing Evidence

{chr(10).join(f'- {item}' for item in missing) if missing else '- Unknown — no evidence-gap assessment was recorded; an empty list does not establish completeness.'}

## Raw HTTP Request

```http
{raw_request}
```

## Raw HTTP Response

```http
{raw_response}
```

## Remediation

Apply a control specific to the confirmed root cause, then rerun the same deterministic checks. Do not rely on this generic report to infer a framework-specific patch.
"""

    def _hidden_discovery_markdown(self, task_results: Dict[str, Any]) -> str:
        """Render the hidden-discovery ledger as triage evidence.

        Public deployment identifiers remain visible here because a triager
        needs the exact tenant/project/pool to reproduce the observation.
        Secret-bearing fields are limited to masked values and fingerprints;
        this method never reconstructs or emits a raw credential.
        """
        hidden = task_results.get("hidden_assets") or {}
        if not isinstance(hidden, dict):
            return ""
        stats = hidden.get("stats") or {}
        assets = hidden.get("assets") or []
        endpoints = hidden.get("endpoints") or []
        credentials = hidden.get("credentials") or []
        projects = hidden.get("baas_projects") or []
        runtime_configs = hidden.get("runtime_configs") or []
        source_maps = hidden.get("source_maps") or []
        auth_flows = hidden.get("auth_flows") or []
        relationships = hidden.get("relationships") or []
        if not any((assets, endpoints, credentials, projects, runtime_configs, source_maps, auth_flows, relationships)):
            return ""

        def safe_url(value: Any) -> str:
            return self.redactor.redact_url(str(value or "")).replace("\n", " ")

        def safe_public(value: Any) -> str:
            value = str(value or "").replace("\n", " ")
            return safe_url(value) if value.startswith(("http://", "https://")) else value

        def safe_json(value: Any) -> str:
            return json.dumps(self.redactor.redact_json(value), sort_keys=True, default=str)

        md = "\n## Hidden Asset & Credential Discovery\n\n"
        md += ("This is the source-trace ledger used to reproduce hidden frontend observations. "
               "Public client IDs, pool IDs, tenant IDs, project refs, domains, realms, and endpoints are retained as triage evidence. "
               "Secret material is represented by a mask and SHA-256 fingerprint. Discovery metadata is not silently converted into an empty finding.\n\n")
        md += (f"- **Assets**: `{stats.get('assets', len(assets))}`; JavaScript assets: `"
                f"{stats.get('javascript_assets', 0)}`\n"
                f"- **Endpoints**: `{stats.get('endpoints', len(endpoints))}`\n"
                f"- **Credential references**: `{stats.get('credentials', len(credentials))}`\n"
                f"- **BaaS/cloud projects**: `{stats.get('baas_projects', len(projects))}`\n"
                f"- **Source maps**: `{stats.get('source_maps', len(source_maps))}`; auth flows: `"
                f"{stats.get('auth_flows', len(auth_flows))}`; relationships: `{stats.get('relationships', len(relationships))}`\n\n")

        if projects:
            md += "### Correlated BaaS / Cloud Projects\n\n"
            for project in projects[:100]:
                if not isinstance(project, dict):
                    continue
                public_ids = project.get("public_identifiers") or (project.get("auth") or {}).get("public_identifiers") or {}
                public_id_text = ", ".join(
                    f"`{key}={safe_public(value)}`" for key, value in sorted(public_ids.items())
                    if value is not None and value != ""
                ) or "none retained"
                verification = project.get("verification") or {}
                checks = verification.get("checks") or []
                check_text = ""
                if checks:
                    check_text = "; checks=" + safe_json([
                        {key: item.get(key) for key in ("endpoint", "status_code", "body_length", "accepted")}
                        for item in checks if isinstance(item, dict)
                    ])
                evidence = project.get("evidence") or [{}]
                source_file = project.get("key_source") or (evidence[0].get("source_file") if isinstance(evidence[0], dict) else None) or "unknown"
                md += (f"- **{project.get('provider', 'Cloud')}** — ref: `"
                       f"{safe_public(project.get('project_ref') or 'unknown')}`; URL: `"
                       f"{safe_url(project.get('url'))}`; key classification: `"
                       f"{project.get('key_type') or 'not paired'}`; services: `"
                       f"{', '.join(str(item) for item in (project.get('services') or [])) or 'not observed'}`\n"
                       f"  - Public identifiers: {public_id_text}\n"
                       f"  - Source: `{source_file}`; verification: `"
                       f"{verification.get('status') or 'NOT_RUN'}`; credential accepted: `"
                       f"{verification.get('credential_accepted', False)}`{check_text}\n")
            if len(projects) > 100:
                md += f"- _{len(projects) - 100} additional project records are present in the JSON result._\n"
            md += "\n"

        if credentials:
            md += "### Credential References and Use Sites\n\n"
            for credential in credentials[:200]:
                if not isinstance(credential, dict):
                    continue
                used_by = ", ".join(safe_url(item) for item in (credential.get("linked_endpoints") or [])) or "not linked to an extracted endpoint"
                source = credential.get("source_file") or credential.get("source_url") or "unknown"
                md += (f"- **{credential.get('credential_type', 'UNKNOWN_TOKEN')}** / provider `"
                       f"{credential.get('provider') or 'unknown'}` — status: `"
                       f"{credential.get('status', 'CANDIDATE')}`, public configuration: `"
                       f"{bool(credential.get('public'))}`, masked: `"
                       f"{credential.get('masked_value') or 'not value-bearing'}`, sha256: `"
                       f"{credential.get('sha256') or 'not recorded'}`\n"
                       f"  - Source: `{source}` line `{credential.get('source_line') or 'unknown'}`; variable/property: `"
                       f"{credential.get('variable_name') or 'literal/reference'}`; used by: {used_by}\n"
                       f"  - Verification: `{(credential.get('verification') or {}).get('status') or 'NOT_RUN'}`; reason: "
                       f"{credential.get('reason') or 'static format/context evidence only'}\n")
            if len(credentials) > 200:
                md += f"- _{len(credentials) - 200} additional credential references are present in the JSON result._\n"
            md += "\n"

        if endpoints:
            md += "### Extracted Endpoint Evidence\n\n"
            md += "| Method | URL | Type | Auth headers | Body fields | Source |\n|---|---|---|---|---|---|\n"
            for endpoint in endpoints[:300]:
                if not isinstance(endpoint, dict):
                    continue
                headers = ", ".join(str(key) for key in (endpoint.get("headers") or {}).keys()) or "—"
                fields = ", ".join(str(key) for key in ((endpoint.get("body_shape") or {}).get("fields") or [])) or "—"
                md += (f"| `{endpoint.get('method', 'GET')}` | `{safe_url(endpoint.get('url'))}` | "
                       f"`{endpoint.get('request_type', 'REST')}` | `{headers}` | `{fields}` | "
                       f"`{endpoint.get('source_file') or 'unknown'}:{endpoint.get('source_line') or 'unknown'}` |\n")
            if len(endpoints) > 300:
                md += f"\n_{len(endpoints) - 300} additional endpoints are present in the JSON result._\n"
            md += "\n"

        if runtime_configs:
            md += "### Runtime Configuration Trace\n\n"
            for config in runtime_configs[:100]:
                if not isinstance(config, dict):
                    continue
                values = []
                for item in config.get("values") or []:
                    if not isinstance(item, dict):
                        continue
                    name = item.get("name") or "unnamed"
                    display = safe_public(item.get("value")) if item.get("public_identifier") else (item.get("masked_value") or "[REDACTED]")
                    values.append(f"{name}={display}")
                md += (f"- `{safe_url(config.get('url'))}` — status `{config.get('status', 'DISCOVERED')}`, "
                       f"keys: `{', '.join(str(key) for key in (config.get('keys') or [])) or 'none'}`; "
                       f"values: `{'; '.join(values) or 'names only'}`\n")
            md += "\n"

        if source_maps:
            md += "### Source-Map Trace\n\n"
            for source_map in source_maps[:100]:
                if not isinstance(source_map, dict):
                    continue
                md += (f"- map `{safe_url(source_map.get('map_url'))}` from `{safe_url(source_map.get('parent_asset'))}` — "
                       f"status `{source_map.get('status', 'DISCOVERED')}`, sources `{len(source_map.get('sources') or [])}`, "
                       f"sourcesContent processed `{source_map.get('sources_content_count', 0)}`\n")
            md += "\n"

        if auth_flows:
            md += "### Authentication Flow Graphs\n\n"
            for flow in auth_flows[:100]:
                if not isinstance(flow, dict):
                    continue
                nodes = "; ".join(
                    f"{node.get('node_type')}: {safe_url(node.get('label'))}"
                    for node in (flow.get('nodes') or []) if isinstance(node, dict)
                ) or "no nodes"
                edges = "; ".join(
                    f"{edge.get('from')} -> {edge.get('to')} ({edge.get('relationship')})"
                    for edge in (flow.get('edges') or []) if isinstance(edge, dict)
                ) or "no edges"
                md += (f"- `{flow.get('flow_id', 'auth-flow')}`; confidence `{flow.get('confidence', 'unknown')}`, "
                       f"runtime observed `{bool(flow.get('runtime_observed'))}`\n  - Nodes: {nodes}\n  - Edges: {edges}\n")
            md += "\n"

        if relationships:
            md += "### Relationship Evidence\n\n"
            for relationship in relationships[:300]:
                if not isinstance(relationship, dict):
                    continue
                md += (f"- `{relationship.get('relationship_type', 'relationship')}`: `"
                       f"{relationship.get('from_node') or relationship.get('from')}` -> `"
                       f"{relationship.get('to_node') or relationship.get('to')}`; source `"
                       f"{relationship.get('source') or 'unknown'}`; confidence `"
                       f"{relationship.get('confidence', 'unknown')}`\n")
            md += "\n"
        return md

    def _deep_exploit_markdown(self, task_results: Dict[str, Any]) -> str:
        """Render the offensive planner ledger without losing attack detail."""
        report = task_results.get("deep_exploit") or {}
        if not isinstance(report, dict) or not (report.get("plan") or report.get("reports") or report.get("primitives")):
            return ""

        def safe_url(value: Any) -> str:
            return self.redactor.redact_url(str(value or "")).replace("\n", " ")

        def safe_json(value: Any) -> str:
            return json.dumps(self.redactor.redact_json(value), sort_keys=True, default=str)

        md = "\n## Deep Offensive Exploit Planner\n\n"
        md += ("This section records active hypotheses generated from discovered request shapes. "
               "A plan entry is not a vulnerability by itself; a primitive is retained only when the relevant behavior proof passed.\n\n")
        md += (f"- **Mode**: `{report.get('mode', 'unknown')}`\n"
                f"- **Hypotheses**: `{len(report.get('plan') or [])}`\n"
                f"- **Requests used**: `{report.get('requests_used', 0)}` / `{report.get('request_budget', 0)}`\n"
                f"- **Verified findings**: `{len(report.get('verified_findings') or [])}`\n"
                f"- **Verified primitives**: `{len(report.get('primitives') or [])}`\n\n")

        if report.get("plan"):
            md += "### Target-Specific Attack Plan\n\n"
            md += "| Technique | Method | Endpoint | Field | Source | Identity |\n|---|---|---|---|---|---|\n"
            for item in (report.get("plan") or [])[:300]:
                if not isinstance(item, dict):
                    continue
                md += (f"| `{item.get('technique', 'unknown')}` | `{item.get('method', 'GET')}` | "
                       f"`{safe_url(item.get('endpoint'))}` | `{item.get('field') or 'route-level'}` | "
                       f"`{item.get('source_file') or 'unknown'}:{item.get('source_line') or 'unknown'}` | "
                       f"`{item.get('identity') or 'anonymous'}` |\n")
            md += "\n"

        if report.get("reports"):
            md += "### Active Attempt Ledger\n\n"
            for item in (report.get("reports") or [])[:300]:
                if not isinstance(item, dict):
                    continue
                hypothesis = item.get("hypothesis") or {}
                finding = item.get("finding")
                md += (f"- **{hypothesis.get('technique', 'attempt')}** `{hypothesis.get('method', 'GET')}` "
                       f"`{safe_url(hypothesis.get('endpoint'))}` — status `{item.get('status', 'unknown')}`, "
                       f"requests `{item.get('requests_used', 0)}`\n")
                if isinstance(finding, dict):
                    md += (f"  - Finding: `{finding.get('type') or 'finding'}` / `"
                           f"{finding.get('status') or 'unknown'}`; observed: "
                           f"{finding.get('observed_impact') or finding.get('verification_note') or 'not proven'}\n")
                authorization = item.get("authorization")
                if isinstance(authorization, dict):
                    md += (f"  - Authorization strategy: `{authorization.get('strategy', 'cross_identity')}`; "
                           f"verified: `{bool(authorization.get('verified_primitives'))}`; checks: "
                           f"`{safe_json(authorization.get('checks') or [])}`\n")
                bypass = item.get("bypass")
                if isinstance(bypass, dict):
                    md += (f"  - Adaptive status: `{bypass.get('status', 'unknown')}`; protection: "
                           f"`{safe_json(bypass.get('protection') or {})}`\n")
            md += "\n"

        if report.get("primitives"):
            md += "### Verified Offensive Primitives\n\n"
            for primitive in (report.get("primitives") or [])[:100]:
                if not isinstance(primitive, dict):
                    continue
                md += (f"- `{primitive.get('id', 'primitive')}` — type `"
                       f"{primitive.get('type', 'unknown')}`, status `"
                       f"{primitive.get('status', 'unknown')}`, depth `"
                       f"{primitive.get('depth', 'unknown')}`; evidence: `"
                       f"{safe_json(primitive.get('evidence') or {})}`\n")
            md += "\n"

        if report.get("chains"):
            md += "### Exploit Chains\n\n"
            for chain in (report.get("chains") or [])[:50]:
                if not isinstance(chain, dict):
                    continue
                md += (f"- `{chain.get('chain_name', 'chain')}` — status `"
                       f"{chain.get('status', 'unknown')}`, primitives: `"
                       f"{safe_json(chain.get('primitives') or [])}`\n")
            md += "\n"
        return md

    def _web3_recon_markdown(self, task_results: Dict[str, Any]) -> str:
        web3 = task_results.get("web3_recon") or {}
        if not isinstance(web3, dict) or not web3.get("detected"):
            return ""
        stats = web3.get("stats") or {}
        md = "\n## Web3 Recon Evidence\n\n"
        md += ("Contract/program records below are inventory evidence. A `VERIFIED_CONTRACT`, "
               "`VERIFIED_EIP1967_PROXY`, or `VERIFIED_PROGRAM` state requires a successful read-only RPC response; "
               "static address or ABI matches remain candidates.\n\n")
        md += (f"- **RPC candidates / verified**: `{stats.get('rpc_candidates', 0)}` / `{stats.get('rpc_verified', 0)}`\n"
               f"- **EVM contracts / verified**: `{stats.get('contract_candidates', 0)}` / `{stats.get('contracts_verified', 0)}`\n"
               f"- **EIP-1967 proxies verified**: `{stats.get('proxies_verified', 0)}`\n"
               f"- **Solana programs verified**: `{stats.get('solana_programs_verified', 0)}`\n"
               f"- **Read-only RPC requests**: `{stats.get('verification_requests', 0)}`\n\n")
        if web3.get("rpc_endpoints"):
            md += "### RPC Identity\n\n| Protocol | Chain | Endpoint | Status | Source |\n|---|---:|---|---|---|\n"
            for rpc in web3["rpc_endpoints"][:100]:
                md += (f"| `{rpc.get('protocol') or 'unknown'}` | `{rpc.get('chain_id') or '—'}` | "
                       f"`{self.redactor.redact_url(str(rpc.get('url') or ''))}` | `{rpc.get('status')}` | "
                       f"`{', '.join(str(item) for item in rpc.get('sources', []))}` |\n")
            md += "\n"
        if web3.get("contracts"):
            md += "### EVM Contract Inventory\n\n| Address | Chain | Bytecode | Proxy implementation | Status | Sources |\n|---|---:|---:|---|---|---|\n"
            for contract in web3["contracts"][:200]:
                proxy = contract.get("proxy") or {}
                md += (f"| `{contract.get('address')}` | `{contract.get('chain_id') or '—'}` | "
                       f"`{contract.get('bytecode_size', 0)} bytes` | `{proxy.get('implementation') or '—'}` | "
                       f"`{proxy.get('status') or contract.get('status')}` | "
                       f"`{', '.join(str(item) for item in contract.get('sources', []))}` |\n")
            md += "\n"
        if web3.get("solana_accounts"):
            md += "### Solana Account / Program Inventory\n\n"
            for account in web3["solana_accounts"][:200]:
                md += (f"- `{account.get('address')}` — `{account.get('status')}`; executable "
                       f"`{bool(account.get('executable'))}`; owner `{account.get('owner') or 'unknown'}`\n")
            md += "\n"
        high_value_abi = [item for item in web3.get("abi_functions", []) if item.get("surface_tags")]
        if high_value_abi:
            md += "### Privileged / Value-Moving ABI Surface\n\n"
            for item in high_value_abi[:200]:
                md += (f"- `{item.get('signature')}` — tags `"
                       f"{', '.join(str(tag) for tag in item.get('surface_tags', []))}`; sources `"
                       f"{', '.join(str(source) for source in item.get('sources', []))}`\n")
            md += "\n"
        return md

    def generate_full_audit_report(self, task_results: Dict[str, Any]) -> str:
        target = task_results.get("target", "Unknown target")
        stats = task_results.get("stats", {})
        findings = task_results.get("findings", task_results.get("vulnerabilities", []))
        verified = [item for item in findings if item.get("status") == "VERIFIED"]
        candidates = [item for item in findings if item.get("status") not in {"VERIFIED", "REJECTED"}]
        rejected = [item for item in findings if item.get("status") == "REJECTED"]
        md = f"""# Gustiakmal RedTeam Next Security Audit & Recon Report: {target}

## Executive Overview

- **Preset**: `{task_results.get('preset', 'unknown')}`
- **Engagement ID**: `{(task_results.get('engagement') or {}).get('engagement_id') or 'Not supplied; exact target scope'}`
- **Authorization reference**: `{(task_results.get('engagement') or {}).get('authorization_reference') or 'Not supplied'}`
- **Hunt objective**: `{(task_results.get('hunt_focus') or {}).get('objective') or 'No focused objective recorded'}`
- **Selected vulnerability classes**: `{', '.join((task_results.get('hunt_focus') or {}).get('vulnerability_classes') or []) or 'No classes selected'}`
- **Observed/configured domains**: `{stats.get('subdomains', 0)}`
- **Live HTTP services enumerated by recon**: `{stats.get('live_hosts', 0)}`
- **Normalized endpoints**: `{stats.get('endpoints', 0)}`
- **Classified token patterns**: `{stats.get('secrets_found', 0)}`
- **Candidates requiring review**: `{len(candidates)}`
- **Findings marked VERIFIED (subject to final triage)**: `{len(verified)}`
- **Rejected findings**: `{len(rejected)}`
{self._hidden_discovery_markdown(task_results)}
{self._web3_recon_markdown(task_results)}
{self._deep_exploit_markdown(task_results)}

## Verified Findings
"""
        if not verified:
            md += "\nNo finding reached `VERIFIED`; this does not prove the target is vulnerability-free.\n"
        for index, finding in enumerate(verified, 1):
            md += f"\n### {index}. {finding.get('type', finding.get('vuln_type'))}\n\n"
            md += f"- **Endpoint**: `{finding.get('endpoint', finding.get('target_url'))}`\n"
            md += f"- **Observed impact**: {finding.get('observed_impact', finding.get('verification_note', 'Unknown — impact not captured'))}\n"
            md += f"- **Verification source**: {self._verification_source(finding)}\n"
            md += f"- **Confidence**: `{self._confidence(finding)}`\n"
        md += "\n## Candidates (Not Verified)\n"
        if not candidates:
            md += "\nNo non-verified candidates were retained.\n"
        for index, finding in enumerate(candidates, 1):
            missing = "; ".join(finding.get("missing_evidence", [])) or "No missing-evidence explanation was recorded"
            md += f"\n{index}. **{finding.get('type', 'Candidate')}** — `{finding.get('status', 'UNKNOWN')}`, confidence "
            md += f"`{self._confidence(finding)}`. Missing: {missing}.\n"
        md += "\n## Rejected Findings\n"
        if not rejected:
            md += "\nNo finding was marked REJECTED.\n"
        for index, finding in enumerate(rejected, 1):
            reason = (finding.get("human_review") or {}).get("reason") or self._unknown("rejection reason was not recorded")
            md += f"\n{index}. **{finding.get('type') or finding.get('vuln_type') or 'Finding'}** — {reason}\n"
        traffic = task_results.get("traffic", {})
        md += f"""

## Traffic and Scope

- **Traffic preset**: `{traffic.get('preset', 'unknown')}`
- **Requests sent**: `{traffic.get('requests_sent', 0)}`
- **429 / 503 responses**: `{traffic.get('429_count', 0)} / {traffic.get('503_count', 0)}`
- **Scope**: `{json.dumps(task_results.get('scope', {}), default=str)}`
"""
        for finding in verified:
            md += "\n---\n\n" + self.generate_markdown_report(finding, target_info=target) + "\n"
        return md
