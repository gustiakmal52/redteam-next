"""
CLI & Web Launcher for Gustiakmal RedTeam Next.
Usage:
    python3 -m redteam_agent.cli --web --port 8899
    python3 -m redteam_agent.cli --url "https://example.com" --preset full
"""

import sys
import argparse
import json
from pathlib import Path
import uvicorn
from redteam_agent.core.config import DEFAULT_BYPASS_REQUEST_BUDGET, DEFAULT_REQUEST_BUDGET, MAX_BYPASS_DEPTH, SCAN_PRESETS
from redteam_agent.core.agent_engine import RedTeamAgentEngine
from redteam_agent.core.engagement import EngagementError, EngagementProfile, engagement_required
from redteam_agent.core.evidence_bundle import EvidenceBundleBuilder

def main():
    parser = argparse.ArgumentParser(description="Gustiakmal RedTeam Next (Anti-N/A & Anti-Halu)")
    parser.add_argument("target_positional", nargs="?", help="Explicitly authorized target URL/domain (alternative to --url)")
    parser.add_argument("--web", action="store_true", help="Launch the Web Command Center Dashboard")
    parser.add_argument("--port", type=int, default=8899, help="Web Dashboard Port (default: 8899)")
    parser.add_argument("--url", type=str, help="Explicitly authorized target URL or domain to audit")
    parser.add_argument("--preset", type=str, default="full", choices=sorted(SCAN_PRESETS.keys()), help="Audit Preset")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    parser.add_argument("--show-secrets", action="store_true",
                        help="Show discovered plaintext values in this CLI result only; reports/evidence bundles stay redacted")
    parser.add_argument("--listen", type=str, default="127.0.0.1", help="Dashboard bind address (default: 127.0.0.1)")
    parser.add_argument("--traffic", type=str.upper, default="NORMAL", choices=["STEALTH", "NORMAL", "FAST"], help="Traffic profile")
    parser.add_argument("--max-requests", type=int, default=DEFAULT_REQUEST_BUDGET, help=f"Total request budget (default: {DEFAULT_REQUEST_BUDGET})")
    parser.add_argument("--web-auth-token", type=str, default=None,
                        help="Dashboard token when bound beyond loopback (otherwise generated in memory)")
    parser.add_argument("--allow-private", action="store_true", help="Allow explicitly targeted local/private lab destinations")
    parser.add_argument("--offensive", action="store_true",
                        help="Enable target-specific deep exploit planning from discovered request shapes and researcher-owned identities")
    parser.add_argument("--aggressive", action="store_true",
                        help="Compatibility alias for the same focused --offensive planner")
    parser.add_argument("--bypass-budget", type=int, default=DEFAULT_BYPASS_REQUEST_BUDGET,
                        help="Deep bypass sub-budget; default 80 for bug bounty deep exploitation (separate from global request budget)")
    parser.add_argument("--max-depth", type=int, default=3, choices=[0, 1, 2, 3],
                        help="Deep exploit depth: 0 discovery, 1 direct proof, 2 adaptive bypass, 3 exploit chaining (default: 3 for bug bounty)")
    parser.add_argument("--authorization-identities-json", type=str, default=None,
                        help="Operator-supplied JSON list of named identities/headers for authorization comparison (kept in memory)")
    parser.add_argument("--deep-assets", action="store_true", help="Enable recursive modern asset/chunk/config discovery")
    parser.add_argument("--secret-discovery", action="store_true", help="Enable context-aware credential reference analysis")
    parser.add_argument("--auth-flow", action="store_true", help="Build static authentication/storage/header flow graph")
    parser.add_argument("--source-maps", action="store_true", help="Fetch and reprocess in-scope source maps within budget")
    parser.add_argument("--browser-verify", action="store_true", help="Allow only an explicitly supplied researcher-owned runtime observation context")
    parser.add_argument("--auth-context", type=str, default=None,
                        help="Path to researcher-owned auth context JSON; values stay in process memory and are never exported")
    parser.add_argument("--auth-login-url", type=str, default=None,
                        help="Login endpoint URL for one-shot session authentication (token replayed only to the same host)")
    parser.add_argument("--auth-username", type=str, default=None,
                        help="Username / email for login session authentication")
    parser.add_argument("--auth-password", type=str, default=None,
                        help="Password for login session authentication (process memory only, never exported)")
    parser.add_argument("--auth-username-field", type=str, default="username",
                        help="JSON field name for the username in the login request body (default: username)")
    parser.add_argument("--auth-password-field", type=str, default="password",
                        help="JSON field name for the password in the login request body (default: password)")
    parser.add_argument("--scope-include", action="append", default=None, help="In-scope exact/wildcard domain; repeatable")
    parser.add_argument("--scope-exclude", action="append", default=None, help="Excluded domain; repeatable")
    parser.add_argument("--exact-url", action="append", default=None, help="Additional exact in-scope URL; repeatable")
    parser.add_argument("--engagement-file", type=str, default=None,
                        help="Authorization JSON required before any target traffic")
    parser.add_argument("--objective", type=str, default=None,
                        help="Single concrete hunt objective for this session")
    parser.add_argument("--vuln-class", action="append", default=None,
                        help="Selected vulnerability class; repeatable, normally one or two")
    parser.add_argument("--output-dir", type=str, default=None,
                        help="Write a redacted results/report/manifest evidence bundle directory")
    parser.add_argument("--request-corpus", type=str, default=None,
                        help="Target-specific HAR or JSON request corpus used to build the offensive plan")

    args = parser.parse_args()

    # In --json mode the informational banner goes to stderr so stdout stays a
    # single clean JSON document (safe to pipe straight into jq / parsers).
    out = sys.stderr if args.json else sys.stdout

    if args.web:
        print("==========================================================================")
        print(" 🚀 LAUNCHING GUSTIAKMAL REDTEAM NEXT WEB DASHBOARD")
        print("==========================================================================")
        print(f"[*] Serving on: http://{args.listen}:{args.port}")
        print("[*] Real-Time SSE Streaming: ACTIVE")
        print("[*] CISA KEV Threat Intelligence: LOADED")
        print("[*] Anti-N/A & Anti-Halu Engines: ACTIVE\n")
        from redteam_agent.app import app, configure_web_auth
        web_token = configure_web_auth(args.listen, args.web_auth_token)
        if web_token:
            print(f"[*] Dashboard auth token: {web_token}")
        else:
            print("[*] Dashboard auth: loopback-only (no token required)")
        uvicorn.run(app, host=args.listen, port=args.port, reload=False)
        return

    target = args.url or args.target_positional
    if not target:
        parser.error("--url (or positional target) is required unless --web is used")

    print("==========================================================================", file=out)
    print(" 🎯 GUSTIAKMAL REDTEAM NEXT (ANTI-N/A & ANTI-HALU CLI)", file=out)
    print("==========================================================================", file=out)
    print(f"[*] Target: {target}", file=out)
    print(f"[*] Preset: {args.preset}\n", file=out)

    authorization_identities = None
    if args.authorization_identities_json:
        try:
            authorization_identities = json.loads(args.authorization_identities_json)
            if not isinstance(authorization_identities, list):
                raise ValueError("must be a JSON list")
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            parser.error(f"--authorization-identities-json invalid: {exc}")

    auth_context = None
    if args.auth_context:
        try:
            auth_path = Path(args.auth_context)
            if not auth_path.is_file():
                raise ValueError("file does not exist")
            with auth_path.open("r", encoding="utf-8") as handle:
                auth_context = json.load(handle)
            if not isinstance(auth_context, dict):
                raise ValueError("root must be a JSON object")
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            parser.error(f"--auth-context invalid: {exc}")

    request_corpus = None
    if args.request_corpus:
        try:
            corpus_path = Path(args.request_corpus)
            if not corpus_path.is_file():
                raise ValueError("file does not exist")
            with corpus_path.open("r", encoding="utf-8") as handle:
                request_corpus = json.load(handle)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            parser.error(f"--request-corpus invalid: {exc}")

    if args.bypass_budget < 0:
        parser.error("--bypass-budget must be zero or positive")

    offensive = bool(args.offensive or args.aggressive or args.preset in {"active_exploit", "deep_bypass"})

    hunt_focus = {
        "objective": (args.objective or "").strip(),
        "vulnerability_classes": list(dict.fromkeys(args.vuln_class or [])),
    }

    login = None
    if args.auth_login_url or args.auth_username or args.auth_password:
        if not (args.auth_login_url and args.auth_username and args.auth_password):
            parser.error("--auth-login-url, --auth-username, and --auth-password must be supplied together")
        login = {
            "auth_url": args.auth_login_url,
            "username": args.auth_username,
            "password": args.auth_password,
            "username_field": args.auth_username_field,
            "password_field": args.auth_password_field,
        }

    engine = RedTeamAgentEngine()
    results = engine.audit_target(target, preset=args.preset, traffic_preset=args.traffic,
        max_requests=args.max_requests, scope_include=args.scope_include, scope_exclude=args.scope_exclude,
        exact_urls=args.exact_url, allow_private=args.allow_private,
        aggressive=args.aggressive, offensive=offensive,
        bypass_budget=args.bypass_budget, max_depth=args.max_depth,
        authorization_identities=authorization_identities,
        deep_assets=args.deep_assets, secret_discovery=args.secret_discovery,
        auth_flow=args.auth_flow, source_maps=args.source_maps,
        browser_verify=args.browser_verify, auth_context=auth_context,
        engagement=EngagementProfile.from_file(args.engagement_file) if args.engagement_file else None, hunt_focus=hunt_focus,
        request_corpus=request_corpus,
        request_corpus_source=Path(args.request_corpus).name if args.request_corpus else "researcher_capture",
        show_secrets=args.show_secrets, login=login)

    if args.output_dir:
        destination = EvidenceBundleBuilder().write_directory(results, args.output_dir)
        results["evidence_bundle"] = {
            "written": True,
            "directory": str(destination),
            "files": ["manifest.json", "results.json", "report.md"],
        }
        print(f"[*] Evidence bundle: {destination}", file=out)

    if args.json:
        print(json.dumps(results, indent=2))
        return

    stats = results.get("stats", {})
    vulns = results.get("vulnerabilities", [])
    candidates = [f for f in results.get("findings", []) if f.get("status") != "VERIFIED"]
    recon = results.get("recon_depth", {}) or {}
    waf = (recon.get("waf") or {}).get("detected") or []
    tls = recon.get("tls") or {}
    ports = recon.get("ports") or []
    vrt = results.get("vrt_summary", {})
    fp_kill = results.get("fp_kill_summary", {}) or {}
    quarantined = results.get("quarantined_findings", []) or []

    print("--------------------------------------------------------------------------")
    print(f"📊 SUMMARY REPORT FOR: {results.get('target', target)}")
    print("--------------------------------------------------------------------------")
    engagement_summary = results.get("engagement", {}) or {}
    focus_summary = results.get("hunt_focus", {}) or {}
    capture_summary = results.get("captured_requests", {}) or {}
    print(f"• Engagement: {engagement_summary.get('engagement_id') or 'passive/non-offensive'}")
    print(f"• Hunt Objective: {focus_summary.get('objective') or 'not recorded'}")
    print(f"• Focus Classes: {', '.join(focus_summary.get('vulnerability_classes') or []) or 'none'}")
    print(f"• Captured Request Shapes: {capture_summary.get('in_scope_unique_requests', 0)}")
    print(f"• Subdomains Discovered: {stats.get('subdomains', 0)}")
    print(f"• Live HTTP Hosts: {stats.get('live_hosts', 0)}")
    print(f"• Endpoints Harvested: {stats.get('endpoints', 0)}")
    print(f"• JS Files Analyzed: {stats.get('js_files', 0)}")
    print(f"• JS Grep Matches: {stats.get('js_grep_matches', 0)}")
    print(f"• API Calls Traced: {stats.get('js_api_calls', 0)}")
    print(f"• Secrets Discovered: {stats.get('secrets_found', 0)}")
    hidden = results.get("hidden_assets", {}) or {}
    hidden_stats = hidden.get("stats", {}) or {}
    print(f"[ASSET] {hidden_stats.get('assets', 0)} JavaScript/config assets discovered")
    print(f"[MAP] {hidden_stats.get('source_maps', 0)} source maps parsed")
    print(f"[API] {hidden_stats.get('endpoints', 0)} correlated endpoints extracted")
    print(f"[BAAS] {hidden_stats.get('baas_projects', 0)} correlated BaaS projects")
    print(f"[CRED] {hidden_stats.get('credentials', 0)} redacted credential references")
    print(f"[AUTH] {hidden_stats.get('auth_flows', 0)} authentication flows")
    print(f"[GRAPH] {hidden_stats.get('relationships', 0)} credential/endpoint relationships")
    offensive = results.get("deep_exploit", {}) or {}
    print(f"[OFFENSIVE] mode={offensive.get('mode', results.get('exploit_mode', 'unknown'))} "
          f"hypotheses={len(offensive.get('plan', []) or [])} "
          f"requests={offensive.get('requests_used', 0)}/{offensive.get('request_budget', args.bypass_budget)} "
          f"verified_primitives={len(offensive.get('primitives', []) or [])}")
    for project in (hidden.get("baas_projects") or [])[:10]:
        identifiers = project.get("public_identifiers") or (project.get("auth") or {}).get("public_identifiers") or {}
        identifier_text = ", ".join(f"{key}={value}" for key, value in sorted(identifiers.items())) or "no public identifiers retained"
        print(f"    [BAAS] {project.get('provider', 'Cloud')} ref={project.get('project_ref') or 'unknown'} "
              f"url={project.get('url') or 'not observed'} key={project.get('key_type') or 'not paired'}")
        print(f"           identifiers: {identifier_text}")
    for credential in (hidden.get("credentials") or [])[:10]:
        used_by = ", ".join(credential.get("linked_endpoints") or []) or "not linked"
        print(f"    [CRED] {credential.get('credential_type', 'UNKNOWN_TOKEN')} "
              f"status={credential.get('status', 'CANDIDATE')} value={credential.get('_raw_value') or credential.get('masked_value') or '—'} "
              f"source={credential.get('source_file') or 'unknown'} used_by={used_by}")
    print(f"• Cloud/BaaS Misconfigs: {stats.get('cloud_misconfigs', 0)}")
    print(f"• WAF Detected: {', '.join(waf) if waf else 'none observed'}")
    if tls.get("observed"):
        san = tls.get("san") or []
        print(f"• TLS Certificate: {len(san)} SANs, expires {tls.get('not_after') or 'unknown'}")
    if ports:
        print(f"• Open Ports (top-200): {', '.join(str(p.get('port')) for p in ports)}")
    db = results.get("db_hunter", {}) or {}
    db_strings = db.get("connection_strings", []) or []
    db_ports = db.get("exposed_ports", []) or []
    unauth_db = [p for p in db_ports if p.get("probe", {}).get("auth_free")]
    live_poc = [f for f in results.get("findings", []) if f.get("poc_validation", {}).get("passed")]
    waf_bypass = results.get("waf_bypass_findings", []) or []
    bypass = results.get("bypass_engine", {}) or {}
    print(f"• Verified High/Critical Findings: {len(vulns)}")
    print(f"• Candidates Requiring Review: {len(candidates)}")
    print(f"• WAF Bypass Proven: {len(waf_bypass)} (" + ", ".join(f.get('type', '') for f in waf_bypass) + ")" if waf_bypass else "• WAF Bypass Proven: 0")
    print(f"• Adaptive Bypass: {bypass.get('requests_used', 0)}/{bypass.get('request_budget', args.bypass_budget)} requests, "
          f"{len(bypass.get('protection_fingerprints', []) or [])} protection fingerprint(s), "
          f"{len(bypass.get('primitives', []) or [])} verified primitive(s)")
    if results.get("bypass_authorization_identities"):
        print(f"• Authorization identities supplied: {len(results.get('bypass_authorization_identities') or [])} (headers redacted)")
    print(f"• VRT Triage: {vrt.get('approved', 0)} approved / {vrt.get('rejected_anti_na', 0)} anti-N/A / {vrt.get('rejected_no_poc', 0)} no-PoC")
    if db_strings:
        print(f"• DB Connection Strings Exposed: {len(db_strings)}")
        for item in db_strings[:5]:
            print(f"    - [{item.get('scheme')}] {item.get('_raw_value') or item.get('masked')} (src: {item.get('source')})")
    if db_ports:
        print(f"• Exposed DB Ports: " + ", ".join(f"{p.get('host')}:{p.get('port')}({p.get('service')})" for p in db_ports))
    hidden_ports = [p for p in db_ports if p.get("fingerprinted")]
    if hidden_ports:
        print(f"• Hidden/Non-Standard DB Ports (banner-fingerprinted): " + ", ".join(
            f"{p.get('host')}:{p.get('port')}({p.get('service')})" for p in hidden_ports))
    if unauth_db:
        print(f"• !!! UNAUTHENTICATED DB SERVICES (live-proven): " + ", ".join(
            f"{p.get('host')}:{p.get('port')}({p.get('service')})@no-auth" for p in unauth_db))
    admin_panels = db.get("admin_panels", []) or []
    backup_files = db.get("backup_files", []) or []
    hidden_strs = db.get("hidden_db_strings", []) or []
    if admin_panels:
        print(f"• Exposed Web DB Admin Panels: " + ", ".join(f"{p.get('url')}({p.get('panel')})" for p in admin_panels))
    if backup_files:
        print(f"• !!! DOWNLOADABLE DB DUMP/BACKUP FILES: " + ", ".join(b.get('url', '') for b in backup_files))
    if hidden_strs:
        print(f"• Hidden DB Strings in Page HTML: {len(hidden_strs)}")
        for item in hidden_strs[:5]:
            print(f"    - [{item.get('scheme')}] {item.get('_raw_value') or item.get('masked')} (src: {item.get('source')})")
    if live_poc:
        print(f"• Live PoC Re-validated (passed): " + ", ".join(f.get('type', 'finding') for f in live_poc))
    coverage = results.get("exploit_coverage", []) or []
    if coverage:
        gated = [c for c in coverage if c.get("kind") == "auth_gated"]
        json_api = [c for c in coverage if c.get("post_json_api")]
        print(f"• Exploit Coverage: {len(coverage)} endpoint(s) preflighted | "
              f"{len(gated)} auth-gated (deep tests need credentials) | "
              f"{len(json_api)} JSON-body POST endpoint(s) injected (SQLi/SSTI/error-disc)")
        for c in gated:
            print(f"    - AUTH-GATED (deep probes skipped): {c.get('endpoint')} (GET {c.get('get_status')})")
    print(f"• FP Kill Gate: {fp_kill.get('submission_ready', 0)} submission-ready / {fp_kill.get('quarantined', 0)} quarantined")
    if quarantined:
        reasons = fp_kill.get("reasons", {}) or {}
        print(f"• Quarantine Reasons: " + ", ".join(f"{k}: {v}" for k, v in sorted(reasons.items())))
        for q in quarantined[:5]:
            print(f"    - KILLED: {q.get('type') or 'finding'} ({q.get('endpoint')}) => {'/'.join((q.get('fp_kill') or {}).get('reasons', []))}")
    print()

    if vulns:
        print("✅ VERIFIED HIGH-IMPACT FINDINGS (READY FOR SUBMISSION):")
        for idx, finding in enumerate(vulns, 1):
            print(f"  [{idx}] {finding.get('vuln_type')} ({finding.get('severity')} - CVSS {finding.get('cvss_score')})")
            print(f"      Parameter: {finding.get('param')}")
            print(f"      Curl PoC: {finding.get('reproduction_curl')}")
            print(f"      Verification: {finding.get('verification_note')}\n")
    else:
        print("🔒 No high-impact vulnerabilities verified on target. No low-quality reports will be submitted.")

if __name__ == "__main__":
    main()
