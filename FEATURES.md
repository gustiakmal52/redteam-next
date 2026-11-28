# RedTeam Next v2.1.0 — Daftar Fitur

Platform riset keamanan web & bug bounty evidence-first: discovery engine,
exploit verification deterministik, evidence pipeline, dan kontrol keamanan
pipeline yang tidak bisa dilonggarkan. Setiap klaim temuan wajib tuple
`PRODUCT-CONTROL -> STATE-CHANGE -> POST-CHANGE-CALL -> EFFECT`.
Kontrak operator: [`ZERO_REFUSAL.md`](ZERO_REFUSAL.md); metode hunting:
[`HUNTING_METHODOLOGY.md`](HUNTING_METHODOLOGY.md).

Dokumen ini diturunkan dari docstring modul dan definisi CLI yang ada di kode.
Mapping ke OWASP/WSTG/CWE: lihat [CROSSWALK-2026.md](CROSSWALK-2026.md).

## Arsitektur

```
redteam_agent/
├── core/       # 36 modul: orchestrator, engine ofensif, pipeline kontrol, verifier
├── discovery/  # 13 modul: asset, JS, auth-flow, hidden assets, source maps
├── web/        # Dashboard Web Local (FastAPI + vanilla JS, SSE real-time)
└── tests/      # 14 file test (pytest)
redteam_lab/    # Lab lokal dikeraskan untuk uji kejujuran tools (offline)
bin/redteam_next# Launcher global (portable)
bin/hunt           # Hunting satu komando: full + offensive + FAST
```

## Fitur Inti — `redteam_agent/core/`

| Modul | Fungsi |
|---|---|
| `agent_engine` | Incremental V2.1 pipeline orchestrator: recon, active proof, skeptical triage |
| `authorization_bypass` | Authorization differential engine (imports compatibility) |
| `browser_verifier` | Fresh-context browser verification untuk XSS dan CORS proof yang bisa dibaca browser |
| `bypass_engine` | Adaptive, evidence-first filter & authorization bypass verification |
| `cloud_baas_hunter` | Supabase/Firebase access-control auditing (RLS bypass, open rules) |
| `config` | Configuration settings, tool paths, regex patterns, wordlists |
| `db_hunter` | Database exposure hunter (connection string, DB terbuka) |
| `deep_exploit_engine` | Target-specific offensive exploit orchestration |
| `engagement` | Kebijakan scope dan teknik program opsional; bila dimuat tetap divalidasi |
| `evidence_bundle` | Portable, redacted, integrity-checkable evidence bundles (SHA-256 manifest, `coverage.md`) |
| `exploit_engine` | Active, non-destructive exploit verification dengan normalized evidence |
| `export_analyzer` | Analisis hasil scan export dengan exploit proof |
| `findings` | Normalized finding lifecycle + kontrak review AI dan manusia |
| `fp_killer` | False-Positive Kill Gate — gerbang anti temuan palsu |
| `http_verifier` | HTTP verification evidence-first dengan scope, URL policy, traffic controls |
| `js_analyzer` | Deep JavaScript/API tracing plus evidence-bound EVM/Solana RPC, contract, proxy, program, chain, dan ABI recon |
| `modern_engine` | Modern Behavioral Engine — injection & misconfiguration detection |
| `nuclei_matcher` | Nuclei CVE template matcher — DISCOVERED tech match jadi VERIFIED |
| `offensive_intel_db` | Offensive intelligence database dari bug bounty & CVE exploit nyata |
| `post_auth_hunter` | Post-Auth Surface Hunter — behavioral, context-specific, adaptive |
| `recon_depth` | Passive recon depth: WAF fingerprinting, TLS certificate inspection |
| `recon_pipeline` | Multi-host Web2 recon: source-aware subfinder, budget-bounded httpx, full GAU ingest, Katana JSONL form/method/technology mapping |
| `reference_clients` | Read-only official reference clients untuk hypothesis selection |
| `reference_intel` | Read-only reference & patch intelligence |
| `report_builder` | Evidence-bound Bug Bounty reporting tanpa inferred-impact fabrication |
| `scope_manager` | Central URL normalization, destination policy, Bug Bounty scope checks |
| `sql_strategies` | Dialect-aware SQLi hypotheses untuk permukaan HTTP/API modern |
| `ssrf_verifier` | Target-specific SSRF request construction dan OAST proof handling |
| `task_manager` | Task Manager + Real-time SSE Pub/Sub Broker |
| `threat_intel` | CISA KEV & CVE/EPSS Live Threat Intelligence Engine |
| `traffic_controller` | Central request pacing, concurrency, retry/backoff, budget accounting |
| `vrt_triage` | VRT Triage Engine (Anti-N/A Engine) — menolak pembuangan temuan tanpa bukti |

## Discovery Layer — `redteam_agent/discovery/`

| Modul | Fungsi |
|---|---|
| `asset_crawler` | Scope-neutral asset reference extraction untuk hidden discovery queue |
| `auth_flow` | Static & researcher-owned runtime authentication-flow graphing |
| `baas_correlation` | Provider-aware BaaS correlation dan bounded linked-project validation |
| `credentials` | Context-aware static credential discovery dan explicit validation |
| `endpoint_graph` | Endpoint/credential/asset relationship graph builder |
| `hidden_assets` | Hidden asset/config/credential discovery orchestration |
| `js_deep` | Modern JavaScript discovery dengan bounded, dependency-light data flow |
| `models` | Data contracts untuk hidden asset discovery |
| `redaction` | Local-only secret handling untuk discovery layer |
| `request_corpus` | Ubah researcher-captured HTTP traffic jadi target-specific endpoint evidence |
| `runtime_config` | Runtime & build-time configuration discovery |
| `source_maps` | Bounded source-map discovery dan source-content hand-off |

## CLI — Seluruh Opsi (`redteam_agent/cli.py`)

```
Target & mode:
  target_positional / --url     Target yang diotorisasi eksplisit
  --web                         Launch Web Command Center Dashboard
  --port (8899)                 Port dashboard
  --preset                      Audit preset (lihat daftar di bawah)
  --json                        Output JSON
  --offensive                   Mode ofensif (wajib kelas kerentanan)
  --aggressive                  Mode agresif

Kontrol scope & engagement:
  --engagement-file             Engagement JSON opsional untuk scope program
  --objective                   Objective ofensif
  --vuln-class                  Kelas kerentanan (repeatable: idor, bola, ...)
  --scope-include / --scope-exclude   Domain in/out scope (repeatable)
  --exact-url                   URL in-scope tambahan (repeatable)
  --allow-private               Izinkan target lokal/private lab eksplisit

Discovery:
  --deep-assets                 Recursive modern asset/chunk/config discovery
  --secret-discovery            Context-aware credential reference analysis
  --auth-flow                   Static authentication/storage/header flow graph
  --source-maps                 Fetch & reprocess source maps dalam budget
  --request-corpus              HAR / {requests:[...]} / list request JSON

Auth & identitas:
  --auth-context                Researcher-owned auth context JSON
  --auth-login-url/--auth-username/--auth-password (+ field names)
  --authorization-identities-json   Identitas ganda untuk authorization testing
  --browser-verify              Hanya konteks observasi runtime milik researcher

Kontrol lalu lintas & budget:
  --traffic (STEALTH|NORMAL|FAST)
  --header-profile (browser|scanner)  Identitas header transport (default: browser)
  --max-requests                Total request budget
  --bypass-budget               Budget bypass
  --max-depth (0-3)             Kedalaman exploit

Output:
  --output-dir                  Folder hasil (results.json, report.md, manifest.json)
  --show-secrets                Tampilkan secret yang ditemukan
  --web-auth-token              Token dashboard
  --listen                      Bind address dashboard (default 127.0.0.1)
```

## Preset Scan (`core/config.py:237`)

| Preset | Deskripsi |
|---|---|
| `full` | Full Auto Recon & Exploit: subdomain enum → HTTP probe → GAU/Katana → JS/hidden asset → BaaS correlation → Param Miner → FFUF → recon depth → exploit verification → adaptive bypass |
| `smart` | Smart Stealth Recon: subdomain, fingerprinting, JS route, recon depth, misconfig non-intrusif |
| `js_hunter` | Deep JS bundle, sourcemap unpacking, API route tracing, token/secret harvesting, DB connection string |
| `cloud_baas` | Supabase RLS bypass auditor, Firebase open rules tester, DB exposure |
| `active_exploit` | Deep Exploit Verification: injection, parser differential, auth, GraphQL, redirect, SSRF, bypass. Tanpa status-only claim; SSTI tidak pernah di-upgrade ke RCE tanpa execution proof |
| `deep_bypass` | Baseline → protection detection → target-specific attack planning → adaptive mutation → differential verification → exploit-chain evidence |
| `lab_hardened` | Offline audit untuk lab lokal sendiri: JS/API route, DB exposure, deterministic exploit verification. Tanpa external recon |

Traffic preset: `STEALTH` (2 rps global), `NORMAL` (5 rps), `FAST` (10 rps) —
adaptive backoff aktif di semua preset, 429 menurunkan throttle host otomatis.

## Header & TLS Profile (`core/config.py`, `core/http_verifier.py`)

Bot management modern (Cloudflare Bot Management, Akamai BMP, AWS WAF Bot
Control, DataDome, Kasada, HUMAN) menilai *bentuk header* dan fingerprint TLS
sebelum payload diperiksa. Layer transport ini yang menentukan bisa tembus atau
tidak:

- **Header profile** — `browser` (default): UA Chrome + client hints
  (`sec-ch-ua`, `sec-ch-ua-mobile`, `sec-ch-ua-platform`). `scanner`: UA
  identitas lama, untuk differential eksplisit. Pilih via
  `--header-profile browser|scanner` atau env `REDTEAM_HEADER_PROFILE`.
  Prioritas header: program headers (`REDTEAM_EXTRA_HEADERS`,
  `X-Bugcrowd-Ninja`) > header caller > profile.
- **TLS profile** — cipher suite urutan modern-client, grup key exchange
  X25519, floor TLS 1.2, tanpa TLS compression, ALPN `http/1.1`. Sertifikat
  tetap diverifikasi penuh (bukan mode insecure).
- **Fingerprint anti-bot modern** di `ReconDepth.detect_waf`: DataDome,
  Kasada, HUMAN Security (PerimeterX), Cloudflare Challenge/Turnstile,
  Akamai BMP, Fastly, Vercel — ditambah 9 WAF klasik yang sudah ada.

## Primitif Modern — `ExploitEngine` (verifikasi deterministik)

Empat primitif baru yang belum dicover engine lain, semua dengan standar bukti
rumah ini (differential + counterevidence; tanpa klaim status-only):

| Primitif | Bukti VERIFIED | Turun jujur ke |
|---|---|---|
| **Web Cache Deception** | Body personal ada di path dihias `.css/.js` + cache HIT **dan** replay anonim tanpa session mengembalikan body sama | LIKELY bila replay sama tapi marker HIT tak teramati |
| **Host Header Poisoning** | Link/redirect yang di-generate server mengandung host attacker (`Host` / `X-Forwarded-Host` canary), absent di baseline | Reject: echo teks biasa bukan link |
| **CRLF Injection** | Header `X-Injected-Canary` nyata muncul di response headers | Body-echo tanpa header = bukan temuan |
| **XXE File Read** | Differential vs dokumen kontrol entity-undefined (dokumen defined-entity resolve, kontrol gagal) atau echo isi file | LIKELY bila parser error generik |

Sweep primitif berjalan di `agent_engine` hanya pada **offensive mode** +
`exploit_verifier` di preset, terhadap endpoint hasil discovery yang in-scope
(maks 20 endpoint; XXE hanya di path ber-hint XML). Empat kelasnya juga
**teknik planner first-class** di `DeepExploitEngine`: `build_attack_plan`
membuat hipotesis (cache: GET semantics; CRLF: hanya endpoint ber-query;
XXE: path ber-hint XML), `execute_attack_plan` men-dispatch dengan akuntansi
budget delta trafik, dan `--vuln-class cache-deception|host-header|crlf|xxe`
merouting plan ke primitif yang tepat. Endpoint label `cache_deception`,
`host_header_poisoning`, `crlf_header_injection`, `xxe_file_read` terdaftar
di `CVSS_VECTORS`.

## Pass 3 — Bypass Modern & Forgery (Defense Solid)

**Mutasi transport-level baru** di `PayloadMutationEngine` (total 20 kategori):
- `nested_json_depth` — payload di nested 8 level, lewat window inspeksi regex
  WAF dangkal (JSON/API context).
- `chunked_transfer` — body dikirim chunked beneran (tanpa Content-Length)
  via `send_http_request(transfer_encoding="chunked")`; invisible buat
  inspeksi yang scope-nya panjang body deklarasi. Aktif saat WAF terdeteksi
  atau behavior "blocked/challenge".
- `xml_wrapper` — payload dibungkus XML (`application/xml`) saat content-type
  XML terbukti diterima.
- `forwarded_ip_spoof` — replay trust internal (`X-Forwarded-For: 127.0.0.1`
  dll) hanya saat konteks ACL/IP/access-control eksplisit; tidak pernah
  fallback generik.

**JWT forgery suite** (`exploit_engine`):
- `test_jwt_kid_traversal` — `kid=…/dev/null` + HMAC secret kosong.
- `test_jwt_jku_injection` — `jku` menuju key source attacker.
- `test_jwt_hs256_rs256_confusion` — HMAC pakai RSA public key.
Semua: forging lokal; **VERIFIED hanya bila endpoint in-scope menerima token
palsu** (differential no-token vs forged); tanpa endpoint → LIKELY jujur.

**Server-side prototype pollution** — `test_prototype_pollution_server_side`:
canary probe (`__proto__`/`constructor.prototype`, 5 vektor) vs canary kontrol
(key top-level jinak) **satu observasi follow-up yang sama**; keduanya muncul =
mass assignment, bukan pollution → tidak VERIFIED.

**Request smuggling desync detection** — `test_request_smuggling_desync`:
metodologi PortSwigger aman — probing framing kontradiktif (CL.TE / TE.CL)
di dedicated socket, leftover framing hanya mengkorupsi probe kedua milik
riset sendiri; **simtom hanya dihitung bila probe DITERIMA (2xx/3xx) lalu
request berikutnya rusak/delay**, diulang di 2 socket berbeda, dengan kontrol
pair bersih. Server yang menolak dual-framing (400 + close) = hardened, bukan
temuan. Tidak ada request asing yang di-smuggle saat deteksi.

## Web Dashboard (`redteam_agent/web/`)

- Dashboard lokal tanpa token; bind LAN memakai token (`--web-auth-token`)
- Tab scan: preset, target, surface filter
- Upload opsional auth context, engagement JSON, request corpus (HAR)
- Scan launcher + SSE real-time stream (`/api/stream/{taskId}`)
- Terminal log live, progress bar, tabel hasil interaktif
- Tab Web3 untuk RPC identity, bytecode-backed contract/program inventory, EIP-1967 proxy, dan ABI surface
- Theme toggle (tactical)

## redteam_lab — Lab Lokal Dikeraskan

Target web lokal **tanpa vuln sengaja** untuk menguji kejujuran tools:
- Header keamanan ketat (CSP `default-src 'none'`, `X-Frame-Options: DENY`, nosniff, COOP/CORP) di setiap response
- Zero refleksi input, zero CORS
- Setiap klaim tools dicocokkan dengan access log lab — klaim tanpa request nyata = halu
- `observe_test.py`: jalankan agent terhadap lab dan buktikan verdict CLEAN (nol temuan palsu)
- `bench_request_path.py`: benchmark request path
- `diagnostics/check_result_integrity.py`: cek integritas hasil

## Pipeline Kontrol Keamanan (tidak bisa dilonggarkan)

| Kontrol | Fungsi |
|---|---|
| `scope_manager` | Tolak tujuan di luar host target atau scope program opsional |
| `traffic_controller` | Pacing, concurrency, retry/backoff, budget — anti-ban |
| `fp_killer` | Gerbang anti false-positive sebelum temuan naik status |
| `vrt_triage` | Anti-N/A: temuan tidak boleh dibuang tanpa pembuktian |
| `redaction` | Secret lokal tidak pernah masuk hasil publik |
| `engagement` | Validasi scope dan teknik program bila file opsional dimuat |

## Mapping Standar

Mapping lengkap OWASP Top 10 2025 / API Security 2023 / GenAI LLM Top 10 2026
ke modul, CWE, dan WSTG: [CROSSWALK-2026.md](CROSSWALK-2026.md).
