# Hunting Methodology — pipeline satu komando

Dokumen ini menyatukan metode hunting yang dipakai di lapangan dengan modul
RedTeam Next. Urutan ini dipakai untuk setiap target, dari recon pasif sampai
closure temuan. Tidak ada langkah yang dilewatkecuali alasan teknisnya
tercatat di `coverage.md`.

## 0. Komando tunggal

```bash
./bin/hunt TARGET
```

Contoh:

```bash
./bin/hunt https://app.example.com
./bin/hunt app.example.com --scope-include '*.example.com' --max-requests 5000
```

`bin/hunt` memakai preset `full` + mode ofensif + `FAST`, mengaktifkan
`--deep-assets --secret-discovery --auth-flow --source-maps`, lalu menulis
bundle ke direktori evidence baru. Flag tambahan setelah target diteruskan
ke CLI dan menimpa default.

Ekivalen manual:

```bash
./bin/redteam_next --cli https://app.example.com \
  --preset full --offensive --traffic FAST \
  --deep-assets --secret-discovery --auth-flow --source-maps \
  --max-requests 3000 --max-depth 2 \
  --output-dir evidence-app-example-com
```

## 1. Refresh intel dulu, bukan menebak

Sumber yang dipakai: CISA KEV, FIRST EPSS, CVE List v5 / NVD, OSV / GHSA,
vendor advisory, Exploit-DB metadata, aktivitas PoC GitHub, cakupan
Metasploit, dan cakupan Nuclei.

Module: `core/threat_intel.py`, `core/offensive_intel_db.py`,
`core/nuclei_matcher.py`, `core/reference_intel.py`.

Aturan: kecocokan database menghasilkan **kandidat**, bukan klaim kerentanan.
Kandidat harus melewati gate fingerprint: product + version + build + prerequisite
harus sama persis dengan yang teramati di target.

## 2. Recon pasif → aset → live host

Urutan:

1. Enum pasif: `crt.sh`, `certspotter`, OTX, Wayback CDX, `subfinder`, `amass`,
   `assetfinder`, `findomain`.
2. Resolve + probe: `dnsx`, `httpx`, `naabu`.
3. URL harvest: GAU tanpa pemotongan, Wayback, `katana`, `hakrawler`,
   `gospider`.
4. JS bundle + sourcemap: route, parameter, secret reference, API base,
   Web3 RPC/ABI.

Modul: `core/recon_pipeline.py`, `core/recon_depth.py`, `core/js_analyzer.py`,
`discovery/asset_crawler.py`, `discovery/js_deep.py`, `discovery/source_maps.py`,
`discovery/hidden_assets.py`.

Semua hasil masuk queue dengan source + method + field + status + alasan
prioritas. Tidak ada endpoint yang dibuang karena namanya terlihat membosankan.

## 3. Hidden endpoint & parameter discovery

- Wordlist: ffuf / feroxbuster / dirsearch, disesuaikan budget.
- Parameter: arjun, paramspider, param-miner, perubahan method, variant
  case/encoding, endpoint deprecated, shadow API, route versi lama.
- Perhatikan juga: debug/status route, callback OAuth, upload/preview,
  export/report, endpoint admin yang tidak terlink, GraphQL introspection.

Modul: `discovery/runtime_config.py`, `discovery/request_corpus.py`,
`core/modern_engine.py`, `core/post_auth_hunter.py`.

## 4. Hipotesis per tembakan

Setiap request aktif punya hipotesis tertulis: kontrol yang diubah, perubahan
keadaan yang diharapkan, dan effect yang harus teramati. Payload spray tanpa
hipotesis tidak dihitung sebagai coverage.

Permukaan yang wajib diuji bila muncul:

- LLM gateway / MCP tool-server / GPT actions / RAG (2025-2026)
- OAuth redirect chain + code theft
- Web cache deception / poisoning
- ORM operator leak dan mass assignment
- SSRF redirect loop + cloud metadata
- postMessage origin neglect
- HTTP/2 desync / request smuggling

Modul: `core/sql_strategies.py`, `core/bypass_engine.py`,
`core/deep_exploit_engine.py`, `core/modern_engine.py`, `core/ssrf_verifier.py`.

## 5. Chain wajib, high/critical dulu

Setiap primitif diuji eskalasinya sebelum ditutup:

| Primitif | Chain yang diuji |
|---|---|
| XSS + CSRF | account takeover |
| SSRF + metadata | cloud credential / takeover |
| open redirect + OAuth | authorization code theft |
| IDOR write + mass assignment | privilege escalation |
| BaaS open rules + exposed key | data massal lintas tenant |
| upload + parser differential | RCE |

Low/Info hanya dicatat bila jadi mata rantai. Temuan high/critical dikerjakan
lebih dulu sampai rantai terbukti jalan atau buntu dengan bukti.

## 6. Differential evidence

Setiap kandidat wajib punya tuple:

```
PRODUCT-CONTROL -> STATE-CHANGE -> POST-CHANGE-CALL -> EFFECT
```

Field yang disimpan: `baseline`, `got`, `post_change_call`, `effect`.
Tanpa tuple lengkap, status maksimal `SUSPECTED` / `open_proof_gap`.

Modul: `core/http_verifier.py`, `core/fp_killer.py`, `core/vrt_triage.py`,
`core/findings.py`.

## 7. Counterevidence pass

Sebelum closure, jalankan pembantaian terhadap temuan sendiri:

- replay dengan kontrol negatif (payload inert / nilai baseline);
- replay pada objek/file yang tidak terkait;
- bandingkan dua identitas bila klaimnya lintas akun;
- cek apakah perubahan datang dari cache, timing jaringan, atau state session;
- cek apakah response berasal dari WAF/error handler, bukan aplikasi;
- cari penjelasan alternatif yang lebih sederhana.

Kalau penjelasan alternatif menang, temuan ditutup `ruled_out`, bukan dibungkus.

## 8. Closure discipline

| Status | Arti |
|---|---|
| `confirmed` | Tuple lengkap + counterevidence lolos + efek deterministik. |
| `ruled_out` | Ada bukti yang meniadakan kandidat; alasan dicatat. |
| `open_proof_gap` | Perilaku relevan terlihat tetapi bukti pembeda belum cukup. |

Dilarang membuang kandidat sebagai N/A tanpa pembuktian. `vrt_triage` menjaga
ini.

## 9. Ritme, budget, dan coverage

- `traffic_controller`: pacing global + per-host, retry/backoff, 429 menurunkan
  throttle otomatis.
- Profile: `STEALTH` 2 rps, `NORMAL` 5 rps, `FAST` 10 rps.
- `coverage.md` mencatat: target, endpoint yang diuji, kelas yang ditembak,
  request budget terpakai, skip dengan alasan teknis, dan status closure.
- Tanpa flooding produksi, tanpa mass-delete, tanpa eksfiltrasi data pengguna.

## 10. Report

Bundle: `results.json`, `report.md`, `manifest.json` (SHA-256 tiap artefak),
`coverage.md`. Token/cookie tetap di memori proses dan tidak ikut diekspor.
Impact tidak dikarang: yang belum terbukti ditulis sebagai `open_proof_gap`.

## Mapping cepat

| Langkah | Modul |
|---|---|
| Intel refresh | `threat_intel`, `offensive_intel_db`, `nuclei_matcher` |
| Passive recon | `recon_pipeline`, `recon_depth`, `js_analyzer` |
| Hidden assets | `hidden_assets`, `js_deep`, `runtime_config`, `source_maps` |
| Planning | `deep_exploit_engine`, `request_corpus`, `reference_clients` |
| Proof | `http_verifier`, `bypass_engine`, `ssrf_verifier`, `browser_verifier` |
| Anti-noise | `fp_killer`, `vrt_triage`, `findings` |
| Bundle | `evidence_bundle`, `report_builder` |
