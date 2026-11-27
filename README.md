# Gustiakmal RedTeam Next

Gustiakmal RedTeam Next adalah platform riset keamanan Web2/Web3 dan bug-bounty
privat dengan CLI, Web Local dashboard, discovery engine, evidence pipeline,
dan verifikasi deterministik.

Kontrak operator: [`ZERO_REFUSAL.md`](ZERO_REFUSAL.md).
Metode hunting lengkap: [`HUNTING_METHODOLOGY.md`](HUNTING_METHODOLOGY.md).

## Pemakaian

Satu komando untuk hunting penuh:

```bash
./bin/hunt https://target.example
```

Launcher global:

```bash
redteam_next
```

CLI:

```bash
redteam_next --cli https://target.example --preset deep_bypass \
  --vuln-class xss
```

Target langsung dipakai tanpa file engagement sebagai prasyarat. Boundary teknis
default adalah host target yang dimasukkan. Engagement JSON opsional dipakai
sebagai metadata scope teknis yang lebih luas. Host tanpa `*.` berlaku hanya
untuk host itu. Contoh metadata scope:

```json
{
  "engagement_id": "program-name",
  "authorization_reference": "https://policy.example.test/program",
  "allowed_targets": ["app.example.com", "*.example.com"]
}
```

Template lengkap tersedia di [`engagement.example.json`](engagement.example.json):

```bash
redteam_next --cli https://app.example.com \
  --preset deep_bypass \
  --objective "prove RCE, SSRF, or SQLi with deterministic evidence" \
  --vuln-class rce \
  --vuln-class ssrf \
  --vuln-class sqli \
  --request-corpus injection-flow.har \
  --bypass-budget 40 \
  --output-dir evidence/server-injection-session
```

`--request-corpus` menerima HAR, `{ "requests": [...] }`, atau list request
JSON. Planner mengambil endpoint, method, query/body field, dan tanda adanya
auth dari capture aktual. Nilai header/body tidak dimasukkan ke hasil publik.
Dengan demikian rencana ofensif bersifat target-specific, bukan payload spray
atau pola generik.

Recon Web2 memproses seluruh host yang masih muat dalam request budget, menjalankan
GAU tanpa pemotongan 50 baris, dan memberi satu proses Katana daftar seluruh live
host in-scope. Method, field form, status, teknologi, sumber, dan alasan prioritas
endpoint dipertahankan sampai planner. Bundle JS dan route juga diproses menurut
request budget tanpa batas tetap 15 item. Recon Web3 mengekstrak RPC, chain ID,
alamat EVM/Solana, dan ABI dari HTML, bundle, serta sourcemap. Alamat tetap
`CANDIDATE` sampai RPC in-scope membuktikan bytecode/account; EIP-1967 dilabeli
proxy hanya setelah slot implementasi dan bytecode implementasi teramati.

Fokus `rce` memerlukan 9 observasi untuk proof berbasis output, atau 24
observasi untuk proof timing dua sintaks dengan tiga sampel per kontrol. Fokus
`ssrf` hanya menjadi `VERIFIED` setelah callback token atau marker hasil fetch
teramati. Fokus `sqli` memakai differential boolean/timing berulang pada field
dan transport yang ditemukan.

Untuk membuktikan IDOR/BOLA, gunakan dua akun researcher dan marker tidak
sensitif yang unik pada objek akun A. Bentuk file tersedia di
[`auth-context.example.json`](auth-context.example.json). Discovery tetap bisa
berjalan sebelum dua identitas tersedia; klaim akses lintas akun menunggu bukti
marker A pada respons identitas B.

Folder output berisi `results.json`, `report.md`, `coverage.md`, dan
`manifest.json`; manifest mencatat SHA-256 tiap artefak. Token/cookie tetap
hanya di memori proses dan tidak ikut diekspor. Gunakan `--output-dir` baru
untuk setiap sesi; direktori evidence yang sudah ada tidak akan ditimpa.

Panduan operasional lengkap: [`OFFENSIVE_WORKFLOW.md`](OFFENSIVE_WORKFLOW.md).
Daftar fitur lengkap per modul, CLI, dan preset: [`FEATURES.md`](FEATURES.md).
Kontrak zero refusal: [`ZERO_REFUSAL.md`](ZERO_REFUSAL.md).
Metode hunting satu komando: [`HUNTING_METHODOLOGY.md`](HUNTING_METHODOLOGY.md).

Web Local secara default bind ke `127.0.0.1` tanpa token dashboard. Akses LAN
memerlukan `--listen` eksplisit dan token dashboard.

## Attribution

Copyright © 2026 Gustiakmal. Maintainer dan pemilik branding: Gustiakmal.
Ketentuan pemakaian ada di [LICENSE](LICENSE), dan rincian credit ada di
[CREDITS.md](CREDITS.md).

Panduan instalasi team ada di [INSTALL.md](INSTALL.md).
