# Gustiakmal RedTeam Next

Gustiakmal RedTeam Next adalah platform riset keamanan web dan bug-bounty
privat dengan CLI, Web Local dashboard, discovery engine, evidence pipeline,
dan verifikasi deterministik.

## Pemakaian

Launcher global:

```bash
redteam_next
```

CLI:

```bash
redteam_next --cli https://target.example --preset full \
  --engagement-file engagement.json
```

Setiap scan target membutuhkan engagement JSON yang mereferensikan izin tertulis,
scope persis, waktu kedaluwarsa, dan teknik yang dilarang. Mode ofensif juga
mewajibkan objective serta satu atau dua kelas kerentanan. Contoh aman tersedia
di [`engagement.example.json`](engagement.example.json):

```bash
redteam_next --cli https://app.example.com \
  --preset deep_bypass \
  --engagement-file engagement.json \
  --objective "prove cross-tenant invoice read" \
  --vuln-class idor \
  --vuln-class bola \
  --request-corpus captured.har \
  --auth-context auth-context.json \
  --output-dir evidence/session-001
```

`--request-corpus` menerima HAR, `{ "requests": [...] }`, atau list request
JSON. Planner mengambil endpoint, method, query/body field, dan tanda adanya
auth dari capture aktual. Nilai header/body tidak dimasukkan ke hasil publik.
Dengan demikian rencana ofensif bersifat target-specific, bukan payload spray
atau pola generik.

Untuk IDOR/BOLA, gunakan dua akun researcher dan marker tidak sensitif yang
unik pada objek akun A. Bentuk file tersedia di
[`auth-context.example.json`](auth-context.example.json). Planner menolak sesi
authorization jika dua identity atau owner marker belum tersedia; respons 200
yang sama tanpa marker lintas akun tidak dianggap bukti IDOR.

Folder output berisi `results.json`, `report.md`, dan `manifest.json`; manifest
mencatat SHA-256 tiap artefak. Token/cookie tetap hanya di memori proses dan
tidak ikut diekspor.

Panduan operasional lengkap: [`OFFENSIVE_WORKFLOW.md`](OFFENSIVE_WORKFLOW.md).

Web Local akan memakai launcher global dan bind ke IP LAN yang terdeteksi,
kecuali `--listen` diberikan secara eksplisit.

## Attribution

Copyright © 2026 Gustiakmal. Maintainer dan pemilik branding: Gustiakmal.
Ketentuan pemakaian ada di [LICENSE](LICENSE), dan rincian credit ada di
[CREDITS.md](CREDITS.md).

Panduan instalasi team ada di [INSTALL.md](INSTALL.md).
