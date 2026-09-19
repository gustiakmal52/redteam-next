# Gustiakmal RedTeam Next — redteam_lab Web Lab Lokal "Dikeraskan" untuk Uji Kejujuran Tools

Folder ini berisi **target web lokal yang dikeraskan** (bukan lab vuln sengaja)
buat menguji `redteam_agent` secara **jujur dan teramati** — persis filosofi bug
bounty resmi: target produksi yang ketat, dan hasil scan yang benar adalah
"tidak ada temuan palsu".

## Kenapa lab-nya sengaja TIDAK punya vuln?

Karena itu justru tes yang paling sulit dan paling jujur:

- Kalau tools mengarang temuan, di target bersih ini **langsung kelihatan**.
- Setiap klaim tools bisa dicocokkan dengan **access log lab** (siapa yang
  benar-benar minta apa). Tidak ada klaim tanpa request nyata = tidak ada halu.
- Verifier tools memang anti-FP: XSS butuh konteks HTML yang *executable*,
  SSTI butuh token aritmetika eksak, SQLi butuh delta timing nyata. Lab ini
  dirancang agar semua itu **tidak mungkin lolos** secara deterministik.

## Fitur "super ketat" yang diaktifkan lab

| Kontrol | Implementasi |
|---|---|
| Header keamanan | CSP `default-src 'none'`, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy`, `Permissions-Policy`, COOP/CORP — di **setiap** response |
| Zero refleksi input | HTML statis; API JSON tidak pernah meng-echo input user |
| Zero CORS | Tidak ada header `Access-Control-Allow-Origin` sama sekali |
| Zero form HTML | Tidak ada permukaan CSRF |
| 404 seragam | `/.env`, `/.git/HEAD`, `/db.sql`, `/phpmyadmin/`, `/graphql`, path admin → semua 404 tanpa petunjuk |
| Auth API | `/api/v1/products` butuh `Authorization: Bearer <token>` yang divalidasi server |
| Tanpa bocor detail | Tanpa stack trace, tanpa banner versi server, konten tidak pernah dibaca dari disk (struktural anti path-traversal) |
| Observability | Setiap request ditulis ke access log JSONL |

## Cara pakai

### 1. Jalankan sekali (otomatis: lab + scan + cek kejujuran)

```bash
python3 redteam_lab/observe_test.py
```

Alurnya:
1. Menyalakan lab di `http://127.0.0.1:<port>` (port bebas).
2. **Self-audit kontrol** — memastikan lab benar-benar ketat sebelum discan.
3. Menjalankan agent: preset `lab_hardened`, `--allow-private` (target sendiri).
4. Mematikan lab, lalu **cross-check**: setiap URL yang diklaim scan harus
   benar-benar muncul di access log lab.
5. Hasil + artefak tersimpan di `redteam_lab/output/run-<timestamp>/`:
   - `lab_access.jsonl` — semua request yang benar-benar diterima lab
   - `scan_results.json` — hasil scan penuh
   - `summary.txt` — ringkasan + verdict

**Verdict yang diharapkan:** `CLEAN` — nol temuan, nol request karangan.

### Interpretasi hasil dan integritas bukti

`CLEAN` berarti tidak ada temuan terverifikasi pada kedua koleksi hasil dan
tidak ada ketidakcocokan klaim request terstruktur yang diperiksa. Kandidat
yang belum terverifikasi boleh tetap ada; statusnya tidak diubah oleh observer.
Ini tidak membuktikan seluruh target bebas kerentanan atau seluruh endpoint tercakup.

Observer mencocokkan klaim dengan metode HTTP, path, dan query persis pada
access log. URL yang hanya disebut sebagai target atau hasil discovery bukan
klaim request. Jika tidak ada klaim terstruktur, cakupan pemeriksaan bukti
dilaporkan `Unknown`. Body request, isi response, dan hubungan sebab-akibat
temuan tidak dibuktikan oleh pencocokan access log ini.

Exit code `0` berarti hasil memenuhi ekspektasi mode yang dijalankan;
`1` berarti kontrol atau penilaian hasil tidak memenuhi ekspektasi;
`2` berarti subprocess scan gagal atau timeout. Ringkasan ditulis ke
`summary.txt` saat keluar, termasuk jalur kegagalan. Penghentian paksa proses
oleh sistem tetap dapat mencegah penulisan file.

### 1b. Mode demo: buktikan probe error_disclosure beneran VERIFIED

```bash
python3 redteam_lab/observe_test.py --demo
```

Mode `--demo` menyalakan satu endpoint **yang sengaja bocor** (`/api/v1/parse`,
500 + stack trace JSON saat input JSON rusak/type-confusion — mensimulasikan
handler error global yang hilang di endpoint util). Hasil yang diharapkan:
**VERDICT: DETECTED** — `Error/Stack-Trace Disclosure on Malformed Input`
VERIFIED (CVSS 5.3) dan klaimnya terbukti di access log lab.

Tanpa `--demo` lab tetap 100% keras (endpoint itu tidak ada sama sekali →
VERDICT: CLEAN). Jadi lab ini punya dua mode: **uji anti-FP** (default) dan
**uji deteksi** (`--demo`).

### 1c. Mode offensive fixture: wajib ada finding positif

Mode hardened/default tetap dipakai untuk menguji bahwa scanner tidak
mengarang vulnerability. Untuk menguji jalur ofensif baru, gunakan fixture
positif yang terpisah:

```bash
python3 redteam_lab/observe_test.py \
    --offensive-fixture --preset lab_hardened --traffic FAST
```

Fixture ini sengaja memiliki surface lokal yang observable:

- reflected XSS di `GET /api/v1/search?q=...` dengan executable HTML canary;
- SSTI di `POST /api/v1/render` dengan dua hasil aritmetika berbeda;
- GraphQL introspection di `POST /api/v1/graphql`;
- open redirect ke `redirect-canary.invalid` yang dikendalikan researcher.

JavaScript fixture juga memuat dynamic chunk, service worker, runtime config,
dan source map agar discovery layer ikut diuji. Observer mengharuskan finding
`VERIFIED` dan primitive ofensif benar-benar masuk access log. Mode ini tidak
menurunkan FP gate pada target hardened; hanya evidence dengan proof spesifik
yang dipertahankan.

### 2. Preset lain

```bash
python3 redteam_lab/observe_test.py --preset full       # semua modul (termasuk subfinder/naabu/ffuf)
python3 redteam_lab/observe_test.py --preset active_exploit
python3 redteam_lab/observe_test.py --traffic NORMAL --max-requests 1500
```

Catatan: preset `full` menjalankan subfinder/naabu/ffuf dan butuh internet;
preset default `lab_hardened` **offline total** dan 100% bisa diatribusikan ke
lab (paling cocok untuk uji kejujuran).

### 3. Manual

```bash
# terminal 1 — nyalakan lab
python3 redteam_lab/lab_server.py --port 8791 --log /tmp/lab.jsonl

# terminal 2 — scan target lab-mu sendiri
cd redteam_agent/..   # project root
python3 -m redteam_agent.cli --url http://127.0.0.1:8791 \
    --preset lab_hardened --allow-private --json
```

## Preset baru: `lab_hardened`

Ditambahkan ke `SCAN_PRESETS` (config), CLI, dan dashboard:

- Modul: `js_analyzer` + `cloud_baas` + `db_hunter` + `exploit_verifier` + `bypass_engine`
- Tanpa subfinder/gau/katana/ffuf/naabu (tanpa subprocess eksternal)
- Tanpa panggilan internet, tanpa port-scan host
- Artinya semua request scan bisa dicocokkan satu-satu dengan log lab

## Deep Adaptive Bypass

`BypassEngine` adalah modul terpisah dari verifier klasik. Pada mode `SAFE`, ia
tetap boleh mencoba mutation/bypass non-destruktif dengan sub-budget terpisah.
Mode `AGGRESSIVE` hanya menambahkan probe yang lebih noticeable. Engine memilih
mutation berdasarkan kelas input,
response, dan fingerprint yang sudah diamati:

```bash
python3 -m redteam_agent.cli --url http://127.0.0.1:8791 \
    --preset deep_bypass --allow-private --aggressive \
    --bypass-budget 40 --max-depth 3 --json
```

Setiap bypass tetap harus melewati bukti perilaku yang relevan. Perubahan
`403 -> 200`, reflection, perbedaan status, atau response error tidak otomatis
menjadi `VERIFIED`. Evidence menyimpan request/response baseline dan mutated,
differential, primitive, proof akhir, score strategy, dan penggunaan budget;
credential/header sensitif di-redact sebelum masuk hasil.
