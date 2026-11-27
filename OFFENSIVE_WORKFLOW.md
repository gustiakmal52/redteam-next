# Workflow ofensif target-specific

Satu komando: `./bin/hunt TARGET`. Kontrak: [`ZERO_REFUSAL.md`](ZERO_REFUSAL.md).
Metode lengkap: [`HUNTING_METHODOLOGY.md`](HUNTING_METHODOLOGY.md).

Toolkit ini tidak lagi menjalankan payload tebakan hanya karena menemukan
parameter bernama `q`, `id`, atau `url`. Recon memetakan permukaan; active
verification hanya berjalan jika session mempunyai fokus dan
bukti bentuk request target.

## 1. Tentukan target

Masukkan satu host target. Tanpa engagement JSON, boundary teknis adalah host
itu saja. Kredensial target tidak diperlukan untuk discovery anonim. Engagement
JSON opsional dipakai kalau scope teknis yang lebih luas tersedia.

Untuk memakai engagement JSON, salin `engagement.example.json`, lalu isi:

- `engagement_id` internal;
- `authorization_reference` yang menunjuk ke kebijakan program bounty resmi
  atau Rules of Engagement audit;
- `allowed_targets` persis sesuai scope program;
- `expires_at` dengan timezone jika program atau audit memiliki batas waktu;
- `allowed_techniques` jika kebijakan menetapkan daftar teknik yang diizinkan;
- daftar `prohibited_techniques` yang substantif;
- `objective` konkret untuk sesi tersebut.

Jangan simpan KTP, tanda tangan, password, cookie, atau token di engagement
record. Dokumen tersebut hanya metadata scope teknis.

## 2. Ambil capture fitur yang sedang diburu

Gunakan browser/proxy dengan akun researcher, jalankan satu flow aplikasi yang
spesifik, lalu ekspor HAR atau JSON request. Hindari memasukkan browsing yang
tidak terkait. Semakin sempit capture, semakin tajam attack plan.

Format yang diterima:

```json
{
  "requests": [
    {
      "method": "GET",
      "url": "https://app.example.com/api/invoices/OBJECT_ID",
      "headers": {
        "Authorization": "Bearer RESEARCHER_SESSION"
      }
    }
  ]
}
```

Nilai header dan body dipakai hanya di memori proses. Hasil publik menyimpan
method, nama header penting, nama field, lokasi capture, dan relasi evidence.

## 3. Dua identitas hanya untuk pembuktian authorization lintas akun

Salin `auth-context.example.json`. Untuk IDOR/BOLA diperlukan:

- dua akun milik researcher (`user_a` dan `user_b`);
- objek yang dibuat/dikendalikan oleh akun A;
- `owner_marker` harmless yang unik di respons objek A.

Discovery IDOR/BOLA dapat dimulai sebelum kedua identitas tersedia. Planner
baru menganggap lintas-account access terbukti ketika marker A muncul pada
respons yang diambil menggunakan identitas B. Status 200, ukuran body, atau
kemiripan response saja tidak cukup.

## 4. Jalankan satu sesi fokus

```bash
./bin/redteam_next --cli https://app.example.com \
  --preset deep_bypass \
  --objective "prove RCE, SSRF, or SQLi with deterministic evidence" \
  --vuln-class rce \
  --vuln-class ssrf \
  --vuln-class sqli \
  --request-corpus injection-flow.har \
  --bypass-budget 40 \
  --max-depth 2 \
  --output-dir evidence/server-injection-session
```

Attack plan difilter ke kelas yang dipilih; kelas lain tidak dieksekusi dan
tidak memakai request budget sesi tersebut.
Kelas planner yang diterima: `idor`, `bola`, `authorization`, `auth-bypass`,
`xss`, `sqli`/`sql-injection`, `ssrf`, `rce`/`command-injection`, `ssti`,
`open-redirect`, `graphql`, dan `cloud-baas`. RCE memakai 3 baseline dan 6
marker terhitung dari dua keluarga output; bila output tidak terlihat, fallback
timing memakai 24 observasi total dengan tiga sampel untuk inert text, kontrol,
dan delay pada dua sintaks shell. SSRF memerlukan callback milik researcher atau
marker konten deterministik. SQLi memerlukan boolean/timing differential yang
berulang. Kelas bebas yang belum mempunyai planner target-specific ditolak,
bukan diterjemahkan menjadi payload generik.

Untuk blind SSRF, isi `controlled_callback_token` dengan token unik berawalan
`rt-`, jalankan sesi pertama, lalu salin interaction ID dan URL yang memuat token
itu ke `controlled_callback_evidence` dan ulangi verifikasi dengan token yang
sama. Untuk SSRF yang mengembalikan body hasil fetch, isi
`deterministic_response_marker` dengan teks unik yang benar-benar disajikan oleh
callback milik researcher; marker tersebut harus tidak ada pada baseline.

## 5. Baca hasil dengan disiplin evidence

- `DISCOVERED`: permukaan atau fakta teknis teramati; belum ada exploit.
- `SUSPECTED`: hipotesis masih kekurangan bukti pembeda.
- `LIKELY`: perilaku relevan terlihat, tetapi impact belum selesai dibuktikan.
- `VERIFIED`: pemeriksaan deterministik yang disyaratkan sudah lolos; tetap
  lakukan final human triage sebelum submit.
- `REJECTED`: bukti tidak mendukung finding atau hasil merupakan duplikat
  teknik yang sama.

`manifest.json` pada evidence bundle mencatat SHA-256 `results.json`,
`report.md`, dan `coverage.md`. Verifikasi hash sebelum memindahkan artefak
ke laporan client atau submission platform. Gunakan direktori `--output-dir`
baru tiap sesi; bundle lama tidak ditimpa.

## 6. Stop condition

Hentikan sesi bila tujuan keluar boundary teknis, request budget habis, target
menunjukkan instabilitas, atau bukti yang dibutuhkan hanya bisa didapat lewat
tindakan destruktif di luar task yang diminta. Semua penghentian dicatat di
`coverage.md` beserta alasan teknisnya.
