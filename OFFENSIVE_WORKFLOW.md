# Workflow ofensif target-specific

Toolkit ini tidak lagi menjalankan payload tebakan hanya karena menemukan
parameter bernama `q`, `id`, atau `url`. Recon memetakan permukaan; active
verification hanya berjalan jika session mempunyai authorization, fokus, dan
bukti bentuk request target.

## 1. Siapkan engagement record

Salin `engagement.example.json`, lalu isi:

- `engagement_id` internal;
- `authorization_reference` yang menunjuk ke Rules of Engagement tertulis;
- `allowed_targets` persis sesuai scope program;
- `expires_at` dengan timezone;
- daftar `prohibited_techniques` yang substantif;
- `objective` konkret untuk sesi tersebut.

Jangan simpan KTP, tanda tangan, password, cookie, atau token di engagement
record. Dokumen tersebut hanya metadata operasional dan referensi izin.

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

## 3. Gunakan dua identitas untuk authorization testing

Salin `auth-context.example.json`. Untuk IDOR/BOLA diperlukan:

- dua akun milik researcher (`user_a` dan `user_b`);
- objek yang dibuat/dikendalikan oleh akun A;
- `owner_marker` harmless yang unik di respons objek A.

Planner baru menganggap lintas-account access terbukti ketika marker A muncul
pada respons yang diambil menggunakan identitas B. Status 200, ukuran body,
atau kemiripan response saja tidak cukup.

## 4. Jalankan satu sesi fokus

```bash
./bin/redteam_next --cli https://app.example.com \
  --preset deep_bypass \
  --engagement-file engagement.json \
  --objective "prove whether user B can read user A invoice" \
  --vuln-class idor \
  --request-corpus invoice-flow.har \
  --auth-context auth-context.json \
  --bypass-budget 24 \
  --max-depth 2 \
  --output-dir evidence/invoice-idor-session
```

Pilih satu atau maksimal dua kelas kerentanan. Attack plan difilter ke kelas
itu; sinyal kelas lain dicatat tetapi tidak dieksekusi pada sesi yang sama.
Kelas planner yang diterima: `idor`, `bola`, `authorization`, `auth-bypass`,
`xss`, `sqli`/`sql-injection`, `ssrf`, `ssti`, `open-redirect`, `graphql`, dan
`cloud-baas`. Kelas bebas yang belum mempunyai planner target-specific ditolak,
bukan diterjemahkan menjadi payload generik.

## 5. Baca hasil dengan disiplin evidence

- `DISCOVERED`: permukaan atau fakta teknis teramati; belum ada exploit.
- `SUSPECTED`: hipotesis masih kekurangan bukti pembeda.
- `LIKELY`: perilaku relevan terlihat, tetapi impact belum selesai dibuktikan.
- `VERIFIED`: pemeriksaan deterministik yang disyaratkan sudah lolos; tetap
  lakukan final human triage sebelum submit.
- `REJECTED`: bukti tidak mendukung finding atau hasil merupakan duplikat
  teknik yang sama.

`manifest.json` pada evidence bundle mencatat SHA-256 `results.json` dan
`report.md`. Verifikasi hash sebelum memindahkan artefak ke laporan client atau
submission platform.

## 6. Stop condition

Hentikan sesi jika target keluar scope, engagement kedaluwarsa, teknik masuk
daftar larangan, request budget habis, target menunjukkan instabilitas, atau
bukti yang diperlukan hanya dapat diperoleh melalui tindakan destruktif yang
tidak tertulis di Rules of Engagement.
