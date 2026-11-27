# Gustiakmal RedTeam Next — Installation & Usage

Panduan ini untuk membagikan project ke team di Linux/Kali. Source utama
berada di folder `redteam_next/`; gunakan virtual environment per instalasi.

## 1. Prasyarat

Minimum:

- Linux/Kali atau environment POSIX yang menyediakan `bash`.
- Python 3.10 atau lebih baru. Workspace maintainer diuji dengan Python 3.14.6.
- `python3-venv` dan `unzip`.

Opsional:

- `node` untuk validasi syntax frontend (`node --check`).
- `curl` dan `jq` untuk inspeksi manual.
- Binary recon eksternal untuk preset yang memanggil tool tersebut.

Di Debian/Kali:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip unzip curl jq nodejs npm
```

## 2. Extract dan buat virtual environment

Dari archive yang dibagikan:

```bash
unzip Gustiakmal-RedTeam-Next.zip
cd redteam_next

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
# Only needed for --browser-verify / browser execution proof:
python -m playwright install chromium
```

Untuk team yang ikut menjalankan test suite, gunakan file dev. File ini sudah
memuat runtime dependencies, jadi tidak perlu menjalankan dua instalasi:

```bash
python -m pip install -r requirements-dev.txt
```

Jangan memasukkan `auth.json`, `auth-context.json`, engagement client, bearer
token, cookie, atau credential client ke dalam archive. Pola file lokal tersebut
dan direktori `evidence/` sudah masuk `.gitignore`; gunakan file `*.example.json`
sebagai template aman.

Launcher `bin/redteam_next` otomatis memilih `.venv/bin/python` bila tersedia,
sehingga dependency Playwright dan runtime proyek yang sudah dipasang benar-benar
digunakan. Jika `.venv` belum dibuat, launcher baru jatuh kembali ke `python3`.

## 3. Health check setelah install

```bash
python -c "import fastapi, uvicorn, pydantic, cvss, brotli, playwright; print('runtime dependencies: OK')"
python -m compileall -q redteam_agent redteam_lab
node --check redteam_agent/web/app.js   # opsional jika Node tersedia
```

Test suite lengkap:

```bash
pytest -q
```

Suite maintainer setelah perombakan evidence-first ini: `177 passed` dengan
Playwright `1.55.0` dan Chromium build `1187`. Dua peringatan deprecation berasal
dari adapter `fastapi/starlette` terhadap dependency test, bukan kegagalan test.
Jika Chromium belum dipasang, test browser canary dapat di-skip; jalankan
`python -m playwright install chromium` dari `.venv` untuk verifikasi lengkap.

## 4. Menjalankan Web Local

Setelah entrypoint global dipasang, Web Local dapat dijalankan dari folder
mana pun tanpa `cd` ke source project:

```bash
redteam_next
```

Entrypoint global hanya wrapper; source of truth tetap
`/home/utopia/redteam_next/bin/redteam_next`. Jika dipasang di mesin team yang
mengekstrak project ke lokasi berbeda, buat ulang link global dari folder
project tersebut:

```bash
mkdir -p "${HOME}/.local/bin"
ln -sfn "$(pwd)/bin/redteam_next" "${HOME}/.local/bin/redteam_next"
hash -r
redteam_next
```

Fallback langsung dari source tetap tersedia:

```bash
./bin/redteam_next
```

Launcher akan menjalankan Web Local di `127.0.0.1`, menunggu server siap, lalu
membuka browser default tanpa token dashboard. Default port adalah `8899`. Setiap scan
memakai satu global request budget finite (default `500`) yang dibagi oleh
recon, asset discovery, PoC, dan deep exploit.

Untuk akses dari HP/Kali pada Wi-Fi yang sama:

```bash
./bin/redteam_next --listen 192.168.1.20 --port 8899
```

Ganti `192.168.1.20` dengan IP LAN mesin yang menjalankan server. URL yang
dibuka dari HP:

```text
http://<LAN-IP>:8899
```

Bind di luar loopback mengaktifkan dashboard authentication. Token dibuat di
memori dan dicetak sekali oleh launcher:

```text
[*] Dashboard auth token: <token>
```

Masukkan token itu pada layar login dari HP/Kali. Atau tetapkan token sendiri
untuk sesi team yang terkontrol:

```bash
./bin/redteam_next --listen 192.168.1.20 --web-auth-token 'token-team-yang-kuat'
```

Bind ke `127.0.0.1` tetap tidak meminta token karena control plane hanya dapat
diakses dari mesin lokal.

Jika hanya ingin akses dari mesin sendiri:

```bash
./bin/redteam_next --listen 127.0.0.1
```

Jika port sedang dipakai:

```bash
./bin/redteam_next --port 8999
```

Tanpa membuka browser otomatis:

```bash
./bin/redteam_next --no-browser
```

Catatan jaringan: HP harus berada pada jaringan yang sama dan AP/client
isolation tidak boleh aktif. Firewall host harus mengizinkan port yang dipilih.

## 5. Menjalankan CLI

Tambahkan `--cli` pada launcher portable:

```bash
./bin/redteam_next --cli https://target.example \
  --preset full \
  --deep-assets \
  --secret-discovery \
  --auth-flow \
  --source-maps
```

Mode deep exploit berbasis evidence:

```bash
./bin/redteam_next --cli https://target.example \
  --preset deep_bypass \
  --objective "prove unauthorized cross-tenant read" \
  --vuln-class idor \
  --request-corpus captured.har \
  --max-depth 3 \
  --bypass-budget 40 \
  --output-dir evidence/current-session
```

Engagement JSON dan auth context bersifat opsional. Tanpa engagement JSON,
mode ofensif dibatasi ke host target yang dimasukkan. Jika memerlukan scope
program yang lebih luas, salin `engagement.example.json` lalu isi metadata
non-sensitif dan gunakan `--engagement-file`.

Pemakaian langsung tanpa launcher juga didukung:

```bash
PYTHONPATH="$PWD" python -m redteam_agent.cli --url https://target.example \
  --preset full
```

Gunakan `--help` untuk seluruh opsi:

```bash
./bin/redteam_next --cli --help
```

## 6. Researcher-owned auth context

Hanya gunakan context milik researcher yang memang berwenang:

```bash
./bin/redteam_next --cli https://target.example \
  --auth-context auth.json \
  --browser-verify \
  --deep-assets \
  --auth-flow
```

Nilai auth context diproses in-memory dan tidak boleh dimasukkan ke zip,
report standar, atau output publik.

Untuk sesi IDOR/BOLA, salin `auth-context.example.json`, isi dua akun pengujian
milik researcher, lalu tetapkan `owner_marker` ke nilai harmless yang hanya ada
pada objek akun A. Planner memerlukan marker tersebut agar status 200 atau
ukuran body yang mirip tidak disalahartikan sebagai broken authorization.

## 7. Menjalankan test lab

Mode lab yang dikeraskan dan tidak membutuhkan binary recon eksternal:

```bash
python redteam_lab/observe_test.py
```

Mode demo untuk membuktikan probe error disclosure pada endpoint lab yang
sengaja dibuat bocor:

```bash
python redteam_lab/observe_test.py --demo
```

Artefak observasi ditulis ke `redteam_lab/output/`. Folder ini tidak perlu
dimasukkan ke archive distribusi baru.

## 8. Optional external recon tools

Runtime Python di `requirements.txt` tidak meng-install binary seperti
`subfinder`, ProjectDiscovery `httpx`, `gau`, `katana`, `ffuf`, `naabu`, atau
`arjun`. Preset `lab_hardened`, `js_hunter`, dan direct asset analysis tetap
dapat dijalankan tanpa seluruh binary tersebut; modul akan mencatat tool yang
tidak tersedia sebagai status yang tidak terobservasi.

Jika team memang memerlukan preset recon lengkap dan sudah memiliki Go:

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/ffuf/ffuf/v2@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
python -m pip install arjun
```

Pastikan `~/go/bin` dan `~/.local/bin` ada di `PATH`:

```bash
export PATH="$HOME/go/bin:$HOME/.local/bin:$PATH"
```

Perhatikan bahwa Python package `httpx` di `requirements-dev.txt` dipakai
untuk FastAPI TestClient; itu berbeda dari binary ProjectDiscovery `httpx`.

## 9. Distribusi dan update

Jangan zip `.venv`, cache Python, `auth.json`, atau output scan pribadi.
Archive project sebaiknya dibuat dari source setelah health check:

```bash
python -m compileall -q redteam_agent redteam_lab
pytest -q
```

Setelah extract archive baru, buat virtual environment baru dan install dari
requirements file yang ikut dalam archive. Jangan menyalin `site-packages`
antar mesin atau antar versi Python.
