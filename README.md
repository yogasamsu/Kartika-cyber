# Tameng

**T**angkal **A**ncaman **M**andiri lewat **E**dukasi, **N**otifikasi, dan **G**erak cepat.

Tameng mendampingi analis siber satuan TNI yang berjaga. Ia membaca temuan
Wazuh (IT) dan Suricata (OT), merangkainya menjadi satu cerita serangan, lalu
menulis laporan insiden berbahasa Indonesia lengkap dengan langkah pertama yang
harus dikerjakan. Di uji lab, satu serangan IT → OT memunculkan 654 temuan
dalam empat menit; Tameng meringkasnya menjadi satu insiden.

Semuanya berjalan di satu laptop tanpa internet. Mesinnya hanya memakai pustaka
standar Python, dan ringkasannya ditulis LLM lokal (Ollama) yang hasilnya dicek
ulang terhadap bukti.

- Situs dan pusat komando: **https://tameng.yogency.work**
- Karya untuk Kartika Cyber Hackathon 2026, kategori Penangkalan (Defensive Shield).

## Coba dalam 2 menit

Yang dibutuhkan hanya **Python 3.9 ke atas** dan Git. Tidak ada `pip install`,
tidak perlu Docker, tidak perlu Ollama.

```bash
git clone https://github.com/yogasamsu/Kartika-cyber.git
cd Kartika-cyber
```

**1. Pastikan mesinnya sehat** (33 tes, kurang dari 1 detik):

```bash
python3 -m unittest discover -s tests
```

**2. Putar ulang skenario deface situs.** Skrip ini menulis log deteksi
sintetis (log akses portal dan File Integrity Monitoring Wazuh) ke folder
sementara, lalu menjalankan Tameng atasnya. Tidak ada serangan yang dijalankan.

```bash
python3 lab/scripts/replay-deface.py
```

Hasilnya laporan insiden di layar: kronologi dengan penanda bukti (`W1`, `W2`,
...), teknik MITRE ATT&CK, rekomendasi, dan materi belajar untuk analis jaga.

Varian ketika Wazuh active response memblokir penyerang sebelum halaman
sempat diubah:

```bash
python3 lab/scripts/replay-deface.py --blokir
```

**3. Ringkas kerentanan** dari contoh alert Wazuh Vulnerability Detection dan
SCA. Urutannya memperhitungkan CVSS, katalog KEV, kritikalitas aset, dan
apakah aset terbuka ke publik.

```bash
python3 -m tameng --kerentanan lab/sample/kerentanan-alerts.json
```

**4. Buka pusat komando di browser lokal.**

```bash
python3 -m http.server 8765 --directory dashboard
```

Buka http://localhost:8765, lalu klik **Masuk pusat komando**. Datanya
(`dashboard/data.js`) sudah tersedia di repo: dua babak dari lab IT → OT dan
dua babak replay deface. Untuk membangunnya ulang dari hasil langkah 2:

```bash
python3 lab/scripts/replay-deface.py --out lab/out
python3 lab/scripts/replay-deface.py --blokir --out lab/out
python3 dashboard/build.py
```

## Pakai LLM lokal (opsional)

Tanpa LLM, Tameng menulis ringkasan cadangan yang deterministik. Dengan LLM,
judul, ringkasan, dan rekomendasi ditulis lebih luwes. Setiap IP, nama host,
waktu, teknik, dan penanda bukti di tulisan LLM dicocokkan dengan bukti; kalau
ada yang tidak cocok, tulisan itu ditolak dan ringkasan cadangan yang dipakai.

```bash
# pasang Ollama dari https://ollama.com, lalu:
ollama pull qwen2.5:7b      # ±4,7 GB, sekali saja
ollama serve                # biarkan berjalan di terminal lain

python3 lab/scripts/replay-deface.py --llm
```

Model lain bisa dipakai lewat `TAMENG_OLLAMA_MODEL`. Kalau Ollama tidak
berjalan, Tameng mencetak `LLM gagal ... pakai ringkasan cadangan` dan tetap
menghasilkan laporan.

## Pakai di log Wazuh dan Suricata sendiri

Tameng membaca `alerts.json` Wazuh dan `eve.json` Suricata apa adanya. Arahkan
ke berkasnya:

```bash
export TAMENG_WAZUH_ALERTS=/var/ossec/logs/alerts/alerts.json
export TAMENG_SURICATA_EVE=/var/log/suricata/eve.json

python3 -m tameng --minutes 60                       # laporan 60 menit terakhir
python3 -m tameng --since 2026-11-07T05:08:30Z       # sejak waktu tertentu (UTC)
python3 -m tameng --minutes 60 --out laporan.md --json insiden.json
python3 -m tameng --watch --interval 30              # pantau terus, beri tahu saat ada insiden
```

Salah satu berkas boleh tidak ada; Tameng memakai yang tersedia.

Dua hal yang perlu disesuaikan dengan jaringan Anda, di `tameng/config.py`:

- `ASSETS`: daftar IP, nama, peran, dan kritikalitas aset. IP yang tidak
  terdaftar diperlakukan sebagai host luar.
- `MODBUS_MASTERS`: HMI/SCADA yang sah mengirim perintah tulis Modbus.

### Variabel lingkungan

| Variabel | Bawaan | Fungsi |
|---|---|---|
| `TAMENG_WAZUH_ALERTS` | `$TAMENG_DATA/wazuh/alerts/alerts.json` | Berkas alert Wazuh |
| `TAMENG_SURICATA_EVE` | `$TAMENG_DATA/suricata/eve/eve.json` | Berkas EVE Suricata |
| `TAMENG_DATA` | `/Volumes/Prika-Tameng/lab-data` | Folder induk bukti (dipakai juga oleh lab Docker) |
| `TAMENG_OLLAMA_URL` | `http://127.0.0.1:11434/api/chat` | Alamat Ollama |
| `TAMENG_OLLAMA_MODEL` | `qwen2.5:7b` | Model LLM lokal |
| `TAMENG_WEB_ROOTS` | `/var/www/html` | Folder situs yang diawasi untuk deface (pisahkan dengan koma) |
| `TAMENG_MODBUS_MASTERS` | `10.10.5.30` | Pengirim Modbus yang sah (pisahkan dengan koma) |
| `TAMENG_CORR_WINDOW_S` | `300` | Jarak maksimum dua kejadian dianggap serantai (detik) |
| `TAMENG_NOTIF_LOG` | (kosong) | Simpan notifikasi mode pantau ke berkas JSONL |
| `TAMENG_NOTIF_DESKTOP` | (kosong) | Isi `1` untuk notifikasi desktop macOS |
| `TAMENG_WEBHOOK` | (kosong) | URL webhook di jaringan internal untuk notifikasi |

## Jalankan lab IT → OT lengkap (lanjutan)

Lab Docker berisi Wazuh manager, dua host korban dengan agen Wazuh, simulator
PLC genset (Modbus TCP), HMI operator, Suricata, dan host penyerang. Skenarionya:
brute force SSH, login dengan kredensial curian, eksekusi payload, gerak lateral,
lalu perintah Modbus mematikan genset. Suricata bisa dijalankan sebagai IDS
(mencatat) atau IPS (memblokir perintah dari host tak sah).

### Docker yang dipakai

| Sistem | Pasang |
|---|---|
| macOS | [Docker Desktop](https://www.docker.com/products/docker-desktop/) |
| Windows | Docker Desktop dengan backend WSL2; jalankan perintah di bawah dari terminal WSL (Ubuntu), bukan PowerShell |
| Linux | Docker Engine plus plugin Compose v2 (`docker-compose-plugin`) |

Perintahnya `docker compose` (Compose v2, dengan spasi), bukan `docker-compose`
versi lama. Cek dengan `docker compose version`.

Lab ini diuji di Docker Desktop pada MacBook Air M4 (RAM 16 GB). Image dasarnya
tersedia untuk arm64 dan amd64, jadi seharusnya jalan juga di laptop Intel/AMD,
tetapi itu belum diuji.

Sebelum mulai:

- **Memori Docker minimal 6 GB.** Di Docker Desktop: Settings → Resources →
  Memory. Lab sendiri memakai ±700 MB; sisanya untuk Wazuh saat start dan
  untuk build.
- **Internet hanya saat build pertama**, untuk mengunduh image dan paket agen
  Wazuh. Setelah itu lab bisa dijalankan tanpa internet.
- **Subnet `10.10.5.0/24` harus belum dipakai** jaringan lain di laptop Anda.
- **Host korban berjalan `privileged`, dan Suricata butuh `NET_ADMIN`** untuk
  mode IPS (NFQUEUE). Jalankan lab ini hanya di laptop uji, bukan di server
  produksi.

### Isi lab

| Container | Image dasar | Peran |
|---|---|---|
| `wazuh-manager` | `wazuh/wazuh-manager:4.14.9` | SIEM sisi IT; menulis `alerts.json` |
| `pc-staf-07`, `srv-file-01` | `ubuntu:22.04` + agen Wazuh 4.14.9 | Host korban dengan sensor Tameng |
| `plc-genset-01` | `python:3.12-slim` + pymodbus | Simulator PLC genset (Modbus TCP :502) |
| `hmi-genset` | sama dengan PLC | Pengirim perintah Modbus yang sah |
| `suricata` | `jasonish/suricata:8.0.8` | Sensor OT (IDS atau IPS); menulis `eve.json` |
| `attacker` | sama dengan host korban | Host penyerang untuk skenario |

### Menjalankan

Dari root repo:

```bash
export TAMENG_DATA="$PWD/lab-data"      # tempat log Wazuh dan Suricata ditulis
cd lab
docker compose up -d --build            # build pertama butuh beberapa menit
```

Tunggu ±30 detik, lalu pastikan dua agen sudah `Active`:

```bash
docker exec wazuh-manager /var/ossec/bin/agent_control -l
```

Jalankan demo dua babak. Babak 1 tanpa blokir (genset mati), babak 2 dengan
Suricata IPS (perintah ke genset diblokir). Laporan Tameng untuk tiap babak
ditulis ke `lab/out/`.

```bash
bash scripts/demo-dua-babak.sh
```

Matikan lab setelah selesai:

```bash
docker compose down
```

Rincian topologi, mode IDS/IPS, dan penyederhanaan lab dibanding produksi ada
di [lab/README.md](lab/README.md).

## Isi repo

| Folder | Isi |
|---|---|
| [`tameng/`](tameng/README.md) | Mesin Tameng: baca bukti, korelasi, MITRE ATT&CK, LLM, laporan, kerentanan, notifikasi |
| [`dashboard/`](dashboard/README.md) | Beranda dan pusat komando (HTML statis, tanpa CDN, bisa dibuka tanpa internet) |
| [`lab/`](lab/README.md) | Lab Docker IT → OT, skrip skenario, replay deface, data contoh |
| `artifacts/` | Laporan dan JSON insiden asli dari uji lab 6–7 November 2026 |
| `tests/` | Tes unit mesin korelasi |
| [`video/`](video/gsap/README.md) | Video presentasi (GSAP, dirender dengan Chrome headless dan ffmpeg) |
| `presentasi/` | Slide presentasi |
| [`PRD.md`](PRD.md) | Dokumen kebutuhan produk: masalah, fitur, batasan, integrasi |

## Cara kerja singkat

1. **Baca.** Alert Wazuh dan event Suricata diubah menjadi kejadian seragam.
   Derau dibuang, misalnya pembacaan `/etc/shadow` akibat login sah.
2. **Rangkai.** Kode, bukan AI, menautkan kejadian per penyerang dan per host
   menjadi insiden, memetakan teknik MITRE ATT&CK (Enterprise dan ICS), dan
   menentukan tingkat bahaya.
3. **Tulis.** LLM lokal menulis judul, ringkasan, dan rekomendasi dari fakta
   yang sudah dikunci. Tulisan yang menyebut fakta di luar bukti ditolak.
4. **Ajarkan.** Tiap teknik dilengkapi penjelasan tertulis manusia: apa yang
   terjadi, kenapa berbahaya, apa yang dikerjakan sekarang, dan cara mencegahnya.

## Batasan

- Data insiden di situs dan repo berasal dari lab satu laptop dan replay
  sintetis, bukan dari jaringan TNI.
- Inventaris aset masih ditulis di `config.py`; di satuan seharusnya diambil
  dari daftar aset atau CMDB.
- Blokir otomatis hanya ada di dua titik: Suricata IPS untuk Modbus dan Wazuh
  active response untuk host web. Tameng sendiri tidak mengubah konfigurasi
  jaringan.

Daftar lengkap ada di bagian "Catatan atas MVP awal" di
[tameng.yogency.work](https://tameng.yogency.work/#limitasi) dan di [PRD.md](PRD.md).
