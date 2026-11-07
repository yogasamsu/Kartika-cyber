# Tameng — mesin korelasi + ringkasan insiden IT/OT (lokal, air-gapped)

**TAMENG** = **T**angkal **A**ncaman **M**andiri lewat **E**dukasi, **N**otifikasi,
dan **G**erak cepat. *Mandiri*: berjalan di dalam satuan tanpa internet.
*Edukasi*: tiap langkah insiden dijelaskan agar analis junior paham. *Notifikasi*:
ribuan alert diringkas menjadi satu insiden berprioritas. *Gerak cepat*: langkah
respons yang langsung bisa dikerjakan, plus mode blokir Modbus.

Membaca bukti mentah dari SSD (`alerts.json` Wazuh + `eve.json` Suricata),
mengorelasikannya menjadi insiden berantai secara **deterministik** (kode),
lalu meminta **LLM lokal** (Ollama/Qwen) menulis narasi ringkas yang
**divalidasi** agar tidak mengarang.

## Prinsip pembagian tugas

| Ditentukan oleh KODE (pasti) | Ditulis oleh LLM (narasi) |
|---|---|
| Kronologi & urutan kejadian | Judul |
| Pemetaan MITRE ATT&CK (Enterprise + ICS) | Ringkasan |
| Tingkat bahaya (severity) | Rekomendasi |
| Penautan host, identitas, alur IT→OT | |
| Pembuangan derau (shadow_read akibat login PAM) | |

LLM tidak boleh mengubah fakta. Output LLM dicek: setiap IP dan penanda bukti
(mis. `W6`, `S1`) yang muncul **wajib** ada di masukan; bila menyimpang atau
gagal, dipakai ringkasan cadangan deterministik.

## Pakai

Tidak perlu dependensi (hanya pustaka standar Python 3). Ollama harus jalan
(`scripts/ollama-serve.sh`).

```bash
python3 -m tameng --minutes 10              # tampilkan laporan di layar
python3 -m tameng --minutes 10 --out laporan.md
python3 -m tameng --minutes 10 --no-llm     # korelasi saja, tanpa LLM
```

Lokasi bukti & model bisa diatur lewat env (lihat `config.py`):
`TAMENG_WAZUH_ALERTS`, `TAMENG_SURICATA_EVE`, `TAMENG_OLLAMA_MODEL`, dst.

## Struktur

| Berkas | Isi |
|---|---|
| `config.py` | Lokasi bukti, setelan LLM, inventaris aset |
| `events.py` | Ingest & normalisasi Wazuh + Suricata → `Event` |
| `mitre.py` | Katalog sinyal & peta teknik ATT&CK |
| `correlate.py` | Disambiguasi derau, klaster waktu, rantai, severity → `Incident` |
| `llm.py` | Panggilan Ollama + validasi anti-halusinasi + cadangan |
| `report.py` | Render laporan Markdown |
| `__main__.py` | CLI |

## Catatan

- Severity `kritis` otomatis bila ada dampak OT (perintah tulis Modbus ke PLC).
- Korelasi berbasis **entitas**, bukan sekadar waktu: brute force dan login
  berhasil membentuk rantai per pelaku (IP luar atau host yang sudah dikuasai);
  eksekusi `/tmp`, pembacaan shadow, dan perintah Modbus ditempelkan ke rantai
  yang menguasai host asalnya. Serangan tak terkait tidak digabung. Login antar
  host internal tanpa rantai dianggap aktivitas normal.
- Waktu kejadian diambil dari sumbernya (`predecoder.timestamp` untuk syslog,
  `data.time` untuk sensor), bukan `timestamp` Wazuh. Agen mengirim log dalam
  batch, sehingga waktu terima manager bisa terlambat puluhan detik dan
  membalik urutan terhadap Suricata. Sisa selisih jam antar-sensor ditoleransi
  hingga `CLOCK_SKEW_S` (default 5 dtk); kronologi diurutkan menurut
  sebab-akibat dan setiap penyesuaian dicatat.
- `shadow_read` hanya dianggap jahat bila terjadi paling lama
  `SHADOW_TMP_WINDOW_S` (default 10 dtk) **setelah** eksekusi `/tmp` di host
  sama, atau prosesnya berasal dari `/tmp`. Pembacaan oleh `sshd`/`unix_chkpwd`
  (login PAM) dan pembacaan rutin agen Wazuh dianggap derau.
- Validasi narasi LLM memeriksa IP, penanda bukti, waktu, ID teknik ATT&CK, dan
  nama host. Satu saja yang di luar bukti membuat narasi ditolak dan diganti
  ringkasan cadangan.

## Skenario deface situs (IT, tanpa OT)

Menjawab kasus yang disebut narasumber Satsiber: deface situs mil.id lewat celah
plugin web. Tameng merangkai empat sinyal Wazuh menjadi satu insiden:

| Sinyal | Rule Wazuh | Kind | ATT&CK |
|---|---|---|---|
| Unggahan berkas lewat celah plugin (log akses) | 100020 | `web_exploit` | T1190 |
| Berkas baru di web root (FIM) | 554 | `web_file_added` | T1505.003 |
| Perintah lewat webshell (log akses `?cmd=`) | 100021 | `webshell_cmd` | T1505.003, T1059.004 |
| Isi halaman berubah (FIM) | 550 | `web_file_changed` | T1491.002 |

- Rantai dibentuk per IP penyerang. Perubahan berkas (FIM) ditempelkan ke
  rantai yang sudah menguasai host web itu.
- FIM di luar `TAMENG_WEB_ROOTS` (default `/var/www/html`) diabaikan, supaya
  perubahan `/etc` dan sejenisnya tidak dibaca sebagai deface.
- Perubahan halaman tanpa jejak eksploitasi tetap dilaporkan (severity
  `sedang`) dengan catatan untuk memastikan ke pengelola situs apakah itu
  pembaruan resmi.
- Rekomendasi cadangan: halaman pemeliharaan, pulihkan dari backup bersih,
  amankan salinan webshell sebagai bukti sebelum dihapus, perbarui plugin.

Demo memakai replay bukti sintetis (tidak ada serangan yang dijalankan):

```bash
python3 lab/scripts/replay-deface.py --out lab/out
```

Rule 100020/100021 disiapkan untuk log akses server web satuan; di lab hanya
dipakai lewat replay.

## Edukasi SDM

Laporan memuat bagian **Pelajari insiden ini**: untuk tiap teknik ATT&CK di
insiden, analis jaga mendapat empat hal (apa yang terjadi, kenapa berbahaya,
kerjakan sekarang, supaya tidak terulang). Materinya tetap, ditulis manusia di
`mitre.EDUKASI`, dan tidak dibuat LLM. Setiap teknik di `mitre.TECHNIQUES` wajib
punya materi; tes akan gagal bila ada yang terlewat. JSON insiden membawa materi
yang sama di kunci `edukasi` untuk dashboard.

## Tes

```bash
python3 -m unittest discover -s tests -v
```

Tes memakai bukti sintetis (tanpa SSD, tanpa Ollama), termasuk rekonstruksi
insiden lab 28 Okt.
- Inventaris aset (`config.ASSETS`) di lab bersifat statis; di produksi diisi
  dari daftar aset/CMDB satuan.
