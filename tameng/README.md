# Tameng — mesin korelasi + ringkasan insiden IT/OT (lokal, air-gapped)

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
- Bukti dari sensor berbeda boleh bergeser jam hingga `CLOCK_SKEW_S` (default
  5 dtk); kronologi diurutkan menurut sebab-akibat dan pergeseran dicatat.
- `shadow_read` hanya dianggap jahat bila terjadi **setelah** eksekusi `/tmp` di
  host sama dalam rentang `SHADOW_TMP_WINDOW_S`, atau prosesnya berasal dari
  `/tmp`. Pembacaan oleh `sshd`/`unix_chkpwd` (login PAM) selalu dianggap derau.
- Validasi narasi LLM memeriksa IP, penanda bukti, waktu, ID teknik ATT&CK, dan
  nama host. Satu saja yang di luar bukti membuat narasi ditolak dan diganti
  ringkasan cadangan.

## Tes

```bash
python3 -m unittest discover -s tests -v
```

Tes memakai bukti sintetis (tanpa SSD, tanpa Ollama), termasuk rekonstruksi
insiden lab 28 Okt.
- Inventaris aset (`config.ASSETS`) di lab bersifat statis; di produksi diisi
  dari daftar aset/CMDB satuan.
