# Lab Tameng SOC — satu laptop (MacBook Air M4)

Lab mini untuk mendemokan deteksi serangan **IT → OT** di satu laptop: Wazuh
(sisi IT) + Suricata (sisi OT, Modbus) + simulator PLC genset, dengan skenario
penyerang yang nyata. Semua bukti ditulis ke SSD terenkripsi (`Prika-Tameng`)
dan dibaca langsung oleh mesin korelasi Tameng.

## Topologi (jaringan 10.10.5.0/24)

| Host | IP | Peran |
|---|---|---|
| wazuh-manager | 10.10.5.2 | Manager Wazuh (single-node, tanpa indexer/dashboard) |
| pc-staf-07 | 10.10.5.66 | Workstation korban + Wazuh agent + sensor Tameng |
| srv-file-01 | 10.10.5.7 | Server file korban + Wazuh agent + sensor Tameng |
| plc-genset-01 | 10.10.5.20 | Simulasi PLC genset (Modbus TCP :502) |
| suricata | (netns PLC) | IDS OT; memantau trafik Modbus ke PLC |
| attacker | 10.10.5.90 | Mesin penyerang (kali-ops) |

Semua image **arm64 native** (Wazuh 4.14.9, Suricata 8, python/pymodbus).

## Menjalankan

> Colok SSD `Prika` dan buka volume `Prika-Tameng` dulu, lalu buka Docker Desktop.

```bash
cd lab
docker compose up -d --build
```

Tunggu ±30 detik sampai agent terhubung:

```bash
docker exec wazuh-manager /var/ossec/bin/agent_control -l
```

### Jalankan skenario serangan IT → OT

```bash
bash scripts/attack.sh
```

Alurnya: brute force SSH → login dengan kredensial curian (`sertu`) di
pc-staf-07 → eksekusi payload dari `/tmp` + baca `/etc/shadow` → gerak lateral
ke srv-file-01 → dari sana perintah Modbus mematikan genset di PLC.

### Lihat linimasa bukti gabungan (Wazuh + Suricata)

```bash
python3 scripts/timeline.py 10     # 10 menit terakhir
```

## Bukti di SSD (dibaca mesin korelasi Tameng)

- Wazuh : `/Volumes/Prika-Tameng/lab-data/wazuh/alerts/alerts.json`
- Suricata : `/Volumes/Prika-Tameng/lab-data/suricata/eve/eve.json`

Sinyal utama:

| Sumber | ID/SID | Arti |
|---|---|---|
| Wazuh | 5710 | Login SSH gagal (brute force) |
| Wazuh | 5715 | Login SSH berhasil |
| Wazuh | 100010 | Eksekusi berkas dari `/tmp` (sensor Tameng) |
| Wazuh | 100011 | Pembacaan `/etc/shadow` (sensor Tameng) |
| Suricata | 7000005 | Modbus WRITE single coil (fc5) ke PLC |

## Penyederhanaan lab vs produksi

Dipilih agar muat di satu laptop dan tetap jujur; didokumentasikan untuk juri.

- **Tanpa Wazuh indexer & dashboard.** Alert dibaca langsung dari `alerts.json`.
  Hemat 2–4 GB RAM. Produksi: pakai indexer/dashboard penuh.
- **Sensor endpoint `/proc` menggantikan auditd.** auditd tidak jalan di VM
  Docker Desktop. `victim/tameng-sensor.py` mendeteksi eksekusi dari `/tmp`
  (inotify `IN_OPEN` pada direktori) dan pembacaan `/etc/shadow` (inotify
  `IN_OPEN` pada berkas, satu event per pembukaan) — berbasis event, seperti
  sensor EDR userland. Atribusi pid/pengguna bersifat upaya terbaik: proses
  sekejap seperti `cat` sering sudah selesai sebelum terbaca di `/proc`.
  Produksi: auditd atau EDR sungguhan.
- **Agen Wazuh memuat ulang konfigurasi ±1 menit setelah terhubung.** Log
  dibaca dengan `only-future-events=no` agar tidak ada yang hilang saat itu,
  dan `attack.sh` menunggu sampai agen benar-benar terhubung sebelum menyerang.
  Bila korban di-recreate tanpa restart manager, manager tetap mengizinkan
  pendaftaran ulang nama yang sama (`disconnected_time` dimatikan).
- **Simulator PLC pymodbus menggantikan OpenPLC.** Ringan & arm64-native;
  perilaku Modbus di kabel tetap nyata sehingga Suricata mendeteksinya sama
  seperti PLC fisik. Produksi/alternatif: OpenPLC atau PLC sungguhan.
- **Suricata berbagi network namespace PLC** (`network_mode: service:plc-genset-01`)
  karena bridge Docker Desktop tidak bisa port-mirror. Ini membuat Suricata
  melihat tepat trafik OT. Produksi: SPAN/TAP port.
- **Catatan `shadow_read`:** login kata sandi via PAM pun membaca `/etc/shadow`,
  jadi event ini bisa muncul saat login sah. Mesin korelasi Tameng membedakannya
  dengan menautkan pembacaan pada sesi/proses mencurigakan (mis. setelah
  eksekusi dari `/tmp`), bukan menilainya sendirian.

## Jejak sumber daya (hasil uji)

| Komponen | RAM |
|---|---|
| wazuh-manager | ~546 MB |
| pc-staf-07 / srv-file-01 | ~34 MB masing-masing |
| suricata | ~50 MB |
| plc-genset-01 | ~19 MB |
| attacker | ~2 MB |
| **Total 6 container** | **~685 MB** |

Ollama + model LLM berjalan **native** di macOS (di luar Docker), memakai sisa
RAM. Dengan alokasi Docker 6 GB, lab dan LLM muat bersama di 16 GB.

## Air-gapped saat demo

- Matikan Wi-Fi untuk membuktikan seluruh analisis berjalan lokal.
- Nonaktifkan Docker AI (Gordon) di Docker Desktop → Settings agar tak ada
  lalu lintas keluar.
