# PRD Tameng: SOC copilot IT/OT lokal untuk satuan siber TNI AD

Versi 0.2, 7 November 2026. Disusun untuk Kartika Cyber Hackathon 2026 (submission 15 Nov, final 24 Nov). Sumber: [riset-kartika-cyber-hackathon.md](riset-kartika-cyber-hackathon.md), [tameng/README.md](tameng/README.md), [lab/README.md](lab/README.md), dan masukan narasumber dari grup peserta (6–7 Nov 2026).

## 1. Ringkasan

Tameng membaca alert Wazuh dan Suricata, merangkainya menjadi insiden berantai dengan aturan deterministik, memetakan tiap langkah ke MITRE ATT&CK (Enterprise dan ICS), lalu meminta LLM lokal menulis ringkasan dan rekomendasi dalam bahasa Indonesia. Semua proses berjalan di satu laptop tanpa internet. Narasi LLM yang menyebut IP, host, waktu, atau teknik di luar bukti ditolak dan diganti ringkasan cadangan.

## 2. Pengguna dan batas peran

**Pengguna utama:** operator SOC di Satsiber TNI dan Tim Tanggap Insiden Siber (TTIS) TNI AD, termasuk bintara siber yang belum berpengalaman menganalisis alert.

**Batas peran (dari narasumber):**

| Lembaga | Tugas siber |
|---|---|
| TNI (Satsiber, TTIS) | Menjaga jaringan dan sistem militer, operasi pertahanan siber, melindungi infrastruktur informasi kritis TNI |
| BSSN | Koordinator keamanan siber nasional |
| Komdigi | Regulasi |
| Polri | Penegakan hukum terhadap pelaku pidana |

Insiden di instansi sipil, BUMN, atau Pemda ditangani BSSN, Komdigi, dan Polri. TNI turun bila yang diserang instansi militer atau ancamannya sudah berskala pertahanan negara. Jadi Tameng memantau dan merespons insiden **di aset milik TNI sendiri**. Tameng bukan alat penyidikan pelaku.

## 3. Masalah yang dijawab

Masalah yang disebut narasumber dan situs Satsiber/TTIS:

1. **Deface situs militer.** Contoh nyata: deface situs mil.id lewat celah WordPress. Operator yang bukan ahli TI tidak bisa membaca jejaknya.
2. **Ransomware, phishing, malware, DDoS, kebocoran data, manipulasi informasi** (daftar ancaman TTIS TNI AD).
3. **Sistem lama yang sulit diperbarui.** Celahnya tidak bisa ditutup sekaligus, sehingga operator butuh urutan prioritas.
4. **Kekurangan SDM siber spesialis.** Alert Wazuh membanjir; satu kejadian menghasilkan puluhan baris, dan analis yang bisa merangkainya sedikit.
5. **Data tidak boleh keluar.** LLM cloud tidak bisa dipakai untuk data militer.

## 4. Pemetaan ke layanan TTIS

| Layanan TTIS | Fitur Tameng | Status |
|---|---|---|
| Monitoring | Ingest Wazuh + Suricata, korelasi insiden berantai | Ada |
| Penanganan | Mode blokir Suricata (IPS) untuk perintah Modbus dari host tak sah; rekomendasi langkah respons | Ada |
| Pendampingan pemulihan | Rekomendasi pemulihan per jenis insiden (isolasi host, reset akun, pulihkan dari backup) | Ada, diperluas untuk deface |
| Risk analysis | Ringkasan kerentanan dari Wazuh Vulnerability Detection dan SCA, diurutkan prioritasnya | Rencana (F6) |

## 5. Fitur

### Sudah jalan

| ID | Fitur | Catatan |
|---|---|---|
| F1 | Korelasi berbasis entitas | Rantai per pelaku (IP luar atau host yang dikuasai), bukan sekadar kedekatan waktu |
| F2 | Pemetaan ATT&CK oleh kode | Enterprise dan ICS; LLM tidak menentukan teknik |
| F3 | Pembuangan derau | Pembacaan `/etc/shadow` oleh login PAM dan pemindaian agen Wazuh tidak dihitung serangan |
| F4 | Narasi LLM lokal tervalidasi | Qwen 2.5 7B via Ollama; narasi ditolak bila menyebut fakta di luar bukti |
| F5 | Mode blokir OT | Suricata inline menjatuhkan perintah tulis Modbus dari host selain HMI resmi |
| F5b | **Skenario deface situs** (baru, 7 Nov) | Unggahan lewat celah plugin, webshell, perintah sistem, halaman berubah. Sinyal: log akses web dan File Integrity Monitoring Wazuh di web root. ATT&CK T1190, T1505.003, T1059.004, T1491.002 |

### Rencana sampai 15 Nov

| ID | Fitur | Lingkup | Alasan |
|---|---|---|---|
| F6 | Ringkasan kerentanan ("scan sistem") | Baca hasil Wazuh Vulnerability Detection dan SCA yang sudah ada; LLM menjelaskan 3 temuan teratas dan alasannya. Tameng **tidak** membuat pemindai sendiri | Menjawab masalah sistem lama: kalau tidak bisa menambal semua, operator perlu urutan |
| F7 | Edukasi di dalam alert | Setiap langkah kronologi diberi penjelasan singkat: apa yang terjadi, teknik ATT&CK, kenapa berbahaya, apa tindakan operator | Menjawab kekurangan SDM tanpa membuat modul pelatihan terpisah |
| F8 | Mode latihan | Putar ulang skenario lab (IT→OT, blokir, deface) untuk melatih operator baru | Opsional bila waktu cukup |
| F9 | Dashboard bergaya militer | Tampilan komando gelap: peta aset, status insiden, kronologi, panel ATT&CK | Diminta tim; referensi dua desain Dribbble |

### Di luar lingkup

- Penyidikan dan atribusi pelaku (ranah Polri).
- Pemindaian aktif ke jaringan OT. PLC lama bisa macet bila dipindai; sisi OT hanya dipantau secara pasif.
- Pelatihan kesadaran phishing untuk seluruh personel. Itu produk tersendiri.
- Lab yang menjalankan eksploitasi web sungguhan. Skenario deface didemokan dengan replay bukti deteksi sintetis.

## 6. Persyaratan nonfungsional

| Aspek | Syarat |
|---|---|
| Kedaulatan data | Seluruh proses lokal; tidak ada panggilan ke layanan di luar mesin |
| Perangkat | Satu laptop (uji: MacBook Air M4, Docker 6 GB); bukti dan model di SSD terenkripsi |
| Dependensi | Python 3 pustaka standar; Wazuh, Suricata, Ollama (semua open-source) |
| Ketepatan | Kronologi, severity, dan teknik ditentukan kode; tes regresi wajib lolos (21 tes per 7 Nov) |
| Keterbacaan | Laporan berbahasa Indonesia yang bisa dikerjakan bintara siber |

## 7. Skenario demo

| Babak | Skenario | Hasil yang ditunjukkan |
|---|---|---|
| 1 | Serangan IT→OT, Suricata mode IDS | Brute force SSH, pencurian shadow, gerak lateral, genset dimatikan; Tameng merangkum jadi satu insiden kritis |
| 2 | Serangan yang sama, mode IPS | Perintah Modbus dijatuhkan, genset tetap menyala; insiden turun ke tinggi |
| 3 | Deface situs (replay) | Empat sinyal web jadi satu insiden "Deface situs web-portal" dengan langkah pemulihan |

Babak 3 dibuka dengan kasus deface mil.id supaya juri langsung melihat masalah mereka sendiri. Babak 1 dan 2 menjadi pembeda karena menyentuh OT.

Perintah:

```bash
bash lab/scripts/demo-dua-babak.sh
python3 lab/scripts/replay-deface.py --out lab/out
```

## 8. Ukuran keberhasilan

Mengikuti bobot juri:

| Kriteria (bobot) | Target |
|---|---|
| Relevansi IT/OT TNI AD (25%) | Tiga skenario: dua OT, satu IT yang diambil dari kasus nyata mil.id |
| Inovasi (25%) | Korelasi deterministik + LLM tervalidasi + blokir OT, semuanya offline |
| Purwarupa (25%) | Demo live babak 1–2 di lab; babak 3 lewat replay; tes lolos |
| Kelayakan (15%) | Satu laptop, open-source, laporan bisa dibaca bintara |
| Dokumentasi (10%) | PRD ini, README, video, deck |

## 9. Pertanyaan terbuka

1. Ancaman mana yang paling sering dialami Satsiber: deface, ransomware, atau phishing? Jawaban dari satu anggota Satsiber akan menentukan urutan slide masalah. Saat ini semua masukan masih dari obrolan informal.
2. Apakah satuan sudah memakai Wazuh atau SIEM lain? Kalau lain, Tameng perlu adaptor ingest.
3. Situs satuan memakai CMS apa? Rule log akses (100020, 100021) perlu disesuaikan dengan format log server web mereka.

## 10. Jadwal

| Tanggal | Target |
|---|---|
| 7 Nov | Skenario deface di mesin korelasi + tes + replay (selesai) |
| 8–9 Nov | F7 edukasi dalam alert; F6 ringkasan kerentanan |
| 10–12 Nov | F9 dashboard gaya militer |
| 13 Nov | Perbarui video dan deck dengan babak deface |
| 14 Nov | Uji ulang penuh, submit lebih awal |
| 15 Nov | Batas submission |
