# Naskah video Tameng (gaya AgMon), ±6 menit

> **Versi tanpa VO.** Video final tidak memakai suara narator. Isi VO di bawah
> sudah dipadatkan menjadi teks layar (`COPY` di `index.html`) yang muncul di
> bagian bawah layar. Bagian VO di dokumen ini tetap berguna sebagai naskah
> presentasi lisan di babak final.

Batas panitia 10 menit. Durasi 5 menit 50 detik: cukup untuk tujuh bagian
termasuk demo, tanpa membuat juri bosan. VO sekitar 480 kata, dibaca tenang
(±2,2 kata per detik, ±3,5 menit bicara); sisa waktunya jeda supaya footage
demo dan angka di layar sempat terbaca. Semua angka di layar punya sumber: riset BSSN dan
pemberitaan 2025, atau uji lab Tameng 6 dan 7 November 2026.

Keterangan footage:
- **[asli]** tangkapan layar atau rekaman dari lab dan Tameng.
- **[rekonstruksi]** tampilan yang disusun dari data asli (mis. output terminal
  yang benar-benar keluar saat uji, diketik ulang di layar).
- **[grafis]** animasi teks, ikon, dan diagram.

---

## 1. Masalah: analisnya (0:00–0:52)

Cerita dimulai dari orang yang berjaga, bukan dari teknologinya.

### 1a. Satu analis jaga (0:00–0:14)
**Visual [grafis]:** judul, lalu empat kartu persona muncul satu per satu.
**Teks layar:** *Malam hari. Satu analis berjaga di ruang server satuan.* ·
*Sering masih junior* · *Senior tidak selalu ada untuk ditanya* · *Harus
melapor ke komandan* · *Tidak boleh memakai AI cloud: ini data militer*

> **VO:** Malam hari, satu analis berjaga di ruang server satuan. Ia sering
> masih junior. Seniornya tidak selalu ada untuk ditanya, ia harus melapor ke
> komandan, dan ia tidak boleh minta bantuan AI cloud, karena ini data militer.

### 1b. Layarnya bergulir (0:14–0:36)
**Visual [asli]:** log Wazuh asli bergulir cepat, penghitung naik ke 654; baris
serangan merah terselip di antara pemeriksaan rutin.
(Sampel 70 baris dari log asli; semua baris serangan ikut, baris rutin diambil merata.)
**Label:** *Data lab Tameng · 6 Nov 2026* · *654 alert dalam 4 menit*

> **VO:** Lalu layarnya mulai bergulir. Dalam simulasi empat menit di lab kami,
> sistem deteksi mengeluarkan 654 alert. Hanya tiga belas yang berkaitan dengan
> serangan. Ia harus menemukan tiga belas baris itu sendiri, lalu memahami
> ceritanya.

### 1c. Yang ia jaga (0:36–0:52)
**Visual [grafis]:** ikon perangkat markas menyala satu per satu dan tersambung
garis: PC staf, server, CCTV, radio, genset.
**Teks layar:** *Markas yang kini hidup di jaringan.* · *BSSN: 5,2 miliar
anomali trafik ke Indonesia, Jan–Nov 2025.*

> **VO:** Yang dipertaruhkan bukan hanya data. PC staf, server, CCTV, radio,
> sampai genset markas, semuanya tersambung ke jaringan. Sepanjang 2025, BSSN
> mencatat 5,2 miliar anomali trafik ke Indonesia.

## 2. Perjalanan analis dan titik sakitnya (0:52–1:24)

**Visual [grafis]:** enam tahap muncul berurutan, masing-masing dengan kartu
masalah. Tahap 2–6 merah, lalu pita *Tahap 2–6 biasanya harus menunggu analis
senior*.

| Tahap | Titik sakit |
|---|---|
| Memantau | Ratusan baris per menit; IT dan OT di layar berbeda |
| Memilah | 654 alert, 13 serangan: mana yang penting? |
| Merangkai | Menyambung SSH, hash, gerak lateral, dan Modbus dari dua sistem |
| Menilai dampak | Apakah "Modbus write" berarti genset mati? |
| Bertindak | SOP terlalu umum, tidak menyebut host dan akun yang kena |
| Melapor | Menulis laporan lama; istilah teknis membingungkan komandan |

> **VO:** Kami petakan perjalanan analis, dari alert pertama sampai laporan.
> Memantau masih bisa dikerjakan siapa saja. Tetapi memilah, merangkai cerita
> serangan, menilai dampak, menentukan tindakan, dan menulis laporan, semuanya
> butuh jam terbang. Di tahap-tahap ini, analis junior biasanya harus menunggu
> senior.

Catatan: alur kerja ini disusun dari riset dan skenario lab tim, belum dari
wawancara analis satuan.

## 3. Solusi yang ada (1:24–1:48)

**Visual [grafis]:** empat kartu kategori; sisi bawahnya menyala merah satu per
satu menunjukkan kekurangannya.
- SIEM/IDS (Wazuh, Suricata) → *satu alert per kejadian, merangkai cerita tetap tugas analis*
- Copilot AI (Microsoft, Google) → *bisa merangkai, tapi data diproses di cloud asing*
- Platform OT (Nozomi, Claroty, Dragos) → *mahal, dan hanya melihat sisi OT*
- n8n + GPT → *isi insiden keluar ke server luar negeri*

> **VO:** Alatnya sebenarnya ada, tapi analisnya tetap sendirian. SIEM berhenti
> di alert. Copilot AI bisa merangkai, tetapi data militer tidak boleh ke cloud
> asing. Platform OT mahal dan hanya melihat satu sisi. Alur GPT buatan sendiri
> juga mengirim isi insiden ke luar negeri.

## 4. Solusi: Tameng (1:48–2:45)

### 4a. Proposisi (1:48–2:12)
**Visual [grafis]:** logo perisai tergambar, nama Tameng dengan kepanjangan
*Tangkal Ancaman Mandiri lewat Edukasi, Notifikasi, dan Gerak cepat*, lalu proposisi dan
empat chip.
**Teks layar:** *Pendamping analis insiden IT/OT, di dalam satuan* ·
*Dengan Tameng, analis junior bisa menangani insiden yang biasanya harus
menunggu analis senior.* · *Lebih sederhana · Lebih mudah · Lebih murah ·
Lebih aman*

> **VO:** Karena itu kami membuat Tameng. Dengan Tameng, analis junior bisa
> menangani insiden yang biasanya harus menunggu analis senior. Tameng tidak
> menggantikan Wazuh, Suricata, atau analisnya. Tameng membantu orang yang
> menjaganya: satu laporan IT dan OT, dalam bahasa Indonesia, di satu laptop
> tanpa internet.

### 4b. Perjalanan yang sama, dengan Tameng (2:12–2:45)
**Visual [grafis]:** enam tahap yang sama, kini biru, dengan status *sudah
jalan* (tahap 1–4) dan *sebagian* (tahap 5–6).

| Tahap | Yang dikerjakan Tameng | Status |
|---|---|---|
| Memantau | Daftar insiden, bukan alert; IT dan OT dalam satu peta | sudah jalan |
| Memilah | 654 alert dipilah kode menjadi 1 insiden | sudah jalan |
| Merangkai | Kronologi IT→OT; tiap baris menunjuk ID bukti | sudah jalan |
| Menilai dampak | "Genset DIMATIKAN" atau "DIBLOKIR, genset menyala" | sudah jalan |
| Bertindak | Host, akun, dan IP yang perlu ditindak | sebagian (checklist SOP menyusul) |
| Melapor | Laporan bahasa Indonesia ±1,5 menit | sebagian (ringkasan komandan menyusul) |

> **VO:** Ini perjalanan yang sama, dengan Tameng. Kode memilah dan merangkai.
> Dampaknya ditulis jelas: genset mati, atau perintahnya diblokir. Checklist
> SOP dan ringkasan untuk komandan sedang kami kerjakan. Keputusan tetap di
> tangan analis. Sekarang, buktinya.


## 5. Proses kerja dan demo (2:45–4:45)

### 5a. Lab yang kami bangun (2:45–3:05)
**Visual [grafis]:** topologi lab: kali-ops (penyerang), pc-staf-07,
srv-file-01, PLC genset; Wazuh di sisi IT, Suricata di sisi OT.
**Label:** *6 container · 685 MB RAM · Docker di MacBook Air*

> **VO:** Untuk membuktikannya, kami membangun lab di satu laptop: PC staf,
> server file, dan PLC yang mengendalikan genset. Wazuh menjaga sisi IT,
> Suricata menjaga jaringan kendali OT.

### 5b. Serangan berjalan (3:05–3:30)
**Visual [rekonstruksi]:** terminal menampilkan output `attack.sh` asli baris
demi baris. Sisipan: log PLC *GENSET DIMATIKAN*.

> **VO:** Lalu kami menyerang. Penyerang menebak kata sandi SSH, masuk dengan
> akun sertu, menjalankan skrip yang menyalin hash kata sandi, pindah ke server
> file, dan dari sana mengirim satu perintah Modbus ke PLC. Genset mati.

### 5c. Tameng merangkai (3:30–3:55)
**Visual [asli]:** dashboard Tameng, kamera bergerak mengikuti tiap langkah:
peta serangan, aliran alert, teknik ATT&CK menyala, genset DIMATIKAN.
**Label:** *Korelasi oleh kode, bukan tebakan AI* · *15 detik · 7 teknik ATT&CK*

> **VO:** Tameng membaca bukti dari Wazuh dan Suricata, lalu kode, bukan AI,
> merangkai rantainya per pelaku dan per host. Hasilnya satu insiden kritis:
> lima belas detik dari tebakan kata sandi pertama sampai genset mati, tujuh
> teknik MITRE ATT&CK, dari IT sampai OT.

### 5d. Laporan dan penjaga AI (3:55–4:15)
**Visual [asli]:** laporan Tameng, kamera menyorot kronologi dan kolom bukti.
Lalu contoh uji: narasi AI yang menyebut IP palsu, disorot merah, stempel
*DITOLAK*.
**Label:** *AI lokal · Qwen 2.5 7B* · *Fakta di luar bukti otomatis ditolak*

> **VO:** Baru di tahap akhir AI lokal menulis judul, ringkasan, dan
> rekomendasi. Setiap fakta di laporan menunjuk ke bukti aslinya. Kalau AI
> menyebut IP, waktu, atau host yang tidak ada di bukti, narasinya ditolak dan
> diganti ringkasan dari kode.

### 5e. Babak 2: mode blokir (4:15–4:45)
**Visual [asli]:** dua kartu berdampingan: *Babak 1 · tanpa blokir: GENSET MATI*
dan *Babak 2 · mode blokir: GENSET NYALA* dengan output asli demo (Suricata
mode IPS, perintah Modbus tidak dijawab PLC, `7100005: blocked`). Lalu laporan
Tameng babak 2 (uji lab 7 Nov), kamera menyorot baris kronologi *DIBLOKIR*.
**Label:** *Laporan Tameng · babak 2 · uji lab 7 Nov 2026*

> **VO:** Sekarang serangan yang sama, dengan mode blokir Tameng. Perintah Modbus
> dari host yang tidak sah dijatuhkan sebelum sampai ke PLC, dan genset tetap
> menyala. Tameng tetap mencatat seluruh rantai dan melaporkannya sebagai
> serangan ke OT yang digagalkan. Hanya HMI resmi yang boleh mengendalikan PLC.

## 6. Manfaat (4:45–5:15)

**Visual [grafis]:** empat angka besar bergantian.
- *654 → 1* alert mentah menjadi satu insiden dengan 13 bukti
- *±1,5 menit* dari bukti mentah sampai laporan berbahasa Indonesia
- *0* data yang keluar dari jaringan satuan
- *1 laptop 16 GB* perangkat lunak open-source

> **VO:** Bagi satuan, artinya begini. Analis tidak lagi mencari tiga belas
> baris di antara ratusan: ia menerima satu insiden dengan tiga belas bukti. Laporan
> siap dalam sekitar satu setengah menit, dalam bahasa yang bisa langsung dipakai analis junior.
> Tidak ada data yang keluar, dan biayanya sebatas satu laptop dengan
> perangkat lunak open-source.

## 7. Mengapa Tameng (5:15–5:40)

**Visual [grafis]:** tabel perbandingan; kolom Tameng menyala.

| | SIEM/IDS | Copilot AI | Platform OT | AI SOC open-source | **Tameng** |
|---|---|---|---|---|---|
| Dirancang untuk | analis ahli | analis ahli | operator OT | analis ahli | **analis junior satuan** |
| Merangkai insiden | tidak | ya | sebagian | ya | **ya** |
| IT dan OT dalam satu insiden | tidak | sebagian | OT saja | IT saja | **ya** |
| Data tetap di satuan | ya | tidak | ya | ya | **ya** |
| Biaya untuk satuan | rendah | tinggi | sangat tinggi | rendah | **rendah** |

AI SOC open-source: misalnya AiSOC dan AI_SOC, yang memakai LLM lokal tetapi
hanya untuk sisi IT.

> **VO:** Bagian-bagiannya sudah ada. Ada AI SOC open-source dengan LLM lokal,
> tetapi hanya untuk IT dan dibuat untuk analis yang sudah ahli. Tameng
> menyatukannya untuk analis satuan, dari IT sampai OT. Langkah berikutnya:
> uji bersama analis satuan, lalu pilot di satu markas.

## Penutup (5:40–5:50)

**Visual [grafis]:** logo, *Tameng*, *Pendamping analis insiden, di dalam
satuan, untuk satuan*, *Kartika Cyber Hackathon 2026 · Defensive Shield*, nama tim.

> **VO:** Tameng. Pendamping analis insiden, di dalam satuan, untuk satuan.
