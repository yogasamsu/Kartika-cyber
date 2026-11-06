# Naskah video Tameng (gaya AgMon), ±5 menit

> **Versi tanpa VO.** Video final tidak memakai suara narator. Isi VO di bawah
> sudah dipadatkan menjadi teks layar (`COPY` di `index.html`) yang muncul di
> bagian bawah layar. Bagian VO di dokumen ini tetap berguna sebagai naskah
> presentasi lisan di babak final.

Batas panitia 10 menit. Target 5 menit 10 detik: cukup untuk tujuh bagian
termasuk demo, tanpa membuat juri bosan. VO sekitar 480 kata, dibaca tenang
(±2,2 kata per detik, ±3,5 menit bicara); sisa waktunya jeda supaya footage
demo dan angka di layar sempat terbaca. Semua angka di layar punya sumber: riset BSSN dan
pemberitaan 2024–2025, atau uji lab Tameng 6 November 2026.

Keterangan footage:
- **[asli]** tangkapan layar atau rekaman dari lab dan Tameng.
- **[rekonstruksi]** tampilan yang disusun dari data asli (mis. output terminal
  yang benar-benar keluar saat uji, diketik ulang di layar).
- **[grafis]** animasi teks, ikon, dan diagram.

---

## 1. Masalah (0:00–1:00)

### 1a. Markas hidup di jaringan (0:00–0:16)
**Visual [grafis]:** layar gelap, ikon perangkat markas menyala satu per satu
dan tersambung garis: PC staf, server, CCTV, radio, genset.
**Teks layar:** *Markas satuan kini hidup di jaringan.*

> **VO:** Markas satuan TNI AD hari ini hidup di jaringan. Komputer staf,
> server data, CCTV, radio, sampai genset, pembangkit listrik cadangan markas,
> semuanya tersambung dan bisa dikendalikan dari jauh.

### 1b. Ancamannya nyata (0:16–0:38)
**Visual [grafis]:** angka menghitung naik, lalu dua kartu kejadian 2024.
**Teks layar:** *5,2 miliar anomali trafik ke Indonesia (BSSN, Jan–Nov 2025)* ·
*Juni 2024: Pusat Data Nasional lumpuh, 282 instansi terdampak* ·
*Juni 2024: data yang diklaim milik BAIS TNI dijual di forum gelap*

> **VO:** Ancamannya nyata. Sepanjang 2025, BSSN mencatat 5,2 miliar anomali
> trafik ke Indonesia, dan malware terbanyak menyasar perangkat seperti CCTV
> dan router. Pertengahan 2024, ransomware melumpuhkan Pusat Data Nasional dan
> 282 instansi ikut terdampak. Di bulan yang sama, data yang diklaim milik BAIS
> TNI dijual di forum gelap.

### 1c. Masalah di ruang SOC (0:38–1:00)
**Visual [asli]:** log Wazuh asli bergulir cepat, penghitung naik ke 654; baris
serangan merah terselip di antara pemeriksaan rutin.
(Sampel 70 baris dari log asli; semua baris serangan ikut, baris rutin diambil merata.)
**Label:** *Data lab Tameng · 6 Nov 2026* · *654 alert dalam 4 menit*

> **VO:** Lalu lihat layar analisnya. Dalam simulasi empat menit di lab kami,
> sistem deteksi mengeluarkan 654 alert. Hanya tiga belas yang berkaitan
> dengan serangan; sisanya pemeriksaan rutin. Analis siber di satuan jumlahnya
> sedikit, dan mereka harus menemukan tiga belas baris itu sendiri.

## 2. Solusi yang sudah ada (1:00–1:40)

**Visual [grafis]:** empat kartu kategori muncul bergantian, masing-masing
dengan contoh produk.
1. *SIEM dan IDS open-source:* Wazuh, Suricata
2. *Copilot AI komersial:* Microsoft Security Copilot, Google SecOps
3. *Platform keamanan OT:* Nozomi, Claroty, Dragos
4. *Otomasi buatan sendiri:* alur n8n dengan GPT

> **VO:** Alat untuk ini sebenarnya sudah ada. Wazuh dan Suricata gratis dan
> andal untuk mendeteksi. Untuk merangkum alert, ada copilot AI komersial dari
> Microsoft dan Google. Untuk perangkat industri seperti PLC dan genset, ada
> platform khusus OT. Sebagian tim juga merakit sendiri alur otomatis yang
> mengirim alert ke GPT.

## 3. Masalah solusi yang ada (1:40–2:20)

**Visual [grafis + asli]:** kartu yang sama dibalik satu per satu, sisi
belakangnya memperlihatkan kelemahan; ikon awan dengan gembok merah.
- SIEM/IDS → *satu alert per kejadian, merangkai cerita tetap tugas manusia*
- Copilot AI → *data dikirim ke cloud asing*
- Platform OT → *mahal, di luar jangkauan satuan*
- n8n + GPT → *isi insiden keluar ke server luar negeri*

> **VO:** Masing-masing punya lubang. SIEM berhenti di alert: satu kejadian,
> satu baris, dan merangkai cerita serangan tetap pekerjaan manusia. Copilot
> AI bisa merangkai, tetapi datanya diproses di cloud asing, sesuatu yang
> tidak boleh terjadi pada data militer. Platform OT harganya jauh di luar
> anggaran satuan. Alur GPT buatan sendiri punya masalah yang sama: isi insiden
> keluar dari jaringan.

## 4. Solusi: Tameng (2:20–2:45)

**Visual [grafis]:** logo perisai tergambar, nama Tameng, lalu satu kalimat.
**Teks layar:** *Tameng: analis insiden IT/OT yang bekerja di dalam satuan.*

> **VO:** Karena itu kami membuat Tameng. Tameng duduk di atas Wazuh dan
> Suricata yang sudah dipakai, merangkai alert menjadi insiden, dan menulis
> laporannya dalam bahasa Indonesia. Semuanya di satu laptop, tanpa internet.

## 5. Proses kerja dan demo (2:45–4:15)

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

## 6. Manfaat (4:15–4:45)

**Visual [grafis]:** empat angka besar bergantian.
- *654 → 1* alert mentah menjadi satu insiden dengan 13 bukti
- *±1,5 menit* dari bukti mentah sampai laporan berbahasa Indonesia
- *0* data yang keluar dari jaringan satuan
- *1 laptop 16 GB* perangkat lunak open-source

> **VO:** Bagi satuan, artinya begini. Analis tidak lagi mencari tiga belas
> baris di antara ratusan: ia menerima satu insiden dengan tiga belas bukti. Laporan
> siap dalam sekitar satu setengah menit, dalam bahasa yang bisa dibaca bintara.
> Tidak ada data yang keluar, dan biayanya sebatas satu laptop dengan
> perangkat lunak open-source.

## 7. Mengapa Tameng (4:45–5:10)

**Visual [grafis]:** tabel perbandingan singkat; kolom Tameng menyala.

| | SIEM/IDS | Copilot AI | Platform OT | **Tameng** |
|---|---|---|---|---|
| Merangkai insiden | tidak | ya | sebagian | **ya** |
| Data tetap di satuan | ya | tidak | ya | **ya** |
| IT dan OT sekaligus | sebagian | sebagian | OT saja | **ya** |
| Biaya untuk satuan | rendah | tinggi | sangat tinggi | **rendah** |

> **VO:** Mengapa Tameng? Karena hanya Tameng yang merangkai insiden, menjaga
> data tetap di satuan, membaca IT dan OT sekaligus, dengan biaya yang
> terjangkau satuan. Langkah berikutnya: pilot di satu markas.

## Penutup (5:10–5:20)

**Visual [grafis]:** logo, *Tameng*, *Kartika Cyber Hackathon 2026 ·
Defensive Shield*, nama tim.

> **VO:** Tameng. Analis insiden yang bekerja di dalam satuan, untuk satuan.
