# Riset Kartika Cyber Hackathon 2026

Disusun 27 Oktober 2026. Sumber utama: [kartikacyberhackathon.id](https://kartikacyberhackathon.id/) dan pemberitaan/riset publik (daftar di bagian akhir).

## 1. Ringkasan tema

| Aspek | Detail |
|---|---|
| Penyelenggara | PUSSIBERAD (Pusat Siber TNI AD) dan CODEPOLITAN, rangka Hari Juang Kartika 2026 |
| Peserta | Tim 2–3 orang atau individu, gratis, terbuka se-Indonesia |
| Babak 1 | Online ±4 minggu. Submit: link project, video presentasi/demo, slide + proposal & dokumentasi teknis |
| Babak 2 | 10 finalis, presentasi 10 menit + demo di Hotel Aston Kartika, Jakarta |
| Hadiah | Total Rp 100,7 juta; Juara 1–3 dapat **Golden Ticket** seleksi Bintara Siber TNI AD per anggota |
| Peluang | Karya terbaik berpeluang diadopsi TNI AD |

**Timeline penting**
- 15 Nov 2026: batas submission (**±19 hari dari hari ini**)
- 16 Nov: penjurian online
- 20 Nov: pengumuman finalis
- 24 Nov: final + closing

> Catatan: bagian "Format Kompetisi" di situs menulis final 20 November, sedangkan timeline dan FAQ menulis 24 November. Konfirmasi ke grup WhatsApp panitia.

**Empat kategori**
1. **Offensive Tech (Penindakan)**: exploitation tool, payload generator, malware sandbox, red team automation, AI target profiling
2. **Defensive Shield (Penangkalan)**: smart IDS/IPS, threat intel platform, automated IR, zero-day detection, enkripsi
3. **Core Infra (Dukungan Teknologi)**: cyber ops dashboard, SIEM ringan, forensic toolkit, secure comms, asset management
4. **Cognitive Domain (Siber Sosial)**: bot/buzzer detection, hoax classifier, sentiment dashboard, SNA, early warning isu viral

**Kriteria penilaian** (ini yang menentukan ide mana yang layak)

| Bobot | Kriteria | Implikasi |
|---|---|---|
| 25% | Relevansi untuk pengamanan **IT/OT TNI AD** | Ide harus menjawab masalah satuan, bukan masalah umum |
| 25% | Inovasi teknis | Jangan sekadar membungkus Wazuh/ELK; perlu sudut baru |
| 25% | Purwarupa berfungsi | Demo harus jalan live; scope kecil tapi tuntas |
| 15% | Kelayakan implementasi | On-prem, open-source, murah, bisa dioperasikan personel non-ahli |
| 10% | Dokumentasi | Proposal, arsitektur, video jelas |

Kata kunci "IT/OT" di kriteria pertama penting: juri dari TNI AD akan menghargai solusi yang menyentuh perangkat lapangan (radio, CCTV, genset, drone, jaringan taktis), bukan hanya server kantor.

## 2. Permasalahan saat ini

### 2.1 Volume ancaman tinggi, kapasitas pantau rendah
- BSSN mencatat ±5,2 miliar anomali trafik (Jan–15 Nov 2025), rata-rata ±182 per detik. Sekitar 93,8% berupa aktivitas malware; terbanyak **Mirai botnet** (menyasar IoT: CCTV, router, DVR), lalu Remcos RAT dan generic trojan.
- BSSN mengakui kapasitas monitoringnya **belum mencapai 10%** dari total trafik internet nasional.
- Ancaman yang tumbuh paling cepat menurut ITSEC Asia: **infostealer** yang mencuri password, cookie, dan token untuk pengambilalihan akun atau pintu masuk ransomware.

### 2.2 Ransomware dan ketahanan pemulihan
- Juni 2024, PDNS 2 Surabaya lumpuh oleh **Brain Cipher** (varian LockBit 3.0), berdampak ke 282 tenant instansi, gangguan ±2 bulan, tebusan US$8 juta.
- Pelajaran terbesar: hanya 44 dari 282 instansi punya backup; laporan lain menyebut hanya ±2% data yang di-backup. Sistem backup disiapkan tetapi tidak dipakai. Forensik terhambat karena bukti ikut terenkripsi.

### 2.3 Kebocoran data militer
- Juni 2024, data yang diklaim milik **BAIS TNI** dijual di BreachForums. Panglima TNI merespons dengan rencana mengubah doktrin satuan siber dan membuka rekrutmen khusus talenta siber (konteks lahirnya jalur Bintara Siber dan hackathon ini).

### 2.4 Rekayasa sosial yang menyasar personel dan keluarga
- Modus APK "undangan pernikahan", "foto paket", "surat tilang" via WhatsApp terus berulang. Kaspersky melaporkan **Tria Stealer** (2025) yang mencuri SMS/OTP. Kerugian individu bisa miliaran rupiah.
- Ponsel pribadi prajurit sering menjadi jalur masuk: dipakai untuk grup koordinasi satuan sekaligus untuk urusan pribadi.

### 2.5 Domain kognitif
- Mafindo memetakan 1.593 hoaks (Okt 2024–Okt 2025). Deepfake mendominasi hoaks video bertema penipuan; konten deepfake dilaporkan naik ±550%.
- Hoaks melonjak saat demonstrasi (Agustus–September 2025). Institusi TNI dan pejabatnya sering dicatut untuk penipuan dan propaganda.
- Komdigi mendesak platform menyediakan deteksi konten AI, tetapi belum ada alat deteksi yang teruji untuk konteks bahasa dan kompresi video Indonesia.

### 2.6 OT, perangkat lapangan, dan peperangan elektronik
- Perang Ukraina menunjukkan GNSS sering tidak tersedia di garis depan; jamming dan spoofing menyebabkan ratusan drone hilang. Ukraina sendiri dilaporkan kehilangan hampir 100 drone karena GPS spoofing.
- Komunikasi taktis yang bergantung pada aplikasi komersial (WhatsApp) membawa risiko metadata dan ketergantungan pada server asing.
- Perangkat IoT/OT di markas (CCTV, akses pintu, UPS, genset, gateway radio) jarang terinventarisasi, padahal Mirai adalah malware paling dominan.

### 2.7 SDM dan alert fatigue
- SOC kecil kebanjiran alert. Riset NeurIPS 2025 (CORTEX) menyebut hanya sebagian kecil dari puluhan ribu alert harian yang benar-benar serangan.
- Wazuh secara default membuat satu alert per kejadian sehingga dashboard banjir; studi Univ. Turku menunjukkan LLM lokal (Llama 3, Mistral 7B) mempercepat triage tingkat 1, dengan risiko halusinasi dan privasi.
- Data militer tidak boleh dikirim ke LLM cloud, sehingga pendekatan "pakai ChatGPT untuk triage" tidak bisa dipakai.

## 3. Solusi yang ada dan kelemahannya

| Area | Solusi existing | Kelemahan untuk konteks TNI AD |
|---|---|---|
| SIEM/IDS | Wazuh, Suricata, Zeek, Security Onion, ELK | Alert banjir, butuh analis berpengalaman, tidak ada konteks ATT&CK dalam bahasa Indonesia, tuning manual |
| Triage AI | Copilot komersial (MS Security Copilot, Google SecOps), workflow n8n + GPT | Berbasis cloud asing; tidak bisa air-gapped; mahal |
| Threat intel | MISP, OpenCTI, feed komersial | Butuh kurasi manusia; tidak memantau kebocoran kredensial domain sendiri secara otomatis |
| Kebocoran kredensial | Have I Been Pwned, Hudson Rock, SpyCloud | HIBP tidak memuat log stealer terbaru; layanan komersial mahal dan data diproses di luar negeri |
| Backup/ransomware | Veeam, Bacula, restic, BorgBackup | Backup dibuat tetapi jarang diuji restore; tidak ada laporan cakupan backup lintas sistem; deteksi enkripsi massal minim |
| Asset & OT | Nozomi, Claroty, Dragos; GRASSMARLIN (tidak dirawat lagi) | Produk OT sangat mahal; open-source terbatas; perangkat IoT markas tidak terdata |
| Keamanan ponsel | Antivirus umum, Google Play Protect | Tidak tertarget ke modus lokal; tidak ada pelaporan ke CSIRT satuan; APK sideload lolos |
| OPSEC | Pelatihan manual, edaran | Tidak ada alat ukur jejak digital personel/satuan secara berkala |
| Bot/disinformasi | Drone Emprit, Botometer, Mafindo/TurnBackHoax | Drone Emprit komersial; Botometer fokus X dan bahasa Inggris, API X kini mahal; cek fakta manual dan lambat; TikTok sulit dipantau |
| Deepfake | Detektor generik (Hive, Reality Defender, model riset) | Akurasi turun pada video terkompresi WhatsApp/TikTok dan audio berbahasa Indonesia; tidak ada provenance untuk rilis resmi |
| Komunikasi lapangan | WhatsApp, radio analog, Meshtastic | WA bergantung server asing; Meshtastic memakai PSK bersama sehingga lemah bila satu perangkat jatuh |
| Red team / validasi | MITRE Caldera, Atomic Red Team, Infection Monkey, BloodHound | Terpisah-pisah, butuh ahli, tidak langsung menjawab "apakah SIEM kita mendeteksi serangan ini?" |

**Pola kelemahan umum**
1. **Bergantung pada cloud/vendor asing**: bertentangan dengan kedaulatan data pertahanan.
2. **Butuh ahli**: TNI AD sedang membangun SDM, sehingga alat harus bisa dipakai personel tingkat bintara.
3. **Tidak dalam konteks lokal**: bahasa Indonesia/daerah, modus penipuan lokal, platform lokal.
4. **Deteksi tanpa validasi**: tidak ada cara rutin membuktikan kontrol keamanan benar-benar bekerja (backup, IDS).
5. **OT dan lapangan terlupakan**: fokus solusi ada di server kantor, bukan perangkat dan jaringan taktis.

## 4. Sepuluh rekomendasi ide

Skor 1–5 per kriteria juri (R = relevansi IT/OT, I = inovasi, P = kemungkinan purwarupa jalan dalam 19 hari, K = kelayakan implementasi). Total berbobot = 25%R + 25%I + 25%P + 15%K (maks 4,5; dokumentasi diasumsikan sama).

| # | Ide | Kategori | R | I | P | K | Total |
|---|---|---|---|---|---|---|---|
| 1 | SOC Copilot Lokal (air-gapped) | Defensive / Core Infra | 5 | 4 | 4 | 5 | **4,00** |
| 2 | Purple Team Validator | Offensive | 5 | 5 | 3 | 4 | **3,85** |
| 3 | OT/IoT Asset Radar Markas | Core Infra | 5 | 4 | 4 | 4 | **3,85** |
| 4 | Ransomware Resilience Checker | Defensive | 5 | 4 | 4 | 4 | **3,85** |
| 5 | Pengawas Kebocoran Kredensial | Defensive | 5 | 3 | 5 | 4 | **3,85** |
| 6 | Tameng Prajurit (anti-APK & phishing) | Defensive | 4 | 4 | 4 | 4 | **3,60** |
| 7 | Detektor Operasi Bot Terkoordinasi | Cognitive | 4 | 4 | 4 | 4 | **3,60** |
| 8 | Verifikasi Deepfake + Tanda Tangan Rilis Resmi | Cognitive | 4 | 5 | 3 | 4 | **3,60** |
| 9 | OPSEC Self-Audit | Defensive / Cognitive | 4 | 4 | 4 | 3 | **3,45** |
| 10 | Mesh Komunikasi Taktis Terenkripsi | Core Infra (hardware) | 5 | 4 | 3 | 3 | **3,45** |

---

### Ide 1. SOC Copilot Lokal (air-gapped)
**Masalah:** Alert Wazuh/Suricata membanjir, analis sedikit, data tidak boleh ke LLM cloud.
**Solusi:** Lapisan AI on-prem di atas Wazuh + Suricata. LLM lokal (Ollama dengan Qwen/Llama ukuran 7–14B) mengelompokkan alert menjadi insiden, memetakan ke MITRE ATT&CK, menulis ringkasan dan langkah respons dalam **bahasa Indonesia**, dan menyarankan playbook (isolasi host, blokir IP). Analis menyetujui atau menolak; keputusan itu menjadi data untuk mengurangi false positive.
**Inovasi:** Korelasi multi-alert ke satu narasi insiden; RAG atas SOP satuan dan basis ATT&CK; berjalan 100% offline di satu server/GPU kelas menengah.
**Demo:** Lab 3 VM (Wazuh, target Windows/Linux, penyerang). Jalankan Atomic Red Team, tunjukkan 200 alert diringkas menjadi 3 insiden dengan rekomendasi.
**Stack:** Wazuh, Suricata, Ollama, LangGraph/LlamaIndex, FastAPI, React.
**Pembeda dari existing:** Copilot komersial butuh cloud; workflow n8n+GPT bocor data.

### Ide 2. Purple Team Validator
**Masalah:** Satuan punya IDS/SIEM tetapi tidak tahu apakah deteksinya bekerja.
**Solusi:** Platform yang menjalankan emulasi teknik serangan terkontrol (Atomic Red Team/Caldera) di lingkungan milik sendiri, lalu otomatis mengecek apakah SIEM mengeluarkan alert. Hasilnya **heatmap cakupan deteksi ATT&CK**, daftar celah, dan saran rule Sigma/Wazuh untuk menutupnya (bisa dibantu LLM lokal).
**Inovasi:** Menyatukan sisi ofensif dan defensif dalam satu loop "serang → cek deteksi → perbaiki rule → uji ulang". Kuat untuk kategori Offensive tanpa membuat senjata siber baru.
**Demo:** Jalankan 15 teknik, tampilkan 9 terdeteksi dan 6 tidak, generate rule, uji ulang menjadi 13/15.
**Catatan etika:** Hanya untuk aset sendiri dengan otorisasi; sertakan mode safe (tanpa payload destruktif).

### Ide 3. OT/IoT Asset Radar Markas
**Masalah:** Mirai adalah malware paling dominan di Indonesia; CCTV, DVR, akses pintu, UPS, dan gateway radio di markas jarang terdata dan masih memakai password default.
**Solusi:** Sensor pasif murah (Raspberry Pi/mini PC dengan port mirror) yang mengenali perangkat dari trafik (Zeek, fingerprint DHCP/MAC/banner), membangun inventaris otomatis, mencocokkan ke CVE/KEV, mendeteksi password default (mode aktif opsional), dan memberi alert saat perangkat berperilaku seperti bot (koneksi telnet keluar, scanning).
**Inovasi:** "Nozomi versi murah" untuk satuan; peta jaringan visual; skor risiko per perangkat.
**Demo:** Jaringan mini dengan kamera IP, router, dan satu perangkat terinfeksi simulasi Mirai; sensor menemukan dan menandainya.
**Relevansi IT/OT:** Langsung menjawab kata "OT" di kriteria juri.

### Ide 4. Ransomware Resilience Checker
**Masalah:** Kasus PDNS 2: backup ada tetapi tidak dipakai, cakupan minim, bukti forensik ikut terenkripsi.
**Solusi:** Tiga modul. (a) **Auditor cakupan backup**: memeriksa sistem mana yang punya backup, kapan terakhir, apakah immutable/offline. (b) **Restore drill otomatis**: memulihkan backup ke sandbox berkala dan memverifikasi aplikasi bisa jalan, lalu memberi "nilai kesiapan pulih". (c) **Canary & deteksi enkripsi massal**: file umpan dan pemantauan entropi yang memicu isolasi host serta snapshot forensik sebelum bukti hilang.
**Demo:** Simulator ransomware aman (enkripsi folder uji) memicu canary, host diisolasi, lalu restore dari backup terverifikasi dalam hitungan menit.

### Ide 5. Pengawas Kebocoran Kredensial Satuan
**Masalah:** Infostealer menjadi ancaman yang tumbuh paling cepat; kredensial personel bocor di Telegram/forum tanpa ada yang tahu.
**Solusi:** Layanan on-prem yang mengindeks dump kebocoran publik dan log stealer (sumber legal/terbuka), mencocokkan dengan domain dan email satuan, lalu otomatis memberi notifikasi, memaksa reset password, dan mencabut sesi. Pencocokan memakai hash (k-anonymity) supaya data tidak menyebar.
**Kelebihan:** Paling mudah dibuat jalan; dampaknya langsung terasa.
**Kelemahan:** Inovasi teknis sedang. Tambahkan nilai lewat analisis "mesin mana yang terinfeksi stealer" (dari metadata log) untuk tindak lanjut forensik.
**Catatan:** Purwarupa memakai data sintetis; jangan mengunduh atau menyimpan data bocor asli.

### Ide 6. Tameng Prajurit (anti-APK & phishing)
**Masalah:** Modus APK undangan/paket/tilang via WhatsApp terus memakan korban; ponsel prajurit adalah jalur masuk ke grup satuan.
**Solusi:** Aplikasi Android ringan. Pengguna cukup "Share" file APK atau link dari WhatsApp ke aplikasi ini; aplikasi menganalisis izin, signature, dan string secara statis dengan model ML on-device, memeriksa reputasi URL, lalu memberi vonis dalam bahasa sederhana. Temuan dilaporkan anonim ke CSIRT satuan sehingga kampanye bisa dideteksi lebih awal (misalnya 30 prajurit menerima APK yang sama).
**Inovasi:** Sensor ancaman terdistribusi dari ribuan ponsel personel; konteks modus lokal.
**Demo:** Analisis sampel APK jinak dan berbahaya (dari dataset publik seperti AndroZoo/CIC-MalDroid) dan dashboard kampanye di sisi CSIRT.

### Ide 7. Detektor Operasi Bot Terkoordinasi
**Masalah:** Kampanye buzzer dan disinformasi menyasar TNI saat isu panas; alat yang ada komersial atau berbahasa Inggris.
**Solusi:** Pipeline yang mendeteksi **coordinated inauthentic behavior**: kemiripan teks (embedding IndoBERT), sinkronisasi waktu posting, jaringan retweet/mention, umur akun. Output: klaster akun terkoordinasi, narasi utama, dan early warning saat narasi menyebar cepat.
**Inovasi:** Fokus pada koordinasi (perilaku kelompok), bukan klasifikasi bot per akun yang mudah dikelabui; mendukung slang dan bahasa campur.
**Demo:** Dataset publik atau hasil crawl terbatas tentang satu isu; tampilkan graf klaster dan timeline.
**Catatan:** Posisikan sebagai alat deteksi dan analisis, bukan alat membuat atau mengamplifikasi narasi.

### Ide 8. Verifikasi Deepfake + Tanda Tangan Rilis Resmi
**Masalah:** Deepfake pimpinan TNI dipakai untuk penipuan dan propaganda; detektor generik lemah pada video terkompresi.
**Solusi:** Dua sisi. (a) **Provenance**: rilis resmi (video, foto, surat) ditandatangani digital (standar C2PA), sehingga publik bisa memverifikasi lewat bot WhatsApp/web. (b) **Deteksi**: model deteksi deepfake audio/video yang di-fine-tune untuk kompresi WhatsApp/TikTok sebagai lapisan kedua untuk konten tanpa tanda tangan.
**Inovasi:** Mengubah pertanyaan dari "apakah ini palsu?" (sulit) menjadi "apakah ini terbukti asli?" (mudah dibuktikan).
**Risiko:** Akurasi detektor dalam 19 hari terbatas. Jadikan sisi provenance sebagai inti demo.

### Ide 9. OPSEC Self-Audit
**Masalah:** Foto bergeotag, aplikasi olahraga (kasus heatmap Strava 2018 yang membuka lokasi pangkalan militer), unggahan seragam dan kendaraan dapat membuka lokasi dan struktur satuan.
**Solusi:** Alat audit yang dijalankan satuan terhadap personelnya sendiri dengan persetujuan: memindai akun publik yang didaftarkan, mendeteksi EXIF/geotag, wajah berseragam, plat nomor, dan pola lokasi, lalu memberi skor risiko dan saran perbaikan per orang dan agregat per satuan.
**Inovasi:** Computer vision (deteksi seragam, plat, landmark) dan agregasi pola lintas unggahan.
**Catatan:** Wajib berbasis persetujuan dan hanya untuk personel sendiri; jelaskan aspek privasi di proposal.

### Ide 10. Mesh Komunikasi Taktis Terenkripsi
**Masalah:** Komunikasi lapangan bergantung pada aplikasi komersial dan infrastruktur seluler yang bisa padam (operasi di daerah terpencil, bencana/OMSP, jamming).
**Solusi:** Jaringan mesh LoRa (perangkat ESP32 + LoRa, ±Rp 300 ribu per node) dengan aplikasi pendamping di ponsel; enkripsi end-to-end per perangkat (bukan PSK bersama seperti Meshtastic), kunci bisa dicabut bila perangkat jatuh ke tangan lawan, pesan status/lokasi singkat, dan deteksi gangguan sinyal (indikasi jamming).
**Inovasi:** Manajemen kunci dan revocation di jaringan bandwidth sangat rendah.
**Risiko:** Hardware perlu dibeli dan diuji; butuh anggota yang paham embedded.

## 5. Rekomendasi pilihan

Dengan sisa waktu ±19 hari dan tim 2–3 orang:

1. **Pilihan utama: Ide 1 (SOC Copilot Lokal)**. Paling seimbang di semua kriteria, demo meyakinkan, sejalan dengan tema keynote ("AI dari industri ke pertahanan siber"), dan menjawab isu kedaulatan data.
2. **Alternatif dengan relevansi OT tertinggi: Ide 3 (OT/IoT Asset Radar)** atau **Ide 4 (Ransomware Resilience)**. Cocok bila tim lebih kuat di jaringan atau infrastruktur.
3. **Kombinasi yang kuat:** Ide 1 + modul kecil dari Ide 2 (validasi deteksi). Ceritanya menjadi "kami tidak hanya merangkum alert, kami membuktikan deteksinya bekerja". Kombinasi ini menaikkan skor inovasi tanpa melebarkan scope terlalu jauh.

**Hindari**
- Ide yang hanya memasang ulang tools open-source tanpa lapisan baru (skor inovasi rendah).
- Alat ofensif murni seperti payload generator atau exploit baru: berisiko etik, sulit didemokan aman, dan juri biasanya mempertanyakan kelayakannya di lingkungan satuan.
- Scope besar (misalnya platform cognitive multi-platform penuh) yang tidak akan selesai dalam 19 hari.

## 6. Rencana kerja singkat (untuk ide terpilih)

| Hari | Target |
|---|---|
| 1–2 | Finalisasi ide, daftar tim di CODEPOLITAN, arsitektur, lab VM |
| 3–8 | Inti fungsi berjalan end-to-end (versi kasar) |
| 9–13 | Fitur pembeda, UI dashboard, skenario demo |
| 14–16 | Uji, perbaiki bug, dokumentasi teknis dan proposal |
| 17–18 | Rekam video demo, slide |
| 19 | Submit (jangan menunggu hari terakhir) |

## Sumber
- [Kartika Cyber Hackathon 2026](https://kartikacyberhackathon.id/)
- [BSSN sebut 5,2 miliar anomali trafik (Investortrust)](https://investortrust.id/business/100269/bssn-sebut-5-2-miliar-anomali-trafik-jadi-ancaman-siber-sektor-keungan-paling-rentan)
- [BSSN: 4,4 miliar trafik anomali hingga September 2025 (Bisnis.com)](https://teknologi.bisnis.com/read/20251201/84/1933240/bssn-temukan-44-miliar-trafik-anomali-menyasar-ke-ri-hingga-september-2025)
- [BSSN ungkap 5,2 miliar anomali, mayoritas berpotensi jadi ransomware (Infobanknews)](https://infobanknews.com/bssn-ungkap-52-miliar-anomali-trafik-internet-mayoritas-berpotensi-jadi-ransomware)
- [Serangan siber 182 kali per detik, ITSEC Asia (Investortrust)](https://investortrust.id/business/105230/serangan-siber-capai-182-kali-per-detik-itsec-asia-dorong-penguatan-keamanan-digital)
- [BSSN: hanya 2% data PDN yang di-backup (Investortrust)](https://investortrust.id/national/31570/bssn-hanya-2-data-di-pusat-data-nasional-yang-di-backup)
- [Telkom: data yang diserang ransomware tak bisa dipulihkan (Investortrust)](https://investortrust.id/national/31450/telkom-data-pemerintah-yang-diserang-ransomware-tak-bisa-dipulihkan)
- [Detik-detik ransomware Brain Cipher lumpuhkan PDN (Detik)](https://inet.detik.com/security/d-7409192/detik-detik-ransomware-brain-cipher-lumpuhkan-pusat-data-indonesia)
- [Data intelijen militer bocor di dark web (Investortrust)](https://investortrust.id/national/31218/data-intelijen-militer-bocor-dan-dijual-di-dark-web-begini-respons-tni)
- [Panglima TNI siapkan rekrutmen khusus ahli siber (Investortrust)](https://investortrust.id/national/33116/panglima-tni-siapkan-rekrutmen-khusus-ahli-siber-untuk-cegah-kebocoran-data)
- [Info Singkat P3DI DPR, Agustus 2025](https://berkas.dpr.go.id/pusaka/files/info_singkat/Info%20Singkat-XVII-15-I-P3DI-Agustus-2025-1947.pdf)
- [Mafindo: deepfake dan scam warnai tahun pertama (Katadata)](https://katadata.co.id/amp/digital/teknologi/68fc642383ae9/mafindo-ungkap-deepfake-dan-scam-warnai-tahun-pertama-prabowo-gibran/)
- [Konten deepfake di Indonesia naik 550% (Selular.id)](https://selular.id/2025/09/konten-deepfake-di-indonesia-naik-550/)
- [Hoaks meningkat saat aksi demo (Selular.id)](https://selular.id/2025/09/hoax-meningkat-saat-aksi-demo-deepfake-makin-sulit-diidentifikasi/)
- [Deepfake dan digital scam dominasi lanskap hoaks 2025 (TIMES Indonesia)](https://timesindonesia.co.id/peristiwa-nasional/561378/deepfake-dan-digital-scam-dominasi-lanskap-hoaks-nasional-2025)
- [Wamenkomdigi minta platform hadirkan deteksi konten AI (Investortrust)](https://investortrust.id/national/78565/wamenkomdigi-desak-tiktok-cs-hadirkan-fitur-deteksi-konten-ai-untuk-cegah-hoaks-dan-deepfake)
- [Malware bobol rekening di undangan pernikahan (Detik)](https://inet.detik.com/security/d-7760196/waspada-malware-bobol-rekening-bersembunyi-di-undangan-pernikahan)
- [7 modus penipuan WhatsApp (Selular.id)](https://selular.id/2025/07/waspada-7-modus-penipuan-whatsapp-yang-kuras-rekening/)
- [IISS: UAVs, ISR, deterrence and war (2026)](https://www.iiss.org/globalassets/media-library---content--migration/files/publications---free-files/strategic-dossier/uavs-2026/iiss_uavs-isr-deterrence-and-war_032026.pdf)
- [How Ukraine's killer drones are beating Russian jamming (IEEE Spectrum)](https://spectrum.ieee.org/ukraine-killer-drones)
- [CORTEX: Collaborative LLM agents for alert triage (arXiv/NeurIPS 2025)](https://arxiv.org/pdf/2510.00311)
- [Evaluation of LLM agents for SOC Tier 1 triage (Univ. Turku)](https://www.utupub.fi/items/52a15c8a-63ac-41bf-8f22-fc38690bfb29/full)
