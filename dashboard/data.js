// Dibuat oleh dashboard/build.py. Jangan disunting tangan.
window.TAMENG_DATA = {
 "incidents": [
  {
   "id": "INC-20261107-051158",
   "severity": "kritis",
   "has_ot_impact": true,
   "ot_blocked": false,
   "start": "2026-11-07T05:11:58+00:00",
   "end": "2026-11-07T05:12:13.449942+00:00",
   "entry_ip": "10.10.5.90",
   "hosts": [
    "pc-staf-07",
    "srv-file-01",
    "plc-genset-01"
   ],
   "identities": [
    "sertu"
   ],
   "techniques": [
    {
     "id": "T1110",
     "name": "Brute Force",
     "domain": "enterprise",
     "tactic": "Credential Access"
    },
    {
     "id": "T1078",
     "name": "Valid Accounts",
     "domain": "enterprise",
     "tactic": "Initial Access / Lateral Movement"
    },
    {
     "id": "T1021.004",
     "name": "Remote Services: SSH",
     "domain": "enterprise",
     "tactic": "Initial Access / Lateral Movement"
    },
    {
     "id": "T1059.004",
     "name": "Command and Scripting Interpreter: Unix Shell",
     "domain": "enterprise",
     "tactic": "Execution"
    },
    {
     "id": "T1003.008",
     "name": "OS Credential Dumping: /etc/passwd and /etc/shadow",
     "domain": "enterprise",
     "tactic": "Credential Access"
    },
    {
     "id": "T0855",
     "name": "Unauthorized Command Message",
     "domain": "ics",
     "tactic": "Impair Process Control"
    },
    {
     "id": "T0816",
     "name": "Device Restart/Shutdown",
     "domain": "ics",
     "tactic": "Impair Process Control"
    }
   ],
   "steps": [
    {
     "time": "05:11:58",
     "text": "4 percobaan login SSH gagal ke pc-staf-07 dari 10.10.5.90 (kali-ops) — pola brute force",
     "evidence": [
      "W1",
      "W2",
      "W4",
      "W5"
     ],
     "tech": [
      "T1110"
     ]
    },
    {
     "time": "05:12:10",
     "text": "Login SSH BERHASIL ke pc-staf-07 sebagai 'sertu' dari 10.10.5.90 (akses awal dari luar jaringan)",
     "evidence": [
      "W6"
     ],
     "tech": [
      "T1078",
      "T1021.004"
     ]
    },
    {
     "time": "05:12:11",
     "text": "Login SSH BERHASIL ke pc-staf-07 sebagai 'sertu' dari 10.10.5.90 (akses awal dari luar jaringan)",
     "evidence": [
      "W10"
     ],
     "tech": [
      "T1078",
      "T1021.004"
     ]
    },
    {
     "time": "05:12:11",
     "text": "Login SSH BERHASIL ke srv-file-01 sebagai 'sertu' dari 10.10.5.66 (gerak lateral dari pc-staf-07)",
     "evidence": [
      "W15"
     ],
     "tech": [
      "T1078",
      "T1021.004"
     ]
    },
    {
     "time": "05:12:11",
     "text": "Eksekusi berkas dari /tmp di pc-staf-07 (pengguna '?') — payload penyerang",
     "evidence": [
      "W12"
     ],
     "tech": [
      "T1059.004"
     ]
    },
    {
     "time": "05:12:11",
     "text": "Pembacaan /etc/shadow di pc-staf-07 — pencurian hash kredensial",
     "evidence": [
      "W13",
      "W14"
     ],
     "tech": [
      "T1003.008"
     ]
    },
    {
     "time": "05:12:13",
     "text": "Perintah tulis Modbus dari 10.10.5.7 (srv-file-01) ke PLC plc-genset-01 — mematikan genset (DAMPAK OT)",
     "evidence": [
      "S2"
     ],
     "tech": [
      "T0855",
      "T0816"
     ]
    }
   ],
   "events": [
    {
     "eid": "W1",
     "source": "wazuh",
     "sid": "5710",
     "label": "Login SSH gagal (indikasi brute force)",
     "src_ip": "10.10.5.90",
     "dst_ip": null,
     "host": "pc-staf-07",
     "time": "05:11:58",
     "domain": "it"
    },
    {
     "eid": "W2",
     "source": "wazuh",
     "sid": "5710",
     "label": "Login SSH gagal (indikasi brute force)",
     "src_ip": "10.10.5.90",
     "dst_ip": null,
     "host": "pc-staf-07",
     "time": "05:12:00",
     "domain": "it"
    },
    {
     "eid": "W4",
     "source": "wazuh",
     "sid": "5710",
     "label": "Login SSH gagal (indikasi brute force)",
     "src_ip": "10.10.5.90",
     "dst_ip": null,
     "host": "pc-staf-07",
     "time": "05:12:07",
     "domain": "it"
    },
    {
     "eid": "W5",
     "source": "wazuh",
     "sid": "5710",
     "label": "Login SSH gagal (indikasi brute force)",
     "src_ip": "10.10.5.90",
     "dst_ip": null,
     "host": "pc-staf-07",
     "time": "05:12:09",
     "domain": "it"
    },
    {
     "eid": "W6",
     "source": "wazuh",
     "sid": "40112",
     "label": "Login SSH BERHASIL setelah rentetan kegagalan",
     "src_ip": "10.10.5.90",
     "dst_ip": null,
     "host": "pc-staf-07",
     "time": "05:12:10",
     "domain": "it"
    },
    {
     "eid": "W10",
     "source": "wazuh",
     "sid": "40112",
     "label": "Login SSH BERHASIL setelah rentetan kegagalan",
     "src_ip": "10.10.5.90",
     "dst_ip": null,
     "host": "pc-staf-07",
     "time": "05:12:11",
     "domain": "it"
    },
    {
     "eid": "W15",
     "source": "wazuh",
     "sid": "5715",
     "label": "Login SSH BERHASIL",
     "src_ip": "10.10.5.66",
     "dst_ip": null,
     "host": "srv-file-01",
     "time": "05:12:11",
     "domain": "it"
    },
    {
     "eid": "W12",
     "source": "wazuh",
     "sid": "100010",
     "label": "Eksekusi berkas dari /tmp",
     "src_ip": null,
     "dst_ip": null,
     "host": "pc-staf-07",
     "time": "05:12:11",
     "domain": "it"
    },
    {
     "eid": "W13",
     "source": "wazuh",
     "sid": "100011",
     "label": "Pembacaan /etc/shadow",
     "src_ip": null,
     "dst_ip": null,
     "host": "pc-staf-07",
     "time": "05:12:11",
     "domain": "it"
    },
    {
     "eid": "W14",
     "source": "wazuh",
     "sid": "100011",
     "label": "Pembacaan /etc/shadow",
     "src_ip": null,
     "dst_ip": null,
     "host": "pc-staf-07",
     "time": "05:12:11",
     "domain": "it"
    },
    {
     "eid": "S2",
     "source": "suricata",
     "sid": "7000005",
     "label": "Perintah tulis Modbus (fc5) ke PLC",
     "src_ip": "10.10.5.7",
     "dst_ip": "10.10.5.20",
     "host": "10.10.5.20",
     "time": "05:12:13",
     "domain": "ot"
    }
   ],
   "notes": [
    "5 pembacaan /etc/shadow diabaikan sebagai derau (login PAM atau pemindaian agen Wazuh), karena tidak terjadi sesaat setelah eksekusi /tmp."
   ],
   "summary": {
    "judul": "Serangan kritis IT ke OT: perintah tak sah ke PLC",
    "ringkasan": "Penyerang dari 10.10.5.90 menyasar pc-staf-07, srv-file-01, plc-genset-01 lalu mengirim perintah tulis tak sah ke PLC (dampak OT). Teknik yang terlihat: Brute Force, Valid Accounts, Remote Services: SSH, Command and Scripting Interpreter: Unix Shell.",
    "rekomendasi": [
     "Isolasi host terdampak (pc-staf-07, srv-file-01) dari jaringan.",
     "Reset kata sandi akun sertu dan cabut sesi SSH yang aktif.",
     "Periksa PLC dan kembalikan peralatan ke status aman secara manual.",
     "Batasi akses Modbus ke PLC hanya dari HMI/SCADA yang sah.",
     "Blokir 10.10.5.90 di perimeter.",
     "Anggap seluruh hash kata sandi di host terdampak bocor; ganti kata sandi akun lokal."
    ]
   },
   "meta": {
    "fallback": true,
    "model": null,
    "warnings": [],
    "elapsed_s": null
   },
   "defaced": false,
   "edukasi": [
    {
     "id": "T1110",
     "name": "Brute Force",
     "apa": "Penyerang menebak kata sandi berkali-kali, biasanya dengan daftar sandi umum, sampai ada yang cocok.",
     "bahaya": "Satu akun bersandi lemah sudah cukup untuk masuk ke jaringan satuan.",
     "tindakan": "Catat IP sumber dan akun yang dicoba. Periksa apakah ada login BERHASIL dari IP yang sama sesudahnya.",
     "cegah": "Wajibkan sandi panjang, kunci akun setelah beberapa kali gagal, dan batasi SSH hanya dari jaringan admin."
    },
    {
     "id": "T1078",
     "name": "Valid Accounts",
     "apa": "Penyerang masuk memakai akun asli milik personel, sehingga terlihat seperti pengguna biasa.",
     "bahaya": "Aktivitasnya sulit dibedakan dari pekerjaan normal, dan hak akses akun itu ikut jatuh ke tangan penyerang.",
     "tindakan": "Hubungi pemilik akun: apakah dia yang login? Bila bukan, reset sandinya dan putus sesi yang aktif.",
     "cegah": "Pasang autentikasi dua langkah untuk akses jarak jauh dan tinjau akun yang jarang dipakai."
    },
    {
     "id": "T1021.004",
     "name": "Remote Services: SSH",
     "apa": "Penyerang memakai SSH untuk mengendalikan komputer dari jauh, lalu melompat ke komputer lain.",
     "bahaya": "Dari satu PC staf, penyerang bisa berpindah ke server penting tanpa perlu menembus perimeter lagi.",
     "tindakan": "Telusuri semua login SSH dari host yang sudah dikuasai. Tiap host tujuan ikut diperiksa.",
     "cegah": "Segmentasi jaringan: PC staf tidak perlu bisa SSH ke server atau jaringan kendali."
    },
    {
     "id": "T1059.004",
     "name": "Command and Scripting Interpreter: Unix Shell",
     "apa": "Penyerang menjalankan perintah atau skrip shell di komputer korban, sering dari folder /tmp.",
     "bahaya": "Ini tanda penyerang sudah memegang kendali dan mulai menjalankan alatnya sendiri.",
     "tindakan": "Amankan salinan skrip sebagai bukti (catat hash-nya) sebelum dihapus, lalu isolasi host.",
     "cegah": "Pasang /tmp dengan opsi noexec dan pantau eksekusi dari folder sementara."
    },
    {
     "id": "T1003.008",
     "name": "OS Credential Dumping: /etc/passwd and /etc/shadow",
     "apa": "Penyerang membaca /etc/shadow, berkas berisi hash kata sandi semua akun lokal.",
     "bahaya": "Hash bisa dipecahkan di luar jaringan; sandi yang sama sering dipakai di host lain.",
     "tindakan": "Anggap semua sandi akun lokal di host itu bocor. Ganti sandinya, terutama yang juga dipakai di tempat lain.",
     "cegah": "Jangan pakai sandi yang sama di banyak host; batasi akun yang punya hak sudo."
    },
    {
     "id": "T0855",
     "name": "Unauthorized Command Message",
     "apa": "Penyerang mengirim perintah ke PLC (pengendali mesin) dari komputer yang bukan HMI resmi.",
     "bahaya": "PLC menjalankan perintah apa pun yang diterimanya; mesin fisik seperti genset bisa dimatikan.",
     "tindakan": "Pastikan status mesin lewat HMI resmi atau cek fisik, lalu cari komputer pengirim perintah.",
     "cegah": "Hanya HMI resmi yang boleh menulis ke PLC; pakai mode blokir Tameng untuk menjatuhkan perintah lain."
    },
    {
     "id": "T0816",
     "name": "Device Restart/Shutdown",
     "apa": "Perintah penyerang mematikan atau menyalakan ulang perangkat di lapangan.",
     "bahaya": "Layanan yang bergantung pada perangkat itu ikut berhenti, misalnya listrik cadangan markas.",
     "tindakan": "Nyalakan kembali perangkat secara manual sesuai SOP dan catat lama gangguannya.",
     "cegah": "Siapkan prosedur pengoperasian manual dan uji secara berkala."
    }
   ],
   "skenario": "Babak 1 · IT→OT tanpa perlindungan"
  },
  {
   "id": "INC-20261107-051245",
   "severity": "tinggi",
   "has_ot_impact": false,
   "ot_blocked": true,
   "start": "2026-11-07T05:12:45+00:00",
   "end": "2026-11-07T05:12:54.643560+00:00",
   "entry_ip": "10.10.5.90",
   "hosts": [
    "pc-staf-07",
    "srv-file-01",
    "plc-genset-01"
   ],
   "identities": [
    "sertu"
   ],
   "techniques": [
    {
     "id": "T1110",
     "name": "Brute Force",
     "domain": "enterprise",
     "tactic": "Credential Access"
    },
    {
     "id": "T1078",
     "name": "Valid Accounts",
     "domain": "enterprise",
     "tactic": "Initial Access / Lateral Movement"
    },
    {
     "id": "T1021.004",
     "name": "Remote Services: SSH",
     "domain": "enterprise",
     "tactic": "Initial Access / Lateral Movement"
    },
    {
     "id": "T1059.004",
     "name": "Command and Scripting Interpreter: Unix Shell",
     "domain": "enterprise",
     "tactic": "Execution"
    },
    {
     "id": "T1003.008",
     "name": "OS Credential Dumping: /etc/passwd and /etc/shadow",
     "domain": "enterprise",
     "tactic": "Credential Access"
    },
    {
     "id": "T0855",
     "name": "Unauthorized Command Message",
     "domain": "ics",
     "tactic": "Impair Process Control"
    }
   ],
   "steps": [
    {
     "time": "05:12:45",
     "text": "4 percobaan login SSH gagal ke pc-staf-07 dari 10.10.5.90 (kali-ops) — pola brute force",
     "evidence": [
      "W1",
      "W2",
      "W4",
      "W5"
     ],
     "tech": [
      "T1110"
     ]
    },
    {
     "time": "05:12:52",
     "text": "Login SSH BERHASIL ke pc-staf-07 sebagai 'sertu' dari 10.10.5.90 (akses awal dari luar jaringan)",
     "evidence": [
      "W7"
     ],
     "tech": [
      "T1078",
      "T1021.004"
     ]
    },
    {
     "time": "05:12:52",
     "text": "Login SSH BERHASIL ke pc-staf-07 sebagai 'sertu' dari 10.10.5.90 (akses awal dari luar jaringan)",
     "evidence": [
      "W12"
     ],
     "tech": [
      "T1078",
      "T1021.004"
     ]
    },
    {
     "time": "05:12:52",
     "text": "Login SSH BERHASIL ke srv-file-01 sebagai 'sertu' dari 10.10.5.66 (gerak lateral dari pc-staf-07)",
     "evidence": [
      "W16"
     ],
     "tech": [
      "T1078",
      "T1021.004"
     ]
    },
    {
     "time": "05:12:52",
     "text": "Eksekusi berkas dari /tmp di pc-staf-07 (pengguna '?') — payload penyerang",
     "evidence": [
      "W15"
     ],
     "tech": [
      "T1059.004"
     ]
    },
    {
     "time": "05:12:52",
     "text": "Pembacaan /etc/shadow di pc-staf-07 — pencurian hash kredensial",
     "evidence": [
      "W9",
      "W10",
      "W13",
      "W14"
     ],
     "tech": [
      "T1003.008"
     ]
    },
    {
     "time": "05:12:54",
     "text": "Perintah tulis Modbus dari 10.10.5.7 (srv-file-01) ke PLC plc-genset-01 DIBLOKIR — genset tetap menyala (serangan OT digagalkan)",
     "evidence": [
      "S2"
     ],
     "tech": [
      "T0855"
     ]
    }
   ],
   "events": [
    {
     "eid": "W1",
     "source": "wazuh",
     "sid": "5710",
     "label": "Login SSH gagal (indikasi brute force)",
     "src_ip": "10.10.5.90",
     "dst_ip": null,
     "host": "pc-staf-07",
     "time": "05:12:45",
     "domain": "it"
    },
    {
     "eid": "W2",
     "source": "wazuh",
     "sid": "5710",
     "label": "Login SSH gagal (indikasi brute force)",
     "src_ip": "10.10.5.90",
     "dst_ip": null,
     "host": "pc-staf-07",
     "time": "05:12:47",
     "domain": "it"
    },
    {
     "eid": "W4",
     "source": "wazuh",
     "sid": "5710",
     "label": "Login SSH gagal (indikasi brute force)",
     "src_ip": "10.10.5.90",
     "dst_ip": null,
     "host": "pc-staf-07",
     "time": "05:12:50",
     "domain": "it"
    },
    {
     "eid": "W5",
     "source": "wazuh",
     "sid": "5712",
     "label": "Brute force SSH (banyak kegagalan beruntun)",
     "src_ip": "10.10.5.90",
     "dst_ip": null,
     "host": "pc-staf-07",
     "time": "05:12:51",
     "domain": "it"
    },
    {
     "eid": "W7",
     "source": "wazuh",
     "sid": "40112",
     "label": "Login SSH BERHASIL setelah rentetan kegagalan",
     "src_ip": "10.10.5.90",
     "dst_ip": null,
     "host": "pc-staf-07",
     "time": "05:12:52",
     "domain": "it"
    },
    {
     "eid": "W12",
     "source": "wazuh",
     "sid": "40112",
     "label": "Login SSH BERHASIL setelah rentetan kegagalan",
     "src_ip": "10.10.5.90",
     "dst_ip": null,
     "host": "pc-staf-07",
     "time": "05:12:52",
     "domain": "it"
    },
    {
     "eid": "W16",
     "source": "wazuh",
     "sid": "5715",
     "label": "Login SSH BERHASIL",
     "src_ip": "10.10.5.66",
     "dst_ip": null,
     "host": "srv-file-01",
     "time": "05:12:52",
     "domain": "it"
    },
    {
     "eid": "W15",
     "source": "wazuh",
     "sid": "100010",
     "label": "Eksekusi berkas dari /tmp",
     "src_ip": null,
     "dst_ip": null,
     "host": "pc-staf-07",
     "time": "05:12:52",
     "domain": "it"
    },
    {
     "eid": "W9",
     "source": "wazuh",
     "sid": "100011",
     "label": "Pembacaan /etc/shadow",
     "src_ip": null,
     "dst_ip": null,
     "host": "pc-staf-07",
     "time": "05:12:52",
     "domain": "it"
    },
    {
     "eid": "W10",
     "source": "wazuh",
     "sid": "100011",
     "label": "Pembacaan /etc/shadow",
     "src_ip": null,
     "dst_ip": null,
     "host": "pc-staf-07",
     "time": "05:12:52",
     "domain": "it"
    },
    {
     "eid": "W13",
     "source": "wazuh",
     "sid": "100011",
     "label": "Pembacaan /etc/shadow",
     "src_ip": null,
     "dst_ip": null,
     "host": "pc-staf-07",
     "time": "05:12:52",
     "domain": "it"
    },
    {
     "eid": "W14",
     "source": "wazuh",
     "sid": "100011",
     "label": "Pembacaan /etc/shadow",
     "src_ip": null,
     "dst_ip": null,
     "host": "pc-staf-07",
     "time": "05:12:52",
     "domain": "it"
    },
    {
     "eid": "S2",
     "source": "suricata",
     "sid": "7100005",
     "label": "Perintah tulis Modbus (fc5) ke PLC DIBLOKIR",
     "src_ip": "10.10.5.7",
     "dst_ip": "10.10.5.20",
     "host": "10.10.5.20",
     "time": "05:12:54",
     "domain": "ot"
    }
   ],
   "notes": [
    "Serangan ke OT digagalkan: 1 perintah tulis Modbus dari host tak sah dijatuhkan Suricata (mode IPS) sebelum sampai ke PLC.",
    "3 pembacaan /etc/shadow diabaikan sebagai derau (login PAM atau pemindaian agen Wazuh), karena tidak terjadi sesaat setelah eksekusi /tmp."
   ],
   "summary": {
    "judul": "Serangan tinggi IT ke OT digagalkan: perintah ke PLC diblokir",
    "ringkasan": "Penyerang dari 10.10.5.90 menyasar pc-staf-07, srv-file-01, plc-genset-01 lalu mencoba mengirim perintah tulis tak sah ke PLC, tetapi perintah itu diblokir sehingga genset tetap menyala. Teknik yang terlihat: Brute Force, Valid Accounts, Remote Services: SSH, Command and Scripting Interpreter: Unix Shell.",
    "rekomendasi": [
     "Isolasi host terdampak (pc-staf-07, srv-file-01) dari jaringan.",
     "Reset kata sandi akun sertu dan cabut sesi SSH yang aktif.",
     "Pertahankan mode blokir Suricata; tinjau daftar HMI yang diizinkan menulis ke PLC.",
     "Selidiki bagaimana penyerang mencapai jaringan kendali OT dan tutup jalurnya (segmentasi).",
     "Blokir 10.10.5.90 di perimeter.",
     "Anggap seluruh hash kata sandi di host terdampak bocor; ganti kata sandi akun lokal."
    ]
   },
   "meta": {
    "fallback": true,
    "model": null,
    "warnings": [],
    "elapsed_s": null
   },
   "defaced": false,
   "edukasi": [
    {
     "id": "T1110",
     "name": "Brute Force",
     "apa": "Penyerang menebak kata sandi berkali-kali, biasanya dengan daftar sandi umum, sampai ada yang cocok.",
     "bahaya": "Satu akun bersandi lemah sudah cukup untuk masuk ke jaringan satuan.",
     "tindakan": "Catat IP sumber dan akun yang dicoba. Periksa apakah ada login BERHASIL dari IP yang sama sesudahnya.",
     "cegah": "Wajibkan sandi panjang, kunci akun setelah beberapa kali gagal, dan batasi SSH hanya dari jaringan admin."
    },
    {
     "id": "T1078",
     "name": "Valid Accounts",
     "apa": "Penyerang masuk memakai akun asli milik personel, sehingga terlihat seperti pengguna biasa.",
     "bahaya": "Aktivitasnya sulit dibedakan dari pekerjaan normal, dan hak akses akun itu ikut jatuh ke tangan penyerang.",
     "tindakan": "Hubungi pemilik akun: apakah dia yang login? Bila bukan, reset sandinya dan putus sesi yang aktif.",
     "cegah": "Pasang autentikasi dua langkah untuk akses jarak jauh dan tinjau akun yang jarang dipakai."
    },
    {
     "id": "T1021.004",
     "name": "Remote Services: SSH",
     "apa": "Penyerang memakai SSH untuk mengendalikan komputer dari jauh, lalu melompat ke komputer lain.",
     "bahaya": "Dari satu PC staf, penyerang bisa berpindah ke server penting tanpa perlu menembus perimeter lagi.",
     "tindakan": "Telusuri semua login SSH dari host yang sudah dikuasai. Tiap host tujuan ikut diperiksa.",
     "cegah": "Segmentasi jaringan: PC staf tidak perlu bisa SSH ke server atau jaringan kendali."
    },
    {
     "id": "T1059.004",
     "name": "Command and Scripting Interpreter: Unix Shell",
     "apa": "Penyerang menjalankan perintah atau skrip shell di komputer korban, sering dari folder /tmp.",
     "bahaya": "Ini tanda penyerang sudah memegang kendali dan mulai menjalankan alatnya sendiri.",
     "tindakan": "Amankan salinan skrip sebagai bukti (catat hash-nya) sebelum dihapus, lalu isolasi host.",
     "cegah": "Pasang /tmp dengan opsi noexec dan pantau eksekusi dari folder sementara."
    },
    {
     "id": "T1003.008",
     "name": "OS Credential Dumping: /etc/passwd and /etc/shadow",
     "apa": "Penyerang membaca /etc/shadow, berkas berisi hash kata sandi semua akun lokal.",
     "bahaya": "Hash bisa dipecahkan di luar jaringan; sandi yang sama sering dipakai di host lain.",
     "tindakan": "Anggap semua sandi akun lokal di host itu bocor. Ganti sandinya, terutama yang juga dipakai di tempat lain.",
     "cegah": "Jangan pakai sandi yang sama di banyak host; batasi akun yang punya hak sudo."
    },
    {
     "id": "T0855",
     "name": "Unauthorized Command Message",
     "apa": "Penyerang mengirim perintah ke PLC (pengendali mesin) dari komputer yang bukan HMI resmi.",
     "bahaya": "PLC menjalankan perintah apa pun yang diterimanya; mesin fisik seperti genset bisa dimatikan.",
     "tindakan": "Pastikan status mesin lewat HMI resmi atau cek fisik, lalu cari komputer pengirim perintah.",
     "cegah": "Hanya HMI resmi yang boleh menulis ke PLC; pakai mode blokir Tameng untuk menjatuhkan perintah lain."
    }
   ],
   "skenario": "Babak 2 · IT→OT dengan mode blokir"
  },
  {
   "id": "INC-20261107-112251",
   "severity": "tinggi",
   "has_ot_impact": false,
   "ot_blocked": false,
   "defaced": true,
   "start": "2026-11-07T11:22:51+00:00",
   "end": "2026-11-07T11:23:01+00:00",
   "entry_ip": "10.10.5.90",
   "hosts": [
    "web-portal"
   ],
   "identities": [],
   "techniques": [
    {
     "id": "T1190",
     "name": "Exploit Public-Facing Application",
     "domain": "enterprise",
     "tactic": "Initial Access"
    },
    {
     "id": "T1505.003",
     "name": "Server Software Component: Web Shell",
     "domain": "enterprise",
     "tactic": "Persistence"
    },
    {
     "id": "T1059.004",
     "name": "Command and Scripting Interpreter: Unix Shell",
     "domain": "enterprise",
     "tactic": "Persistence / Execution"
    },
    {
     "id": "T1491.002",
     "name": "Defacement: External Defacement",
     "domain": "enterprise",
     "tactic": "Impact"
    }
   ],
   "steps": [
    {
     "time": "11:22:51",
     "text": "Eksploitasi celah unggah berkas di web-portal dari 10.10.5.90 (/wp-admin/admin-ajax.php?action=fm_upload)",
     "evidence": [
      "W1"
     ],
     "tech": [
      "T1190"
     ]
    },
    {
     "time": "11:22:52",
     "text": "Berkas baru /var/www/html/wp-content/uploads/wp-cache.php muncul di web-portal — webshell ditanam",
     "evidence": [
      "W2"
     ],
     "tech": [
      "T1505.003"
     ]
    },
    {
     "time": "11:22:55",
     "text": "2 perintah sistem dijalankan lewat webshell di web-portal dari 10.10.5.90: `id`; `cp /tmp/h.html /var/www/html/index.html`",
     "evidence": [
      "W3",
      "W4"
     ],
     "tech": [
      "T1505.003",
      "T1059.004"
     ]
    },
    {
     "time": "11:23:01",
     "text": "Isi /var/www/html/index.html di web-portal diubah — DEFACE halaman situs publik",
     "evidence": [
      "W5"
     ],
     "tech": [
      "T1491.002"
     ]
    }
   ],
   "events": [
    {
     "eid": "W1",
     "source": "wazuh",
     "sid": "100020",
     "label": "Unggahan berkas lewat celah plugin web",
     "src_ip": "10.10.5.90",
     "dst_ip": null,
     "host": "web-portal",
     "time": "11:22:51",
     "domain": "it"
    },
    {
     "eid": "W2",
     "source": "wazuh",
     "sid": "554",
     "label": "Berkas baru di direktori situs web",
     "src_ip": null,
     "dst_ip": null,
     "host": "web-portal",
     "time": "11:22:52",
     "domain": "it"
    },
    {
     "eid": "W3",
     "source": "wazuh",
     "sid": "100021",
     "label": "Perintah sistem lewat webshell",
     "src_ip": "10.10.5.90",
     "dst_ip": null,
     "host": "web-portal",
     "time": "11:22:55",
     "domain": "it"
    },
    {
     "eid": "W4",
     "source": "wazuh",
     "sid": "100021",
     "label": "Perintah sistem lewat webshell",
     "src_ip": "10.10.5.90",
     "dst_ip": null,
     "host": "web-portal",
     "time": "11:23:00",
     "domain": "it"
    },
    {
     "eid": "W5",
     "source": "wazuh",
     "sid": "550",
     "label": "Isi halaman situs web berubah",
     "src_ip": null,
     "dst_ip": null,
     "host": "web-portal",
     "time": "11:23:01",
     "domain": "it"
    }
   ],
   "notes": [],
   "edukasi": [
    {
     "id": "T1190",
     "name": "Exploit Public-Facing Application",
     "apa": "Penyerang memanfaatkan celah pada aplikasi yang terbuka ke internet, misalnya plugin situs yang belum diperbarui.",
     "bahaya": "Situs publik bisa diakses siapa saja, jadi celahnya bisa dipakai tanpa perlu akun.",
     "tindakan": "Cari tahu aplikasi atau plugin mana yang diserang dari URL di bukti, lalu matikan sementara.",
     "cegah": "Perbarui CMS dan plugin secara rutin, hapus plugin yang tidak dipakai, dan pasang WAF di depan situs."
    },
    {
     "id": "T1505.003",
     "name": "Server Software Component: Web Shell",
     "apa": "Penyerang menaruh webshell: berkas kecil di server web yang menerima perintah lewat alamat situs.",
     "bahaya": "Selama webshell masih ada, penyerang bisa kembali kapan saja walaupun celah awalnya sudah ditutup.",
     "tindakan": "Salin berkas webshell ke media bukti dan catat hash-nya, baru hapus. Cari berkas serupa di folder unggahan.",
     "cegah": "Larang eksekusi skrip di folder unggahan dan pantau berkas baru di direktori situs (FIM)."
    },
    {
     "id": "T1059.004",
     "name": "Command and Scripting Interpreter: Unix Shell",
     "apa": "Penyerang menjalankan perintah atau skrip shell di komputer korban, sering dari folder /tmp.",
     "bahaya": "Ini tanda penyerang sudah memegang kendali dan mulai menjalankan alatnya sendiri.",
     "tindakan": "Amankan salinan skrip sebagai bukti (catat hash-nya) sebelum dihapus, lalu isolasi host.",
     "cegah": "Pasang /tmp dengan opsi noexec dan pantau eksekusi dari folder sementara."
    },
    {
     "id": "T1491.002",
     "name": "Defacement: External Defacement",
     "apa": "Penyerang mengganti tampilan halaman situs publik (deface), biasanya dengan pesan atau logo kelompoknya.",
     "bahaya": "Merusak citra dan kepercayaan publik pada satuan; sering juga dipakai sebagai propaganda.",
     "tindakan": "Pasang halaman pemeliharaan, laporkan ke atasan, dan pulihkan dari backup bersih yang sudah diverifikasi.",
     "cegah": "Simpan backup situs yang terpisah dari server dan uji pemulihannya secara berkala."
    }
   ],
   "summary": {
    "judul": "Deface situs web-portal: halaman publik diubah penyerang",
    "ringkasan": "Penyerang dari 10.10.5.90 menyasar web-portal lalu menanam webshell dan mengubah halaman situs publik (deface). Teknik yang terlihat: Exploit Public-Facing Application, Server Software Component: Web Shell, Command and Scripting Interpreter: Unix Shell, Defacement: External Defacement.",
    "rekomendasi": [
     "Isolasi host terdampak (web-portal) dari jaringan.",
     "Ganti situs ke halaman pemeliharaan, lalu pulihkan berkas dari backup bersih yang sudah diverifikasi.",
     "Salin /var/www/html/wp-content/uploads/wp-cache.php ke media bukti (hash dulu), baru hapus dari server.",
     "Nonaktifkan atau perbarui plugin yang dieksploitasi; periksa berkas lain di direktori situs yang berubah.",
     "Blokir 10.10.5.90 di perimeter."
    ]
   },
   "meta": {
    "fallback": true,
    "model": null,
    "warnings": [],
    "elapsed_s": null
   },
   "skenario": "Babak 3 · Deface situs (replay)"
  }
 ],
 "assets": {
  "10.10.5.2": {
   "name": "wazuh-manager",
   "role": "SOC manager",
   "crit": "tinggi",
   "internal": true
  },
  "10.10.5.66": {
   "name": "pc-staf-07",
   "role": "Workstation staf",
   "crit": "sedang",
   "internal": true
  },
  "10.10.5.7": {
   "name": "srv-file-01",
   "role": "Server file satuan",
   "crit": "tinggi",
   "internal": true
  },
  "10.10.5.20": {
   "name": "plc-genset-01",
   "role": "PLC pengendali genset (OT, kritis)",
   "crit": "kritis",
   "internal": true
  },
  "10.10.5.30": {
   "name": "hmi-genset",
   "role": "HMI operator genset (pengendali sah)",
   "crit": "tinggi",
   "internal": true
  },
  "10.10.5.40": {
   "name": "web-portal",
   "role": "Portal web satuan (situs publik)",
   "crit": "tinggi",
   "internal": true
  },
  "10.10.5.90": {
   "name": "kali-ops",
   "role": "Host tak terdaftar (indikasi penyerang)",
   "crit": "-",
   "internal": false
  }
 },
 "model": "qwen2.5:7b"
};
