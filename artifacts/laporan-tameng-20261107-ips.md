# Serangan tinggi IT ke OT digagalkan: perintah ke PLC diblokir

**Insiden** `INC-20261107-051245` · **Tingkat bahaya** 🟠 TINGGI · **Dampak OT** Dicoba, DIBLOKIR
**Waktu** 2026-11-07 05:12:45 – 05:12:54 UTC · **IP masuk** 10.10.5.90 · **Host** pc-staf-07, srv-file-01, plc-genset-01
**Akun disalahgunakan** sertu

## Ringkasan
Penyerang dari 10.10.5.90 menyasar pc-staf-07, srv-file-01, plc-genset-01 lalu mencoba mengirim perintah tulis tak sah ke PLC, tetapi perintah itu diblokir sehingga genset tetap menyala. Teknik yang terlihat: Brute Force, Valid Accounts, Remote Services: SSH, Command and Scripting Interpreter: Unix Shell.

## Kronologi
| Waktu | Kejadian | Bukti | ATT&CK |
|---|---|---|---|
| 05:12:45 | 4 percobaan login SSH gagal ke pc-staf-07 dari 10.10.5.90 (kali-ops) — pola brute force | W1, W2, W4, W5 | T1110 |
| 05:12:52 | Login SSH BERHASIL ke pc-staf-07 sebagai 'sertu' dari 10.10.5.90 (akses awal dari luar jaringan) | W7 | T1078, T1021.004 |
| 05:12:52 | Login SSH BERHASIL ke pc-staf-07 sebagai 'sertu' dari 10.10.5.90 (akses awal dari luar jaringan) | W12 | T1078, T1021.004 |
| 05:12:52 | Login SSH BERHASIL ke srv-file-01 sebagai 'sertu' dari 10.10.5.66 (gerak lateral dari pc-staf-07) | W16 | T1078, T1021.004 |
| 05:12:52 | Eksekusi berkas dari /tmp di pc-staf-07 (pengguna '?') — payload penyerang | W15 | T1059.004 |
| 05:12:52 | Pembacaan /etc/shadow di pc-staf-07 — pencurian hash kredensial | W9, W10, W13, W14 | T1003.008 |
| 05:12:54 | Perintah tulis Modbus dari 10.10.5.7 (srv-file-01) ke PLC plc-genset-01 DIBLOKIR — genset tetap menyala (serangan OT digagalkan) | S2 | T0855 |

## Teknik MITRE ATT&CK
**Enterprise:** T1110 (Brute Force), T1078 (Valid Accounts), T1021.004 (Remote Services: SSH), T1059.004 (Command and Scripting Interpreter: Unix Shell), T1003.008 (OS Credential Dumping: /etc/passwd and /etc/shadow)
**ICS:** T0855 (Unauthorized Command Message)

## Rekomendasi
- Isolasi host terdampak (pc-staf-07, srv-file-01) dari jaringan.
- Reset kata sandi akun sertu dan cabut sesi SSH yang aktif.
- Pertahankan mode blokir Suricata; tinjau daftar HMI yang diizinkan menulis ke PLC.
- Selidiki bagaimana penyerang mencapai jaringan kendali OT dan tutup jalurnya (segmentasi).
- Blokir 10.10.5.90 di perimeter.
- Anggap seluruh hash kata sandi di host terdampak bocor; ganti kata sandi akun lokal.

## Bukti
| ID | Sumber | Sinyal | Host/Alur | Waktu |
|---|---|---|---|---|
| W1 | wazuh (5710) | Login SSH gagal (indikasi brute force) | 10.10.5.90 → pc-staf-07 | 05:12:45 |
| W2 | wazuh (5710) | Login SSH gagal (indikasi brute force) | 10.10.5.90 → pc-staf-07 | 05:12:47 |
| W4 | wazuh (5710) | Login SSH gagal (indikasi brute force) | 10.10.5.90 → pc-staf-07 | 05:12:50 |
| W5 | wazuh (5712) | Brute force SSH (banyak kegagalan beruntun) | 10.10.5.90 → pc-staf-07 | 05:12:51 |
| W7 | wazuh (40112) | Login SSH BERHASIL setelah rentetan kegagalan | 10.10.5.90 → pc-staf-07 | 05:12:52 |
| W12 | wazuh (40112) | Login SSH BERHASIL setelah rentetan kegagalan | 10.10.5.90 → pc-staf-07 | 05:12:52 |
| W16 | wazuh (5715) | Login SSH BERHASIL | 10.10.5.66 → srv-file-01 | 05:12:52 |
| W15 | wazuh (100010) | Eksekusi berkas dari /tmp | pc-staf-07 | 05:12:52 |
| W9 | wazuh (100011) | Pembacaan /etc/shadow | pc-staf-07 | 05:12:52 |
| W10 | wazuh (100011) | Pembacaan /etc/shadow | pc-staf-07 | 05:12:52 |
| W13 | wazuh (100011) | Pembacaan /etc/shadow | pc-staf-07 | 05:12:52 |
| W14 | wazuh (100011) | Pembacaan /etc/shadow | pc-staf-07 | 05:12:52 |
| S2 | suricata (7100005) | Perintah tulis Modbus (fc5) ke PLC DIBLOKIR | 10.10.5.7 → 10.10.5.20 | 05:12:54 |

## Catatan analisis
- Serangan ke OT digagalkan: 1 perintah tulis Modbus dari host tak sah dijatuhkan Suricata (mode IPS) sebelum sampai ke PLC.
- 3 pembacaan /etc/shadow diabaikan sebagai derau (login PAM atau pemindaian agen Wazuh), karena tidak terjadi sesaat setelah eksekusi /tmp.

---
*Dihasilkan lokal (air-gapped) oleh Tameng · narasi: ringkasan cadangan (LLM tidak dipakai).*
