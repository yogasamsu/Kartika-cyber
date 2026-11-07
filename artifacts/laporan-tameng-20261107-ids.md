# Serangan kritis IT ke OT: perintah tak sah ke PLC

**Insiden** `INC-20261107-051158` · **Tingkat bahaya** 🔴 KRITIS · **Dampak OT** Ya
**Waktu** 2026-11-07 05:11:58 – 05:12:13 UTC · **IP masuk** 10.10.5.90 · **Host** pc-staf-07, srv-file-01, plc-genset-01
**Akun disalahgunakan** sertu

## Ringkasan
Penyerang dari 10.10.5.90 menyasar pc-staf-07, srv-file-01, plc-genset-01 lalu mengirim perintah tulis tak sah ke PLC (dampak OT). Teknik yang terlihat: Brute Force, Valid Accounts, Remote Services: SSH, Command and Scripting Interpreter: Unix Shell.

## Kronologi
| Waktu | Kejadian | Bukti | ATT&CK |
|---|---|---|---|
| 05:11:58 | 4 percobaan login SSH gagal ke pc-staf-07 dari 10.10.5.90 (kali-ops) — pola brute force | W1, W2, W4, W5 | T1110 |
| 05:12:10 | Login SSH BERHASIL ke pc-staf-07 sebagai 'sertu' dari 10.10.5.90 (akses awal dari luar jaringan) | W6 | T1078, T1021.004 |
| 05:12:11 | Login SSH BERHASIL ke pc-staf-07 sebagai 'sertu' dari 10.10.5.90 (akses awal dari luar jaringan) | W10 | T1078, T1021.004 |
| 05:12:11 | Login SSH BERHASIL ke srv-file-01 sebagai 'sertu' dari 10.10.5.66 (gerak lateral dari pc-staf-07) | W15 | T1078, T1021.004 |
| 05:12:11 | Eksekusi berkas dari /tmp di pc-staf-07 (pengguna '?') — payload penyerang | W12 | T1059.004 |
| 05:12:11 | Pembacaan /etc/shadow di pc-staf-07 — pencurian hash kredensial | W13, W14 | T1003.008 |
| 05:12:13 | Perintah tulis Modbus dari 10.10.5.7 (srv-file-01) ke PLC plc-genset-01 — mematikan genset (DAMPAK OT) | S2 | T0855, T0816 |

## Teknik MITRE ATT&CK
**Enterprise:** T1110 (Brute Force), T1078 (Valid Accounts), T1021.004 (Remote Services: SSH), T1059.004 (Command and Scripting Interpreter: Unix Shell), T1003.008 (OS Credential Dumping: /etc/passwd and /etc/shadow)
**ICS:** T0855 (Unauthorized Command Message), T0816 (Device Restart/Shutdown)

## Rekomendasi
- Isolasi host terdampak (pc-staf-07, srv-file-01) dari jaringan.
- Reset kata sandi akun sertu dan cabut sesi SSH yang aktif.
- Periksa PLC dan kembalikan peralatan ke status aman secara manual.
- Batasi akses Modbus ke PLC hanya dari HMI/SCADA yang sah.
- Blokir 10.10.5.90 di perimeter.
- Anggap seluruh hash kata sandi di host terdampak bocor; ganti kata sandi akun lokal.

## Bukti
| ID | Sumber | Sinyal | Host/Alur | Waktu |
|---|---|---|---|---|
| W1 | wazuh (5710) | Login SSH gagal (indikasi brute force) | 10.10.5.90 → pc-staf-07 | 05:11:58 |
| W2 | wazuh (5710) | Login SSH gagal (indikasi brute force) | 10.10.5.90 → pc-staf-07 | 05:12:00 |
| W4 | wazuh (5710) | Login SSH gagal (indikasi brute force) | 10.10.5.90 → pc-staf-07 | 05:12:07 |
| W5 | wazuh (5710) | Login SSH gagal (indikasi brute force) | 10.10.5.90 → pc-staf-07 | 05:12:09 |
| W6 | wazuh (40112) | Login SSH BERHASIL setelah rentetan kegagalan | 10.10.5.90 → pc-staf-07 | 05:12:10 |
| W10 | wazuh (40112) | Login SSH BERHASIL setelah rentetan kegagalan | 10.10.5.90 → pc-staf-07 | 05:12:11 |
| W15 | wazuh (5715) | Login SSH BERHASIL | 10.10.5.66 → srv-file-01 | 05:12:11 |
| W12 | wazuh (100010) | Eksekusi berkas dari /tmp | pc-staf-07 | 05:12:11 |
| W13 | wazuh (100011) | Pembacaan /etc/shadow | pc-staf-07 | 05:12:11 |
| W14 | wazuh (100011) | Pembacaan /etc/shadow | pc-staf-07 | 05:12:11 |
| S2 | suricata (7000005) | Perintah tulis Modbus (fc5) ke PLC | 10.10.5.7 → 10.10.5.20 | 05:12:13 |

## Catatan analisis
- 5 pembacaan /etc/shadow diabaikan sebagai derau (login PAM atau pemindaian agen Wazuh), karena tidak terjadi sesaat setelah eksekusi /tmp.

---
*Dihasilkan lokal (air-gapped) oleh Tameng · narasi: ringkasan cadangan (LLM tidak dipakai).*
