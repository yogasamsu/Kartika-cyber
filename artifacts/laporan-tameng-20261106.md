# Penyerangan Sistem Kritis dengan Brute Force dan Lateral Movement

**Insiden** `INC-20261106-101926` · **Tingkat bahaya** 🔴 KRITIS · **Dampak OT** Ya
**Waktu** 2026-11-06 10:19:26 – 10:19:41 UTC · **IP masuk** 10.10.5.90 · **Host** pc-staf-07, srv-file-01, plc-genset-01
**Akun disalahgunakan** sertu

## Ringkasan
Penyerangan dengan tingkat bahaya kritis ini melibatkan serangan brute force dan lateral movement, mengakibatkan shutdown genset. Serangan dimulai dengan serangan brute force terhadap SSH di pc-staf-07, berhasil dengan akun 'sertu'. Penyerang kemudian melakukan lateral movement ke srv-file-01 dan mematikan genset melalui perintah Modbus.

## Kronologi
| Waktu | Kejadian | Bukti | ATT&CK |
|---|---|---|---|
| 10:19:26 | 4 percobaan login SSH gagal ke pc-staf-07 dari 10.10.5.90 (kali-ops) — pola brute force | W13, W14, W16, W17 | T1110 |
| 10:19:37 | Login SSH BERHASIL ke pc-staf-07 sebagai 'sertu' dari 10.10.5.90 (akses awal dari luar jaringan) | W18 | T1078, T1021.004 |
| 10:19:37 | Login SSH BERHASIL ke pc-staf-07 sebagai 'sertu' dari 10.10.5.90 (akses awal dari luar jaringan) | W19 | T1078, T1021.004 |
| 10:19:37 | Eksekusi berkas dari /tmp di pc-staf-07 (pengguna '?') — payload penyerang | W24 | T1059.004 |
| 10:19:37 | Pembacaan /etc/shadow di pc-staf-07 — pencurian hash kredensial | W22, W23, W25, W26 | T1003.008 |
| 10:19:38 | Login SSH BERHASIL ke srv-file-01 sebagai 'sertu' dari 10.10.5.66 (gerak lateral dari pc-staf-07) | W27 | T1078, T1021.004 |
| 10:19:41 | Perintah tulis Modbus dari 10.10.5.7 (srv-file-01) ke PLC plc-genset-01 — mematikan genset (DAMPAK OT) | S1 | T0855, T0816 |

## Teknik MITRE ATT&CK
**Enterprise:** T1110 (Brute Force), T1078 (Valid Accounts), T1021.004 (Remote Services: SSH), T1059.004 (Command and Scripting Interpreter: Unix Shell), T1003.008 (OS Credential Dumping: /etc/passwd and /etc/shadow)
**ICS:** T0855 (Unauthorized Command Message), T0816 (Device Restart/Shutdown)

## Rekomendasi
- Menerapkan firewall yang lebih ketat untuk membatasi akses SSH dari luar jaringan.
- Mengimplementasikan autentikasi dua faktor (2FA) pada akun yang sensitif.
- Meningkatkan monitoring dan logging pada sistem untuk mendeteksi aktivitas mencurigakan.
- Melakukan audit kredensial dan memastikan keamanan file /etc/shadow.
- Menerapkan isolasi antar sistem kritis untuk mencegah lateral movement.

## Bukti
| ID | Sumber | Sinyal | Host/Alur | Waktu |
|---|---|---|---|---|
| W13 | wazuh (5710) | Login SSH gagal (indikasi brute force) | 10.10.5.90 → pc-staf-07 | 10:19:26 |
| W14 | wazuh (5710) | Login SSH gagal (indikasi brute force) | 10.10.5.90 → pc-staf-07 | 10:19:27 |
| W16 | wazuh (5710) | Login SSH gagal (indikasi brute force) | 10.10.5.90 → pc-staf-07 | 10:19:33 |
| W17 | wazuh (5710) | Login SSH gagal (indikasi brute force) | 10.10.5.90 → pc-staf-07 | 10:19:36 |
| W18 | wazuh (5715) | Login SSH BERHASIL | 10.10.5.90 → pc-staf-07 | 10:19:37 |
| W19 | wazuh (5715) | Login SSH BERHASIL | 10.10.5.90 → pc-staf-07 | 10:19:37 |
| W24 | wazuh (100010) | Eksekusi berkas dari /tmp | pc-staf-07 | 10:19:37 |
| W22 | wazuh (100011) | Pembacaan /etc/shadow | pc-staf-07 | 10:19:37 |
| W23 | wazuh (100011) | Pembacaan /etc/shadow | pc-staf-07 | 10:19:37 |
| W25 | wazuh (100011) | Pembacaan /etc/shadow | pc-staf-07 | 10:19:37 |
| W26 | wazuh (100011) | Pembacaan /etc/shadow | pc-staf-07 | 10:19:37 |
| W27 | wazuh (5715) | Login SSH BERHASIL | 10.10.5.66 → srv-file-01 | 10:19:38 |
| S1 | suricata (7000005) | Perintah tulis Modbus (fc5) ke PLC | 10.10.5.7 → 10.10.5.20 | 10:19:41 |

## Catatan analisis
- 27 pembacaan /etc/shadow diabaikan sebagai derau login PAM (tidak didahului eksekusi /tmp di host yang sama).

---
*Dihasilkan lokal (air-gapped) oleh Tameng · narasi: LLM qwen2.5:7b · 80.3 dtk · 249 token.*
