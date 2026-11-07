#!/usr/bin/env bash
# Suricata Tameng, dua mode (TAMENG_MODE):
#   ids : memantau eth0 secara pasif dan mencatat setiap perintah tulis Modbus.
#   ips : semua paket Modbus ke/dari PLC lewat NFQUEUE; perintah tulis dari host
#         selain HMI resmi DIJATUHKAN sebelum sampai ke PLC.
# Suricata berbagi network namespace dengan PLC, jadi aturan iptables di sini
# berlaku untuk PLC. Aturan lama selalu dibersihkan dulu: sisa NFQUEUE tanpa
# Suricata yang mendengarkan akan memutus semua trafik Modbus.
set -euo pipefail
MODE="${TAMENG_MODE:-ids}"
COMMON=(-k none
  --set app-layer.protocols.modbus.enabled=yes
  --set app-layer.protocols.modbus.detection-ports.dp=502)

iptables -F INPUT
iptables -F OUTPUT

if [ "$MODE" = "ips" ]; then
  iptables -A INPUT  -p tcp --dport 502 -j NFQUEUE --queue-num 0
  iptables -A OUTPUT -p tcp --sport 502 -j NFQUEUE --queue-num 0
  echo "[tameng] Suricata mode IPS: perintah tulis Modbus dari host tak sah diblokir"
  exec suricata -q 0 -S /etc/suricata/rules/tameng-ips.rules "${COMMON[@]}"
fi

echo "[tameng] Suricata mode IDS: hanya mencatat"
exec suricata -i eth0 -S /etc/suricata/rules/tameng.rules "${COMMON[@]}"
