#!/usr/bin/env bash
# Demo dua babak untuk juri:
#   Babak 1 (IDS, hanya mencatat) : serangan IT -> OT berhasil, genset MATI.
#   Babak 2 (IPS, mode blokir)    : serangan yang sama, perintah Modbus dijatuhkan,
#                                   genset tetap NYALA.
# Setelah tiap babak, laporan Tameng ditulis ke out/.
set -u
cd "$(dirname "$0")/.."
export PATH="$HOME/.docker/bin:$PATH"
ROOT="$(cd .. && pwd)"
mkdir -p out
P='\033[1;35m'; N='\033[0m'
banner(){ echo -e "\n${P}############ $* ############${N}"; }

babak(){
  local mode=$1 label=$2
  banner "$label (Suricata mode $mode)"
  local mulai; mulai=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  TAMENG_MODE=$mode docker compose up -d --force-recreate suricata >/dev/null 2>&1
  sleep 4
  docker logs suricata 2>&1 | grep "\[tameng\]" | tail -1
  bash scripts/attack.sh
  echo "  menunggu Wazuh mengirim log..."
  sleep 25
  (cd "$ROOT" && python3 -m tameng --since "$mulai" --out "lab/out/laporan-$mode.md" --json "lab/out/insiden-$mode.json" --no-llm | head -3)
}

babak ids "BABAK 1: TANPA PERLINDUNGAN"
babak ips "BABAK 2: DENGAN MODE BLOKIR TAMENG"
banner "Selesai. Laporan: lab/out/laporan-ids.md dan lab/out/laporan-ips.md"
