#!/usr/bin/env python3
"""Linimasa bukti gabungan: Wazuh (IT) + Suricata (OT).

Membaca alerts.json dan eve.json langsung dari SSD, menggabungkan berdasarkan
waktu, lalu menampilkan kronologi insiden. Ini pola yang akan dipakai mesin
korelasi deterministik Tameng sebelum LLM menulis ringkasannya.

Pakai:  python3 scripts/timeline.py [menit_terakhir]   (default 15)
"""
import datetime as dt
import json
import os
import sys

DATA = os.environ.get("TAMENG_DATA", "/Volumes/Prika-Tameng/lab-data")
WAZUH = os.environ.get("TAMENG_WAZUH_ALERTS", os.path.join(DATA, "wazuh/alerts/alerts.json"))
EVE = os.environ.get("TAMENG_SURICATA_EVE", os.path.join(DATA, "suricata/eve/eve.json"))

# Rule Wazuh yang relevan untuk narasi serangan (abaikan derau SCA/CIS).
WAZUH_RULES = {
    "5710": "Login SSH gagal (brute force)",
    "5712": "Brute force SSH (banyak gagal)",
    "5715": "Login SSH BERHASIL",
    "5501": "Sesi login dibuka (PAM)",
    "100010": "Eksekusi berkas dari /tmp",
    "100011": "Pembacaan /etc/shadow",
}

minutes = int(sys.argv[1]) if len(sys.argv) > 1 else 15
cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=minutes)


def parse_ts(s):
    # Wazuh: 2026-10-28T09:26:12.345+0000 ; Suricata: 2026-10-28T09:26:12.345678+0000
    try:
        return dt.datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=dt.timezone.utc)
    except Exception:
        return None


events = []

try:
    for line in open(WAZUH, encoding="utf-8", errors="replace"):
        line = line.strip()
        if not line:
            continue
        try:
            a = json.loads(line)
        except Exception:
            continue
        rid = a.get("rule", {}).get("id")
        if rid not in WAZUH_RULES:
            continue
        ts = parse_ts(a.get("timestamp", ""))
        if not ts or ts < cutoff:
            continue
        d = a.get("data", {})
        who = d.get("srcip") or d.get("srcuser") or d.get("dstuser") or ""
        agent = a.get("agent", {}).get("name", "?")
        events.append((ts, "WAZUH", a["rule"]["level"], WAZUH_RULES[rid],
                       f"host={agent} src={who}"))
except FileNotFoundError:
    print("alerts.json tidak ditemukan:", WAZUH)

try:
    for line in open(EVE, encoding="utf-8", errors="replace"):
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except Exception:
            continue
        if e.get("event_type") != "alert":
            continue
        ts = parse_ts(e.get("timestamp", ""))
        if not ts or ts < cutoff:
            continue
        al = e.get("alert", {})
        events.append((ts, "SURICATA", al.get("severity", 3), al.get("signature", ""),
                       f"{e.get('src_ip')} -> {e.get('dest_ip')}"))
except FileNotFoundError:
    print("eve.json tidak ditemukan:", EVE)

events.sort(key=lambda x: x[0])

print(f"\n=== Linimasa insiden ({minutes} menit terakhir) — {len(events)} kejadian ===\n")
print(f"{'Waktu':8}  {'Sumber':8}  {'Lvl':3}  {'Sinyal':42}  Detail")
print("-" * 100)
for ts, src, lvl, sig, detail in events:
    print(f"{ts.strftime('%H:%M:%S'):8}  {src:8}  {str(lvl):3}  {sig[:42]:42}  {detail}")
