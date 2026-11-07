#!/usr/bin/env python3
"""Siapkan data dashboard Tameng (dashboard/data.js).

Dashboard dibuka tanpa server dan tanpa internet, jadi data ditanam sebagai
skrip, bukan diambil dengan fetch. Isi data.js:
  incidents      : JSON insiden keluaran `python3 -m tameng --json`
  notifications  : linimasa notifikasi (BARU / MEMBURUK / DITANGANI)
  vulnerabilities: ringkasan kerentanan (tameng.vuln)
  status         : status sensor dan mesin
  assets         : inventaris aset lab

Pakai (dari root repo):
  python3 lab/scripts/replay-deface.py --out lab/out
  python3 lab/scripts/replay-deface.py --blokir --out lab/out
  python3 dashboard/build.py
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from tameng import config, mitre, vuln  # noqa: E402

SKENARIO = [
    ("artifacts/insiden-tameng-20261107-ids.json", "Babak 1 · IT→OT tanpa perlindungan"),
    ("artifacts/insiden-tameng-20261107-ips.json", "Babak 2 · IT→OT dengan mode blokir"),
    ("lab/out/insiden-deface.json", "Babak 3 · Deface situs (replay)"),
    ("lab/out/insiden-deface-blokir.json", "Babak 4 · Deface dihentikan blokir otomatis (replay)"),
]
KERENTANAN = "lab/sample/kerentanan-alerts.json"


def lengkapi(inc, label):
    """Isi kunci yang belum ada di JSON lama."""
    inc.setdefault("defaced", False)
    inc.setdefault("it_blocked", False)
    if not inc.get("edukasi"):
        inc["edukasi"] = [dict(id=t["id"], name=t["name"], **mitre.edukasi(t["id"]))
                          for t in inc["techniques"] if mitre.edukasi(t["id"])]
    inc["skenario"] = label
    return inc


def notifikasi(inc):
    """Linimasa notifikasi yang akan dikirim mode pantau untuk insiden ini."""
    out = []
    first = inc["summary"]["rekomendasi"][0] if inc["summary"]["rekomendasi"] else ""
    day = inc["start"][:10]

    def add(time, jenis, teks):
        out.append({"time": f"{day}T{time}", "jenis": jenis, "insiden": inc["id"],
                    "severity": inc["severity"], "teks": teks, "langkah_pertama": first})

    add(inc["start"][11:19], "BARU", f"Insiden baru di {', '.join(inc['hosts'])} dari {inc['entry_ip']}")
    for s in inc["steps"]:
        if "DAMPAK OT" in s["text"]:
            add(s["time"], "MEMBURUK", "Perintah tak sah sampai ke PLC: genset dimatikan")
        elif "DEFACE" in s["text"]:
            add(s["time"], "MEMBURUK", "Halaman situs publik diubah (deface)")
        elif "DIBLOKIR" in s["text"]:
            what = "IP penyerang diblokir otomatis" if "active response" in s["text"] else "Perintah Modbus ke PLC diblokir"
            add(s["time"], "DITANGANI", what)
    return out


def main():
    incidents = []
    for path, label in SKENARIO:
        full = os.path.join(ROOT, path)
        if not os.path.exists(full):
            print(f"lewati (tidak ada): {path}")
            continue
        for inc in json.load(open(full, encoding="utf-8")):
            incidents.append(lengkapi(inc, label))
    notifs = sorted((n for i in incidents for n in notifikasi(i)), key=lambda n: n["time"], reverse=True)
    hosts = sorted({h for i in incidents for h in i["hosts"]})
    vul = vuln.summarize(os.path.join(ROOT, KERENTANAN), hosts)
    status = [
        {"nama": "Wazuh manager", "peran": "Sensor IT: log, FIM, active response", "status": "aktif"},
        {"nama": "Suricata", "peran": "Sensor OT: Modbus, mode blokir (IPS)", "status": "aktif"},
        {"nama": "Mesin korelasi", "peran": "Merangkai alert jadi insiden", "status": "aktif"},
        {"nama": f"LLM lokal {config.OLLAMA_MODEL}", "peran": "Narasi tervalidasi, tanpa internet", "status": "aktif"},
        {"nama": "Notifikasi", "peran": "Terminal, desktop, chat internal", "status": "aktif"},
        {"nama": "Internet", "peran": "Tidak dibutuhkan (air-gapped)", "status": "terputus"},
    ]
    assets = {ip: dict(name=a[0], role=a[1], crit=a[2], internal=a[3]) for ip, a in config.ASSETS.items()}
    data = dict(incidents=incidents, notifications=notifs, vulnerabilities=vul, status=status,
                assets=assets, model=config.OLLAMA_MODEL)
    out = os.path.join(ROOT, "dashboard", "data.js")
    with open(out, "w", encoding="utf-8") as f:
        f.write("// Dibuat oleh dashboard/build.py. Jangan disunting tangan.\n")
        f.write("window.TAMENG_DATA = " + json.dumps(data, ensure_ascii=False, indent=1) + ";\n")
    print(f"{len(incidents)} insiden, {len(notifs)} notifikasi, {vul['total_cve']} CVE -> dashboard/data.js")


if __name__ == "__main__":
    main()
