#!/usr/bin/env python3
"""Siapkan data dashboard Tameng (dashboard/data.js) dari JSON insiden.

Dashboard dibuka langsung sebagai berkas (file://) tanpa server dan tanpa
internet, jadi data ditanam sebagai skrip, bukan diambil dengan fetch.

Pakai (dari root repo):
  python3 dashboard/build.py                       # tiga skenario demo bawaan
  python3 dashboard/build.py a.json b.json ...     # JSON keluaran `python3 -m tameng --json`
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from tameng import config, mitre  # noqa: E402

BAWAAN = [
    ("artifacts/insiden-tameng-20261107-ids.json", "Babak 1 · IT→OT tanpa perlindungan"),
    ("artifacts/insiden-tameng-20261107-ips.json", "Babak 2 · IT→OT dengan mode blokir"),
    ("lab/out/insiden-deface.json", "Babak 3 · Deface situs (replay)"),
]


def lengkapi(inc, label):
    """Isi kunci yang belum ada di JSON lama (edukasi, defaced)."""
    inc.setdefault("defaced", False)
    if not inc.get("edukasi"):
        inc["edukasi"] = [dict(id=t["id"], name=t["name"], **mitre.edukasi(t["id"]))
                          for t in inc["techniques"] if mitre.edukasi(t["id"])]
    inc["skenario"] = label
    return inc


def main():
    files = [(p, os.path.basename(p)) for p in sys.argv[1:]] or BAWAAN
    incidents = []
    for path, label in files:
        full = os.path.join(ROOT, path)
        if not os.path.exists(full):
            print(f"lewati (tidak ada): {path}")
            continue
        for inc in json.load(open(full, encoding="utf-8")):
            incidents.append(lengkapi(inc, label))
    assets = {ip: dict(name=a[0], role=a[1], crit=a[2], internal=a[3]) for ip, a in config.ASSETS.items()}
    data = dict(incidents=incidents, assets=assets, model=config.OLLAMA_MODEL)
    out = os.path.join(ROOT, "dashboard", "data.js")
    with open(out, "w", encoding="utf-8") as f:
        f.write("// Dibuat oleh dashboard/build.py. Jangan disunting tangan.\n")
        f.write("window.TAMENG_DATA = " + json.dumps(data, ensure_ascii=False, indent=1) + ";\n")
    print(f"{len(incidents)} insiden ditulis ke dashboard/data.js")


if __name__ == "__main__":
    main()
