#!/usr/bin/env python3
"""Replay bukti sintetis skenario deface situs untuk demo Tameng.

Tidak ada serangan yang dijalankan. Skrip ini hanya menulis log DETEKSI
(seperti yang dihasilkan Wazuh: log akses portal dan File Integrity Monitoring
web root) ke direktori sementara, lalu menjalankan Tameng atasnya.

Alur yang direpresentasikan bukti:
  1. Unggahan berkas lewat celah plugin web       (T1190)
  2. Berkas .php baru di web root (FIM 554)        (T1505.003)
  3. Perintah sistem lewat berkas itu              (T1505.003, T1059.004)
  4. index.html berubah (FIM 550) = deface         (T1491.002)

Pakai (dari root repo):
  python3 lab/scripts/replay-deface.py                  # laporan ke layar
  python3 lab/scripts/replay-deface.py --out lab/out    # + laporan-deface.md & insiden-deface.json
  python3 lab/scripts/replay-deface.py --blokir         # varian dengan blokir otomatis (active response)

Varian --blokir: setelah perintah webshell pertama, Wazuh active response
(firewall-drop) memblokir IP penyerang di web-portal, sehingga perintah kedua dan
perubahan halaman tidak pernah terjadi.
"""
import argparse
import datetime as dt
import json
import os
import subprocess
import sys
import tempfile

ATK = "10.10.5.90"
SHELL = "/var/www/html/wp-content/uploads/wp-cache.php"


def bukti(t0, blokir=False):
    def ts(s):
        return (t0 + dt.timedelta(seconds=s)).strftime("%Y-%m-%dT%H:%M:%S")

    def akses(s, rid, url, method="GET", desc=""):
        return {"timestamp": ts(s) + ".000+0000", "rule": {"id": rid, "level": 12, "description": desc},
                "agent": {"name": "web-portal"}, "id": f"r{s}",
                "data": {"srcip": ATK, "url": url, "method": method, "time": ts(s)}}

    def fim(s, rid, path, diff, desc):
        return {"timestamp": ts(s) + ".000+0000", "rule": {"id": rid, "level": 7, "description": desc},
                "agent": {"name": "web-portal"}, "id": f"f{s}",
                "syscheck": {"path": path, "diff": diff}}

    if blokir:
        ar = {"timestamp": ts(5) + ".000+0000",
              "rule": {"id": "651", "level": 3, "description": "Host Blocked by firewall-drop Active Response"},
              "agent": {"name": "web-portal"}, "id": "ar5",
              "data": {"command": "add", "time": ts(5),
                       "parameters": {"program": "active-response/bin/firewall-drop",
                                      "alert": {"rule": {"id": "100021"}, "data": {"srcip": ATK}}}}}
        return [
            akses(0, "100020", "/wp-admin/admin-ajax.php?action=fm_upload", "POST",
                  "Unggahan berkas ke endpoint plugin"),
            fim(1, "554", SHELL, "", "File added to the system."),
            akses(4, "100021", "/wp-content/uploads/wp-cache.php?cmd=id", desc="Perintah lewat webshell"),
            ar,
        ]
    return [
        akses(0, "100020", "/wp-admin/admin-ajax.php?action=fm_upload", "POST",
              "Unggahan berkas ke endpoint plugin"),
        fim(1, "554", SHELL, "", "File added to the system."),
        akses(4, "100021", "/wp-content/uploads/wp-cache.php?cmd=id", desc="Perintah lewat webshell"),
        akses(9, "100021", "/wp-content/uploads/wp-cache.php?cmd=cp /tmp/h.html /var/www/html/index.html",
              desc="Perintah lewat webshell"),
        fim(10, "550", "/var/www/html/index.html", "> <h1>HACKED</h1>", "Integrity checksum changed."),
    ]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", help="direktori keluaran laporan (opsional)")
    ap.add_argument("--blokir", action="store_true", help="varian dengan blokir otomatis (active response)")
    ap.add_argument("--llm", action="store_true", help="pakai LLM lokal (Ollama) untuk narasi")
    args = ap.parse_args()

    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    t0 = dt.datetime.now(dt.timezone.utc).replace(microsecond=0) - dt.timedelta(minutes=2)
    with tempfile.TemporaryDirectory() as d:
        alerts = os.path.join(d, "alerts.json")
        eve = os.path.join(d, "eve.json")
        with open(alerts, "w") as f:
            f.write("\n".join(json.dumps(r) for r in bukti(t0, args.blokir)) + "\n")
        open(eve, "w").close()
        env = dict(os.environ, TAMENG_WAZUH_ALERTS=alerts, TAMENG_SURICATA_EVE=eve)
        cmd = [sys.executable, "-m", "tameng", "--minutes", "10"]
        if not args.llm:
            cmd.append("--no-llm")
        if args.out:
            os.makedirs(args.out, exist_ok=True)
            nama = "deface-blokir" if args.blokir else "deface"
            cmd += ["--out", os.path.join(args.out, f"laporan-{nama}.md"),
                    "--json", os.path.join(args.out, f"insiden-{nama}.json")]
        return subprocess.call(cmd, cwd=root, env=env)


if __name__ == "__main__":
    sys.exit(main())
