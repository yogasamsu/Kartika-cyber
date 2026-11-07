"""CLI Tameng: baca bukti dari SSD -> korelasi -> ringkasan LLM -> laporan.

Contoh:
  python3 -m tameng --minutes 10
  python3 -m tameng --minutes 10 --out laporan.md
  python3 -m tameng --no-llm           # hanya korelasi deterministik
  python3 -m tameng --watch            # mode pantau: notifikasi saat insiden baru/memburuk
  python3 -m tameng --kerentanan lab/sample/kerentanan-alerts.json   # ringkasan kerentanan
"""
import argparse
import datetime as dt
import json
import os
import time

from . import correlate, events, notify, report, vuln
from .llm import summarize, _fallback


def incident_to_dict(inc, summary):
    """Serialisasi insiden + ringkasan untuk konsumsi UI/dashboard."""
    return {
        "id": inc.id,
        "severity": inc.severity,
        "has_ot_impact": inc.has_ot_impact,
        "ot_blocked": inc.ot_blocked,
        "defaced": inc.defaced,
        "it_blocked": inc.it_blocked,
        "start": inc.start.isoformat(),
        "end": inc.end.isoformat(),
        "entry_ip": inc.entry_ip,
        "hosts": inc.hosts,
        "identities": inc.identities,
        "techniques": [{"id": t[0], "name": t[1], "domain": t[2], "tactic": t[3]}
                       for t in inc.techniques],
        "steps": [{"time": s.time, "text": s.text, "evidence": s.evidence, "tech": s.tech}
                  for s in inc.steps],
        "events": [{"eid": e.eid, "source": e.source, "sid": e.sid, "label": e.label,
                    "src_ip": e.src_ip, "dst_ip": e.dst_ip, "host": e.host,
                    "time": e.ts.strftime("%H:%M:%S"), "domain": e.domain}
                   for e in inc.events],
        "notes": inc.notes,
        "edukasi": report.edukasi_list(inc),
        "summary": {k: v for k, v in summary.items() if k != "_meta"},
        "meta": summary.get("_meta", {}),
    }


def main():
    ap = argparse.ArgumentParser(prog="tameng", description="Analis insiden IT/OT lokal Tameng")
    ap.add_argument("--minutes", type=int, default=15, help="rentang bukti yang dibaca (menit terakhir)")
    ap.add_argument("--since", help="baca bukti sejak waktu ini (ISO UTC, mis. 2026-11-07T05:08:30Z); menimpa --minutes")
    ap.add_argument("--out", help="tulis laporan Markdown ke berkas (atau direktori)")
    ap.add_argument("--json", dest="json_out", help="tulis insiden sebagai JSON (untuk dashboard/UI)")
    ap.add_argument("--no-llm", action="store_true", help="lewati LLM, pakai ringkasan deterministik")
    ap.add_argument("--watch", action="store_true", help="mode pantau: cek bukti berkala dan kirim notifikasi")
    ap.add_argument("--interval", type=int, default=15, help="jeda antar-pengecekan mode pantau (detik)")
    ap.add_argument("--state", default=".tameng-notif.json", help="berkas status notifikasi mode pantau")
    ap.add_argument("--kerentanan", metavar="ALERTS", help="ringkas kerentanan dari alert Wazuh VD/SCA")
    args = ap.parse_args()

    if args.kerentanan:
        s = vuln.summarize(args.kerentanan)
        if args.json_out:
            with open(args.json_out, "w", encoding="utf-8") as f:
                json.dump(s, f, ensure_ascii=False, indent=2)
        md = vuln.render_markdown(s)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(md + "\n")
        print(md)
        return

    if args.watch:
        n = notify.Notifier(state_path=args.state)
        summ = _fallback if args.no_llm else summarize
        print(f"Tameng memantau bukti tiap {args.interval} dtk (jendela {args.minutes} menit). Ctrl+C untuk berhenti.")
        try:
            while True:
                evs = events.load_all(minutes=args.minutes)
                n.process(correlate.build_incidents(evs), summ)
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\nPemantauan dihentikan.")
        return

    since = events._parse_ts(args.since) if args.since else None
    if args.since and since is None:
        ap.error(f"format --since tidak dikenali: {args.since}")
    evs = events.load_all(minutes=args.minutes, since=since)
    incidents = correlate.build_incidents(evs)

    if not incidents:
        rentang = f"sejak {args.since}" if args.since else f"dalam {args.minutes} menit terakhir"
        print(f"Tidak ada insiden {rentang} "
              f"({len(evs)} event relevan).")
        return

    print(f"{len(incidents)} insiden ditemukan dari {len(evs)} event relevan.\n")
    reports = []
    dicts = []
    for inc in incidents:
        if args.no_llm:
            summary = _fallback(inc)
            summary["_meta"] = {"fallback": True, "model": None, "warnings": [], "elapsed_s": None}
        else:
            print(f"[{inc.id}] menulis ringkasan dengan LLM lokal...")
            summary = summarize(inc)
        md = report.render_markdown(inc, summary)
        reports.append((inc, md))
        dicts.append(incident_to_dict(inc, summary))

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(dicts, f, ensure_ascii=False, indent=2)
        print(f"JSON insiden ditulis ke: {args.json_out}")

    full = ("\n\n" + "=" * 80 + "\n\n").join(md for _, md in reports)

    if args.out:
        path = args.out
        if os.path.isdir(path):
            stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
            path = os.path.join(path, f"laporan-tameng-{stamp}.md")
        with open(path, "w", encoding="utf-8") as f:
            f.write(full + "\n")
        print(f"\nLaporan ditulis ke: {path}")
    else:
        print("\n" + full)


if __name__ == "__main__":
    main()
