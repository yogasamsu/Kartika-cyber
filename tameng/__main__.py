"""CLI Tameng: baca bukti dari SSD -> korelasi -> ringkasan LLM -> laporan.

Contoh:
  python3 -m tameng --minutes 10
  python3 -m tameng --minutes 10 --out laporan.md
  python3 -m tameng --no-llm           # hanya korelasi deterministik
"""
import argparse
import datetime as dt
import os

from . import correlate, events, report
from .llm import summarize, _fallback


def main():
    ap = argparse.ArgumentParser(prog="tameng", description="Analis insiden IT/OT lokal Tameng")
    ap.add_argument("--minutes", type=int, default=15, help="rentang bukti yang dibaca (menit terakhir)")
    ap.add_argument("--out", help="tulis laporan Markdown ke berkas (atau direktori)")
    ap.add_argument("--no-llm", action="store_true", help="lewati LLM, pakai ringkasan deterministik")
    args = ap.parse_args()

    evs = events.load_all(minutes=args.minutes)
    incidents = correlate.build_incidents(evs)

    if not incidents:
        print(f"Tidak ada insiden dalam {args.minutes} menit terakhir "
              f"({len(evs)} event relevan).")
        return

    print(f"{len(incidents)} insiden ditemukan dari {len(evs)} event relevan.\n")
    reports = []
    for inc in incidents:
        if args.no_llm:
            summary = _fallback(inc)
            summary["_meta"] = {"fallback": True, "model": None, "warnings": [], "elapsed_s": None}
        else:
            print(f"[{inc.id}] menulis ringkasan dengan LLM lokal...")
            summary = summarize(inc)
        md = report.render_markdown(inc, summary)
        reports.append((inc, md))

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
