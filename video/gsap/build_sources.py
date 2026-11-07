"""Bangun halaman sumber footage dari data asli: log Wazuh dan laporan Tameng.

Pakai: python3 gsap/build_sources.py [alerts.json]
  - sources/log.html     : 70 baris alert Wazuh asli sekitar serangan 6 Nov 10:19 UTC
  - sources/laporan.html : artifacts/laporan-tameng-20261106.md sebagai halaman laporan
"""
import html, json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
# Wazuh merotasi alerts.json tiap hari; bukti uji 6 Nov ada di arsip harian.
ARSIP = "/Volumes/Prika-Tameng/lab-data/wazuh/alerts/2026/Nov/ossec-alerts-06.json"
ALERTS = sys.argv[1] if len(sys.argv) > 1 else (ARSIP if os.path.exists(ARSIP) else
                                                 "/Volumes/Prika-Tameng/lab-data/wazuh/alerts/alerts.json")

# ---------- log ----------
rows = []
for line in open(ALERTS, encoding="utf-8", errors="replace"):
    try:
        a = json.loads(line)
    except json.JSONDecodeError:
        continue
    if "2026-11-06T10:19:20" <= a["timestamp"] <= "2026-11-06T10:20:10":
        rows.append(a)
ATTACK = {"5710", "5715", "100010"}
# Semua baris serangan + baris rutin yang disebar merata, total 70 baris.
atk = [a for a in rows if a["rule"]["id"] in ATTACK]
rut = [a for a in rows if a["rule"]["id"] not in ATTACK]
step = max(1, len(rut) // (70 - len(atk)))
rows = sorted(atk + rut[::step][: 70 - len(atk)], key=lambda a: a["timestamp"])
out = []
for a in rows:
    r = a["rule"]
    cls = "atk" if r["id"] in ATTACK else ""
    out.append(
        f'<div class="r {cls}"><span class="t">{a["timestamp"][11:23]}</span>'
        f'<span class="id">{r["id"]:>6}</span><span class="lv">L{r["level"]:<2}</span>'
        f'<span class="ag">{html.escape(a.get("agent", {}).get("name", "?")):<13}</span>'
        f'<span class="d">{html.escape(r["description"][:96])}</span></div>')
open(os.path.join(HERE, "sources", "log.html"), "w").write(f"""<!doctype html><meta charset="utf-8">
<style>
body{{margin:0;background:#06090d;color:#7f93a3;font:15px/1.55 "SF Mono",Menlo,monospace;width:1600px;padding:22px 26px;box-sizing:border-box}}
.bar{{color:#3d5466;margin-bottom:10px}} .bar b{{color:#36c3e0;font-weight:500}}
.r{{display:flex;gap:16px;white-space:nowrap}} .t{{color:#4f6475}} .id{{color:#5f7a8d}} .lv{{color:#4f6475}} .ag{{color:#8aa0b2;width:120px}}
.r.atk .d{{color:#ff6b6d}} .r.atk .id{{color:#ff6b6d}}
</style>
<div class="bar">wazuh-manager:/var/ossec/logs/alerts$ <b>tail -f alerts.json</b> | jq -r '[.timestamp,.rule.id,.rule.level,.agent.name,.rule.description]'</div>
{''.join(out)}""")

# ---------- laporan ----------
def inline(s):
    s = html.escape(s)
    s = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", s)
    s = re.sub(r"`(.+?)`", r"<code>\1</code>", s)
    s = re.sub(r"\*(.+?)\*", r"<i>\1</i>", s)
    return s


def laporan(md_name, out_name):
    md = open(os.path.join(ROOT, "artifacts", md_name), encoding="utf-8").read()
    parts, table, ul = [], None, False
    for ln in md.splitlines() + [""]:
        if ln.startswith("|"):
            cells = [c.strip() for c in ln.strip("|").split("|")]
            if set("".join(cells)) <= set("-: "):
                continue
            if table is None:
                table = ["<table><tr>" + "".join(f"<th>{inline(c)}</th>" for c in cells) + "</tr>"]
            else:
                table.append("<tr>" + "".join(f"<td>{inline(c)}</td>" for c in cells) + "</tr>")
            continue
        if table is not None:
            parts.append("".join(table) + "</table>"); table = None
        if ln.startswith("- "):
            if not ul: parts.append("<ul>"); ul = True
            parts.append(f"<li>{inline(ln[2:])}</li>"); continue
        if ul: parts.append("</ul>"); ul = False
        if ln.startswith("# "): parts.append(f"<h1>{inline(ln[2:])}</h1>")
        elif ln.startswith("## "): parts.append(f"<h2>{inline(ln[3:])}</h2>")
        elif ln.strip() == "---": parts.append("<hr>")
        elif ln.strip(): parts.append(f"<p>{inline(ln)}</p>")
    open(os.path.join(HERE, "sources", out_name), "w").write("""<!doctype html><meta charset="utf-8">
    <style>
    body{margin:0;background:#fff;color:#1b2733;font:17px/1.6 -apple-system,"SF Pro Text",sans-serif;width:1600px;padding:48px 64px;box-sizing:border-box}
    h1{font-size:34px;margin:0 0 14px} h2{font-size:23px;margin:30px 0 10px;border-bottom:1px solid #e3e8ee;padding-bottom:6px}
    p{margin:6px 0} code{font:15px "SF Mono",Menlo,monospace;background:#eef2f6;padding:1px 6px;border-radius:4px}
    table{border-collapse:collapse;width:100%;font-size:15.5px;margin:8px 0} th,td{border:1px solid #dde4ea;padding:7px 10px;text-align:left;vertical-align:top}
    th{background:#f3f6f9} ul{margin:6px 0;padding-left:24px} hr{border:0;border-top:1px solid #e3e8ee;margin:24px 0} i{color:#6b7c8c}
    </style>""" + "\n".join(parts))



laporan("laporan-tameng-20261106.md", "laporan.html")                 # uji lab 6 Nov (mode IDS)
laporan("laporan-tameng-20261107-ips.md", "laporan-ips.html")         # babak 2: mode blokir
print("sources/log.html", len(rows), "baris; sources/laporan.html; sources/laporan-ips.html")
