"""Render laporan insiden (Markdown). Fakta dari kode; narasi dari LLM."""
from . import mitre

SEV_BADGE = {"kritis": "🔴 KRITIS", "tinggi": "🟠 TINGGI",
             "sedang": "🟡 SEDANG", "rendah": "🟢 RENDAH"}


def render_markdown(inc, summary):
    L = []
    L.append(f"# {summary['judul']}")
    L.append("")
    L.append(f"**Insiden** `{inc.id}` · **Tingkat bahaya** {SEV_BADGE.get(inc.severity, inc.severity)}"
             f" · **Dampak OT** {'Ya' if inc.has_ot_impact else 'Tidak'}")
    L.append(f"**Waktu** {inc.start.strftime('%Y-%m-%d %H:%M:%S')} – {inc.end.strftime('%H:%M:%S')} UTC"
             f" · **IP masuk** {inc.entry_ip} · **Host** {', '.join(inc.hosts)}")
    if inc.identities:
        L.append(f"**Akun disalahgunakan** {', '.join(inc.identities)}")
    L.append("")
    L.append("## Ringkasan")
    L.append(summary["ringkasan"])
    L.append("")

    L.append("## Kronologi")
    L.append("| Waktu | Kejadian | Bukti | ATT&CK |")
    L.append("|---|---|---|---|")
    for s in inc.steps:
        tech = ", ".join(s.tech)
        L.append(f"| {s.time} | {s.text} | {', '.join(s.evidence)} | {tech} |")
    L.append("")

    L.append("## Teknik MITRE ATT&CK")
    ent = [t for t in inc.techniques if t[2] == "enterprise"]
    ics = [t for t in inc.techniques if t[2] == "ics"]
    if ent:
        L.append("**Enterprise:** " + ", ".join(f"{t[0]} ({t[1]})" for t in ent))
    if ics:
        L.append("**ICS:** " + ", ".join(f"{t[0]} ({t[1]})" for t in ics))
    L.append("")

    L.append("## Rekomendasi")
    for r in summary["rekomendasi"]:
        L.append(f"- {r}")
    L.append("")

    L.append("## Bukti")
    L.append("| ID | Sumber | Sinyal | Host/Alur | Waktu |")
    L.append("|---|---|---|---|---|")
    for e in inc.events:
        flow = e.host or ""
        if e.src_ip and e.dst_ip:
            flow = f"{e.src_ip} → {e.dst_ip}"
        elif e.src_ip:
            flow = f"{e.src_ip} → {e.host}"
        L.append(f"| {e.eid} | {e.source} ({e.sid}) | {e.label} | {flow} | {e.ts.strftime('%H:%M:%S')} |")
    L.append("")

    meta = summary.get("_meta", {})
    notes = list(inc.notes) + list(meta.get("warnings", []))
    if notes:
        L.append("## Catatan analisis")
        for n in notes:
            L.append(f"- {n}")
        L.append("")

    mode = "ringkasan cadangan (LLM tidak dipakai)" if meta.get("fallback") else f"LLM {meta.get('model')}"
    L.append("---")
    L.append(f"*Dihasilkan lokal (air-gapped) oleh Tameng · narasi: {mode}"
             + (f" · {meta.get('elapsed_s')} dtk" if meta.get("elapsed_s") is not None else "")
             + (f" · {meta.get('tokens')} token" if meta.get("tokens") else "") + ".*")
    return "\n".join(L)
