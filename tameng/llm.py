"""Ringkasan naratif oleh LLM lokal (Ollama/Qwen), air-gapped.

Prinsip: kronologi, teknik ATT&CK, dan tingkat bahaya sudah ditetapkan oleh
kode. LLM HANYA menulis judul, ringkasan, dan rekomendasi. Keluarannya
divalidasi: IP, penanda bukti, waktu, teknik ATT&CK, dan nama host yang muncul
wajib ada di masukan (anti halusinasi). Bila LLM gagal atau menyimpang,
narasinya DITOLAK dan dipakai ringkasan cadangan deterministik.
"""
import json
import re
import time
import urllib.request

from . import config

IP_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
EID_RE = re.compile(r"\b[WS]\d+\b")
TIME_RE = re.compile(r"\b\d{1,2}[:.]\d{2}(?:[:.]\d{2})?\b")
TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
# Nama host bergaya inventaris (mengandung tanda hubung dan angka, mis. srv-file-01).
HOST_RE = re.compile(r"\b[a-z][a-z0-9]*(?:-[a-z0-9]+)*-[a-z]*\d[a-z0-9]*\b", re.IGNORECASE)

SYSTEM = (
    "Kamu analis SOC satuan TNI AD. Insiden SUDAH dianalisis mesin: kronologi, "
    "teknik MITRE ATT&CK, dan tingkat bahaya sudah pasti dan tidak boleh kamu ubah. "
    "Tugasmu HANYA menulis narasi ringkas berbahasa Indonesia untuk laporan. "
    "Dilarang menambah atau mengarang fakta, IP, nama host, waktu, atau angka baru; "
    "gunakan hanya yang diberikan. Jawab HANYA JSON dengan kunci: "
    "judul (maks 12 kata), ringkasan (2-4 kalimat), rekomendasi (daftar 3-5 langkah "
    "konkret yang bisa dikerjakan bintara siber)."
)


def _facts(inc):
    lines = []
    lines.append(f"ID insiden: {inc.id}")
    lines.append(f"Tingkat bahaya (sudah ditetapkan): {inc.severity}")
    lines.append(f"Dampak OT: {'ya, genset dimatikan' if inc.has_ot_impact else 'tidak'}")
    lines.append(f"IP masuk penyerang: {inc.entry_ip}")
    lines.append(f"Host terdampak: {', '.join(inc.hosts)}")
    if inc.identities:
        lines.append(f"Akun disalahgunakan: {', '.join(inc.identities)}")
    lines.append("Teknik ATT&CK: " + ", ".join(f"{t[0]} {t[1]}" for t in inc.techniques))
    lines.append("Kronologi (waktu - kejadian - bukti):")
    for s in inc.steps:
        lines.append(f"  {s.time} - {s.text} - bukti {','.join(s.evidence)}")
    return "\n".join(lines)


def _call_ollama(system, user, num_predict=320):
    body = json.dumps({
        "model": config.OLLAMA_MODEL,
        "stream": False,
        "format": "json",
        "options": {"temperature": 0.1, "num_predict": num_predict},
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": user}],
    }).encode()
    req = urllib.request.Request(config.OLLAMA_URL, data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=180) as resp:
        return json.load(resp)


def _validate(text, facts):
    """Kembalikan daftar peringatan bila output menyebut fakta di luar masukan."""
    warn = []
    checks = (
        (IP_RE, "IP di luar bukti"),
        (EID_RE, "penanda bukti tak dikenal"),
        (TECH_RE, "teknik ATT&CK di luar analisis"),
        (HOST_RE, "nama host di luar bukti"),
    )
    for rx, msg in checks:
        allowed = set(rx.findall(facts))
        for tok in sorted(set(rx.findall(text))):
            if tok not in allowed:
                warn.append(f"{msg}: {tok}")
    # Waktu dicek setelah IP dibuang, agar "10.10" dari 10.10.5.90 tidak terbaca jam.
    allowed_times = {t.replace(".", ":") for t in TIME_RE.findall(IP_RE.sub(" ", facts))}
    allowed_times |= {t[:5] for t in allowed_times}          # HH:MM dari HH:MM:SS
    for tok in sorted(set(TIME_RE.findall(IP_RE.sub(" ", text)))):
        if tok.replace(".", ":") not in allowed_times:
            warn.append(f"waktu di luar bukti: {tok}")
    # Nama aset inventaris (mis. kali-ops) yang disebut tapi tidak terlibat.
    for name, _role, _crit, _internal in config.ASSETS.values():
        if name in text and name not in facts:
            warn.append(f"nama host di luar bukti: {name}")
    return sorted(set(warn))


def _fallback(inc):
    tnames = ", ".join(t[1] for t in inc.techniques[:4])
    hosts = ", ".join(inc.hosts) or "host tak dikenal"
    if inc.has_ot_impact:
        judul = f"Serangan {inc.severity} IT ke OT: perintah tak sah ke PLC"
        dampak = "mengirim perintah tulis tak sah ke PLC (dampak OT)"
    else:
        judul = f"Insiden {inc.severity}: akses tidak sah ke {hosts}"
        dampak = "melakukan aktivitas tidak sah"
    sumber = f"dari {inc.entry_ip} " if inc.entry_ip else ""
    rek = []
    it_hosts = [h for h in inc.hosts if not h.startswith("plc-")]
    if it_hosts:
        rek.append(f"Isolasi host terdampak ({', '.join(it_hosts)}) dari jaringan.")
    if inc.identities:
        rek.append(f"Reset kata sandi akun {', '.join(inc.identities)} dan cabut sesi SSH yang aktif.")
    if inc.has_ot_impact:
        rek.append("Periksa PLC dan kembalikan peralatan ke status aman secara manual.")
        rek.append("Batasi akses Modbus ke PLC hanya dari HMI/SCADA yang sah.")
    if inc.entry_ip and not config.asset(inc.entry_ip)[3]:
        rek.append(f"Blokir {inc.entry_ip} di perimeter.")
    if any(t[0] == "T1003.008" for t in inc.techniques):
        rek.append("Anggap seluruh hash kata sandi di host terdampak bocor; ganti kata sandi akun lokal.")
    if not rek:
        rek.append("Verifikasi kejadian bersama pemilik host dan pantau aktivitas lanjutan.")
    return {
        "judul": judul,
        "ringkasan": (
            f"Penyerang {sumber}menyasar {hosts} lalu {dampak}. "
            + (f"Teknik yang terlihat: {tnames}." if tnames else "")
        ).strip(),
        "rekomendasi": rek,
    }


def summarize(inc):
    facts = _facts(inc)
    meta = {"model": config.OLLAMA_MODEL, "elapsed_s": None, "tokens": None,
            "warnings": [], "fallback": False, "rejected": False}
    t0 = time.time()
    try:
        out = _call_ollama(SYSTEM, facts)
        meta["elapsed_s"] = round(time.time() - t0, 1)
        meta["tokens"] = out.get("eval_count")
        data = json.loads(out["message"]["content"])
        judul = str(data.get("judul", "")).strip()
        ringkasan = str(data.get("ringkasan", "")).strip()
        rek = data.get("rekomendasi", [])
        if isinstance(rek, str):
            rek = [rek]
        rek = [str(x).strip() for x in rek if str(x).strip()]
        if not (judul and ringkasan and rek):
            raise ValueError("field kosong")
    except Exception as e:
        meta["fallback"] = True
        meta["warnings"] = [f"LLM gagal ({e}); pakai ringkasan cadangan"]
        if meta["elapsed_s"] is None:
            meta["elapsed_s"] = round(time.time() - t0, 1)
        res = _fallback(inc)
        res["_meta"] = meta
        return res

    warnings = _validate(judul + " " + ringkasan + " " + " ".join(rek), facts)
    if warnings:
        # Narasi yang menyebut fakta di luar bukti tidak boleh masuk laporan.
        meta["fallback"] = True
        meta["rejected"] = True
        meta["warnings"] = ["Narasi LLM ditolak validasi: " + "; ".join(warnings)]
        res = _fallback(inc)
        res["_meta"] = meta
        return res
    return {"judul": judul, "ringkasan": ringkasan, "rekomendasi": rek, "_meta": meta}
