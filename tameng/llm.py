"""Ringkasan naratif oleh LLM lokal (Ollama/Qwen), air-gapped.

Prinsip: kronologi, teknik ATT&CK, dan tingkat bahaya sudah ditetapkan oleh
kode. LLM HANYA menulis judul, ringkasan, dan rekomendasi. Keluarannya
divalidasi: IP dan penanda bukti yang muncul wajib ada di masukan (anti
halusinasi). Bila LLM gagal/menyimpang, dipakai ringkasan cadangan deterministik.
"""
import json
import re
import time
import urllib.request

from . import config

IP_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
EID_RE = re.compile(r"\b[WS]\d+\b")

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


def _validate(text, allowed_ips, allowed_eids):
    """Kembalikan daftar peringatan bila output menyebut IP/bukti di luar masukan."""
    warn = []
    for ip in set(IP_RE.findall(text)):
        if ip not in allowed_ips:
            warn.append(f"IP di luar bukti: {ip}")
    for eid in set(EID_RE.findall(text)):
        if eid not in allowed_eids:
            warn.append(f"penanda bukti tak dikenal: {eid}")
    return warn


def _fallback(inc):
    tnames = ", ".join(t[1] for t in inc.techniques[:4])
    dampak = "mematikan genset (dampak OT)" if inc.has_ot_impact else "akses tidak sah"
    return {
        "judul": f"Serangan {inc.severity} IT ke OT: {dampak}",
        "ringkasan": (
            f"Penyerang dari {inc.entry_ip} menembus {', '.join(inc.hosts)} lalu {dampak}. "
            f"Teknik yang terlihat: {tnames}."
        ),
        "rekomendasi": [
            "Isolasi host terdampak dari jaringan OT.",
            "Reset kredensial akun yang disalahgunakan dan paksa kunci SSH.",
            "Periksa PLC genset dan kembalikan ke status aman.",
            "Blokir IP penyerang di perimeter.",
        ],
    }


def summarize(inc):
    allowed_ips = set(IP_RE.findall(_facts(inc)))
    allowed_eids = set(inc.evidence_ids())
    user = _facts(inc)
    meta = {"model": config.OLLAMA_MODEL, "elapsed_s": None, "tokens": None,
            "warnings": [], "fallback": False}
    t0 = time.time()
    try:
        out = _call_ollama(SYSTEM, user)
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
        meta["warnings"] = _validate(judul + " " + ringkasan + " " + " ".join(rek),
                                     allowed_ips, allowed_eids)
        return {"judul": judul, "ringkasan": ringkasan, "rekomendasi": rek, "_meta": meta}
    except Exception as e:
        meta["fallback"] = True
        meta["warnings"] = [f"LLM gagal/menyimpang ({e}); pakai ringkasan cadangan"]
        if meta["elapsed_s"] is None:
            meta["elapsed_s"] = round(time.time() - t0, 1)
        res = _fallback(inc)
        res["_meta"] = meta
        return res
