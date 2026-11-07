"""Notifikasi aktif: beri tahu operator saat insiden BARU muncul atau MEMBURUK.

Mode pantau (`python3 -m tameng --watch`) membaca bukti berkala, merangkai
insiden, lalu memanggil Notifier. Notifier hanya bersuara bila ada perubahan
yang berarti, supaya operator tidak kebanjiran pesan:

  BARU     : insiden yang belum pernah dilaporkan
  MEMBURUK : tingkat bahaya naik, atau muncul dampak OT / deface
  DITANGANI: serangan diblokir otomatis (Modbus atau IP penyerang)

Saluran (semua lokal, tanpa layanan luar):
  - terminal (dengan bunyi bel)
  - berkas JSONL (dibaca dashboard)             TAMENG_NOTIF_LOG
  - notifikasi desktop macOS                    TAMENG_NOTIF_DESKTOP=1
  - webhook ke server chat internal satuan      TAMENG_WEBHOOK (mis. Mattermost/Rocket.Chat di LAN)
"""
import datetime as dt
import json
import os
import shutil
import subprocess
import sys
import urllib.request

SEV_RANK = {"rendah": 0, "sedang": 1, "tinggi": 2, "kritis": 3}


def _flags(inc):
    return {"ot": inc.has_ot_impact, "ot_blokir": inc.ot_blocked,
            "it_blokir": getattr(inc, "it_blocked", False), "deface": getattr(inc, "defaced", False)}


def classify(inc, prev):
    """Jenis notifikasi untuk insiden ini dibanding status sebelumnya, atau None."""
    cur = {"severity": inc.severity, **_flags(inc)}
    if prev is None:
        return "BARU"
    if SEV_RANK[cur["severity"]] > SEV_RANK.get(prev.get("severity"), 0):
        return "MEMBURUK"
    if (cur["ot"] and not prev.get("ot")) or (cur["deface"] and not prev.get("deface")):
        return "MEMBURUK"
    if (cur["ot_blokir"] and not prev.get("ot_blokir")) or (cur["it_blokir"] and not prev.get("it_blokir")):
        return "DITANGANI"
    return None


def message(inc, summary, jenis):
    """Satu baris yang bisa langsung dipahami operator jaga."""
    langkah = (summary.get("rekomendasi") or ["Periksa laporan insiden."])[0]
    return {
        "time": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "jenis": jenis,
        "insiden": inc.id,
        "severity": inc.severity,
        "judul": summary.get("judul", inc.id),
        "host": inc.hosts,
        "langkah_pertama": langkah,
        "teks": f"[{jenis}] [{inc.severity.upper()}] {summary.get('judul', inc.id)} · "
                f"host: {', '.join(inc.hosts)} · langkah pertama: {langkah}",
    }


class Notifier:
    def __init__(self, state_path=None, log_path=None, desktop=None, webhook=None, out=sys.stdout):
        self.state_path = state_path
        self.log_path = log_path if log_path is not None else os.environ.get("TAMENG_NOTIF_LOG")
        self.desktop = desktop if desktop is not None else os.environ.get("TAMENG_NOTIF_DESKTOP") == "1"
        self.webhook = webhook if webhook is not None else os.environ.get("TAMENG_WEBHOOK")
        self.out = out
        self.state = {}
        if state_path and os.path.exists(state_path):
            with open(state_path, encoding="utf-8") as f:
                self.state = json.load(f)

    def process(self, incidents, summarize):
        """Kirim notifikasi untuk insiden baru/berubah. Kembalikan daftar pesan terkirim."""
        sent = []
        for inc in incidents:
            jenis = classify(inc, self.state.get(inc.id))
            self.state[inc.id] = {"severity": inc.severity, **_flags(inc)}
            if jenis:
                msg = message(inc, summarize(inc), jenis)
                self._send(msg)
                sent.append(msg)
        if self.state_path:
            with open(self.state_path, "w", encoding="utf-8") as f:
                json.dump(self.state, f)
        return sent

    def _send(self, msg):
        bell = "\a" if msg["severity"] in ("kritis", "tinggi") and msg["jenis"] != "DITANGANI" else ""
        print(f"{bell}{msg['time']} {msg['teks']}", file=self.out, flush=True)
        if self.log_path:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(msg, ensure_ascii=False) + "\n")
        if self.desktop and sys.platform == "darwin" and shutil.which("osascript"):
            title = f"Tameng · {msg['jenis']} · {msg['severity'].upper()}"
            script = f"display notification {json.dumps(msg['judul'])} with title {json.dumps(title)}"
            subprocess.run(["osascript", "-e", script], check=False, capture_output=True)
        if self.webhook:
            body = json.dumps({"text": msg["teks"], "tameng": msg}).encode()
            req = urllib.request.Request(self.webhook, data=body, headers={"Content-Type": "application/json"})
            try:
                urllib.request.urlopen(req, timeout=5).close()
            except Exception as e:      # notifikasi gagal tidak boleh menghentikan pemantauan
                print(f"  (webhook gagal: {e})", file=self.out)
