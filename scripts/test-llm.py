"""Uji cepat: LLM lokal merangkum satu insiden dari alert contoh menjadi JSON."""
import json
import sys
import time
import urllib.request

MODEL = sys.argv[1] if len(sys.argv) > 1 else "qwen2.5:7b"
OLLAMA = "http://127.0.0.1:11434/api/chat"

ALERTS = [
    {"id": "8801", "time": "09:10:02", "host": "pc-staf-07", "rule": "sshd: authentication success", "src_ip": "10.10.5.66", "user": "admin"},
    {"id": "8812", "time": "09:12:40", "host": "pc-staf-07", "rule": "Suspicious script executed from /tmp", "user": "admin", "mitre": "T1059.004"},
    {"id": "8830", "time": "09:20:11", "host": "pc-staf-07", "rule": "Read access to /etc/shadow", "user": "admin", "mitre": "T1003.008"},
    {"id": "8851", "time": "09:31:05", "host": "srv-file-01", "rule": "sshd: authentication success", "src_ip": "10.10.5.7", "user": "admin", "mitre": "T1021.004"},
    {"id": "8870", "time": "09:34:48", "host": "plc-genset-01", "rule": "Modbus write single coil from unauthorized host", "src_ip": "10.10.5.20", "mitre": "T0855"},
]
ASSETS = {
    "10.10.5.7": "pc-staf-07 (Sertu A, bagian logistik)",
    "10.10.5.20": "srv-file-01 (server file satuan)",
    "plc-genset-01": "PLC pengendali genset markas (OT, kritis)",
}

SYSTEM = (
    "Kamu analis SOC satuan TNI AD. Tulis dalam bahasa Indonesia yang singkat dan jelas. "
    "Gunakan HANYA fakta dari alert yang diberikan. Setiap kejadian di kronologi wajib "
    "menyebut ID alert sebagai bukti. Jawab hanya dengan JSON dengan kunci: judul, tingkat "
    "(rendah|sedang|tinggi|kritis), ringkasan, taktik (daftar nama taktik MITRE ATT&CK), "
    "kronologi (daftar {waktu, kejadian, bukti: [id]}), rekomendasi (daftar langkah)."
)
USER = "Aset:\n" + json.dumps(ASSETS, ensure_ascii=False) + "\n\nAlert:\n" + json.dumps(ALERTS, ensure_ascii=False)

body = json.dumps({
    "model": MODEL,
    "stream": False,
    "format": "json",
    "options": {"temperature": 0.1},
    "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": USER}],
}).encode()

start = time.time()
req = urllib.request.Request(OLLAMA, data=body, headers={"Content-Type": "application/json"})
with urllib.request.urlopen(req, timeout=600) as resp:
    out = json.load(resp)
elapsed = time.time() - start

summary = json.loads(out["message"]["content"])
print(json.dumps(summary, ensure_ascii=False, indent=2))

# Validasi bukti sederhana: setiap ID yang disebut harus ada di data alert.
known = {a["id"] for a in ALERTS}
cited = {i for step in summary.get("kronologi", []) for i in step.get("bukti", [])}
print("\n--- Validasi bukti")
print("ID dikutip :", sorted(cited))
print("ID tak dikenal (halusinasi):", sorted(cited - known) or "tidak ada")
print("Alert tak dikutip :", sorted(known - cited) or "tidak ada")

tokens = out.get("eval_count", 0)
gen_s = out.get("eval_duration", 1) / 1e9
print("\n--- Kinerja")
print(f"Total waktu      : {elapsed:.1f} detik (termasuk memuat model)")
print(f"Token dihasilkan : {tokens} ({tokens / gen_s:.1f} token/detik)")
