"""Konfigurasi Tameng: lokasi bukti di SSD dan setelan LLM lokal."""
import os

# Sumber bukti (dibaca langsung dari SSD terenkripsi Prika-Tameng).
WAZUH_ALERTS = os.environ.get(
    "TAMENG_WAZUH_ALERTS",
    "/Volumes/Prika-Tameng/lab-data/wazuh/alerts/alerts.json",
)
SURICATA_EVE = os.environ.get(
    "TAMENG_SURICATA_EVE",
    "/Volumes/Prika-Tameng/lab-data/suricata/eve/eve.json",
)

# LLM lokal (Ollama, air-gapped).
OLLAMA_URL = os.environ.get("TAMENG_OLLAMA_URL", "http://127.0.0.1:11434/api/chat")
OLLAMA_MODEL = os.environ.get("TAMENG_OLLAMA_MODEL", "qwen2.5:7b")

# Jendela korelasi: dua kejadian dianggap serantai bila selisihnya <= ini (detik).
CORR_WINDOW_S = int(os.environ.get("TAMENG_CORR_WINDOW_S", "300"))
# shadow_read dianggap derau login bila berdekatan dengan login (detik).
PAM_WINDOW_S = int(os.environ.get("TAMENG_PAM_WINDOW_S", "3"))
# shadow_read dianggap jahat bila terjadi paling lama sekian detik SETELAH eksekusi
# /tmp di host sama. Sengaja sempit: agen Wazuh sendiri (SCA/rootcheck) membaca
# /etc/shadow belasan detik setelah memuat ulang konfigurasi.
SHADOW_TMP_WINDOW_S = int(os.environ.get("TAMENG_SHADOW_TMP_WINDOW_S", "10"))
# Toleransi selisih jam antar-sensor (Wazuh vs Suricata, latensi ingest), detik.
CLOCK_SKEW_S = int(os.environ.get("TAMENG_CLOCK_SKEW_S", "5"))

# Inventaris aset lab (di produksi berasal dari CMDB/daftar aset satuan).
# ip -> (nama, peran, kritikalitas, internal?)
ASSETS = {
    "10.10.5.2":  ("wazuh-manager", "SOC manager", "tinggi", True),
    "10.10.5.66": ("pc-staf-07", "Workstation staf", "sedang", True),
    "10.10.5.7":  ("srv-file-01", "Server file satuan", "tinggi", True),
    "10.10.5.20": ("plc-genset-01", "PLC pengendali genset (OT, kritis)", "kritis", True),
    "10.10.5.30": ("hmi-genset", "HMI operator genset (pengendali sah)", "tinggi", True),
    "10.10.5.40": ("web-portal", "Portal web satuan (situs publik)", "tinggi", True),
    "10.10.5.90": ("kali-ops", "Host tak terdaftar (indikasi penyerang)", "-", False),
}


# Direktori situs web yang dipantau FIM. Perubahan berkas di luar sini (mis. /etc)
# bukan sinyal deface dan diabaikan oleh Tameng.
WEB_ROOTS = tuple(os.environ.get("TAMENG_WEB_ROOTS", "/var/www/html").split(","))


# Pengirim perintah Modbus yang sah (HMI/SCADA). Perintah tulis dari sini bukan serangan.
MODBUS_MASTERS = set(os.environ.get("TAMENG_MODBUS_MASTERS", "10.10.5.30").split(","))


def asset(ip):
    """Kembalikan (nama, peran, kritikalitas, internal) untuk sebuah IP."""
    return ASSETS.get(ip, (ip or "?", "tak dikenal", "-", False))
