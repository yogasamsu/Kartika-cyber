"""Ringkasan kerentanan ("scan sistem") dari hasil Wazuh yang sudah ada.

Tameng tidak membuat pemindai sendiri. Modul ini membaca alert Wazuh
Vulnerability Detection (CVE per paket) dan SCA (cek konfigurasi gagal), lalu
menyusun URUTAN PRIORITAS tambalan untuk satuan yang tidak bisa menambal semua
sekaligus (sistem lama). Skor dan alasannya ditentukan kode, bukan LLM.

Sisi OT (PLC) sengaja tidak dipindai aktif: perangkat lama bisa macet.
"""
import json
from dataclasses import dataclass, field

from . import config

# Subset lokal katalog CISA Known Exploited Vulnerabilities (KEV). Di satuan,
# perbarui dari salinan KEV yang dibawa lewat media offline.
KEV = {
    "CVE-2020-25213",   # WordPress plugin wp-file-manager: unggah berkas tanpa autentikasi
    "CVE-2021-4034",    # polkit pkexec (PwnKit): naik hak akses lokal
    "CVE-2021-44228",   # Apache Log4j (Log4Shell)
    "CVE-2014-6271",    # Bash (Shellshock)
}

CRIT_BONUS = {"kritis": 3, "tinggi": 2, "sedang": 1}
SEV_FROM_CVSS = ((9.0, "kritis"), (7.0, "tinggi"), (4.0, "sedang"), (0.0, "rendah"))


@dataclass
class Temuan:
    cve: str
    host: str
    package: str
    version: str
    cvss: float
    title: str
    kev: bool = False
    skor: float = 0.0
    alasan: list = field(default_factory=list)

    @property
    def tingkat(self):
        for lo, name in SEV_FROM_CVSS:
            if self.cvss >= lo:
                return name
        return "rendah"


def _host_info(host):
    """(peran, kritikalitas) aset dari nama host di inventaris."""
    for _ip, (name, role, crit, _internal) in config.ASSETS.items():
        if name == host:
            return role, crit
    return "tak dikenal", "-"


def _iter(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        continue
    except FileNotFoundError:
        return


def load(path):
    """Baca alert VD dan SCA. Kembalikan (temuan CVE, cek SCA gagal per host)."""
    vulns, sca = {}, {}
    for a in _iter(path):
        d = a.get("data") or {}
        host = (a.get("agent") or {}).get("name", "?")
        v = d.get("vulnerability")
        if v:
            if str(v.get("status", "Active")).lower() == "solved":
                continue
            cve = v.get("cve") or v.get("id")
            if not cve:
                continue
            pkg = v.get("package") or {}
            cvss = (((v.get("cvss") or {}).get("cvss3") or {}).get("base_score")
                    or (v.get("score") or {}).get("base") or 0)
            key = (cve, host)
            vulns[key] = Temuan(cve=cve, host=host, package=pkg.get("name", "?"),
                                version=pkg.get("version", ""), cvss=float(cvss or 0),
                                title=v.get("title", "") or v.get("description", "")[:120])
            continue
        check = (d.get("sca") or {}).get("check") or {}
        if check.get("result") == "failed":
            sca.setdefault(host, [])
            title = check.get("title", "?")
            if title not in sca[host]:
                sca[host].append(title)
    return list(vulns.values()), sca


def prioritize(vulns, incident_hosts=()):
    """Beri skor dan alasan, lalu urutkan dari yang paling mendesak."""
    incident_hosts = set(incident_hosts)
    for t in vulns:
        role, crit = _host_info(t.host)
        t.kev = t.cve in KEV
        t.skor = t.cvss
        t.alasan = [f"CVSS {t.cvss:.1f} ({t.tingkat})"]
        if t.kev:
            t.skor += 3
            t.alasan.append("masuk katalog KEV: sudah dieksploitasi di dunia nyata")
        if crit in CRIT_BONUS:
            t.skor += CRIT_BONUS[crit]
            t.alasan.append(f"aset berkritikalitas {crit} ({role})")
        if "publik" in role.lower():
            t.skor += 2
            t.alasan.append("terbuka ke publik")
        if t.host in incident_hosts:
            t.skor += 2
            t.alasan.append("host ini terlibat insiden aktif")
    vulns.sort(key=lambda t: (-t.skor, -t.cvss, t.cve, t.host))
    return vulns


def summarize(path, incident_hosts=(), top=3):
    """Ringkasan siap pakai untuk laporan dan dashboard."""
    vulns, sca = load(path)
    ranked = prioritize(vulns, incident_hosts)
    per_host = {}
    for t in ranked:
        per_host.setdefault(t.host, {"host": t.host, "cve": 0, "kritis": 0, "kev": 0})
        per_host[t.host]["cve"] += 1
        per_host[t.host]["kritis"] += t.tingkat == "kritis"
        per_host[t.host]["kev"] += t.kev
    for h, checks in sca.items():
        per_host.setdefault(h, {"host": h, "cve": 0, "kritis": 0, "kev": 0})
        per_host[h]["sca_gagal"] = len(checks)
    return {
        "total_cve": len(ranked),
        "total_kev": sum(t.kev for t in ranked),
        "prioritas": [
            {"urutan": i + 1, "cve": t.cve, "host": t.host, "package": t.package,
             "version": t.version, "cvss": t.cvss, "tingkat": t.tingkat, "kev": t.kev,
             "skor": round(t.skor, 1), "alasan": t.alasan, "judul": t.title}
            for i, t in enumerate(ranked)
        ],
        "tambal_dulu": [t.cve + " di " + t.host for t in ranked[:top]],
        "per_host": sorted(per_host.values(), key=lambda x: (-x["kritis"], -x["cve"], x["host"])),
        "sca_gagal": sca,
        "catatan": "Perangkat OT (PLC) tidak dipindai aktif; kerentanannya dinilai dari inventaris dan pemantauan pasif.",
    }


def render_markdown(s):
    L = ["# Ringkasan kerentanan", ""]
    L.append(f"{s['total_cve']} CVE aktif, {s['total_kev']} di antaranya sudah dieksploitasi di dunia nyata (KEV).")
    L.append("")
    L.append("## Tambal dulu")
    for p in s["prioritas"][:3]:
        L.append(f"{p['urutan']}. **{p['cve']}** di `{p['host']}` ({p['package']} {p['version']}): "
                 + "; ".join(p["alasan"]) + ".")
    L.append("")
    L.append("## Semua temuan")
    L.append("| # | CVE | Host | Paket | CVSS | KEV | Skor |")
    L.append("|---|---|---|---|---|---|---|")
    for p in s["prioritas"]:
        L.append(f"| {p['urutan']} | {p['cve']} | {p['host']} | {p['package']} {p['version']} | "
                 f"{p['cvss']:.1f} | {'ya' if p['kev'] else '-'} | {p['skor']} |")
    if s["sca_gagal"]:
        L.append("")
        L.append("## Konfigurasi yang gagal cek (SCA)")
        for h, checks in s["sca_gagal"].items():
            L.append(f"- **{h}**: " + "; ".join(checks))
    L.append("")
    L.append(f"*{s['catatan']}*")
    return "\n".join(L)
