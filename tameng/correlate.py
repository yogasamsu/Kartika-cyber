"""Korelasi deterministik: dari event mentah menjadi insiden berantai.

Semua logika di sini berbasis aturan (bukan LLM): disambiguasi derau,
pengelompokan per waktu, penyusunan rantai serangan, pemetaan ATT&CK, dan
penilaian tingkat bahaya. LLM hanya dipakai belakangan untuk menulis narasi.
"""
import datetime as dt
from dataclasses import dataclass, field

from . import config, mitre


@dataclass
class Step:
    time: str
    text: str
    evidence: list          # daftar eid
    tech: list              # daftar id teknik


@dataclass
class Incident:
    id: str
    start: dt.datetime
    end: dt.datetime
    events: list
    hosts: list
    identities: list
    entry_ip: str
    techniques: list        # [(id, nama, domain, taktik)]
    has_ot_impact: bool
    severity: str
    steps: list             # list[Step]
    notes: list = field(default_factory=list)

    def evidence_ids(self):
        return [e.eid for e in self.events]


def _shadow_is_malicious(ev, tmp_by_host):
    for t in tmp_by_host.get(ev.host, []):
        if abs((ev.ts - t).total_seconds()) <= config.SHADOW_TMP_WINDOW_S:
            return True
    return False


def _prepare(events):
    """Buang derau: shadow_read akibat login PAM, serta event konteks."""
    tmp_by_host = {}
    for e in events:
        if e.kind == "tmp_exec":
            tmp_by_host.setdefault(e.host, []).append(e.ts)

    kept, benign_shadow = [], 0
    for e in events:
        if e.kind == "shadow_read":
            if _shadow_is_malicious(e, tmp_by_host):
                kept.append(e)
            else:
                benign_shadow += 1
        elif e.kind in ("modbus_connect", "pam_open"):
            continue          # konteks saja, tidak masuk rantai
        else:
            kept.append(e)
    kept.sort(key=lambda e: e.ts)
    return kept, benign_shadow


def _cluster(events, window):
    clusters, cur = [], []
    for e in events:
        if cur and (e.ts - cur[-1].ts).total_seconds() > window:
            clusters.append(cur)
            cur = []
        cur.append(e)
    if cur:
        clusters.append(cur)
    return clusters


def _hhmmss(ts):
    return ts.strftime("%H:%M:%S")


def _build_steps(events):
    steps = []
    i = 0
    n = len(events)
    while i < n:
        e = events[i]
        if e.kind == "brute_force":
            # gabungkan brute force beruntun dengan host & sumber sama
            j = i
            grp = []
            while j < n and events[j].kind == "brute_force" and \
                    events[j].host == e.host and events[j].src_ip == e.src_ip:
                grp.append(events[j])
                j += 1
            src_name = config.asset(e.src_ip)[0]
            steps.append(Step(
                time=_hhmmss(e.ts),
                text=f"{len(grp)} percobaan login SSH gagal ke {e.host} dari {e.src_ip} ({src_name}) — pola brute force",
                evidence=[x.eid for x in grp],
                tech=["T1110"],
            ))
            i = j
            continue

        if e.kind == "auth_success":
            name, role, crit, internal = config.asset(e.src_ip)
            if internal:
                how = f"gerak lateral dari {name}"
            else:
                how = "akses awal dari luar jaringan"
            user = e.user or "?"
            steps.append(Step(
                time=_hhmmss(e.ts),
                text=f"Login SSH BERHASIL ke {e.host} sebagai '{user}' dari {e.src_ip} ({how})",
                evidence=[e.eid],
                tech=["T1078", "T1021.004"],
            ))
        elif e.kind == "tmp_exec":
            user = e.user or "?"
            steps.append(Step(
                time=_hhmmss(e.ts),
                text=f"Eksekusi berkas dari /tmp di {e.host} (pengguna '{user}') — payload penyerang",
                evidence=[e.eid],
                tech=["T1059.004"],
            ))
        elif e.kind == "shadow_read":
            steps.append(Step(
                time=_hhmmss(e.ts),
                text=f"Pembacaan /etc/shadow di {e.host} — pencurian hash kredensial",
                evidence=[e.eid],
                tech=["T1003.008"],
            ))
        elif e.kind == "modbus_write":
            tgt = config.asset(e.dst_ip)[0]
            src_name = config.asset(e.src_ip)[0]
            steps.append(Step(
                time=_hhmmss(e.ts),
                text=f"Perintah tulis Modbus dari {e.src_ip} ({src_name}) ke PLC {tgt} — mematikan genset (DAMPAK OT)",
                evidence=[e.eid],
                tech=["T0855", "T0816"],
            ))
        i += 1
    return steps


def _severity(events, has_ot):
    if has_ot:
        return "kritis"
    kinds = {e.kind for e in events}
    if "shadow_read" in kinds or ("auth_success" in kinds and "brute_force" in kinds):
        return "tinggi"
    if "auth_success" in kinds or "tmp_exec" in kinds:
        return "sedang"
    return "rendah"


def _techniques_in_order(events):
    seen, out = set(), []
    for e in events:
        for tid in e.tech:
            if tid not in seen:
                seen.add(tid)
                out.append((tid, mitre.technique_name(tid), mitre.technique_domain(tid), e.tactic))
    return out


def build_incidents(events, window=None):
    window = window or config.CORR_WINDOW_S
    kept, benign_shadow = _prepare(events)
    incidents = []
    for k, cluster in enumerate(_cluster(kept, window), 1):
        has_ot = any(e.kind == "modbus_write" for e in cluster)
        hosts, identities = [], []
        for e in cluster:
            # tampilkan host sebagai nama aset bila IP dikenal
            name = config.asset(e.host)[0] if e.host else None
            if name and name not in hosts:
                hosts.append(name)
            # identitas hanya dari login yang BERHASIL (bukan nama tebakan brute force)
            if e.kind == "auth_success" and e.user and e.user not in identities:
                identities.append(e.user)
        # IP masuk: sumber eksternal pertama, jika ada.
        entry_ip = ""
        for e in cluster:
            if e.src_ip and not config.asset(e.src_ip)[3]:   # tidak internal
                entry_ip = e.src_ip
                break
        if not entry_ip:
            for e in cluster:
                if e.src_ip:
                    entry_ip = e.src_ip
                    break
        inc = Incident(
            id=f"INC-{cluster[0].ts.strftime('%Y%m%d-%H%M%S')}",
            start=cluster[0].ts, end=cluster[-1].ts,
            events=cluster, hosts=hosts, identities=identities,
            entry_ip=entry_ip,
            techniques=_techniques_in_order(cluster),
            has_ot_impact=has_ot,
            severity=_severity(cluster, has_ot),
            steps=_build_steps(cluster),
        )
        if benign_shadow:
            inc.notes.append(
                f"{benign_shadow} pembacaan /etc/shadow diabaikan sebagai derau login PAM "
                f"(tidak berkaitan dengan eksekusi /tmp)."
            )
        incidents.append(inc)
    return incidents
