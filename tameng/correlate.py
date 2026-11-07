"""Korelasi deterministik: dari event mentah menjadi insiden berantai.

Semua logika di sini berbasis aturan (bukan LLM): disambiguasi derau,
pengelompokan per waktu, penyusunan rantai serangan, pemetaan ATT&CK, dan
penilaian tingkat bahaya. LLM hanya dipakai belakangan untuk menulis narasi.
"""
import datetime as dt
import re
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
    ot_blocked: bool
    severity: str
    steps: list             # list[Step]
    notes: list = field(default_factory=list)

    def evidence_ids(self):
        return [e.eid for e in self.events]


# Pembacaan /etc/shadow oleh proses login (PAM) adalah derau, bukan pencurian.
# Urutan rantai bila waktu urutnya sama: akses dulu, baru aksi di host, lalu OT.
KIND_RANK = {"brute_force": 0, "auth_success": 1, "tmp_exec": 2, "shadow_read": 3, "modbus_write": 4, "modbus_block": 4}

PAM_CMD_RE = re.compile(r"^(\S*/)?(sshd|unix_chkpwd|login)\b")


def _actor(ip):
    """Entitas pelaku: nama aset bila IP internal yang dikenal, selainnya IP itu sendiri."""
    name, _role, _crit, internal = config.asset(ip)
    return name if internal else ip


class _Draft:
    """Insiden yang sedang dirakit: event, entitas pelaku, dan host yang dikuasai."""

    def __init__(self):
        self.events = []
        self.actors = set()     # entitas yang dikendalikan penyerang (IP luar / host)
        self.owned = {}         # host -> waktu pertama kali dikuasai (login berhasil)
        self.order = {}         # id(event) -> waktu urut kausal
        self.last = None        # waktu event rantai terakhir
        self.notes = []

    def add(self, e, order_ts=None):
        self.events.append(e)
        self.order[id(e)] = max(order_ts or e.ts, e.ts)
        if self.last is None or e.ts > self.last:
            self.last = e.ts


def _find_by_actor(drafts, entity, ts, window):
    """Draft terbaru yang memuat entitas pelaku ini dan masih dalam jendela waktu."""
    for d in reversed(drafts):
        if (entity in d.actors or entity in d.owned) and \
                (ts - d.last).total_seconds() <= window:
            return d
    return None


def _find_owner(drafts, host, ts, window):
    """Draft yang sudah menguasai host ini pada waktu ts (dengan toleransi jam)."""
    skew = config.CLOCK_SKEW_S
    for d in reversed(drafts):
        t0 = d.owned.get(host)
        if t0 is None:
            continue
        if (t0 - ts).total_seconds() <= skew and (ts - d.last).total_seconds() <= window:
            return d
    return None


def _shadow_verdict(e, draft):
    """True bila pembacaan /etc/shadow ini jahat dalam konteks draft (atau tanpa draft)."""
    cmd = (e.raw or {}).get("cmd", "") or ""
    if PAM_CMD_RE.match(cmd):
        return False
    if "/tmp/" in cmd:
        return True
    if draft is None:
        return False
    # Sensor yang sama di host yang sama: urutan jamnya bisa dipercaya, jadi
    # pembacaan harus terjadi SETELAH eksekusi /tmp, bukan sebelumnya.
    for t in draft.events:
        if t.kind == "tmp_exec" and t.host == e.host:
            dt_s = (e.ts - t.ts).total_seconds()
            if 0 <= dt_s <= config.SHADOW_TMP_WINDOW_S:
                return True
    return False


def _assemble(events, window):
    """Rakit event menjadi draft insiden berdasarkan entitas, bukan sekadar waktu.

    Tahap 1 membangun rantai akses (brute force, login berhasil) dan mencatat
    host yang dikuasai. Tahap 2 menempelkan aktivitas di host (eksekusi /tmp,
    pembacaan shadow) dan perintah OT ke draft yang menguasai host asalnya.
    Toleransi CLOCK_SKEW_S menangani bukti dari sensor berbeda yang jamnya
    sedikit bergeser (mis. Modbus tercatat 1 dtk sebelum login lateral).
    """
    drafts, benign = [], []

    def own(d, e):
        d.add(e)
        if e.host and e.host not in d.owned:
            d.owned[e.host] = e.ts
        d.actors.add(e.host)

    pending = []    # login internal yang belum punya rantai (mungkin rantainya diproses sedetik kemudian)
    for e in events:
        if e.kind == "brute_force":
            actor = _actor(e.src_ip)
            d = _find_by_actor(drafts, actor, e.ts, window)
            if d is None:
                d = _Draft()
                d.actors.add(actor)
                drafts.append(d)
            d.add(e)
        elif e.kind == "auth_success":
            actor = _actor(e.src_ip)
            d = _find_by_actor(drafts, actor, e.ts, window)
            if d is None:
                if config.asset(e.src_ip)[3]:
                    pending.append(e)
                    continue
                d = _Draft()
                d.actors.add(actor)
                drafts.append(d)
            own(d, e)

    # Ulangi login internal yang tertunda sampai tidak ada yang bertambah. Bukti
    # berpresisi detik: login lateral bisa tercatat sebelum login penyerang ke host
    # asalnya di detik yang sama. Yang tetap tanpa rantai = aktivitas normal.
    while pending:
        rest = []
        for e in pending:
            d = _find_owner(drafts, _actor(e.src_ip), e.ts, window)
            if d is None:
                rest.append(e)
            else:
                own(d, e)
        if len(rest) == len(pending):
            break
        pending = rest

    for kind in ("tmp_exec", "modbus_write", "modbus_block", "shadow_read"):
        for e in events:
            if e.kind != kind:
                continue
            ot = kind in ("modbus_write", "modbus_block")
            if ot and e.src_ip in config.MODBUS_MASTERS:
                continue    # perintah dari HMI/SCADA resmi: operasi sah
            host = _actor(e.src_ip) if ot else e.host
            d = _find_owner(drafts, host, e.ts, window)
            if kind == "shadow_read":
                if _shadow_verdict(e, d):
                    if d is None:
                        d = _Draft()
                        drafts.append(d)
                    d.add(e, d.owned.get(host))
                else:
                    benign.append(e)
                continue
            if d is None:
                d = _Draft()
                drafts.append(d)
                if ot:
                    d.notes.append("Sumber perintah Modbus tidak terhubung ke rantai serangan IT yang terdeteksi.")
            d.add(e, d.owned.get(host))

    return drafts, benign


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
            # gabungkan pembacaan beruntun di host sama menjadi satu langkah
            j = i
            grp = []
            while j < n and events[j].kind == "shadow_read" and events[j].host == e.host:
                grp.append(events[j])
                j += 1
            steps.append(Step(
                time=_hhmmss(e.ts),
                text=f"Pembacaan /etc/shadow di {e.host} — pencurian hash kredensial",
                evidence=[x.eid for x in grp],
                tech=["T1003.008"],
            ))
            i = j
            continue
        elif e.kind == "modbus_write":
            tgt = config.asset(e.dst_ip)[0]
            src_name = config.asset(e.src_ip)[0]
            steps.append(Step(
                time=_hhmmss(e.ts),
                text=f"Perintah tulis Modbus dari {e.src_ip} ({src_name}) ke PLC {tgt} — mematikan genset (DAMPAK OT)",
                evidence=[e.eid],
                tech=["T0855", "T0816"],
            ))
        elif e.kind == "modbus_block":
            tgt = config.asset(e.dst_ip)[0]
            src_name = config.asset(e.src_ip)[0]
            steps.append(Step(
                time=_hhmmss(e.ts),
                text=f"Perintah tulis Modbus dari {e.src_ip} ({src_name}) ke PLC {tgt} DIBLOKIR — genset tetap menyala (serangan OT digagalkan)",
                evidence=[e.eid],
                tech=["T0855"],
            ))
        i += 1
    return steps


def _severity(events, has_ot):
    if has_ot:
        return "kritis"
    kinds = {e.kind for e in events}
    if "modbus_block" in kinds:
        return "tinggi"       # penyerang sudah sampai ke jaringan kendali, walau diblokir
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
    drafts, benign = _assemble(events, window)
    incidents, used_ids = [], set()
    for d in sorted(drafts, key=lambda d: min(e.ts for e in d.events)):
        # Urut kausal: aktivitas di host tidak ditampilkan sebelum host itu dikuasai.
        cluster = sorted(d.events, key=lambda e: (d.order[id(e)], KIND_RANK.get(e.kind, 9), e.ts))
        reordered = sum(1 for e in cluster if d.order[id(e)] > e.ts)
        has_ot = any(e.kind == "modbus_write" for e in cluster)
        blocked = sum(1 for e in cluster if e.kind == "modbus_block")
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
        start = min(e.ts for e in cluster)
        inc_id = f"INC-{start.strftime('%Y%m%d-%H%M%S')}"
        n = 2
        while inc_id in used_ids:
            inc_id = f"INC-{start.strftime('%Y%m%d-%H%M%S')}-{n}"
            n += 1
        used_ids.add(inc_id)
        inc = Incident(
            id=inc_id,
            start=start, end=max(e.ts for e in cluster),
            events=cluster, hosts=hosts, identities=identities,
            entry_ip=entry_ip,
            techniques=_techniques_in_order(cluster),
            has_ot_impact=has_ot,
            ot_blocked=blocked > 0,
            severity=_severity(cluster, has_ot),
            steps=_build_steps(cluster),
            notes=list(d.notes),
        )
        if blocked:
            inc.notes.append(
                f"Serangan ke OT digagalkan: {blocked} perintah tulis Modbus dari host tak sah "
                f"dijatuhkan Suricata (mode IPS) sebelum sampai ke PLC."
            )
        if reordered:
            inc.notes.append(
                f"Urutan {reordered} kejadian disesuaikan mengikuti rantai sebab-akibat "
                f"(selisih jam antar-sensor <= {config.CLOCK_SKEW_S} dtk)."
            )
        # Derau shadow_read hanya dilaporkan pada insiden yang menyangkut host tersebut.
        lo = inc.start - dt.timedelta(seconds=window)
        hi = inc.end + dt.timedelta(seconds=window)
        n_benign = sum(1 for b in benign if b.host in hosts and lo <= b.ts <= hi)
        if n_benign:
            inc.notes.append(
                f"{n_benign} pembacaan /etc/shadow diabaikan sebagai derau (login PAM atau "
                f"pemindaian agen Wazuh), karena tidak terjadi sesaat setelah eksekusi /tmp."
            )
        incidents.append(inc)
    return incidents
