"""Ingest & normalisasi bukti dari Wazuh (IT) dan Suricata (OT).

Keluaran: daftar Event seragam, masing-masing dengan penanda bukti (eid)
yang stabil untuk dikutip di laporan.
"""
import datetime as dt
import json
from dataclasses import dataclass, field
from typing import Optional

from . import config, mitre


@dataclass
class Event:
    eid: str                      # penanda bukti, mis. "W1", "S1"
    ts: dt.datetime
    source: str                   # "wazuh" | "suricata"
    sid: str                      # id rule Wazuh / sid Suricata
    kind: str                     # jenis kanonik (dari katalog)
    label: str
    tactic: str
    tech: list
    domain: str                   # "it" | "ot"
    level: int = 0
    host: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    user: Optional[str] = None
    native_id: Optional[str] = None
    raw: dict = field(default_factory=dict)


def _parse_ts(s):
    if not s:
        return None
    s = s.strip().replace("Z", "+0000")
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return dt.datetime.strptime(s, fmt).astimezone(dt.timezone.utc)
        except ValueError:
            continue
    try:
        return dt.datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=dt.timezone.utc)
    except ValueError:
        return None


def _source_ts(alert):
    """Waktu kejadian di sumber, bukan waktu alert diterima manager.

    Stempel `timestamp` Wazuh adalah waktu manager memproses log; agen bisa
    mengirim dalam batch puluhan detik kemudian, sehingga urutan antar-host dan
    terhadap Suricata (waktu paket) kacau. Waktu asli diambil dari:
      - data.time         : sensor Tameng (ISO, UTC container)
      - predecoder.timestamp : baris syslog sshd ("Nov  6 10:19:26", UTC container)
    Bila keduanya tidak ada, dipakai waktu manager.
    """
    received = _parse_ts(alert.get("timestamp", ""))
    sensor = (alert.get("data") or {}).get("time")
    if sensor:
        ts = _parse_ts(sensor)
        if ts:
            return ts, received
    pre = (alert.get("predecoder") or {}).get("timestamp")
    if pre and received:
        try:
            ts = dt.datetime.strptime(f"{received.year} {' '.join(pre.split())}", "%Y %b %d %H:%M:%S")
            ts = ts.replace(tzinfo=dt.timezone.utc)
            if ts - received > dt.timedelta(days=1):     # log Desember dibaca di Januari
                ts = ts.replace(year=ts.year - 1)
            return ts, received
        except ValueError:
            pass
    return received, received


def _iter_json(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        return


def load_wazuh(since=None):
    out = []
    for a in _iter_json(config.WAZUH_ALERTS):
        sid = str(a.get("rule", {}).get("id", ""))
        meta = mitre.lookup("wazuh", sid)
        if not meta:
            continue
        ts, received = _source_ts(a)
        if not ts or (since and ts < since):
            continue
        d = a.get("data", {})
        out.append(Event(
            eid="", ts=ts, source="wazuh", sid=sid,
            kind=meta["kind"], label=meta["label"], tactic=meta["tactic"],
            tech=list(meta["tech"]), domain=meta["domain"],
            level=a.get("rule", {}).get("level", 0),
            host=a.get("agent", {}).get("name"),
            src_ip=d.get("srcip"),
            # sshd memakai dstuser/srcuser; sensor Tameng (JSON) memakai user.
            user=d.get("dstuser") or d.get("srcuser") or d.get("user"),
            native_id=a.get("id"),
            raw={"full_log": a.get("full_log", ""), "rule_desc": a.get("rule", {}).get("description", ""),
                 "cmd": d.get("cmd", ""),
                 "received": received.isoformat() if received else ""},
        ))
    return out


def load_suricata(since=None):
    out = []
    for e in _iter_json(config.SURICATA_EVE):
        if e.get("event_type") != "alert":
            continue
        sid = str(e.get("alert", {}).get("signature_id", ""))
        meta = mitre.lookup("suricata", sid)
        if not meta:
            continue
        ts = _parse_ts(e.get("timestamp", ""))
        if not ts or (since and ts < since):
            continue
        out.append(Event(
            eid="", ts=ts, source="suricata", sid=sid,
            kind=meta["kind"], label=meta["label"], tactic=meta["tactic"],
            tech=list(meta["tech"]), domain=meta["domain"],
            level=e.get("alert", {}).get("severity", 3),
            host=e.get("dest_ip"),
            src_ip=e.get("src_ip"),
            dst_ip=e.get("dest_ip"),
            native_id=str(e.get("flow_id", "")),
            raw={"proto": e.get("proto", ""), "signature": e.get("alert", {}).get("signature", "")},
        ))
    return out


def load_all(minutes=None):
    """Muat semua event relevan. minutes=None berarti seluruh berkas."""
    since = None
    if minutes:
        since = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=minutes)
    events = load_wazuh(since) + load_suricata(since)
    events.sort(key=lambda e: e.ts)
    # Penanda bukti berurutan per sumber.
    nw = ns = 0
    for e in events:
        if e.source == "wazuh":
            nw += 1
            e.eid = f"W{nw}"
        else:
            ns += 1
            e.eid = f"S{ns}"
    return events
