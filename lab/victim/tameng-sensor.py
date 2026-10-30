#!/usr/bin/env python3
"""Sensor endpoint Tameng (pengganti auditd di lab).

Menulis event JSON-lines ke /var/log/tameng-sensor.log yang dibaca Wazuh agent.
Dua perilaku dipantau:

  1. tmp_exec    : proses yang berkas program atau argv-nya berada di /tmp
                   (menangkap biner maupun skrip shell dari /tmp).
  2. shadow_read : pembacaan /etc/shadow, dideteksi lewat inotify IN_ACCESS
                   (berbasis event, menangkap bahkan 'cat' yang sekejap).

Mirip sensor EDR userland; dipakai karena auditd tidak tersedia di VM
Docker Desktop.
"""
import ctypes
import json
import os
import pwd
import struct
import threading
import time

LOG = "/var/log/tameng-sensor.log"
SHADOW = "/etc/shadow"
POLL = 0.2

_lock = threading.Lock()


def owner(pid):
    try:
        return pwd.getpwuid(os.stat(f"/proc/{pid}").st_uid).pw_name
    except Exception:
        return "?"


def cmdline(pid):
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            return f.read().replace(b"\x00", b" ").decode(errors="replace").strip()
    except Exception:
        return ""


def emit(event, extra, pid=None):
    rec = {
        "sensor": "tameng",
        "event": event,
        "time": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "pid": pid or 0,
        "user": owner(pid) if pid else "?",
        "cmd": cmdline(pid) if pid else "",
    }
    rec.update(extra)
    with _lock, open(LOG, "a") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def find_pid_running(path):
    """Best-effort: pid yang exe atau argv0-nya == path."""
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            if os.readlink(f"/proc/{pid}/exe") == path:
                return int(pid)
        except Exception:
            pass
        if path in cmdline(pid).split(" "):   # mis. bash /tmp/dump.sh
            return int(pid)
    return None


def watch_tmp_exec():
    """inotify IN_OPEN pada /tmp; lapor berkas executable yang dibuka/dieksekusi.

    Eksekusi skrip maupun biner memicu pembukaan berkasnya, sehingga tertangkap
    berbasis event (tidak tergantung proses yang mungkin sangat singkat)."""
    IN_OPEN = 0x00000020
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    fd = libc.inotify_init1(0)
    if fd < 0:
        return
    if libc.inotify_add_watch(fd, b"/tmp", IN_OPEN) < 0:
        return
    HDR = struct.calcsize("iIII")
    last = {}
    while True:
        data = os.read(fd, 8192)
        off = 0
        while off + HDR <= len(data):
            _wd, mask, _cookie, length = struct.unpack_from("iIII", data, off)
            name = data[off + HDR:off + HDR + length].split(b"\x00", 1)[0].decode(errors="replace")
            off += HDR + length
            if not (mask & IN_OPEN) or not name:
                continue
            path = f"/tmp/{name}"
            try:
                if not os.access(path, os.X_OK):   # hanya berkas executable
                    continue
            except Exception:
                continue
            now = time.time()
            if now - last.get(path, 0) < 2:
                continue
            last[path] = now
            emit("tmp_exec", {"exe": path}, pid=find_pid_running(path))


def attribute_reader():
    """Best-effort: cari pid yang sedang membuka /etc/shadow."""
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            for fd in os.listdir(f"/proc/{pid}/fd"):
                if os.readlink(f"/proc/{pid}/fd/{fd}") == SHADOW:
                    return int(pid)
        except Exception:
            continue
    return None


def watch_shadow_read():
    """inotify IN_ACCESS pada /etc/shadow (berbasis event)."""
    IN_ACCESS = 0x00000001
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    fd = libc.inotify_init1(0)
    if fd < 0:
        return
    wd = libc.inotify_add_watch(fd, SHADOW.encode(), IN_ACCESS)
    if wd < 0:
        return
    last = {}
    HDR = struct.calcsize("iIII")
    while True:
        data = os.read(fd, 4096)  # blocking
        off = 0
        while off + HDR <= len(data):
            _wd, mask, _cookie, length = struct.unpack_from("iIII", data, off)
            off += HDR + length
            if mask & IN_ACCESS:
                pid = attribute_reader()
                now = time.time()
                # Redam banjir per proses: pembacaan PAM oleh sshd tidak boleh
                # menelan pembacaan oleh payload penyerang sedetik kemudian.
                if now - last.get(pid, 0) < 2:
                    continue
                last[pid] = now
                emit("shadow_read", {"target": SHADOW}, pid=pid)


def main():
    open(LOG, "a").close()
    t1 = threading.Thread(target=watch_tmp_exec, daemon=True)
    t2 = threading.Thread(target=watch_shadow_read, daemon=True)
    t1.start()
    t2.start()
    t1.join()


if __name__ == "__main__":
    main()
