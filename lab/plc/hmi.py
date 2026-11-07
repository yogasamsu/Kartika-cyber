#!/usr/bin/env python3
"""HMI operator genset: satu-satunya pengirim perintah Modbus yang sah.

Pakai:  python3 hmi.py on | off | status
Memakai socket mentah (Modbus TCP fc5 / fc1) tanpa pustaka tambahan.
"""
import socket
import sys

PLC = ("10.10.5.20", 502)


def request(pdu):
    s = socket.create_connection(PLC, timeout=5)
    s.sendall(bytes.fromhex("00010000") + (len(pdu) + 1).to_bytes(2, "big") + b"\x01" + pdu)
    resp = s.recv(64)
    s.close()
    return resp


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"
    if cmd in ("on", "off"):
        request(bytes.fromhex("05" "0000" + ("FF00" if cmd == "on" else "0000")))
    state = request(bytes.fromhex("01" "0000" "0001"))[-1] & 1
    print("GENSET NYALA" if state else "GENSET MATI")


if __name__ == "__main__":
    main()
