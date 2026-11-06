"""Tes regresi mesin Tameng dengan bukti sintetis (tanpa SSD, tanpa LLM).

Jalankan dari root repo:  python3 -m unittest discover -s tests -v
"""
import json
import os
import tempfile
import unittest

from tameng import config, correlate, events, llm


def wazuh(t, rid, agent, **data):
    return {"timestamp": f"2026-10-28T{t}.000+0000", "rule": {"id": rid, "level": 5},
            "agent": {"name": agent}, "data": data, "id": t}


def modbus(t, src, dst="10.10.5.20", sid=7000005):
    return {"timestamp": f"2026-10-28T{t}.000+0000", "event_type": "alert",
            "src_ip": src, "dest_ip": dst,
            "alert": {"signature_id": sid, "signature": "modbus write", "severity": 1}}


class Evidence:
    """Tulis alerts.json + eve.json sementara lalu arahkan config ke sana."""

    def __init__(self, wazuh_rows, eve_rows):
        self.dir = tempfile.TemporaryDirectory()
        self.w = os.path.join(self.dir.name, "alerts.json")
        self.e = os.path.join(self.dir.name, "eve.json")
        with open(self.w, "w") as f:
            f.write("\n".join(json.dumps(r) for r in wazuh_rows) + "\n")
        with open(self.e, "w") as f:
            f.write("\n".join(json.dumps(r) for r in eve_rows) + "\n")

    def __enter__(self):
        self.old = (config.WAZUH_ALERTS, config.SURICATA_EVE)
        config.WAZUH_ALERTS, config.SURICATA_EVE = self.w, self.e
        return events.load_all(minutes=None)

    def __exit__(self, *exc):
        config.WAZUH_ALERTS, config.SURICATA_EVE = self.old
        self.dir.cleanup()


ATK = "10.10.5.90"

# Rekonstruksi insiden lab 28 Okt 10:13 (lihat artifacts/tameng-replay.html):
# shadow_read W3 dari login PAM gagal, W8 dari login PAM berhasil, dan Modbus
# tercatat 1 dtk SEBELUM login lateral karena selisih jam antar-sensor.
DEMO_WAZUH = [
    wazuh("10:13:52", "5710", "pc-staf-07", srcip=ATK, dstuser="admin"),
    wazuh("10:13:53", "5710", "pc-staf-07", srcip=ATK, dstuser="admin"),
    wazuh("10:13:54", "100011", "pc-staf-07", event="shadow_read", user="root", cmd="sshd: admin [priv]"),
    wazuh("10:13:56", "5710", "pc-staf-07", srcip=ATK, dstuser="root"),
    wazuh("10:13:57", "5710", "pc-staf-07", srcip=ATK, dstuser="operator"),
    wazuh("10:13:59", "5715", "pc-staf-07", srcip=ATK, dstuser="sertu"),
    wazuh("10:13:59", "5501", "pc-staf-07", dstuser="sertu"),
    wazuh("10:13:59", "100011", "pc-staf-07", event="shadow_read", user="?", cmd=""),
    wazuh("10:14:00", "100010", "pc-staf-07", event="tmp_exec", user="sertu", cmd="/bin/bash /tmp/exfil.sh"),
    wazuh("10:14:00", "100011", "pc-staf-07", event="shadow_read", user="sertu", cmd="cat /etc/shadow"),
    wazuh("10:14:01", "5715", "srv-file-01", srcip="10.10.5.66", dstuser="sertu"),
]
DEMO_EVE = [modbus("10:14:00", "10.10.5.7")]


class DemoIncident(unittest.TestCase):
    def setUp(self):
        with Evidence(DEMO_WAZUH, DEMO_EVE) as evs:
            self.incs = correlate.build_incidents(evs)

    def test_satu_insiden_kritis(self):
        self.assertEqual(len(self.incs), 1)
        inc = self.incs[0]
        self.assertEqual(inc.severity, "kritis")
        self.assertEqual(inc.entry_ip, ATK)
        self.assertEqual(inc.identities, ["sertu"])

    def test_derau_pam_dibuang(self):
        inc = self.incs[0]
        shadow = [e for e in inc.events if e.kind == "shadow_read"]
        # Hanya pembacaan oleh cat setelah eksekusi /tmp yang dianggap jahat.
        self.assertEqual([e.raw["cmd"] for e in shadow], ["cat /etc/shadow"])
        self.assertTrue(any("2 pembacaan /etc/shadow diabaikan" in n for n in inc.notes))

    def test_urutan_kausal(self):
        evs = self.incs[0].events
        kinds = [e.kind for e in evs]
        lateral = next(i for i, e in enumerate(evs) if e.kind == "auth_success" and e.host == "srv-file-01")
        # Modbus tidak boleh tampil sebelum login lateral ke srv-file-01.
        self.assertLess(lateral, kinds.index("modbus_write"))
        self.assertEqual(self.incs[0].steps[-1].tech, ["T0855", "T0816"])
        # Pencurian shadow tidak boleh tampil sebelum login berhasil.
        self.assertLess(kinds.index("auth_success"), kinds.index("shadow_read"))
        self.assertTrue(any("disesuaikan" in n for n in self.incs[0].notes))

    def test_pengguna_tmp_exec_terbaca(self):
        step = next(s for s in self.incs[0].steps if "/tmp" in s.text)
        self.assertIn("'sertu'", step.text)


class Separation(unittest.TestCase):
    def test_serangan_tak_terkait_tidak_digabung(self):
        w = [
            wazuh("10:00:00", "5710", "pc-staf-07", srcip=ATK, dstuser="admin"),
            wazuh("10:00:05", "5715", "pc-staf-07", srcip=ATK, dstuser="sertu"),
            wazuh("10:00:40", "100010", "pc-staf-07", event="tmp_exec", user="sertu"),
            wazuh("10:02:00", "5710", "srv-file-01", srcip="10.10.5.91", dstuser="root"),
            wazuh("10:02:05", "5715", "srv-file-01", srcip="10.10.5.91", dstuser="kopral"),
        ]
        e = [modbus("10:03:00", "10.10.5.50")]
        with Evidence(w, e) as evs:
            incs = correlate.build_incidents(evs)
        self.assertEqual(len(incs), 3)
        by_entry = {i.entry_ip: i for i in incs}
        self.assertEqual(by_entry[ATK].identities, ["sertu"])
        self.assertEqual(by_entry[ATK].severity, "tinggi")   # brute force + login berhasil
        self.assertFalse(by_entry[ATK].has_ot_impact)
        self.assertEqual(by_entry["10.10.5.91"].identities, ["kopral"])
        ot = by_entry["10.10.5.50"]
        self.assertTrue(ot.has_ot_impact)
        self.assertTrue(any("tidak terhubung" in n for n in ot.notes))

    def test_login_internal_tanpa_rantai_bukan_insiden(self):
        w = [wazuh("10:00:00", "5715", "srv-file-01", srcip="10.10.5.66", dstuser="sertu")]
        with Evidence(w, []) as evs:
            self.assertEqual(correlate.build_incidents(evs), [])

    def test_shadow_sebelum_tmp_exec_tetap_derau(self):
        w = [
            wazuh("10:00:00", "5715", "pc-staf-07", srcip=ATK, dstuser="sertu"),
            wazuh("10:00:10", "100011", "pc-staf-07", event="shadow_read", cmd=""),
            wazuh("10:00:40", "100010", "pc-staf-07", event="tmp_exec", user="sertu"),
        ]
        with Evidence(w, []) as evs:
            inc, = correlate.build_incidents(evs)
        self.assertNotIn("shadow_read", [e.kind for e in inc.events])


class SourceTime(unittest.TestCase):
    """Bukti lab 6 Nov: agen mengirim batch ~20 dtk setelah kejadian."""

    def test_waktu_sumber_dipakai_bukan_waktu_manager(self):
        late = "10:20:06"     # waktu manager menerima batch
        w = [
            dict(wazuh(late, "5710", "pc-staf-07", srcip=ATK, dstuser="admin"),
                 predecoder={"timestamp": "Oct 28 10:19:26"}),
            dict(wazuh(late, "5715", "pc-staf-07", srcip=ATK, dstuser="sertu"),
                 predecoder={"timestamp": "Oct 28 10:19:37"}),
            wazuh(late, "100010", "pc-staf-07", event="tmp_exec", user="sertu",
                  time="2026-10-28T10:19:37"),
            wazuh(late, "100011", "pc-staf-07", event="shadow_read", time="2026-10-28T10:19:37"),
            # agen Wazuh (SCA) membaca shadow 18 dtk kemudian: bukan pencurian
            wazuh(late, "100011", "pc-staf-07", event="shadow_read", time="2026-10-28T10:19:55"),
            dict(wazuh(late, "5715", "srv-file-01", srcip="10.10.5.66", dstuser="sertu"),
                 predecoder={"timestamp": "Oct 28 10:19:38"}),
        ]
        with Evidence(w, [modbus("10:19:41", "10.10.5.7")]) as evs:
            inc, = correlate.build_incidents(evs)
        self.assertEqual(inc.start.strftime("%H:%M:%S"), "10:19:26")
        self.assertEqual([e.kind for e in inc.events],
                         ["brute_force", "auth_success", "tmp_exec", "shadow_read",
                          "auth_success", "modbus_write"])
        self.assertFalse(any("disesuaikan" in n for n in inc.notes))


class Narration(unittest.TestCase):
    def setUp(self):
        with Evidence(DEMO_WAZUH, DEMO_EVE) as evs:
            self.inc = correlate.build_incidents(evs)[0]
        self._orig = llm._call_ollama

    def tearDown(self):
        llm._call_ollama = self._orig

    def fake(self, judul, ringkasan, rek):
        content = json.dumps({"judul": judul, "ringkasan": ringkasan, "rekomendasi": rek})
        llm._call_ollama = lambda *a, **k: {"message": {"content": content}, "eval_count": 10}

    def test_narasi_valid_dipakai(self):
        self.fake("Genset dimatikan lewat srv-file-01",
                  f"Penyerang dari {ATK} masuk ke pc-staf-07 pukul 10:13:59 (bukti W6).",
                  ["Isolasi pc-staf-07 dan srv-file-01."])
        r = llm.summarize(self.inc)
        self.assertFalse(r["_meta"]["fallback"], r["_meta"]["warnings"])
        self.assertEqual(r["judul"], "Genset dimatikan lewat srv-file-01")

    def test_halusinasi_ditolak(self):
        cases = [
            "Penyerang memakai 8.8.8.8 (bukti W6).",       # IP asing
            "Terlihat pada bukti W99.",                      # bukti asing
            "Serangan dimulai pukul 09:00.",                 # waktu asing
            "Teknik T1486 dipakai.",                         # teknik asing
            "Host srv-db-02 juga terdampak.",                # host asing
        ]
        for ringkasan in cases:
            with self.subTest(ringkasan=ringkasan):
                self.fake("Judul", ringkasan, ["a"])
                r = llm.summarize(self.inc)
                self.assertTrue(r["_meta"]["rejected"])
                self.assertNotIn(ringkasan, r["ringkasan"])

    def test_cadangan_tanpa_ot_tidak_menyebut_genset(self):
        w = [
            wazuh("10:00:00", "5715", "pc-staf-07", srcip=ATK, dstuser="sertu"),
            wazuh("10:00:40", "100010", "pc-staf-07", event="tmp_exec", user="sertu"),
        ]
        with Evidence(w, []) as evs:
            inc, = correlate.build_incidents(evs)
        fb = llm._fallback(inc)
        text = " ".join([fb["judul"], fb["ringkasan"]] + fb["rekomendasi"]).lower()
        for word in ("genset", "plc", " ot"):
            self.assertNotIn(word, text)
        self.assertIn("sertu", text)


if __name__ == "__main__":
    unittest.main()
