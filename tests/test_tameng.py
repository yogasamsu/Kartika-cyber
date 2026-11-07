"""Tes regresi mesin Tameng dengan bukti sintetis (tanpa SSD, tanpa LLM).

Jalankan dari root repo:  python3 -m unittest discover -s tests -v
"""
import json
import os
import tempfile
import unittest

import io

from tameng import config, correlate, events, llm, mitre, notify, report, vuln


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


class ModeBlokir(unittest.TestCase):
    """Suricata mode IPS: perintah Modbus penyerang dijatuhkan, genset tetap menyala."""

    def test_serangan_ot_digagalkan(self):
        w = DEMO_WAZUH
        e = [modbus("10:14:00", "10.10.5.7", sid=7100005)]
        with Evidence(w, e) as evs:
            inc, = correlate.build_incidents(evs)
        self.assertFalse(inc.has_ot_impact)
        self.assertTrue(inc.ot_blocked)
        self.assertEqual(inc.severity, "tinggi")
        self.assertIn("DIBLOKIR", inc.steps[-1].text)
        self.assertTrue(any("digagalkan" in n for n in inc.notes))
        fb = llm._fallback(inc)
        self.assertIn("digagalkan", fb["judul"])
        self.assertNotIn("dimatikan", fb["judul"] + fb["ringkasan"])

    def test_login_lateral_di_detik_sama_tetap_terangkai(self):
        # Bukti asli 7 Nov: login lateral ke srv-file-01 tercatat lebih dulu di berkas
        # daripada login penyerang ke pc-staf-07, padahal detiknya sama.
        w = [
            wazuh("05:08:38", "5710", "pc-staf-07", srcip=ATK, dstuser="admin"),
            wazuh("05:08:45", "5715", "srv-file-01", srcip="10.10.5.66", dstuser="sertu"),
            wazuh("05:08:45", "40112", "pc-staf-07", srcip=ATK, dstuser="sertu"),
        ]
        with Evidence(w, [modbus("05:08:47", "10.10.5.7")]) as evs:
            inc, = correlate.build_incidents(evs)
        self.assertEqual(inc.identities, ["sertu"])
        self.assertTrue(inc.has_ot_impact)
        self.assertEqual([e.kind for e in inc.events],
                         ["brute_force", "auth_success", "auth_success", "modbus_write"])
        self.assertIn("srv-file-01", inc.hosts)

    def test_perintah_hmi_resmi_bukan_serangan(self):
        e = [modbus("10:00:00", "10.10.5.30"), modbus("10:00:05", "10.10.5.30", sid=7000006)]
        with Evidence([], e) as evs:
            self.assertEqual(correlate.build_incidents(evs), [])


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


def web(t, rid, url, src=ATK, method="GET"):
    return {"timestamp": f"2026-10-28T{t}.000+0000", "rule": {"id": rid, "level": 12},
            "agent": {"name": "web-portal"},
            "data": {"srcip": src, "url": url, "method": method, "time": f"2026-10-28T{t}"}, "id": t}


def fim(t, rid, path, diff=""):
    return {"timestamp": f"2026-10-28T{t}.000+0000", "rule": {"id": rid, "level": 7},
            "agent": {"name": "web-portal"}, "syscheck": {"path": path, "diff": diff}, "id": t}


SHELL = "/var/www/html/wp-content/uploads/wp-cache.php"
DEFACE_WAZUH = [
    web("11:00:01", "100020", "/wp-admin/admin-ajax.php?action=fm_upload", method="POST"),
    fim("11:00:02", "554", SHELL),
    web("11:00:05", "100021", "/wp-content/uploads/wp-cache.php?cmd=id"),
    web("11:00:07", "100021", "/wp-content/uploads/wp-cache.php?cmd=cp /tmp/h.html /var/www/html/index.html"),
    fim("11:00:08", "550", "/var/www/html/index.html", diff="> HACKED"),
]


class Deface(unittest.TestCase):
    """Skenario deface situs (mirip kasus mil.id): celah plugin -> webshell -> halaman diubah."""

    def setUp(self):
        with Evidence(DEFACE_WAZUH, []) as evs:
            self.incs = correlate.build_incidents(evs)

    def test_satu_insiden_rantai_lengkap(self):
        inc, = self.incs
        self.assertTrue(inc.defaced)
        self.assertEqual(inc.severity, "tinggi")
        self.assertEqual(inc.entry_ip, ATK)
        self.assertEqual(inc.hosts, ["web-portal"])
        self.assertEqual([e.kind for e in inc.events],
                         ["web_exploit", "web_file_added", "webshell_cmd", "webshell_cmd", "web_file_changed"])
        self.assertEqual([t[0] for t in inc.techniques],
                         ["T1190", "T1505.003", "T1059.004", "T1491.002"])

    def test_langkah_kronologi(self):
        steps = self.incs[0].steps
        self.assertEqual(len(steps), 4)        # dua perintah webshell digabung
        self.assertIn("webshell ditanam", steps[1].text)
        self.assertIn("`id`", steps[2].text)
        self.assertIn("DEFACE", steps[3].text)

    def test_cadangan_deface(self):
        fb = llm._fallback(self.incs[0])
        self.assertIn("Deface", fb["judul"])
        rek = " ".join(fb["rekomendasi"])
        self.assertIn("backup bersih", rek)
        self.assertIn(SHELL, rek)
        self.assertNotIn("genset", (fb["judul"] + fb["ringkasan"] + rek).lower())

    def test_fakta_llm_menyebut_dampak_publik(self):
        self.assertIn("deface", llm._facts(self.incs[0]))

    def test_fim_di_luar_web_root_diabaikan(self):
        with Evidence([fim("11:00:00", "550", "/etc/hosts")], []) as evs:
            self.assertEqual(evs, [])

    def test_perubahan_tanpa_eksploitasi_tetap_dilaporkan(self):
        with Evidence([fim("11:00:00", "550", "/var/www/html/index.html")], []) as evs:
            inc, = correlate.build_incidents(evs)
        self.assertTrue(inc.defaced)
        self.assertEqual(inc.severity, "sedang")
        self.assertTrue(any("pembaruan resmi" in n for n in inc.notes))

    def test_deface_tidak_bergabung_dengan_serangan_ssh(self):
        with Evidence(DEMO_WAZUH + DEFACE_WAZUH, DEMO_EVE) as evs:
            incs = correlate.build_incidents(evs)
        self.assertEqual(len(incs), 2)


class Edukasi(unittest.TestCase):
    """F7: materi belajar tetap per teknik, ikut di laporan dan JSON."""

    def test_semua_teknik_punya_materi(self):
        for tid in mitre.TECHNIQUES:
            with self.subTest(tid=tid):
                e = mitre.edukasi(tid)
                self.assertIsNotNone(e)
                for k in ("apa", "bahaya", "tindakan", "cegah"):
                    self.assertTrue(e[k].strip())

    def test_materi_ikut_urutan_teknik_insiden(self):
        with Evidence(DEFACE_WAZUH, []) as evs:
            inc, = correlate.build_incidents(evs)
        edu = report.edukasi_list(inc)
        self.assertEqual([x["id"] for x in edu], [t[0] for t in inc.techniques])
        md = report.render_markdown(inc, llm._fallback(inc))
        self.assertIn("## Pelajari insiden ini", md)
        self.assertIn("### T1491.002", md)
        self.assertLess(md.index("## Rekomendasi"), md.index("## Pelajari insiden ini"))

    def test_materi_ot_hanya_di_insiden_ot(self):
        with Evidence(DEFACE_WAZUH, []) as evs:
            inc, = correlate.build_incidents(evs)
        self.assertNotIn("PLC", report.render_markdown(inc, llm._fallback(inc)))
        with Evidence(DEMO_WAZUH, DEMO_EVE) as evs:
            inc, = correlate.build_incidents(evs)
        self.assertIn("### T0855", report.render_markdown(inc, llm._fallback(inc)))


def ar_block(t, src=ATK, host="web-portal", command="add"):
    return {"timestamp": f"2026-10-28T{t}.000+0000", "rule": {"id": "651", "level": 3},
            "agent": {"name": host}, "id": t,
            "data": {"command": command, "parameters": {"alert": {"data": {"srcip": src}}}}}


class BlokirOtomatisIT(unittest.TestCase):
    """Netralisasi IT: Wazuh active response memblokir IP penyerang."""

    def test_blokir_menempel_ke_rantai_dan_menghentikan_deface(self):
        w = DEFACE_WAZUH[:3] + [ar_block("11:00:06")]
        with Evidence(w, []) as evs:
            inc, = correlate.build_incidents(evs)
        self.assertTrue(inc.it_blocked)
        self.assertFalse(inc.defaced)
        self.assertIn("DIBLOKIR otomatis", inc.steps[-1].text)
        self.assertTrue(any("Netralisasi otomatis" in n for n in inc.notes))
        fb = llm._fallback(inc)
        self.assertIn("diblokir otomatis", fb["judul"])
        self.assertNotIn(f"Blokir {ATK} di perimeter.", fb["rekomendasi"])

    def test_blokir_tanpa_rantai_bukan_insiden(self):
        with Evidence([ar_block("11:00:00", src="10.10.5.77")], []) as evs:
            self.assertEqual(correlate.build_incidents(evs), [])

    def test_pembukaan_blokir_diabaikan(self):
        with Evidence([ar_block("11:00:00", command="delete")], []) as evs:
            self.assertEqual(evs, [])


SAMPLE_VULN = os.path.join(os.path.dirname(__file__), "..", "lab", "sample", "kerentanan-alerts.json")


class Kerentanan(unittest.TestCase):
    def test_prioritas_kev_dan_aset_publik_di_atas(self):
        s = vuln.summarize(SAMPLE_VULN)
        top = s["prioritas"][0]
        self.assertEqual((top["cve"], top["host"]), ("CVE-2020-25213", "web-portal"))
        self.assertTrue(top["kev"])
        self.assertIn("terbuka ke publik", top["alasan"])
        self.assertEqual(s["total_kev"], 2)
        self.assertEqual(len(s["tambal_dulu"]), 3)

    def test_host_insiden_naik_prioritas(self):
        a = {p["cve"] + p["host"]: p["skor"] for p in vuln.summarize(SAMPLE_VULN)["prioritas"]}
        b = {p["cve"] + p["host"]: p["skor"] for p in vuln.summarize(SAMPLE_VULN, ["pc-staf-07"])["prioritas"]}
        self.assertEqual(b["CVE-2024-6387pc-staf-07"] - a["CVE-2024-6387pc-staf-07"], 2)

    def test_status_solved_dan_sca(self):
        rows = [
            {"agent": {"name": "pc-staf-07"}, "data": {"vulnerability": {"cve": "CVE-1", "status": "Solved"}}},
            {"agent": {"name": "pc-staf-07"}, "data": {"sca": {"check": {"title": "Cek A", "result": "failed"}}}},
            {"agent": {"name": "pc-staf-07"}, "data": {"sca": {"check": {"title": "Cek B", "result": "passed"}}}},
        ]
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write("\n".join(json.dumps(r) for r in rows))
        try:
            s = vuln.summarize(f.name)
        finally:
            os.unlink(f.name)
        self.assertEqual(s["total_cve"], 0)
        self.assertEqual(s["sca_gagal"], {"pc-staf-07": ["Cek A"]})


class Notifikasi(unittest.TestCase):
    def run_notifier(self, *rounds):
        out = io.StringIO()
        n = notify.Notifier(log_path="", desktop=False, webhook="", out=out)
        sent = []
        for w, e in rounds:
            with Evidence(w, e) as evs:
                sent.append([m["jenis"] for m in n.process(correlate.build_incidents(evs), llm._fallback)])
        return sent, out.getvalue()

    def test_baru_lalu_diam_bila_tidak_berubah(self):
        sent, out = self.run_notifier((DEFACE_WAZUH, []), (DEFACE_WAZUH, []))
        self.assertEqual(sent, [["BARU"], []])
        self.assertIn("langkah pertama:", out)

    def test_memburuk_saat_muncul_dampak_ot(self):
        w = DEMO_WAZUH
        sent, _ = self.run_notifier((w, []), (w, DEMO_EVE))
        self.assertEqual(sent, [["BARU"], ["MEMBURUK"]])

    def test_ditangani_saat_diblokir(self):
        base = DEFACE_WAZUH[:3]
        sent, _ = self.run_notifier((base, []), (base + [ar_block("11:00:06")], []))
        self.assertEqual(sent, [["BARU"], ["DITANGANI"]])


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
