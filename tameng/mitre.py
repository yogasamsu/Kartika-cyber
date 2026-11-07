"""Katalog sinyal Tameng dan pemetaan MITRE ATT&CK (Enterprise + ICS).

Pemetaan dilakukan oleh KODE, bukan LLM. Setiap sinyal yang dikenal ditautkan
ke teknik ATT&CK yang pasti, sehingga laporan tidak bergantung pada tebakan
model bahasa.
"""

# Teknik ATT&CK yang dipakai (id -> nama, domain).
TECHNIQUES = {
    "T1110":     ("Brute Force", "enterprise"),
    "T1078":     ("Valid Accounts", "enterprise"),
    "T1021.004": ("Remote Services: SSH", "enterprise"),
    "T1059.004": ("Command and Scripting Interpreter: Unix Shell", "enterprise"),
    "T1003.008": ("OS Credential Dumping: /etc/passwd and /etc/shadow", "enterprise"),
    "T1190":     ("Exploit Public-Facing Application", "enterprise"),
    "T1505.003": ("Server Software Component: Web Shell", "enterprise"),
    "T1491.002": ("Defacement: External Defacement", "enterprise"),
    "T0855":     ("Unauthorized Command Message", "ics"),
    "T0816":     ("Device Restart/Shutdown", "ics"),
    "T0826":     ("Loss of Availability", "ics"),
}

# Katalog sinyal: (sumber, id) -> metadata.
#   kind   : jenis kanonik dipakai mesin korelasi
#   label  : kalimat singkat untuk kronologi
#   tactic : taktik ATT&CK
#   tech   : daftar id teknik
#   domain : "it" atau "ot"
SIGNALS = {
    ("wazuh", "5710"): dict(kind="brute_force", label="Login SSH gagal (indikasi brute force)",
                            tactic="Credential Access", tech=["T1110"], domain="it"),
    ("wazuh", "5712"): dict(kind="brute_force", label="Brute force SSH (banyak kegagalan beruntun)",
                            tactic="Credential Access", tech=["T1110"], domain="it"),
    ("wazuh", "5715"): dict(kind="auth_success", label="Login SSH BERHASIL",
                            tactic="Initial Access / Lateral Movement", tech=["T1078", "T1021.004"], domain="it"),
    # Wazuh memakai 40112 (bukan 5715) bila login berhasil didahului rentetan kegagalan.
    ("wazuh", "40112"): dict(kind="auth_success", label="Login SSH BERHASIL setelah rentetan kegagalan",
                             tactic="Initial Access / Lateral Movement", tech=["T1078", "T1021.004"], domain="it"),
    ("wazuh", "5501"): dict(kind="pam_open", label="Sesi login dibuka (PAM)",
                            tactic="Initial Access", tech=["T1078"], domain="it"),
    ("wazuh", "100010"): dict(kind="tmp_exec", label="Eksekusi berkas dari /tmp",
                              tactic="Execution", tech=["T1059.004"], domain="it"),
    ("wazuh", "100011"): dict(kind="shadow_read", label="Pembacaan /etc/shadow",
                              tactic="Credential Access", tech=["T1003.008"], domain="it"),
    # Portal web (log akses JSON) dan File Integrity Monitoring Wazuh di web root.
    ("wazuh", "100020"): dict(kind="web_exploit", label="Unggahan berkas lewat celah plugin web",
                              tactic="Initial Access", tech=["T1190"], domain="it"),
    ("wazuh", "100021"): dict(kind="webshell_cmd", label="Perintah sistem lewat webshell",
                              tactic="Persistence / Execution", tech=["T1505.003", "T1059.004"], domain="it"),
    # 554 = berkas baru, 550 = isi berkas berubah (FIM). Hanya web root yang dipantau.
    ("wazuh", "554"): dict(kind="web_file_added", label="Berkas baru di direktori situs web",
                           tactic="Persistence", tech=["T1505.003"], domain="it"),
    ("wazuh", "550"): dict(kind="web_file_changed", label="Isi halaman situs web berubah",
                           tactic="Impact", tech=["T1491.002"], domain="it"),
    # Suricata (OT) — semua fungsi tulis Modbus dianggap perintah tak sah ke PLC.
    ("suricata", "7000005"): dict(kind="modbus_write", label="Perintah tulis Modbus (fc5) ke PLC",
                                  tactic="Impair Process Control", tech=["T0855", "T0816"], domain="ot"),
    ("suricata", "7000006"): dict(kind="modbus_write", label="Perintah tulis Modbus (fc6) ke PLC",
                                  tactic="Impair Process Control", tech=["T0855", "T0816"], domain="ot"),
    ("suricata", "7000015"): dict(kind="modbus_write", label="Perintah tulis Modbus (fc15) ke PLC",
                                  tactic="Impair Process Control", tech=["T0855", "T0816"], domain="ot"),
    ("suricata", "7000016"): dict(kind="modbus_write", label="Perintah tulis Modbus (fc16) ke PLC",
                                  tactic="Impair Process Control", tech=["T0855", "T0816"], domain="ot"),
    # Suricata mode IPS: perintah tulis dari host tak sah DIJATUHKAN sebelum sampai ke PLC.
    ("suricata", "7100005"): dict(kind="modbus_block", label="Perintah tulis Modbus (fc5) ke PLC DIBLOKIR",
                                  tactic="Impair Process Control", tech=["T0855"], domain="ot"),
    ("suricata", "7100006"): dict(kind="modbus_block", label="Perintah tulis Modbus (fc6) ke PLC DIBLOKIR",
                                  tactic="Impair Process Control", tech=["T0855"], domain="ot"),
    ("suricata", "7100015"): dict(kind="modbus_block", label="Perintah tulis Modbus (fc15) ke PLC DIBLOKIR",
                                  tactic="Impair Process Control", tech=["T0855"], domain="ot"),
    ("suricata", "7100016"): dict(kind="modbus_block", label="Perintah tulis Modbus (fc16) ke PLC DIBLOKIR",
                                  tactic="Impair Process Control", tech=["T0855"], domain="ot"),
    ("suricata", "7000100"): dict(kind="modbus_connect", label="Koneksi ke port Modbus PLC",
                                  tactic="Discovery", tech=[], domain="ot"),
}


def lookup(source, sid):
    """Kembalikan metadata sinyal, atau None bila tidak dikenal."""
    return SIGNALS.get((source, str(sid)))


def technique_name(tid):
    t = TECHNIQUES.get(tid)
    return t[0] if t else tid


def technique_domain(tid):
    t = TECHNIQUES.get(tid)
    return t[1] if t else "enterprise"
