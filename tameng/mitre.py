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
    # Respons otomatis Wazuh (active response firewall-drop): IP penyerang diblokir di host.
    ("wazuh", "651"): dict(kind="ip_blocked", label="IP penyerang DIBLOKIR otomatis (active response)",
                           tactic="Respons", tech=[], domain="it"),
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


# Edukasi SDM: penjelasan tetap per teknik untuk analis junior (bintara siber).
# Ditulis manusia dan disimpan di kode, bukan dibuat LLM, supaya materi belajar
# tidak bisa mengarang. Tiap entri menjawab tiga pertanyaan:
#   apa      : apa yang dilakukan penyerang, dalam bahasa sehari-hari
#   bahaya   : kenapa ini berbahaya bagi satuan
#   tindakan : yang dikerjakan analis jaga sekarang
#   cegah    : yang dikerjakan satuan supaya tidak terulang
EDUKASI = {
    "T1110": dict(
        apa="Penyerang menebak kata sandi berkali-kali, biasanya dengan daftar sandi umum, sampai ada yang cocok.",
        bahaya="Satu akun bersandi lemah sudah cukup untuk masuk ke jaringan satuan.",
        tindakan="Catat IP sumber dan akun yang dicoba. Periksa apakah ada login BERHASIL dari IP yang sama sesudahnya.",
        cegah="Wajibkan sandi panjang, kunci akun setelah beberapa kali gagal, dan batasi SSH hanya dari jaringan admin."),
    "T1078": dict(
        apa="Penyerang masuk memakai akun asli milik personel, sehingga terlihat seperti pengguna biasa.",
        bahaya="Aktivitasnya sulit dibedakan dari pekerjaan normal, dan hak akses akun itu ikut jatuh ke tangan penyerang.",
        tindakan="Hubungi pemilik akun: apakah dia yang login? Bila bukan, reset sandinya dan putus sesi yang aktif.",
        cegah="Pasang autentikasi dua langkah untuk akses jarak jauh dan tinjau akun yang jarang dipakai."),
    "T1021.004": dict(
        apa="Penyerang memakai SSH untuk mengendalikan komputer dari jauh, lalu melompat ke komputer lain.",
        bahaya="Dari satu PC staf, penyerang bisa berpindah ke server penting tanpa perlu menembus perimeter lagi.",
        tindakan="Telusuri semua login SSH dari host yang sudah dikuasai. Tiap host tujuan ikut diperiksa.",
        cegah="Segmentasi jaringan: PC staf tidak perlu bisa SSH ke server atau jaringan kendali."),
    "T1059.004": dict(
        apa="Penyerang menjalankan perintah atau skrip shell di komputer korban, sering dari folder /tmp.",
        bahaya="Ini tanda penyerang sudah memegang kendali dan mulai menjalankan alatnya sendiri.",
        tindakan="Amankan salinan skrip sebagai bukti (catat hash-nya) sebelum dihapus, lalu isolasi host.",
        cegah="Pasang /tmp dengan opsi noexec dan pantau eksekusi dari folder sementara."),
    "T1003.008": dict(
        apa="Penyerang membaca /etc/shadow, berkas berisi hash kata sandi semua akun lokal.",
        bahaya="Hash bisa dipecahkan di luar jaringan; sandi yang sama sering dipakai di host lain.",
        tindakan="Anggap semua sandi akun lokal di host itu bocor. Ganti sandinya, terutama yang juga dipakai di tempat lain.",
        cegah="Jangan pakai sandi yang sama di banyak host; batasi akun yang punya hak sudo."),
    "T1190": dict(
        apa="Penyerang memanfaatkan celah pada aplikasi yang terbuka ke internet, misalnya plugin situs yang belum diperbarui.",
        bahaya="Situs publik bisa diakses siapa saja, jadi celahnya bisa dipakai tanpa perlu akun.",
        tindakan="Cari tahu aplikasi atau plugin mana yang diserang dari URL di bukti, lalu matikan sementara.",
        cegah="Perbarui CMS dan plugin secara rutin, hapus plugin yang tidak dipakai, dan pasang WAF di depan situs."),
    "T1505.003": dict(
        apa="Penyerang menaruh webshell: berkas kecil di server web yang menerima perintah lewat alamat situs.",
        bahaya="Selama webshell masih ada, penyerang bisa kembali kapan saja walaupun celah awalnya sudah ditutup.",
        tindakan="Salin berkas webshell ke media bukti dan catat hash-nya, baru hapus. Cari berkas serupa di folder unggahan.",
        cegah="Larang eksekusi skrip di folder unggahan dan pantau berkas baru di direktori situs (FIM)."),
    "T1491.002": dict(
        apa="Penyerang mengganti tampilan halaman situs publik (deface), biasanya dengan pesan atau logo kelompoknya.",
        bahaya="Merusak citra dan kepercayaan publik pada satuan; sering juga dipakai sebagai propaganda.",
        tindakan="Pasang halaman pemeliharaan, laporkan ke atasan, dan pulihkan dari backup bersih yang sudah diverifikasi.",
        cegah="Simpan backup situs yang terpisah dari server dan uji pemulihannya secara berkala."),
    "T0855": dict(
        apa="Penyerang mengirim perintah ke PLC (pengendali mesin) dari komputer yang bukan HMI resmi.",
        bahaya="PLC menjalankan perintah apa pun yang diterimanya; mesin fisik seperti genset bisa dimatikan.",
        tindakan="Pastikan status mesin lewat HMI resmi atau cek fisik, lalu cari komputer pengirim perintah.",
        cegah="Hanya HMI resmi yang boleh menulis ke PLC; pakai mode blokir Tameng untuk menjatuhkan perintah lain."),
    "T0816": dict(
        apa="Perintah penyerang mematikan atau menyalakan ulang perangkat di lapangan.",
        bahaya="Layanan yang bergantung pada perangkat itu ikut berhenti, misalnya listrik cadangan markas.",
        tindakan="Nyalakan kembali perangkat secara manual sesuai SOP dan catat lama gangguannya.",
        cegah="Siapkan prosedur pengoperasian manual dan uji secara berkala."),
    "T0826": dict(
        apa="Proses atau layanan fisik berhenti tersedia akibat serangan.",
        bahaya="Dampaknya langsung terasa pada operasi satuan, bukan hanya pada data.",
        tindakan="Laporkan dampak ke komandan dan jalankan rencana cadangan.",
        cegah="Tentukan perangkat mana yang kritis dan siapkan cadangannya."),
}


def edukasi(tid):
    """Materi edukasi untuk sebuah teknik, atau None bila belum ada."""
    return EDUKASI.get(tid)
