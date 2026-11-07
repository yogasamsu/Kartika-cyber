# Manager Wazuh + aturan kustom Tameng dibakukan ke dalam image.
# (Bind mount satu file tidak andal di Docker Desktop: inode berubah saat
#  file di host ditimpa, sehingga container tetap melihat versi lama.)
FROM wazuh/wazuh-manager:4.14.9

COPY local_rules.xml /var/ossec/etc/rules/local_rules.xml
RUN chown root:wazuh /var/ossec/etc/rules/local_rules.xml && chmod 660 /var/ossec/etc/rules/local_rules.xml

# authd: izinkan pendaftaran ulang nama agen yang sama (lab sering di-recreate).
# Default 4.14 menolak duplikat yang baru terdaftar; set waktu paksa ke 0.
# disconnected_time dimatikan: korban yang di-recreate tanpa restart manager
# tetap boleh mengganti agen lama yang di mata manager masih "Active".
RUN sed -i 's#[[:space:]]*</auth>#    <force>\n      <enabled>yes</enabled>\n      <key_mismatch>yes</key_mismatch>\n      <disconnected_time enabled="no">0</disconnected_time>\n      <after_registration_time>0</after_registration_time>\n    </force>\n  </auth>#' /var/ossec/etc/ossec.conf

# Netralisasi otomatis IT (active response firewall-drop, 10 menit):
#   5712   = brute force SSH (>= 8 kegagalan beruntun; skenario demo hanya 3 kali gagal,
#            jadi babak 1 dan 2 tidak terpengaruh)
#   100021 = perintah lewat webshell (log akses portal)
# Agen mencatat ke active-responses.log; Wazuh membuat alert 651 yang dibaca Tameng.
RUN cat >> /var/ossec/etc/ossec.conf <<'XML'
<ossec_config>
  <active-response>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>5712,100021</rules_id>
    <timeout>600</timeout>
  </active-response>
</ossec_config>
XML
