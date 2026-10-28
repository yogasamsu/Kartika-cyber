# Manager Wazuh + aturan kustom Tameng dibakukan ke dalam image.
# (Bind mount satu file tidak andal di Docker Desktop: inode berubah saat
#  file di host ditimpa, sehingga container tetap melihat versi lama.)
FROM wazuh/wazuh-manager:4.14.9

COPY local_rules.xml /var/ossec/etc/rules/local_rules.xml
RUN chown root:wazuh /var/ossec/etc/rules/local_rules.xml && chmod 660 /var/ossec/etc/rules/local_rules.xml

# authd: izinkan pendaftaran ulang nama agen yang sama (lab sering di-recreate).
# Default 4.14 menolak duplikat yang baru terdaftar; set waktu paksa ke 0.
RUN sed -i 's#[[:space:]]*</auth>#    <force>\n      <enabled>yes</enabled>\n      <key_mismatch>yes</key_mismatch>\n      <disconnected_time enabled="yes">0</disconnected_time>\n      <after_registration_time>0</after_registration_time>\n    </force>\n  </auth>#' /var/ossec/etc/ossec.conf
