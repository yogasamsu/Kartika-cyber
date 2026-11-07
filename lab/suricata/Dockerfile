# Suricata + aturan Modbus Tameng (di-bake agar tidak kena masalah inode mount).
# Versi dipatok supaya lab bisa diulang; iptables dipasang untuk mode IPS (NFQUEUE).
FROM jasonish/suricata:8.0.8
RUN dnf install -y -q iptables-nft && dnf clean all
COPY tameng.rules tameng-ips.rules /etc/suricata/rules/
COPY entrypoint.sh /usr/local/bin/tameng-suricata.sh
RUN chmod +x /usr/local/bin/tameng-suricata.sh
ENTRYPOINT ["/usr/local/bin/tameng-suricata.sh"]
