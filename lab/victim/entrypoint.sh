#!/usr/bin/env bash
# Entrypoint korban: rsyslog + sshd + sensor Tameng + Wazuh agent.
set -u

MANAGER="${WAZUH_MANAGER:-10.10.5.2}"
AGENT_NAME="${AGENT_NAME:-$(hostname)}"

# auth.log butuh rsyslogd (jalankan langsung; "service" tidak bekerja tanpa systemd).
/usr/sbin/rsyslogd 2>/dev/null
mkdir -p /run/sshd
/usr/sbin/sshd

# auditd dicoba; di VM Docker Desktop biasanya gagal -> sensor /proc jadi andalan.
if auditd 2>/dev/null; then
  auditctl -R /etc/audit/rules.d/tameng.rules >/dev/null 2>&1
  echo "[entrypoint] auditd AKTIF"
else
  echo "[entrypoint] auditd tidak aktif; pakai sensor /proc"
fi

# Sensor endpoint Tameng (tmp_exec, shadow_read).
python3 /usr/local/bin/tameng-sensor.py &
echo "[entrypoint] sensor Tameng jalan (pid $!)"

# Daftarkan agent ke manager, set address, lalu jalankan.
/var/ossec/bin/agent-auth -m "$MANAGER" -A "$AGENT_NAME" >/dev/null 2>&1
sed -i "s|<address>.*</address>|<address>${MANAGER}</address>|" /var/ossec/etc/ossec.conf
/var/ossec/bin/wazuh-control start >/dev/null 2>&1
echo "[entrypoint] agent '${AGENT_NAME}' -> manager ${MANAGER}"

touch /var/ossec/logs/ossec.log
exec tail -F /var/ossec/logs/ossec.log
