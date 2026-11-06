# Korban Linux: tampak seperti workstation/server Ubuntu biasa.
# Berisi sshd (menghasilkan auth.log nyata), auditd (opsional), dan Wazuh agent.
FROM ubuntu:22.04

ARG WAZUH_VERSION=4.14.9
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
      openssh-server openssh-client sshpass auditd audispd-plugins \
      curl gnupg2 ca-certificates lsb-release procps sudo rsyslog \
      python3 iproute2 iputils-ping netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Repo resmi Wazuh + agent (arm64 tersedia).
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH \
      | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import \
    && chmod 644 /usr/share/keyrings/wazuh.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
      > /etc/apt/sources.list.d/wazuh.list \
    && apt-get update \
    && WAZUH_MANAGER="10.10.5.2" apt-get install -y wazuh-agent=${WAZUH_VERSION}-1 \
    && rm -rf /var/lib/apt/lists/*

# User "sertu" yang bisa SSH (kredensial lemah sengaja, untuk skenario curian).
RUN useradd -m -s /bin/bash sertu && echo 'sertu:Mawar2024' | chpasswd \
    && usermod -aG sudo sertu \
    && mkdir -p /run/sshd

COPY victim/audit-tameng.rules /etc/audit/rules.d/tameng.rules
COPY victim/tameng-sensor.py /usr/local/bin/tameng-sensor.py
COPY victim/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Agent membaca auth.log (sshd) dan log sensor Tameng sejak boot pertama.
# only-future-events=no: setelah agent memuat ulang konfigurasi dari manager
# (±1 menit setelah terhubung), logcollector melanjutkan dari posisi terakhir.
# Default-nya membaca dari akhir berkas, sehingga log di sela restart hilang.
RUN cat >> /var/ossec/etc/ossec.conf <<'EOF'
<ossec_config>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
    <only-future-events>no</only-future-events>
  </localfile>
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/tameng-sensor.log</location>
    <only-future-events>no</only-future-events>
  </localfile>
</ossec_config>
EOF

EXPOSE 22
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
