FROM debian:bookworm-slim

# Install OpenSSH + tools a real SCADA workstation operator would have
RUN apt-get update --fix-missing && apt-get install -y --no-install-recommends \
    openssh-server \
    python3 \
    python3-pip \
    netcat-openbsd \
    curl \
    iproute2 \
    iputils-ping \
    nmap \
    procps \
    cron \
    sudo \
    less \
    vim-tiny \
    iptables \
    && rm -rf /var/lib/apt/lists/*

# ── Create operator and engineer roles ────────────────────────────────────────
# operator  — works on the machine; has SSH access to PLC subnet
# engineer  — read-only monitoring; uses historian API for data
RUN useradd -m -s /bin/bash -g operator operator && \
    echo "operator:operator123" | chpasswd && \
    useradd -m -s /bin/bash engineer && \
    echo "engineer:engineer456" | chpasswd

# ── SSH server configuration ───────────────────────────────────────────────────
RUN mkdir /var/run/sshd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config && \
    sed -i 's/UsePAM yes/UsePAM no/' /etc/ssh/sshd_config && \
    echo "Port 2222" >> /etc/ssh/sshd_config && \
    ssh-keygen -A

# ── Realistic MOTD ─────────────────────────────────────────────────────────────
RUN printf '\n\
=============================================================\n\
  SCADA Workstation — Purdue Level 2\n\
  Site   : Pump Station 01  |  Asset ID: SCADA-WS-01\n\
  Roles  : operator (rw), engineer (ro)\n\
\n\
  Authorized users only.  All sessions are logged.\n\
  Unauthorized access will be prosecuted.\n\
=============================================================\n\
  OT Network reachable from this host:\n\
    plc_simulator  :502    (Modbus PLC — SIMATIC S7 gateway)\n\
    ics_s7_plc     :102    (Siemens S7-300 direct)\n\
    ics_dnp3       :20000  (DNP3 outstation)\n\
    ics_historian  :8086   (InfluxDB — read-only)\n\
=============================================================\n' \
    > /etc/motd

# ── /etc/hosts — OT device names visible from SCADA ──────────────────────────
# Network resolution is handled by Docker compose DNS

# ── Legitimate data-collection script (justifies the SSH path) ────────────────
# The historian_api's cron calls this via SSH every 5 minutes:
#   ssh operator@ics_scada_ssh -p 2222 /opt/historian/collect_scada_logs.sh
RUN mkdir -p /opt/historian && printf '#!/bin/bash\n\
# collect_scada_logs.sh — run by historian cron every 5 min\n\
# Pulls Modbus register snapshot and appends to daily log archive.\n\
LOGDIR=/var/log/scada\n\
mkdir -p "$LOGDIR"\n\
STAMP=$(date +%%Y%%m%%d_%%H%%M%%S)\n\
echo "$STAMP: collecting PLC state from plc_simulator:502" >> "$LOGDIR/collect.log"\n\
# (pymodbus read would go here in production)\n\
echo "$STAMP: done" >> "$LOGDIR/collect.log"\n' \
    > /opt/historian/collect_scada_logs.sh && \
    chmod +x /opt/historian/collect_scada_logs.sh && \
    chown operator:operator /opt/historian/collect_scada_logs.sh

# ── Fake bash_history for operator ────────────────────────────────────────────
# Shows prior SSH sessions into PLC — realistic forensic artifact
RUN mkdir -p /home/operator && printf '\
nmap -sT -n -p 502,102,20000 plc_simulator\n\
python3 -c "from pymodbus.client import ModbusTcpClient; c=ModbusTcpClient(\"plc_simulator\"); c.connect(); r=c.read_holding_registers(100,4); print(r.registers)"\n\
ssh root@plc_simulator\n\
ping -c 3 plc_simulator\n\
ping -c 3 ics_s7_plc\n\
cat /opt/historian/collect_scada_logs.sh\n\
tail -20 /var/log/scada/collect.log\n\
ip addr show\n\
cat /etc/hosts\n' \
    > /home/operator/.bash_history && \
    chown operator:operator /home/operator/.bash_history

# ── Operator shell prompt ──────────────────────────────────────────────────────
RUN echo 'PS1="[\u@scada-ws-01 \W]\$ "' >> /home/operator/.bashrc && \
    echo 'echo ""' >> /home/operator/.bashrc && \
    echo 'echo "Last login: $(date -u) from ics_historian_api"' >> /home/operator/.bashrc && \
    echo 'echo ""' >> /home/operator/.bashrc

# Engineer gets read-only prompt
RUN echo 'PS1="[\u@scada-ws-01 \W]\$ "' >> /home/engineer/.bashrc && \
    echo 'echo "Engineer role: read-only access to historian data"' >> /home/engineer/.bashrc

# ── Human Artifacts & Credential Leaks ─────────────────────────────────────────
# Operator notes (implies Modbus issues and leaks operator context)
RUN printf "Pump 2 pressure unstable — check Modbus register 100\nEnsure we don't exceed 200 PSI on testing.\n" > /home/operator/notes.txt && \
    chown operator:operator /home/operator/notes.txt

RUN printf "1. Update PLC firmware\n2. Change default SCADA password (operator:operator123) before audit!!\n3. Check why historian API crashes sometimes\n" > /home/operator/todo.txt && \
    chown operator:operator /home/operator/todo.txt

RUN printf "[ERROR] Cannot reach Historian API (Connection refused)\n[WARN] Connection to InfluxDB requires manual flush.\n" > /home/engineer/debug.log && \
    chown engineer:engineer /home/engineer/debug.log

RUN mkdir -p /var/log && printf "2023-10-12: System restart by admin.\n2023-11-05: Maintenance window. Operator used default auth 'operator123' to SSH in. Must fix.\n" > /var/log/scada_maintenance.log && \
    chmod 644 /var/log/scada_maintenance.log

# Engineer bash history (shows them trying to escalate or find info)
RUN printf 'cat /var/log/scada_maintenance.log\nping plc_simulator\nnc -vz plc_simulator 502\ncat /home/engineer/debug.log\n' > /home/engineer/.bash_history && \
    chown engineer:engineer /home/engineer/.bash_history

# ── Entrypoint with Access Control ──────────────────────────────────────────────
# We block out-bound traffic to the PLC for anyone EXCEPT the operator user.
RUN printf '#!/bin/bash\n\
iptables -A OUTPUT -d plc_simulator -p tcp --dport 502 -m owner ! --uid-owner operator -j DROP\n\
iptables -A OUTPUT -d ics_s7_plc -p tcp --dport 102 -m owner ! --uid-owner operator -j DROP\n\
iptables -A OUTPUT -d ics_dnp3 -p tcp --dport 20000 -m owner ! --uid-owner operator -j DROP\n\
iptables -A OUTPUT -d fake_plc_sim -p tcp --dport 502 -m owner ! --uid-owner operator -j DROP\n\
exec /usr/sbin/sshd -D -p 2222 -e\n' > /entrypoint.sh && \
    chmod +x /entrypoint.sh

# ── SSH on port 2222 ──────────────────────────────────────────────────────────
EXPOSE 2222

CMD ["/entrypoint.sh"]
