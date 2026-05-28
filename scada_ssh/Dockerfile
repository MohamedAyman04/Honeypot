# syntax=docker/dockerfile:1.4
FROM debian:bookworm-slim

# ── System tools ───────────────────────────────────────────────────────────────
# Packages a real SCADA workstation would carry: SSH server, Python 3,
# network diagnostics, cron, sudo, lightweight editors.
RUN apt-get update --fix-missing && apt-get install -y --no-install-recommends \
    openssh-server \
    python3 \
    python3-pip \
    netcat-openbsd \
    curl \
    iproute2 \
    iputils-ping \
    dnsutils \
    nmap \
    procps \
    cron \
    sudo \
    less \
    vim-tiny \
    iptables \
    wget \
    && rm -rf /var/lib/apt/lists/*

# ── Install mbtget (Modbus CLI read/write tool) ───────────────────────────────
RUN wget -q --no-check-certificate https://raw.githubusercontent.com/sourceperl/mbtget/master/scripts/mbtget \
    -O /usr/local/bin/mbtget && \
    chmod +x /usr/local/bin/mbtget && \
    python3 -c "with open('/usr/local/bin/mbtget', 'r') as f: t = f.read(); t = t.replace('[a-z][a-z0-9\\\\.\\\\-]+', '[a-z][a-z0-9\\\\._\\\\-]+'); open('/usr/local/bin/mbtget', 'w').write(t)"

# ── Python dependencies for the physics REST API ───────────────────────────────
# flask  — lightweight REST server
# redis  — shared state store with physics_simulator
RUN pip3 install --no-cache-dir --break-system-packages \
    flask \
    redis

# ── User accounts ──────────────────────────────────────────────────────────────
# operator  — higher privileges; owns Modbus/PLC access; credentials in maintenance log
# engineer  — limited read-only role; initial attacker foothold
RUN useradd -m -s /bin/bash -g operator operator && \
    echo "operator:operator123" | chpasswd && \
    useradd -m -s /bin/bash engineer && \
    echo "engineer:engineer456" | chpasswd && \
    chown operator:operator /usr/local/bin/mbtget && \
    chmod 750 /usr/local/bin/mbtget

# ── SSH server configuration ───────────────────────────────────────────────────
RUN mkdir /var/run/sshd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config && \
    sed -i 's/UsePAM yes/UsePAM no/' /etc/ssh/sshd_config && \
    echo "Port 2222" >> /etc/ssh/sshd_config && \
    echo "AcceptEnv STORY_RUN_ID" >> /etc/ssh/sshd_config && \
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
  Internal APIs:\n\
    localhost      :5100   (Physics engine REST API)\n\
=============================================================\n' \
    > /etc/motd

# ── Data-collection helper (justifies the SSH path) ───────────────────────────
# The historian_api cron calls this via SSH every 5 minutes to pull logs.
RUN mkdir -p /opt/historian && printf '#!/bin/bash\n\
# collect_scada_logs.sh — run by historian cron every 5 min\n\
LOGDIR=/var/log/scada\n\
mkdir -p "$LOGDIR"\n\
STAMP=$(date +%%Y%%m%%d_%%H%%M%%S)\n\
echo "$STAMP: collecting PLC state from plc_simulator:502" >> "$LOGDIR/collect.log"\n\
echo "$STAMP: done" >> "$LOGDIR/collect.log"\n' \
    > /opt/historian/collect_scada_logs.sh && \
    chmod +x /opt/historian/collect_scada_logs.sh && \
    chown operator:operator /opt/historian/collect_scada_logs.sh

# ── Operator bash history (realistic forensic artifact) ───────────────────────
RUN mkdir -p /home/operator && printf '\
nmap -sT -n -p 502,102,20000 plc_simulator\n\
python3 -c "from pymodbus.client import ModbusTcpClient; c=ModbusTcpClient(\"plc_simulator\"); c.connect(); r=c.read_holding_registers(100,4); print(r.registers)"\n\
ssh root@plc_simulator\n\
ping -c 3 plc_simulator\n\
ping -c 3 ics_s7_plc\n\
cat /opt/historian/collect_scada_logs.sh\n\
tail -20 /var/log/scada/collect.log\n\
curl http://localhost:5100/api/physics/status\n\
ip addr show\n\
cat /etc/hosts\n' \
    > /home/operator/.bash_history && \
    chown operator:operator /home/operator/.bash_history

# ── Engineer bash history (shows them trying to escalate) ─────────────────────
RUN printf 'cat /var/log/scada_maintenance.log\n\
ping plc_simulator\n\
nc -vz plc_simulator 502\n\
cat /home/engineer/debug.log\n\
sudo -l\n\
ls /opt/config/\n' \
    > /home/engineer/.bash_history && \
    chown engineer:engineer /home/engineer/.bash_history

# ── Operator shell prompt ──────────────────────────────────────────────────────
RUN echo 'PS1="[\u@scada-ws-01 \W]\$ "' >> /home/operator/.bashrc && \
    echo 'echo ""' >> /home/operator/.bashrc && \
    echo 'echo "Last login: $(date -u) from ics_historian_api"' >> /home/operator/.bashrc && \
    echo 'echo ""' >> /home/operator/.bashrc

# ── Engineer shell prompt ──────────────────────────────────────────────────────
RUN echo 'PS1="[\u@scada-ws-01 \W]\$ "' >> /home/engineer/.bashrc && \
    echo 'echo "Engineer role: read-only access to historian data"' >> /home/engineer/.bashrc

# ── Human artifacts & credential leaks ────────────────────────────────────────
# Operator notes — leaks process safety limits
RUN printf "Pump 2 pressure unstable — check Modbus register 100\n\
Ensure we don't exceed 200 PSI on testing.\n" > /home/operator/notes.txt && \
    chown operator:operator /home/operator/notes.txt

# Operator todo — explicitly mentions default SCADA password (intentional bait)
RUN printf "1. Update PLC firmware\n\
2. Change default SCADA password (operator:operator123) before audit!!\n\
3. Check why historian API crashes sometimes\n" > /home/operator/todo.txt && \
    chown operator:operator /home/operator/todo.txt

# Engineer debug log
RUN printf "[INFO] Connected to Historian API successfully.\n\
[INFO] Connection to InfluxDB established.\n" > /home/engineer/debug.log && \
    chown engineer:engineer /home/engineer/debug.log

# Maintenance log — leaks operator password via syslog-style entry (the escalation path)
RUN mkdir -p /var/log && printf \
"2023-10-12: System restart by admin.\n\
2023-11-05: Maintenance window. Username 'operator' used default auth 'operator123' to SSH in. Must fix.\n" \
    > /var/log/scada_maintenance.log && \
    chmod 644 /var/log/scada_maintenance.log

# ── Privilege escalation path: misconfigured sudo ─────────────────────────────
# engineer can run /usr/bin/curl as operator without a password.
# Realistic: a developer gave engineer curl access to restart services.
# Attacker can abuse this with: sudo -u operator curl http://localhost:5100/api/physics/control
RUN echo "engineer ALL=(operator) NOPASSWD: /usr/bin/curl" >> /etc/sudoers

# ── Exposed credential file ───────────────────────────────────────────────────
# /opt/config/creds.txt — weak permissions (readable by all users).
# Realistic: a script deposits credentials for automated maintenance jobs.
RUN mkdir -p /opt/config && printf \
"# SCADA Service Accounts — DO NOT DISTRIBUTE\n\
# Generated by setup.sh on 2023-09-01\n\
operator:operator123   # main control account\n\
historian_svc:hist_svc_2023  # historian bridge service\n" \
    > /opt/config/creds.txt && \
    chmod 644 /opt/config/creds.txt  # world-readable — intentional misconfiguration

# ── Physics API script + physics engine package ───────────────────────────────
# Build context is Level 2 root, so we can reach the physics package directly.
# physics_engine.py is the single-source-of-truth simulator.
COPY physics/ /opt/physics_api/physics/
COPY scada_ssh/physics_api.py /opt/physics_api/physics_api.py
COPY logger/ /opt/logger/
COPY shared/ /opt/shared/
COPY scada_ssh/log_scada_cmd.py /usr/local/bin/log_scada_cmd.py
RUN chmod +x /usr/local/bin/log_scada_cmd.py && \
    echo 'export PROMPT_COMMAND='\''cmd=$(history 1 | sed -e "s/^[ ]*[0-9]*[ ]*//"); python3 /usr/local/bin/log_scada_cmd.py "$cmd"'\''' >> /etc/bash.bashrc

# PYTHONPATH: physics engine, MITRE mapping (shared/), unified logger
ENV PYTHONPATH=/opt/physics_api:/opt/shared:/opt/logger

# ── Log directories ───────────────────────────────────────────────────────────
RUN mkdir -p /var/log/scada && chmod 777 /var/log/scada

# ── iptables access control entrypoint ────────────────────────────────────────
# Blocks Modbus/S7/DNP3 egress for anyone except the operator user.
# The physics API (port 5100) is accessible from all users (no restriction).
COPY <<'ENTRYPOINT_EOF' /entrypoint.sh
#!/bin/bash
set -e

# Safely attempt to add iptables rules; don't fail the container if the
# kernel doesn't permit changes (e.g., when not running with NET_ADMIN).
add_iptables_rule() {
    # Usage: add_iptables_rule <rule-spec...>
    if iptables -C "$@" 2>/dev/null; then
        return 0
    fi
    iptables -A "$@" 2>/dev/null || true
}

add_iptables_rule OUTPUT -d plc_simulator  -p tcp --dport 502   -m owner ! --uid-owner operator -j DROP
add_iptables_rule OUTPUT -d ics_s7_plc     -p tcp --dport 102   -m owner ! --uid-owner operator -j DROP
add_iptables_rule OUTPUT -d ics_dnp3       -p tcp --dport 20000 -m owner ! --uid-owner operator -j DROP
add_iptables_rule OUTPUT -d fake_plc_sim   -p tcp --dport 502   -m owner ! --uid-owner operator -j DROP

# Launch the physics REST API in the background. Keep logs informative.
export PYTHONPATH=/opt/physics_api
cd /opt/physics_api || exit 1
nohup python3 physics_api.py >/var/log/scada/physics_api.log 2>&1 &
echo "[SCADA-SSH] Physics REST API started on :5100 (PID $!)"

# Save env vars for SSH sessions
echo "INFLUX_URL=\"$INFLUX_URL\"" >> /etc/environment
echo "INFLUX_TOKEN=\"$INFLUX_TOKEN\"" >> /etc/environment
echo "INFLUX_ORG=\"$INFLUX_ORG\"" >> /etc/environment
echo "INFLUX_BUCKET=\"$INFLUX_BUCKET\"" >> /etc/environment
echo "STORY_LOGGER_URL=\"$STORY_LOGGER_URL\"" >> /etc/environment
echo "PYTHONPATH=/opt/physics_api:/opt/shared:/opt/logger" >> /etc/environment

# Create an SSH login hook to log lateral movement
cat <<'HOOK_EOF' > /etc/profile.d/log_ssh.sh
if [ -n "$SSH_CONNECTION" ]; then
    python3 -c '
import os, sys
try:
    for _p in ("/opt/shared", "/opt/logger"):
        if _p not in sys.path:
            sys.path.insert(0, _p)
    from unified_logger import UnifiedLogger
    logger = UnifiedLogger(service="scada_ssh", layer="Level 2", log_dir="/var/log/scada")
    user = os.environ.get("USER", "unknown")
    conn = os.environ.get("SSH_CONNECTION", "").split()
    src_ip = conn[0] if conn else "unknown"
    logger.log(
        event_type="LATERAL_MOVEMENT",
        source={"ip": src_ip},
        target={"user": user, "service": "ssh"},
        session_id=os.environ.get("STORY_RUN_ID"),
        payload={"message": f"SSH Login by {user} from {src_ip}"}
    )
except Exception as e:
    pass
' > /dev/null 2>&1
fi
HOOK_EOF
chmod +x /etc/profile.d/log_ssh.sh

# Hand off to the SSH daemon (foreground, keeping the container alive)
exec /usr/sbin/sshd -D -p 2222 -e
ENTRYPOINT_EOF

RUN chmod +x /entrypoint.sh

EXPOSE 2222 5100

CMD ["/entrypoint.sh"]
