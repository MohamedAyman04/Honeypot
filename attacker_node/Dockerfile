FROM debian:bookworm-slim

# ── System tools (equivalent of a Kali Linux attacker VM) ────────────────────
RUN apt-get update --fix-missing && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    # Network recon / scanning
    nmap \
    masscan \
    arp-scan \
    hping3 \
    # Password / brute-force
    hydra \
    medusa \
    ncrack \
    john \
    # SSH / remote access
    sshpass \
    openssh-client \
    openssh-server \
    # Web attack tools
    sqlmap \
    # Packet capture / analysis
    tcpdump \
    tshark \
    # Networking utilities
    netcat-openbsd \
    socat \
    telnet \
    curl \
    wget \
    dnsutils \
    iputils-ping \
    iproute2 \
    net-tools \
    # General utilities
    procps \
    bash \
    build-essential \
    python3 \
    python3-pip \
    python3-dev \
    libssl-dev \
    libffi-dev \
    ca-certificates \
    perl \
    xxd \
    jq \
    git \
    vim \
    nano \
    less \
    && rm -rf /var/lib/apt/lists/*

# ── Install mbtget (Modbus CLI read/write tool) ───────────────────────────────
RUN wget -q --no-check-certificate https://raw.githubusercontent.com/sourceperl/mbtget/master/scripts/mbtget \
    -O /usr/local/bin/mbtget && \
    chmod +x /usr/local/bin/mbtget

# ── Python ICS / attack libraries ─────────────────────────────────────────────
# --break-system-packages needed on Debian 12+ (PEP 668)
RUN pip3 install --no-cache-dir --break-system-packages \
    pymodbus \
    requests \
    scapy \
    python-snap7 \
    impacket \
    paramiko \
    dnspython

# ── Convenience wrappers ──────────────────────────────────────────────────────
# fast-nmap: always -n (no DNS) + -sT (TCP connect, no root needed)
RUN printf '#!/bin/bash\nnmap -n -sT "$@"\n' > /usr/local/bin/fast-nmap && \
    chmod +x /usr/local/bin/fast-nmap

# modbus-read: quick FC3 register read shorthand
RUN printf '#!/bin/bash\n# Usage: modbus-read <host> <start_reg> [count]\nmbtget -r3 -a1 -c ${3:-1} ${1} ${2}\n' \
    > /usr/local/bin/modbus-read && chmod +x /usr/local/bin/modbus-read

# modbus-write: quick FC6 register write shorthand
RUN printf '#!/bin/bash\n# Usage: modbus-write <host> <reg> <value>\nmbtget -w6 ${1} ${2} ${3}\n' \
    > /usr/local/bin/modbus-write && chmod +x /usr/local/bin/modbus-write

# ── Interactive shell banner & aliases ────────────────────────────────────────
RUN echo '' >> /root/.bashrc && \
    echo 'alias nmap="fast-nmap"' >> /root/.bashrc && \
    echo 'alias ll="ls -la --color=auto"' >> /root/.bashrc && \
    echo 'alias mb-read="modbus-read"' >> /root/.bashrc && \
    echo 'alias mb-write="modbus-write"' >> /root/.bashrc && \
    echo 'PS1="\[\033[1;31m\][attacker]\[\033[0m\] \w \$ "' >> /root/.bashrc && \
    echo '' >> /root/.bashrc && \
    echo 'echo ""' >> /root/.bashrc && \
    echo 'echo "╔══════════════════════════════════════════════════════════╗"' >> /root/.bashrc && \
    echo 'echo "║       ICS Honeypot — Attacker Node (Kali-like)           ║"' >> /root/.bashrc && \
    echo 'echo "╠══════════════════════════════════════════════════════════╣"' >> /root/.bashrc && \
    echo 'echo "║  TARGETS                                                 ║"' >> /root/.bashrc && \
    echo 'echo "║    plc_simulator:502      Modbus PLC (main target)       ║"' >> /root/.bashrc && \
    echo 'echo "║    ics_s7_plc:102         Siemens S7-300 PLC             ║"' >> /root/.bashrc && \
    echo 'echo "║    ics_dnp3:20000         DNP3 RTU (power/water)         ║"' >> /root/.bashrc && \
    echo 'echo "║    ics_scada_ssh:2222     SCADA SSH pivot (Level 2)      ║"' >> /root/.bashrc && \
    echo 'echo "║    honeypot_historian_api:5000  Historian REST API       ║"' >> /root/.bashrc && \
    echo 'echo "╠══════════════════════════════════════════════════════════╣"' >> /root/.bashrc && \
    echo 'echo "║  TOOLS AVAILABLE                                         ║"' >> /root/.bashrc && \
    echo 'echo "║    Network:  nmap, masscan, arp-scan, hping3             ║"' >> /root/.bashrc && \
    echo 'echo "║    ICS:      mbtget, mb-read, mb-write, pymodbus         ║"' >> /root/.bashrc && \
    echo 'echo "║              python3 s7comm_probe.py                     ║"' >> /root/.bashrc && \
    echo 'echo "║              python3 dnp3_probe.py                       ║"' >> /root/.bashrc && \
    echo 'echo "║    Web:      sqlmap, curl                                ║"' >> /root/.bashrc && \
    echo 'echo "║    Auth:     hydra, medusa, ncrack, john, sshpass        ║"' >> /root/.bashrc && \
    echo 'echo "║    Packet:   tcpdump, tshark, scapy, netcat, socat       ║"' >> /root/.bashrc && \
    echo 'echo "╠══════════════════════════════════════════════════════════╣"' >> /root/.bashrc && \
    echo 'echo "║  AUTOMATED KILL CHAIN                                    ║"' >> /root/.bashrc && \
    echo 'echo "║    python3 /tools/attack_suite.py --phase 0  (all)       ║"' >> /root/.bashrc && \
    echo 'echo "║    python3 /tools/attack_suite.py --phase 4  (exploit)   ║"' >> /root/.bashrc && \
    echo 'echo "║    python3 /tools/attack_suite.py --phase 6  (lateral)   ║"' >> /root/.bashrc && \
    echo 'echo "╚══════════════════════════════════════════════════════════╝"' >> /root/.bashrc && \
    echo 'echo ""' >> /root/.bashrc

WORKDIR /tools

# Create a script to log interactive bash commands to the story logger
RUN cat <<'EOF' > /tools/log_cmd.py
import sys, os, json, urllib.request, datetime
try:
    cmd = sys.argv[1].strip()
    if not cmd: sys.exit(0)
    last_f = '/tmp/.last_cmd'
    if os.path.exists(last_f):
        with open(last_f, 'r') as f:
            if f.read().strip() == cmd: sys.exit(0)
    with open(last_f, 'w') as f: f.write(cmd)
    
    url = os.environ.get("STORY_LOGGER_URL", "http://story_logger:8600").rstrip("/")
    payload = {
        "ts": datetime.datetime.utcnow().isoformat() + "Z",
        "sensor": "attacker_node",
        "event_type": "INTERACTIVE_COMMAND",
        "src_ip": "172.28.0.50",
        "stage": "S3",
        "journey_id": os.environ.get("STORY_RUN_ID", "interactive_session"),
        "outcome": "observed",
        "severity": "HIGH",
        "meta": {
            "message": f"Attacker executed command: {cmd}",
            "level": "Level 2",
            "command": cmd,
            "mitre_tactic": "Execution",
            "mitre_technique_id": "T1059.004",
            "mitre_technique_name": "Command and Scripting Interpreter: Unix Shell",
            "kill_chain_stage": "Stage 3 - Discovery & Pivot",
            "purdue_level": "Level 2"
        }
    }
    req = urllib.request.Request(
        f"{url}/story/events",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    urllib.request.urlopen(req, timeout=0.5)
except Exception as e:
    pass
EOF

RUN echo 'export PROMPT_COMMAND='\''cmd=$(history 1 | sed -e "s/^[ ]*[0-9]*[ ]*//"); python3 /tools/log_cmd.py "$cmd"'\''' >> /root/.bashrc

# Copy attack scripts
COPY s7comm_probe.py .
COPY dnp3_probe.py .
COPY attack_suite.py .

# Keep container alive so `docker exec` works for interactive use
CMD ["bash"]
