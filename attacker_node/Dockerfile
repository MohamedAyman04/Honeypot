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
    echo 'echo "║       ICS Honeypot — Attacker Node (Kali-like)          ║"' >> /root/.bashrc && \
    echo 'echo "╠══════════════════════════════════════════════════════════╣"' >> /root/.bashrc && \
    echo 'echo "║  TARGETS                                                 ║"' >> /root/.bashrc && \
    echo 'echo "║    plc_simulator:502      Modbus PLC (main target)      ║"' >> /root/.bashrc && \
    echo 'echo "║    ics_s7_plc:102         Siemens S7-300 PLC            ║"' >> /root/.bashrc && \
    echo 'echo "║    ics_dnp3:20000         DNP3 RTU (power/water)        ║"' >> /root/.bashrc && \
    echo 'echo "║    ics_scada_ssh:2222     SCADA SSH pivot (Level 2)     ║"' >> /root/.bashrc && \
    echo 'echo "║    honeypot_historian_api:5000  Historian REST API       ║"' >> /root/.bashrc && \
    echo 'echo "╠══════════════════════════════════════════════════════════╣"' >> /root/.bashrc && \
    echo 'echo "║  TOOLS AVAILABLE                                         ║"' >> /root/.bashrc && \
    echo 'echo "║    Network:  nmap, masscan, arp-scan, hping3             ║"' >> /root/.bashrc && \
    echo 'echo "║    ICS:      mbtget, mb-read, mb-write, pymodbus         ║"' >> /root/.bashrc && \
    echo 'echo "║              python3 s7comm_probe.py                     ║"' >> /root/.bashrc && \
    echo 'echo "║              python3 dnp3_probe.py                       ║"' >> /root/.bashrc && \
    echo 'echo "║    Web:      sqlmap, curl                                        ║"' >> /root/.bashrc && \
    echo 'echo "║    Auth:     hydra, medusa, ncrack, john, sshpass        ║"' >> /root/.bashrc && \
    echo 'echo "║    Packet:   tcpdump, tshark, scapy, netcat, socat       ║"' >> /root/.bashrc && \
    echo 'echo "╠══════════════════════════════════════════════════════════╣"' >> /root/.bashrc && \
    echo 'echo "║  AUTOMATED KILL CHAIN                                    ║"' >> /root/.bashrc && \
    echo 'echo "║    python3 /tools/attack_suite.py --phase 0  (all)      ║"' >> /root/.bashrc && \
    echo 'echo "║    python3 /tools/attack_suite.py --phase 4  (exploit)  ║"' >> /root/.bashrc && \
    echo 'echo "║    python3 /tools/attack_suite.py --phase 6  (lateral)  ║"' >> /root/.bashrc && \
    echo 'echo "╚══════════════════════════════════════════════════════════╝"' >> /root/.bashrc && \
    echo 'echo ""' >> /root/.bashrc

WORKDIR /tools

# Copy attack scripts
COPY s7comm_probe.py .
COPY dnp3_probe.py .
COPY attack_suite.py .

# Keep container alive so `docker exec` works for interactive use
CMD ["bash"]
