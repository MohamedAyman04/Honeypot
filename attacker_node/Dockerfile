FROM debian:bookworm-slim

# ── System tools (equivalent of a Kali Linux attacker VM) ────────────────────
RUN apt-get update --fix-missing && apt-get install -y --no-install-recommends \
    nmap \
    hping3 \
    hydra \
    sshpass \
    openssh-client \
    python3 \
    python3-pip \
    python3-venv \
    iputils-ping \
    netcat-openbsd \
    tcpdump \
    curl \
    wget \
    bash \
    iproute2 \
    procps \
    perl \
    xxd \
    && rm -rf /var/lib/apt/lists/*

# Install mbtget
RUN wget https://raw.githubusercontent.com/sourceperl/mbtget/master/mbtget -O /usr/local/bin/mbtget && \
    chmod +x /usr/local/bin/mbtget

# ── Python ICS attack libraries ───────────────────────────────────────────────
# --break-system-packages needed on Debian 12+ with PEP 668
RUN pip3 install --no-cache-dir --break-system-packages \
    pymodbus \
    requests \
    scapy

# ── Convenience wrappers ──────────────────────────────────────────────────────
# fast-nmap: always add -n (no DNS) and -sT (no root SYN needed)
RUN printf '#!/bin/bash\nnmap -n -sT "$@"\n' > /usr/local/bin/fast-nmap && \
    chmod +x /usr/local/bin/fast-nmap

# ── .bashrc aliases for the attack shell ──────────────────────────────────────
RUN echo 'alias nmap="fast-nmap"' >> /root/.bashrc && \
    echo 'PS1="\[\033[1;31m\][attacker]\[\033[0m\] \w \$ "' >> /root/.bashrc && \
    echo 'echo ""' >> /root/.bashrc && \
    echo 'echo "===== ICS Honeypot Attacker Node ====="' >> /root/.bashrc && \
    echo 'echo "Tools : nmap, hping3, hydra, sshpass, netcat, tcpdump, scapy, pymodbus"' >> /root/.bashrc && \
    echo 'echo "Targets:"' >> /root/.bashrc && \
    echo 'echo "  plc_simulator:502    (Modbus PLC)"' >> /root/.bashrc && \
    echo 'echo "  ics_s7_plc:102       (Siemens S7-300)"' >> /root/.bashrc && \
    echo 'echo "  ics_dnp3:20000       (DNP3 RTU)"' >> /root/.bashrc && \
    echo 'echo "  ics_scada_ssh:2222   (SCADA SSH pivot — Level 2)"' >> /root/.bashrc && \
    echo 'echo "  ics_historian_api:5000 (Level 3 REST API)"' >> /root/.bashrc && \
    echo 'echo ""' >> /root/.bashrc && \
    echo 'echo "Kill chain:  python3 /tools/attack_suite.py --phase 0"' >> /root/.bashrc && \
    echo 'echo "Single phase: python3 /tools/attack_suite.py --phase 6  (lateral movement)"' >> /root/.bashrc && \
    echo 'echo ""' >> /root/.bashrc

WORKDIR /tools

# Copy attack scripts
COPY s7comm_probe.py .
COPY dnp3_probe.py .
COPY attack_suite.py .

# Keep container alive so `docker exec` works for interactive use
CMD ["bash"]
