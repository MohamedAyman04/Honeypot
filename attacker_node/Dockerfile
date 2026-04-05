FROM debian:bookworm-slim

# Use a single reliable mirror and retry on failure
RUN apt-get update --fix-missing && apt-get install -y --no-install-recommends \
    nmap \
    python3 \
    python3-pip \
    python3-venv \
    iputils-ping \
    netcat-openbsd \
    tcpdump \
    curl \
    wget \
    bash \
    && rm -rf /var/lib/apt/lists/*

# Python ICS attack tools
# --break-system-packages needed on Debian 12+ with PEP 668
RUN pip3 install --no-cache-dir --break-system-packages \
    pymodbus \
    requests \
    scapy

# Write a fast-nmap wrapper so users don't need to remember -n -sT
# -n  = no DNS lookups  (eliminates the main source of nmap slowness in Docker)
# -sT = TCP connect scan (works without root/CAP_NET_RAW)
RUN printf '#!/bin/bash\nnmap -n -sT "$@"\n' > /usr/local/bin/fast-nmap && \
    chmod +x /usr/local/bin/fast-nmap

# Helpful .bashrc aliases for the attack shell
RUN echo 'alias nmap="fast-nmap"' >> /root/.bashrc && \
    echo 'PS1="\[\033[1;31m\][attacker]\[\033[0m\] \w \$ "' >> /root/.bashrc && \
    echo 'echo "ICS Honeypot Attacker Node — tools: nmap, nc, python3"' >> /root/.bashrc && \
    echo 'echo "Quick scan: nmap -p 502,102,20000 plc_simulator"' >> /root/.bashrc && \
    echo 'echo "Attack suite: python3 /tools/attack_suite.py --phase 0"' >> /root/.bashrc

WORKDIR /tools

# Copy attack scripts
COPY s7comm_probe.py .
COPY dnp3_probe.py .
COPY attack_suite.py .

# Keep container alive so `docker exec` works for interactive use
CMD ["bash"]
