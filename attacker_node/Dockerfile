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
    && rm -rf /var/lib/apt/lists/*

# Python ICS attack tools
# --break-system-packages needed on Debian 12+ with PEP 668
RUN pip3 install --no-cache-dir --break-system-packages \
    pymodbus \
    requests \
    scapy

WORKDIR /tools

# Copy attack scripts
COPY s7comm_probe.py .
COPY dnp3_probe.py .

# Keep container alive so `docker exec` works for interactive use
CMD ["tail", "-f", "/dev/null"]
