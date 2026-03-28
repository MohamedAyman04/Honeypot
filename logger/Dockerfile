FROM python:3.10-slim
RUN apt-get update && apt-get install -y libpcap-dev gcc && rm -rf /var/lib/apt/lists/*
RUN pip install scapy pymodbus influxdb-client redis
WORKDIR /app
COPY . .
CMD ["python", "-u", "correlator.py"]