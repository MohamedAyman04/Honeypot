FROM python:3.10-slim

# snap7 via pip bundles the shared lib — no apt needed
RUN pip install --no-cache-dir pymodbus==3.1.3 python-snap7

WORKDIR /app

COPY plc/modbus_server.py ./plc/
COPY plc/s7_server.py ./plc/
COPY plc/healthcheck.py ./plc/
COPY physics/ ./physics/

ENV PYTHONPATH=/app

CMD ["python", "plc/modbus_server.py"]