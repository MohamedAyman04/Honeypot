FROM python:3.10-slim

WORKDIR /app

RUN pip install dash dash-bootstrap-components pandas influxdb-client requests pymodbus==3.1.3 redis

COPY . .

CMD ["python", "hmi_app.py"]