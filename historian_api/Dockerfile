FROM python:3.10-slim

RUN pip install --no-cache-dir \
    flask \
    influxdb-client \
    requests

WORKDIR /app

COPY app.py .

EXPOSE 5000

CMD ["python", "-u", "app.py"]
