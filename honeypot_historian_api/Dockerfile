FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir flask requests influxdb-client
COPY app.py .
CMD ["python", "app.py"]
