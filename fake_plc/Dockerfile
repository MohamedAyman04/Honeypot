FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir pymodbus==3.1.3
COPY fake_plc.py .
CMD ["python", "fake_plc.py"]
