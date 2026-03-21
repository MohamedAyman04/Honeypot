FROM python:3.10-slim

RUN pip install --no-cache-dir \
    scikit-learn \
    pandas \
    numpy \
    joblib \
    influxdb-client

WORKDIR /app

COPY trainer.py .
COPY detector.py .

CMD ["python", "-u", "trainer.py"]