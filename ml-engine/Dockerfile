FROM python:3.10-slim

RUN pip install scikit-learn pandas joblib influxdb-client

WORKDIR /app

COPY trainer.py .
COPY detector.py .

CMD ["python", "trainer.py"]