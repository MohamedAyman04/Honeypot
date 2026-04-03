FROM python:3.10-slim

RUN pip install --no-cache-dir \
    scikit-learn \
    pandas \
    numpy \
    joblib \
    influxdb-client \
    redis \
    fastapi \
    uvicorn[standard]

WORKDIR /app

COPY trainer.py .
COPY detector.py .

EXPOSE 8000

CMD ["python", "-u", "trainer.py"]