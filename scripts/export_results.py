import pandas as pd
from influxdb_client import InfluxDBClient

def generate_thesis_csv():
    client = InfluxDBClient(url="http://localhost:8086", token="supersecrettoken", org="my_refinery")
    query_api = client.query_api()

    query = 'from(bucket:"sensor_logs") |> range(start: -24h) |> filter(fn: (r) => r["_measurement"] == "correlation_logs")'
    df = query_api.query_data_frame(query)

    if not df.empty:
        pivot_df = df.pivot(index='_time', columns='_field', values='_value')
        pivot_df.to_csv('honeypot_evaluation_results.csv')
        print("Dataset exported: honeypot_evaluation_results.csv")

if __name__ == "__main__":
    generate_thesis_csv()