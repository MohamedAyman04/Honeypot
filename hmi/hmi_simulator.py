import time
import random
import os
from pymodbus.client import ModbusTcpClient
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS

# Configuration
PLC_IP = os.environ.get('PLC_IP', 'plc_simulator')
TOKEN = os.environ.get('INFLUX_TOKEN', "supersecrettoken")
ORG = os.environ.get('INFLUX_ORG', "my_refinery")
BUCKET = os.environ.get('INFLUX_BUCKET', "sensor_logs")
INFLUX_URL = os.environ.get('INFLUX_URL', "http://ics_historian:8086")

# Initialize Clients
plc_client = ModbusTcpClient(PLC_IP, port=5020)
db_client = InfluxDBClient(url=INFLUX_URL, token=TOKEN, org=ORG)
write_api = db_client.write_api(write_options=SYNCHRONOUS)
query_api = db_client.query_api()

print("HMI/Historian Link Started...")

REPLAY_THRESHOLD = 5.0 # Mismatch threshold between PLC and historian

def check_for_anomalies():
    query = f'''from(bucket: "{BUCKET}") |> range(start: -30s) |> filter(fn: (r) => r["_measurement"] == "security_metrics" and r["_field"] == "is_anomaly") |> last()'''
    try:
        tables = query_api.query(query)
        for table in tables:
            for record in table.records:
                if record.get_value() == 1:
                    return True
    except Exception as e:
        pass
    return False

def get_last_historian_pressure():
    query = f'''from(bucket: "{BUCKET}") |> range(start: -5m) |> filter(fn: (r) => r["_measurement"] == "pipeline_metrics" and r["_field"] == "pressure") |> last()'''
    try:
        tables = query_api.query(query)
        for table in tables:
            for record in table.records:
                return float(record.get_value())
    except Exception as e:
        pass
    return None

def trigger_deception_feedback(original_val):
    print("!!! CASCADING FAILURE SIMULATION INITIATED !!!")
    print(f"Real PLC value: {original_val}, scrambling HMI readout...")
    return original_val * random.uniform(0.1, 5.0)

while True:
    try:
        res = plc_client.read_holding_registers(address=100, count=1)
        if hasattr(res, 'isError') and not res.isError():
            pressure_val = float(res.registers[0])
            
            # Replay Attack Detection
            hist_val = get_last_historian_pressure()
            if hist_val is not None:
                mismatch = abs(pressure_val - hist_val)
                if mismatch > REPLAY_THRESHOLD:
                    print(f"!!! REPLAY ATTACK ALERT !!! Live: {pressure_val} vs Historian: {hist_val}")
                    
            # Deception Feedback Loop
            if check_for_anomalies():
                pressure_val = trigger_deception_feedback(pressure_val)
            
            # Record to Historian (InfluxDB)
            point = Point("pipeline_metrics") \
                .tag("location", "pump_station_01") \
                .field("pressure", float(pressure_val)) \
                .time(time.time_ns(), WritePrecision.NS)
            
            write_api.write(bucket=BUCKET, record=point)
            print(f"Logged Pressure: {pressure_val} PSI")
        else:
            print(f"Failed to read Modbus data. Response: {res}")
    except Exception as e:
        print(f"Modbus connection error: {e}")
        # Try to reconnect implicitly upon next iteration
        pass
    
    time.sleep(2)