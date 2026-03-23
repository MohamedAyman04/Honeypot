"""
HMI / Historian Bridge
=======================
Polls Modbus PLC every 2 s, writes all telemetry to InfluxDB.
Detects replay attacks by checking for FLAT historian values while PLC changes.
"""
import time
import os
from pymodbus.client import ModbusTcpClient
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS

PLC_IP     = os.environ.get('PLC_IP',        'plc_simulator')
TOKEN      = os.environ.get('INFLUX_TOKEN',   'supersecrettoken')
ORG        = os.environ.get('INFLUX_ORG',     'my_refinery')
BUCKET     = os.environ.get('INFLUX_BUCKET',  'sensor_logs')
INFLUX_URL = os.environ.get('INFLUX_URL',     'http://ics_historian:8086')

POLL_INTERVAL = 2

# A replay attack shows the historian receiving the SAME value repeatedly
# while the PLC is actually changing.  We track recent historian values.
REPLAY_FLAT_COUNT   = 3      # how many identical historian rows = suspect
REPLAY_PLC_DELTA    = 8.0    # PLC must also have moved this much during flat window

print("HMI/Historian Bridge started...")

db_client = InfluxDBClient(url=INFLUX_URL, token=TOKEN, org=ORG)
write_api  = db_client.write_api(write_options=SYNCHRONOUS)
query_api  = db_client.query_api()

# Rolling history for replay detection
_hist_pressure_history = []   # last N logged values


def read_plc():
    client = ModbusTcpClient(PLC_IP, port=502)
    try:
        if client.connect():
            res = client.read_holding_registers(address=100, count=4)
            if hasattr(res, 'registers') and not res.isError():
                return {
                    'pressure':    float(res.registers[0]),
                    'flow_rate':   float(res.registers[1]) / 10.0,
                    'temperature': float(res.registers[2]),
                    'pump_rpm':    float(res.registers[3]),
                }
    except Exception as e:
        print(f"Modbus error: {e}")
    finally:
        try:
            client.close()
        except Exception:
            pass
    return None


def get_last_historian_pressures(n: int = 5):
    """Return the last n pressure values from InfluxDB."""
    query = f'''
from(bucket: "{BUCKET}")
  |> range(start: -2m)
  |> filter(fn: (r) => r["_measurement"] == "pipeline_metrics" and r["_field"] == "pressure" and r["source"] != "attacker")
  |> sort(columns: ["_time"], desc: true)
  |> limit(n: {n})
'''
    try:
        tables = query_api.query(query)
        vals = []
        for table in tables:
            for record in table.records:
                vals.append(float(record.get_value()))
        return vals
    except Exception:
        return []


def check_replay_attack(live_pressure: float) -> bool:
    """
    Detect replay: historian shows repeated flat values while PLC is at a
    very different reading (attacker froze the historian feed).
    """
    hist = get_last_historian_pressures(REPLAY_FLAT_COUNT)
    if len(hist) < REPLAY_FLAT_COUNT:
        return False
    # All historian values the same (within 1 PSI)?
    if max(hist) - min(hist) > 1.0:
        return False   # historian IS changing, not a replay
    # PLC value differs significantly from the flat historian value?
    if abs(live_pressure - hist[0]) > REPLAY_PLC_DELTA:
        return True
    return False


def check_for_anomaly():
    query = f'''
from(bucket: "{BUCKET}")
  |> range(start: -30s)
  |> filter(fn: (r) => r["_measurement"] == "security_metrics" and r["_field"] == "is_anomaly")
  |> last()
'''
    try:
        tables = query_api.query(query)
        for table in tables:
            for record in table.records:
                if record.get_value() == 1:
                    return True
    except Exception:
        pass
    return False


while True:
    try:
        data = read_plc()
        if data is not None:
            pressure_val = data['pressure']

            # ── Replay attack detection ──────────────────────────────────────
            if check_replay_attack(pressure_val):
                print(f"!!! REPLAY ATTACK ALERT !!! PLC={pressure_val:.1f} but historian is flat")
                alert = (Point("security_alerts")
                         .tag("alert_type", "replay_attack")
                         .field("live_pressure", pressure_val)
                         .field("detail", "Historian frozen while PLC changed")
                         .time(time.time_ns(), WritePrecision.NS))
                write_api.write(bucket=BUCKET, record=alert)

            # ── Deception feedback ───────────────────────────────────────────
            if check_for_anomaly():
                import random
                pressure_val = pressure_val * random.uniform(0.5, 2.0)
                print(f"!!! DECEPTION ACTIVE !!! Scrambled to {pressure_val:.1f}")

            # ── Write to historian ───────────────────────────────────────────
            p = (Point("pipeline_metrics")
                 .tag("location", "pump_station_01")
                 .tag("source", "historian_bridge")
                 .field("pressure",    data['pressure'])
                 .field("flow_rate",   data['flow_rate'])
                 .field("temperature", data['temperature'])
                 .field("pump_rpm",    data['pump_rpm'])
                 .time(time.time_ns(), WritePrecision.NS))
            write_api.write(bucket=BUCKET, record=p)
            print(f"Logged → P={data['pressure']:.1f} PSI  "
                  f"F={data['flow_rate']:.2f}  "
                  f"T={data['temperature']:.1f}°C  "
                  f"RPM={data['pump_rpm']:.0f}")
        else:
            print("WARNING: Could not reach Modbus PLC, retrying...")

    except Exception as e:
        print(f"Bridge error: {e}")

    time.sleep(POLL_INTERVAL)