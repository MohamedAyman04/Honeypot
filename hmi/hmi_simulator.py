"""
HMI / Historian Bridge
=======================
Polls Modbus PLC every 2 s, writes ALL telemetry to InfluxDB:
  - pipeline_metrics   (process telemetry)
  - process_state      (canonical state per thesis Table 4.1)
  - security_alerts    (replay attack detection)
  - hmi_access         (access log for historian bridge)
Detects replay attacks by checking for FLAT historian values while PLC changes.
"""
import time
import os
import uuid
from pymodbus.client import ModbusTcpClient
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS

PLC_IP     = os.environ.get('PLC_IP',        'plc_simulator')
TOKEN      = os.environ.get('INFLUX_TOKEN',   'supersecrettoken')
ORG        = os.environ.get('INFLUX_ORG',     'my_refinery')
BUCKET     = os.environ.get('INFLUX_BUCKET',  'sensor_logs')
INFLUX_URL = os.environ.get('INFLUX_URL',     'http://ics_historian:8086')

POLL_INTERVAL = 0.5   # 500 ms — high-frequency OT historian (was 2 s)

# Session ID – matches the modbus_server session for cross-referencing
SESSION_ID = os.environ.get('SESSION_ID', str(uuid.uuid4())[:8])

# Replay detection thresholds
# At 0.5 s poll: normal rate = 2 writes/s = ~20 writes/10 s
# Replay flood = 15 writes in 1.5 s = 10/s → threshold 30 = 1.5x normal
REPLAY_FLAT_COUNT = 6     # how many identical historian rows = suspect (3s window at 0.5s)
REPLAY_PLC_DELTA  = 8.0   # PLC must also have moved this much

print(f"HMI/Historian Bridge started [session={SESSION_ID}]...")

db_client = InfluxDBClient(url=INFLUX_URL, token=TOKEN, org=ORG)
write_api  = db_client.write_api(write_options=SYNCHRONOUS)
query_api  = db_client.query_api()


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
    """Return the last n pressure values from InfluxDB (excluding attacker writes)."""
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


def get_historian_write_count(seconds: int = 10) -> int:
    """
    Count writes tagged source=historian_bridge in the last N seconds.
    Normal rate: 1 write / 2 s = ~5 writes in 10 s.
    Replay attack: 15 writes in 1.5 s -- detectable as a flood.
    """
    query = f'''
from(bucket: "{BUCKET}")
  |> range(start: -{seconds}s)
  |> filter(fn: (r) => r["_measurement"] == "pipeline_metrics"
            and r["_field"] == "pressure"
            and r["source"] == "historian_bridge")
  |> group()
  |> count()
'''
    try:
        tables = query_api.query(query)
        for table in tables:
            for record in table.records:
                return int(record.get_value())
    except Exception:
        pass
    return 0


def check_replay_attack(live_pressure: float) -> tuple:
    """
    Detect replay attack via TWO independent signals (either alone fires alert):
      1. FLAT FEED: historian shows >= REPLAY_FLAT_COUNT identical values while
         the live PLC reading differs by > REPLAY_PLC_DELTA PSI.
      2. WRITE FLOOD: historian_bridge writes arrive at > 2x the normal rate
         (normal = 1 write / 2 s; attack = 15 writes / 1.5 s).

    Returns (detected: bool, delta: float).
    """
    hist = get_last_historian_pressures(REPLAY_FLAT_COUNT)
    hist_mean = (sum(hist) / len(hist)) if hist else live_pressure
    delta = abs(live_pressure - hist_mean)

    # Signal 1: flat historian feed + PLC divergence
    if len(hist) >= REPLAY_FLAT_COUNT:
        flat = (max(hist) - min(hist)) <= 1.0
        if flat and delta > REPLAY_PLC_DELTA:
            print(f"[REPLAY] Flat feed detected: hist_mean={hist_mean:.1f} PLC={live_pressure:.1f} delta={delta:.1f}")
            return True, delta

    # Signal 2: write flood (attack sprays 15 writes in 1.5 s)
    # Normal: ~5 writes in 10 s; threshold 10 = 2x normal
    write_count = get_historian_write_count(seconds=10)
    if write_count > 10:
        print(f"[REPLAY] Write flood detected: {write_count} writes in 10 s (normal ~5)")
        return True, delta

    return False, delta


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


def log_hmi_access(endpoint: str, src_ip: str = "historian_bridge", http_code: int = 200):
    """
    Log access events to hmi_access measurement (Table 4.1 in thesis).
    """
    try:
        p = (Point("hmi_access")
             .tag("session_id", SESSION_ID)
             .tag("src_ip",     src_ip)
             .tag("endpoint",   endpoint)
             .field("http_code", http_code)
             .time(time.time_ns(), WritePrecision.NS))
        write_api.write(bucket=BUCKET, record=p)
    except Exception as e:
        print(f"hmi_access log error: {e}")


poll_count = 0
while True:
    try:
        start_ts = time.time_ns()
        data = read_plc()
        poll_count += 1

        if data is not None:
            pressure_val = data['pressure']
            pump_state   = "running" if data['pump_rpm'] > 0 else "stopped"

            # ── Replay attack detection ──────────────────────────────────────
            replay_detected, replay_delta = check_replay_attack(pressure_val)
            if replay_detected:
                print(f"!!! REPLAY ATTACK ALERT !!! PLC={pressure_val:.1f} PSI  delta={replay_delta:.1f} PSI")
                alert = (Point("security_alerts")
                         .tag("alert_type", "REPLAY_ATTACK")
                         .tag("session_id", SESSION_ID)
                         .field("live_pressure", pressure_val)
                         .field("delta", replay_delta)          # Grafana panel 8 queries this field
                         .field("detail", "Historian frozen/flooded while PLC changed")
                         .time(time.time_ns(), WritePrecision.NS))
                write_api.write(bucket=BUCKET, record=alert)

            # ── Deception feedback ───────────────────────────────────────────
            display_pressure = pressure_val
            if check_for_anomaly():
                import random
                display_pressure = pressure_val * random.uniform(0.5, 2.0)
                print(f"!!! DECEPTION ACTIVE !!! Scrambled to {display_pressure:.1f}")

            # ── Write pipeline_metrics (legacy + ML engine compat) ──────────
            p = (Point("pipeline_metrics")
                 .tag("location",   "pump_station_01")
                 .tag("source",     "historian_bridge")
                 .tag("session_id", SESSION_ID)
                 .field("pressure",    data['pressure'])
                 .field("flow_rate",   data['flow_rate'])
                 .field("temperature", data['temperature'])
                 .field("pump_rpm",    data['pump_rpm'])
                 .time(start_ts, WritePrecision.NS))
            write_api.write(bucket=BUCKET, record=p)

            # ── Write process_state (Table 4.1: canonical state measurement) ─
            ps = (Point("process_state")
                  .tag("location",   "pump_station_01")
                  .tag("session_id", SESSION_ID)
                  .field("pressure",    data['pressure'])
                  .field("flow_rate",   data['flow_rate'])
                  .field("temperature", data['temperature'])
                  .field("pump_rpm",    data['pump_rpm'])
                  .field("pump_state",  pump_state)
                  .field("setpoint",    200.0)   # default safe operating setpoint
                  .time(start_ts, WritePrecision.NS))
            write_api.write(bucket=BUCKET, record=ps)

            # ── Log this historian poll as HMI access ────────────────────────
            if poll_count % 10 == 0:  # log every 20 s to avoid noise
                log_hmi_access("/api/plc/poll", src_ip="historian_bridge", http_code=200)

            print(f"Logged → P={data['pressure']:.1f} PSI  "
                  f"F={data['flow_rate']:.2f}  "
                  f"T={data['temperature']:.1f}°C  "
                  f"RPM={data['pump_rpm']:.0f}")
        else:
            print("WARNING: Could not reach Modbus PLC, retrying...")
            log_hmi_access("/api/plc/poll", src_ip="historian_bridge", http_code=503)

    except Exception as e:
        print(f"Bridge error: {e}")

    time.sleep(POLL_INTERVAL)