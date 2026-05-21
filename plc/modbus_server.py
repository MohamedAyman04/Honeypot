import asyncio
import logging
import os
import threading
import time
import uuid
from pymodbus.server import StartAsyncTcpServer
from pymodbus.device import ModbusDeviceIdentification
from pymodbus.datastore import ModbusSequentialDataBlock, ModbusSlaveContext, ModbusServerContext
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS
from physics.physics_engine import PipelineSimulator

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("modbus_server")

# --- InfluxDB Logging for ML detection of forced writes ---
INFLUX_URL    = os.environ.get("INFLUX_URL",    "http://ics_historian:8086")
INFLUX_TOKEN  = os.environ.get("INFLUX_TOKEN",  "supersecrettoken")
INFLUX_ORG    = os.environ.get("INFLUX_ORG",    "my_refinery")
INFLUX_BUCKET = os.environ.get("INFLUX_BUCKET", "sensor_logs")

# Session ID for cross-layer tracking
SESSION_ID = str(uuid.uuid4())[:8]

_influx_write = None
def get_influx():
    global _influx_write
    if _influx_write is None:
        try:
            c = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
            _influx_write = c.write_api(write_options=SYNCHRONOUS)
        except Exception: pass
    return _influx_write

def log_modbus_event(src_ip, fc, address, value, is_write):
    try:
        api = get_influx()
        if not api: return
        p = (Point("modbus_events")
             .tag("session_id", SESSION_ID)
             .tag("fc_type", "write" if is_write else "read")
             .tag("src_ip", src_ip)
             .field("func_code", fc)
             .field("register", address)
             .field("value", float(value) if value is not None else 0.0)
             .time(time.time_ns(), WritePrecision.NS))
        api.write(bucket=INFLUX_BUCKET, record=p)
    except Exception: pass

def log_forced_write(address, value):
    try:
        api = get_influx()
        if not api: return
        # 1. Log to forced_writes (ML semantic injection trigger)
        p = (Point("forced_writes").tag("source", "modbus_write")
             .tag("session_id", SESSION_ID)
             .field("register", address).field("value", float(value))
             .time(time.time_ns(), WritePrecision.NS))
        api.write(bucket=INFLUX_BUCKET, record=p)
        # 2. Also write injected value to pipeline_metrics so Grafana shows the spike
        if address == 100:  # pressure register
            spike = (Point("pipeline_metrics")
                     .tag("location",   "pump_station_01")
                     .tag("source",     "attacker")
                     .tag("session_id", SESSION_ID)
                     .field("pressure", float(value))
                     .time(time.time_ns(), WritePrecision.NS))
            api.write(bucket=INFLUX_BUCKET, record=spike)
            log.warning(f"[INJECTION] Wrote {value} PSI to pipeline_metrics (Grafana spike)")
    except Exception: pass

def log_auth_attempt(src_ip, service="modbus", detail="connection"):
    try:
        api = get_influx()
        if not api: return
        p = (Point("auth_attempts")
             .tag("session_id", SESSION_ID)
             .tag("src_ip", src_ip)
             .tag("service", service)
             .field("detail", detail)
             .time(time.time_ns(), WritePrecision.NS))
        api.write(bucket=INFLUX_BUCKET, record=p)
    except Exception: pass

class PhysicsAwareDataBlock(ModbusSequentialDataBlock):
    def __init__(self, address, values, physics_engine):
        super().__init__(address, values)
        self.physics_engine = physics_engine
        self._lock = threading.Lock()
        self._current_rpm = 1200  # Initial pump RPM seed
        self.injected = {}        # address -> (value, timestamp)

        # Fix 1: Pre-seed registers from physics engine state.
        # Valve starts CLOSED (register 202=0, 201=0) to match physics startup.
        # Physics engine enforces valve_pos=0 → flow_rate=0 as single source of truth.
        state = self.physics_engine.get_state()
        p = int(state["pressure"])
        f = int(state["flow_rate"] * 10)   # will be 0 because valve is closed
        t = int(state["temperature"])
        r = int(state["pump_rpm"])
        super().setValues(100, [p, f, t, r])
        # Register 200=pump_rpm, 201=valve_percent(0=closed), 202=valve_toggle(0=closed)
        super().setValues(200, [1200, 0, 0])

    def setValues(self, address, values):
        super().setValues(address, values)
        log.info(f"MODBUS write address={address} values={values}")

        # Register write logic
        if address == 200:
            rpm = max(0, min(int(values[0]), 3000))
            self.physics_engine.set_pump_rpm(rpm)
            self._current_rpm = rpm
            log_forced_write(address, values[0])
            log_modbus_event("attacker", 6, address, values[0], is_write=True)
        elif address == 201:
            raw = int(values[0])
            pos = raw / 1000.0 if raw > 1 else float(raw)
            self.physics_engine.set_valve_pos(pos)
            log_forced_write(address, values[0])
            log_modbus_event("attacker", 6, address, values[0], is_write=True)
        elif address == 202:
            self.physics_engine.set_valve_pos(1.0 if int(values[0]) == 1 else 0.0)
            log_forced_write(address, values[0])
            log_modbus_event("attacker", 6, address, values[0], is_write=True)
        elif 100 <= address <= 103:
            self.injected[address] = (values[0], time.time())
            log_forced_write(address, values[0])   # writes to forced_writes + pipeline_metrics
            log_modbus_event("attacker", 6, address, values[0], is_write=True)
            log.warning(f"[FORCED WRITE] Sensor register {address} = {values[0]} (SEMANTIC INJECTION)")

    def getValues(self, address, count=1):
        with self._lock:
            # Refresh registers from Redis (physics engine keeps this updated)
            self.physics_engine.load_state()
            state = self.physics_engine.get_state()

            p, f, t, r = (int(state["pressure"]),
                          int(state["flow_rate"] * 10),
                          int(state["temperature"]),
                          int(state["pump_rpm"]))
            
            # Apply any injected values indefinitely (stay forever until changed)
            now = time.time()
            if 100 in self.injected: p = self.injected[100][0]
            if 101 in self.injected: f = self.injected[101][0]
            if 102 in self.injected: t = self.injected[102][0]
            if 103 in self.injected: r = self.injected[103][0]

            super().setValues(100, [p, f, t, r])

            # ── Recon detection (false-positive-resistant) ────────────────────
            # A read is considered suspicious reconnaissance when:
            #   (a) it targets registers OUTSIDE the normal sensor block (100-103), OR
            #   (b) it scans an unusual address with a large count (port-sweep style), OR
            #   (c) it probes the actuator block (200+) which HMI never reads directly.
            # Normal HMI poll: address=100, count=4  →  always ignored.
            # Normal physics reads: address=200, count≤3 done by THIS server, not remote.
            is_hmi_sensor_poll = (address == 100 and count == 4)
            is_actuator_probe  = (address >= 200)
            is_unusual_address = (address < 100 or (103 < address < 200))
            is_wide_scan       = (count > 10)

            if not is_hmi_sensor_poll and (is_actuator_probe or is_unusual_address or is_wide_scan):
                # Throttle: max one log per (address) per 5 seconds to stop floods
                now = time.time()
                last_key = f"_last_recon_{address}"
                if now - getattr(self, last_key, 0) > 5:
                    setattr(self, last_key, now)
                    log_modbus_event("attacker", 3, address, None, is_write=False)
                    log.info(f"[RECON] Suspicious read: address={address} count={count}")

            return super().getValues(address, count)

async def run_server():
    # Use Redis to read state updated by physical process simulator
    physics = PipelineSimulator(use_redis=True)

    store = PhysicsAwareDataBlock(0, [0] * 300, physics)
    context = ModbusSlaveContext(hr=store, zero_mode=True)
    single_context = ModbusServerContext(slaves=context, single=True)

    identity = ModbusDeviceIdentification()
    identity.ProductName = 'SIMATIC S7-300 Modbus Gateway'

    log.info(f"Starting Modbus PLC Simulator on port 502 with Redis session {SESSION_ID}")
    await StartAsyncTcpServer(context=single_context, identity=identity, address=("0.0.0.0", 502))

if __name__ == "__main__":
    try: asyncio.run(run_server())
    except KeyboardInterrupt: pass