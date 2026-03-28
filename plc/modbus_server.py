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
        p = (Point("forced_writes").tag("source", "modbus_write")
             .tag("session_id", SESSION_ID)
             .field("register", address).field("value", float(value))
             .time(time.time_ns(), WritePrecision.NS))
        api.write(bucket=INFLUX_BUCKET, record=p)
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
        self._current_rpm = 1200 # Initial seed

    def setValues(self, address, values):
        super().setValues(address, values)
        log.info(f"MODBUS write address={address} values={values}")

        # Register write logic
        if address == 200:
            rpm = max(0, min(int(values[0]), 3000))
            self.physics_engine.set_pump_rpm(rpm)
            self._current_rpm = rpm
            log_modbus_event("attacker", 6, address, values[0], is_write=True)
        elif address == 201:
            raw = int(values[0])
            pos = raw / 1000.0 if raw > 1 else float(raw)
            self.physics_engine.set_valve_pos(pos)
            log_modbus_event("attacker", 6, address, values[0], is_write=True)
        elif address == 202:
            self.physics_engine.set_valve_pos(1.0 if int(values[0]) == 1 else 0.0)
            log_modbus_event("attacker", 6, address, values[0], is_write=True)
        elif 100 <= address <= 103:
            log_forced_write(address, values[0])
            log_modbus_event("attacker", 6, address, values[0], is_write=True)

    def getValues(self, address, count=1):
        with self._lock:
            # We don't call update() anymore, it is done by physics_process.py 
            # We just load the state from Redis
            self.physics_engine.load_state() 
            state = self.physics_engine.get_state()
            
            p, f, t, r = int(state["pressure"]), int(state["flow_rate"]*10), int(state["temperature"]), int(state["pump_rpm"])
            super().setValues(100, [p, f, t, r])
            
            # Log read (reconnaissance)
            log_modbus_event("attacker", 3, address, None, is_write=False)
            
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