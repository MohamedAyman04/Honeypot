import asyncio
import logging
import os
import threading
import time
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

_influx_write = None
def get_influx():
    global _influx_write
    if _influx_write is None:
        try:
            c = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
            _influx_write = c.write_api(write_options=SYNCHRONOUS)
        except Exception: pass
    return _influx_write

def log_forced_write(address, value):
    try:
        api = get_influx()
        if not api: return
        p = (Point("forced_writes").tag("source", "modbus_write")
             .field("register", address).field("value", float(value))
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

        if address == 200:
            rpm = max(0, min(int(values[0]), 3000))
            self.physics_engine.set_pump_rpm(rpm)
            self._current_rpm = rpm
        elif address == 201:
            raw = int(values[0])
            pos = raw / 1000.0 if raw > 1 else float(raw)
            self.physics_engine.set_valve_pos(pos)
        elif address == 202:
            self.physics_engine.set_valve_pos(1.0 if int(values[0]) == 1 else 0.0)
        elif 100 <= address <= 103:
            log_forced_write(address, values[0])

    def getValues(self, address, count=1):
        with self._lock:
            self.physics_engine.update()
            state = self.physics_engine.get_state()
            
            # Map physical metrics to registers 100-103
            # 100: Pressure, 101: Flow*10, 102: Temperature, 103: RPM
            p, f, t, r = int(state["pressure"]), int(state["flow_rate"]*10), int(state["temperature"]), self._current_rpm
            
            # Update the block atomically starting at register 100
            super().setValues(100, [p, f, t, r])
            return super().getValues(address, count)

async def run_server():
    physics = PipelineSimulator()
    physics.set_pump_rpm(1200)
    physics.set_valve_pos(0.5)

    store = PhysicsAwareDataBlock(0, [0] * 300, physics)
    context = ModbusSlaveContext(hr=store, zero_mode=True)
    single_context = ModbusServerContext(slaves=context, single=True)

    identity = ModbusDeviceIdentification()
    identity.ProductName = 'SIMATIC S7-300 Modbus Gateway'

    log.info("Starting Modbus PLC Simulator on port 502...")
    await StartAsyncTcpServer(context=single_context, identity=identity, address=("0.0.0.0", 502))

if __name__ == "__main__":
    try: asyncio.run(run_server())
    except KeyboardInterrupt: pass