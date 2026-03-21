import asyncio
import logging
import os
import threading

# Pymodbus v3.x imports
from pymodbus.server import StartAsyncTcpServer
from pymodbus.device import ModbusDeviceIdentification
from pymodbus.datastore import ModbusSequentialDataBlock, ModbusSlaveContext, ModbusServerContext

# Import your physics engine
from physics.physics_engine import PipelineSimulator

# Configure logging
logging.basicConfig()
log = logging.getLogger()
log.setLevel(logging.INFO)

class PhysicsAwareDataBlock(ModbusSequentialDataBlock):
    def __init__(self, address, values, physics_engine):
        super().__init__(address, values)
        self.physics_engine = physics_engine
        self._lock = threading.Lock()   # sync lock, not asyncio

    def setValues(self, address, values):
        super().setValues(address, values)
        log.info(f"setValues called: address={address}, values={values}")  # add this
        if address == 200:
            self.physics_engine.set_pump_rpm(values[0])
            log.info(f"Modbus Write: Pump RPM set to {values[0]}")
        elif address == 201:
            self.physics_engine.set_valve_pos(values[0])
            log.info(f"Modbus Write: Valve State set to {values[0]}")

    def getValues(self, address, count=1):
        with self._lock:
            self.physics_engine.update()
            state = self.physics_engine.get_state()
            super().setValues(100, [int(state["pressure"])])
            super().setValues(101, [int(state["flow_rate"] * 10)])
            return super().getValues(address, count)

async def run_server():
    physics = PipelineSimulator()
    
    # Initialize datastore
    store = PhysicsAwareDataBlock(0, [0] * 300, physics)
    context = ModbusSlaveContext(hr=store)
    single_context = ModbusServerContext(slaves=context, single=True)
    
    # Setup Device Identity
    identity = ModbusDeviceIdentification()
    identity.VendorName = 'PurdueEnergy'
    identity.ProductCode = 'PE-PLC-01'
    identity.VendorUrl = 'http://purdue-energy.com/'
    identity.ProductName = 'Purdue Level 1 Controller'
    identity.ModelName = 'PLC-Simulator'
    identity.MajorMinorRevision = '2.1.0'

    log.info("Starting Modbus PLC Simulator (v3.x) on port 5020...")
    
    # Start the server
    await StartAsyncTcpServer(
        context=single_context, 
        identity=identity, 
        address=("0.0.0.0", 5020)
    )

if __name__ == "__main__":
    try:
        asyncio.run(run_server())
    except KeyboardInterrupt:
        log.info("Stopping server...")