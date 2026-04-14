import logging
from pymodbus.server import StartAsyncTcpServer
from pymodbus.datastore import ModbusSequentialDataBlock, ModbusSlaveContext, ModbusServerContext
import asyncio

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("fake_plc")

# Custom datablock that ignores writes
class FakeDataBlock(ModbusSequentialDataBlock):
    def setValues(self, address, values):
        # Deliberately ignore the values the attacker tries to write
        # just logging the attempt to frustrate them.
        log.info(f"Received write attempt at register {address} with values {values} - IGNORING")
        # We don't propagate the values to super().setValues()
        pass

async def run_server():
    # Initialize with static, plausible "safe" data
    store = ModbusSlaveContext(
        di=FakeDataBlock(0, [0]*100),
        co=FakeDataBlock(0, [0]*100),
        hr=FakeDataBlock(0, [150, 40, 35, 1200]), # Static normal-looking pressure/flow/RPM
        ir=FakeDataBlock(0, [0]*100)
    )
    context = ModbusServerContext(slaves=store, single=True)

    log.info("Starting Fake PLC Modbus Server on 0.0.0.0:502 (Deception Mode)")
    await StartAsyncTcpServer(
        context=context,
        address=("0.0.0.0", 502)
    )

if __name__ == "__main__":
    asyncio.run(run_server())
