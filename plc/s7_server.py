import snap7.server
from snap7.util import set_real
import time
from physics.physics_engine import PipelineSimulator

# Handle both snap7 <= 0.x (snap7.types) and >= 1.x (snap7.type)
# SrvAreaDB is normally 0x04 or 5 depending on the enumeration.
try:
    from snap7.type import SrvArea
    srv_area_db = SrvArea.DB
except (ImportError, AttributeError):
    try:
        from snap7.types import srvAreaDB
        srv_area_db = srvAreaDB
    except ImportError:
        srv_area_db = 0x04 # Generic DB area code

def run_s7_server():
    simulator = PipelineSimulator()
    simulator.set_pump_rpm(1200) # Seed default physics
    simulator.set_valve_pos(0.5)

    server = snap7.server.Server()
    
    # Create a DB (Data Block) 1 with size 100 bytes
    db_data = bytearray(100)
    server.register_area(srv_area_db, 1, db_data)
    
    # Explicitly listen on port 102
    server.start(102)
    print("S7comm Server (Emulated S7-300) started on port 102")

    try:
        while True:
            simulator.update()
            state = simulator.get_state()
            
            # Map physical fields to floating point REALs in the DB
            set_real(db_data, 0,  state['pressure'])    # DB1.DBD0
            set_real(db_data, 4,  state['temperature']) # DB1.DBD4
            set_real(db_data, 8,  state['flow_rate'])   # DB1.DBD8
            set_real(db_data, 12, float(state['pump_rpm'])) # DB1.DBD12
            
            time.sleep(1)
    except KeyboardInterrupt:
        server.stop()

if __name__ == "__main__":
    run_s7_server()