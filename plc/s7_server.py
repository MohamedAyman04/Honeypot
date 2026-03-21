import snap7
from snap7.util import set_real
import time
from physics.physics_engine import PipelineSimulator

def run_s7_server():
    simulator = PipelineSimulator()
    server = snap7.server.Server()
    
    # Create a DB (Data Block) 1 with 100 bytes
    size = 100
    db_data = (snap7.types.wordlen_to_ctypes[snap7.types.S7WLByte] * size)()
    server.register_area(snap7.types.srvAreaDB, 1, db_data)
    
    server.start(port=102)
    print("S7comm Server (Siemens) started on port 102")

    try:
        while True:
            simulator.update()           # update physics
            state = simulator.get_state()  # then read state
            set_real(db_data, 0, state['pressure'])
            set_real(db_data, 4, state['temperature'])
            time.sleep(1)
    except KeyboardInterrupt:
        server.stop()