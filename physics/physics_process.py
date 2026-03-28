"""
Physical Process Simulator
==========================
This script continuously models the pressure-regulated pipeline.
It stores the shared state in Redis, which is read by the Modbus and S7 servers.
Reflects the effects of PLC register writes observed via Redis.
"""
import time
import os
from physics.physics_engine import PipelineSimulator

def run_physics():
    # Standalone simulator linked to Redis
    sim = PipelineSimulator(use_redis=True)
    sim.set_pump_rpm(1200)  # Start with a running process (1200 RPM)
    sim.set_valve_pos(0.5)   # Set valve halfway
    
    print("--- PHYSICAL PROCESS SIMULATOR STARTED ---")
    print(f"Update interval: 1s")
    
    while True:
        sim.update()
        state = sim.get_state()
        print(f"[PHYSICS] P={state['pressure']:.1f}  F={state['flow_rate']:.2f}  T={state['temperature']:.1f}°C")
        time.sleep(1)

if __name__ == "__main__":
    run_physics()
