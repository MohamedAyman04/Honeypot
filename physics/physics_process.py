"""
Physical Process Simulator
==========================
Continuously models the pressure-regulated pipeline.
Stores shared state in Redis, which is read by Modbus and S7 servers.

Fix 1 — Flow Rate Initialization:
  Starts with valve CLOSED (valve_pos=0.0) so flow_rate is guaranteed = 0
  at container startup. The physics engine enforces this constraint internally.
"""
import time
import os
from physics.physics_engine import PipelineSimulator


def run_physics():
    sim = PipelineSimulator(use_redis=True)

    # Fix 1: Start with valve CLOSED — pump runs but no flow until operator opens valve
    sim.set_pump_rpm(1200)    # pump is running (builds pressure)
    sim.set_valve_pos(0.0)    # valve is CLOSED  → flow_rate = 0 (enforced by engine)

    print("--- PHYSICAL PROCESS SIMULATOR STARTED ---")
    print(f"    Initial state: pump=1200 RPM  valve=CLOSED  flow=0.0")
    print(f"    Update interval: 1s")

    while True:
        sim.update()
        state = sim.get_state()
        print(
            f"[PHYSICS] P={state['pressure']:.1f} PSI  "
            f"F={state['flow_rate']:.2f} L/s  "
            f"T={state['temperature']:.1f}°C  "
            f"valve={state['valve_pos']:.2f}"
        )
        time.sleep(1)


if __name__ == "__main__":
    run_physics()
