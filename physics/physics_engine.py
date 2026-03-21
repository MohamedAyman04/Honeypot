import time
import random

class PipelineSimulator:
    def __init__(self):
        self.pump_rpm = 0
        self.valve_pos = 0.0 
        self.pressure = 0.0
        self.flow_rate = 0.0
        self.temperature = 25.0  # Celsius
        self.viscosity = 1.0     # Relative viscosity
        self.last_update = time.time()
        
    def set_pump_rpm(self, rpm):
        self.pump_rpm = max(0, min(rpm, 3000))
        
    def set_valve_pos(self, pos):
        # pos might be 0 or 1 from Modbus, or 0-100 mapped to 0.0-1.0
        self.valve_pos = max(0.0, min(float(pos), 1.0))
        
    def update(self):
        now = time.time()
        dt = now - self.last_update
        self.last_update = now
        
        # Physics Logic: Backpressure and Flow
        target_pressure = (self.pump_rpm / 10.0) * (1.5 - (self.valve_pos * 0.8))
        target_flow = (self.pump_rpm / 50.0) * self.valve_pos
        
        # Thermodynamic Logic: High RPM increases temperature
        temp_gain = (self.pump_rpm / 3000.0) * 0.5 * dt
        temp_loss = (self.temperature - 25.0) * 0.1 * dt
        self.temperature += temp_gain - temp_loss
        
        # Viscosity Logic: Higher temp decreases viscosity (Oil behavior)
        self.viscosity = max(0.2, 1.0 - (self.temperature - 25.0) * 0.02)
        
        # Mechanical Failure Simulation: Heat-induced pressure drop
        if self.temperature > 85.0:
            target_pressure *= 0.4  # Simulated seal leak
        
        # Convergence with Noise
        self.pressure += (target_pressure - self.pressure) * 0.2 + random.uniform(-0.2, 0.2)
        self.flow_rate += (target_flow - self.flow_rate) * 0.2 + random.uniform(-0.05, 0.05)
        
        return self.get_state()

    def get_state(self):
        return {
            "pressure": round(max(0, self.pressure), 2),
            "flow_rate": round(max(0, self.flow_rate), 2),
            "temperature": round(self.temperature, 2),
            "viscosity": round(self.viscosity, 2),
            "pump_rpm": self.pump_rpm,
            "valve_pos": self.valve_pos
        }
