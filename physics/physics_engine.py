import time
import random
import os
import json
import redis

class PipelineSimulator:
    def __init__(self, use_redis=False):
        self.use_redis = use_redis
        self.redis_host = os.environ.get("REDIS_HOST", "localhost")
        self.redis_port = int(os.environ.get("REDIS_PORT", 6379))
        self.r = None
        if self.use_redis:
            try:
                self.r = redis.Redis(host=self.redis_host, port=self.redis_port, db=0, decode_responses=True)
                print(f"[PHYSICS] Connected to Redis at {self.redis_host}:{self.redis_port}")
            except Exception as e:
                print(f"[PHYSICS] Redis connection error: {e}")
                self.use_redis = False

        self.pump_rpm = 1200
        self.valve_pos = 0.5
        self.pressure = 50.0  # approximate starting pressure
        self.flow_rate = 12.0 # approximate starting flow
        self.temperature = 18.5
        self.viscosity = 1.0
        self.last_update = time.time()
        
        # Load initial state if in Redis
        if self.use_redis and self.r.exists("pipeline_state"):
            self.load_state()

    def set_pump_rpm(self, rpm):
        self.pump_rpm = max(0, min(float(rpm), 3000))
        if self.use_redis:
            self.save_state()
        
    def set_valve_pos(self, pos):
        self.valve_pos = max(0.0, min(float(pos), 1.0))
        if self.use_redis:
            self.save_state()
        
    def update(self):
        # If using Redis, ensure we have latest setpoints/RPM
        if self.use_redis:
            self.load_state()

        now = time.time()
        dt = now - self.last_update
        self.last_update = now
        
        # Physics Logic: Backpressure and Flow
        target_pressure = (self.pump_rpm / 10.0) * (1.5 - (self.valve_pos * 0.8))
        target_flow     = (self.pump_rpm / 50.0) * self.valve_pos
        
        # Thermodynamic Logic
        temp_gain = (self.pump_rpm / 3000.0) * 0.5 * dt
        temp_loss = (self.temperature - 25.0) * 0.1 * dt
        self.temperature += temp_gain - temp_loss
        
        # Viscosity (Oil behavior)
        self.viscosity = max(0.2, 1.0 - (self.temperature - 25.0) * 0.02)
        
        # Convergence with Noise
        self.pressure += (target_pressure - self.pressure) * 0.2 + random.uniform(-0.2, 0.2)
        self.flow_rate += (target_flow - self.flow_rate) * 0.2 + random.uniform(-0.05, 0.05)
        
        if self.use_redis:
            self.save_state()
        
        return self.get_state()

    def save_state(self):
        if not self.r: return
        # Re-read the latest actuator setpoints (pump_rpm, valve_pos) from Redis
        # before persisting.  This prevents physics_process.update() from silently
        # overwriting a concurrent Modbus register write with a stale snapshot.
        try:
            live = self.r.get("pipeline_state")
            if live:
                live_state = json.loads(live)
                self.pump_rpm  = live_state.get("pump_rpm",  self.pump_rpm)
                self.valve_pos = live_state.get("valve_pos", self.valve_pos)
        except Exception:
            pass
        state = self.get_state()
        self.r.set("pipeline_state", json.dumps(state))

    def load_state(self):
        if not self.r: return
        data = self.r.get("pipeline_state")
        if data:
            state = json.loads(data)
            self.pump_rpm   = state.get("pump_rpm", self.pump_rpm)
            self.valve_pos  = state.get("valve_pos", self.valve_pos)
            self.pressure   = state.get("pressure", self.pressure)
            self.flow_rate  = state.get("flow_rate", self.flow_rate)
            self.temperature = state.get("temperature", self.temperature)
            self.viscosity  = state.get("viscosity", self.viscosity)

    def get_state(self):
        return {
            "pressure": round(max(0, self.pressure), 2),
            "flow_rate": round(max(0, self.flow_rate), 2),
            "temperature": round(self.temperature, 2),
            "viscosity": round(self.viscosity, 2),
            "pump_rpm": self.pump_rpm,
            "valve_pos": self.valve_pos
        }
