import time
import random
import os
import json
import redis


class PipelineSimulator:
    """
    Physics model for a pressure-regulated oil pipeline.

    Fix 1 — Flow Rate Initialization:
      • Physics engine is the SINGLE SOURCE OF TRUTH for flow_rate.
      • If valve_pos == 0 (closed) → flow_rate is ALWAYS 0, regardless of pump RPM.
      • This constraint is enforced at:
          - __init__   (initial state)
          - update()   (every simulation tick)
          - get_state() (any read of state)
        This eliminates any race condition or stale-state issue because the
        check lives in every path that returns or persists flow_rate.
    """

    def __init__(self, use_redis: bool = False):
        self.use_redis  = use_redis
        self.redis_host = os.environ.get("REDIS_HOST", "localhost")
        self.redis_port = int(os.environ.get("REDIS_PORT", 6379))
        self.r = None

        if self.use_redis:
            try:
                self.r = redis.Redis(
                    host=self.redis_host, port=self.redis_port,
                    db=0, decode_responses=True
                )
                print(f"[PHYSICS] Connected to Redis at {self.redis_host}:{self.redis_port}")
            except Exception as e:
                print(f"[PHYSICS] Redis connection error: {e}")
                self.use_redis = False

        # ── Fix 1: Start with valve CLOSED — flow MUST be 0 ──────────────────
        self.pump_rpm    = 1200      # pump can be running…
        self.valve_pos   = 0.0       # …but valve is CLOSED at startup
        self.pressure    = 0.0       # will build up from 0 as physics converge
        self.flow_rate   = 0.0       # CLOSED valve → zero flow
        self.temperature = 18.5
        self.viscosity   = 1.0
        self.last_update = time.time()

        # Load state from Redis if a previous run's state exists
        if self.use_redis and self.r and self.r.exists("pipeline_state"):
            self.load_state()
            # Re-enforce physical consistency after loading
            self._enforce_valve_constraint()

    # ── Physical consistency enforcement ──────────────────────────────────────
    def _enforce_valve_constraint(self) -> None:
        """If valve is closed, flow rate must be zero. No exceptions."""
        if self.valve_pos <= 0.01:     # treat anything ≤1% as fully closed
            self.flow_rate = 0.0
            self.valve_pos = 0.0       # snap to exact zero to avoid float drift

    def set_pump_rpm(self, rpm: float) -> None:
        self.pump_rpm = max(0.0, min(float(rpm), 3000.0))
        self._enforce_valve_constraint()
        if self.use_redis:
            self.save_state()

    def set_valve_pos(self, pos: float) -> None:
        self.valve_pos = max(0.0, min(float(pos), 1.0))
        self._enforce_valve_constraint()   # immediately zero flow if closing
        if self.use_redis:
            self.save_state()

    def update(self) -> dict:
        if self.use_redis:
            self.load_state()

        now = time.time()
        dt  = now - self.last_update
        self.last_update = now

        # ── Physics: Backpressure and Flow ────────────────────────────────────
        target_pressure = (self.pump_rpm / 10.0) * (1.5 - (self.valve_pos * 0.8))

        # Fix 1: valve closed → target flow = 0, current flow collapses to 0
        if self.valve_pos <= 0.01:
            target_flow    = 0.0
            self.flow_rate = 0.0   # hard clamp — no gradual decay when fully closed
        else:
            target_flow = (self.pump_rpm / 50.0) * self.valve_pos

        # ── Thermodynamics ────────────────────────────────────────────────────
        temp_gain = (self.pump_rpm / 1000.0) * 0.5 * dt
        temp_loss = (self.flow_rate * 0.05) * dt + (self.temperature - 25.0) * 0.02 * dt
        self.temperature += temp_gain - temp_loss

        # ── Viscosity (oil behaviour) ─────────────────────────────────────────
        self.viscosity = max(0.2, 1.0 - (self.temperature - 25.0) * 0.02)

        # ── Convergence with sensor noise ─────────────────────────────────────
        self.pressure  += (target_pressure - self.pressure)  * 0.2 + random.uniform(-0.2, 0.2)
        if self.valve_pos > 0.01:
            self.flow_rate += (target_flow - self.flow_rate) * 0.2 + random.uniform(-0.05, 0.05)

        # Final constraint pass (guards against numeric drift)
        self._enforce_valve_constraint()

        if self.use_redis:
            self.save_state()

        return self.get_state()

    def save_state(self) -> None:
        if not self.r:
            return
        self.r.set("pipeline_state", json.dumps(self.get_state()))

    def load_state(self) -> None:
        if not self.r:
            return
        data = self.r.get("pipeline_state")
        if data:
            state = json.loads(data)
            self.pump_rpm    = state.get("pump_rpm",     self.pump_rpm)
            self.valve_pos   = state.get("valve_pos",    self.valve_pos)
            self.pressure    = state.get("pressure",     self.pressure)
            self.flow_rate   = state.get("flow_rate",    self.flow_rate)
            self.temperature = state.get("temperature",  self.temperature)
            self.viscosity   = state.get("viscosity",    self.viscosity)

    def get_state(self) -> dict:
        # Fix 1: enforce constraint at every read path
        flow = 0.0 if self.valve_pos <= 0.01 else max(0.0, self.flow_rate)
        return {
            "pressure":    round(max(0.0, self.pressure),  2),
            "flow_rate":   round(flow,                      2),
            "temperature": round(self.temperature,          2),
            "viscosity":   round(self.viscosity,            2),
            "pump_rpm":    self.pump_rpm,
            "valve_pos":   self.valve_pos,
        }