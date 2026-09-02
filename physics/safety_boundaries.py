"""
physics/safety_boundaries.py
=============================
Deterministic Physical Safety Boundaries & Engineering Constraints for ICPS.

Grounding & Standards Reference:
--------------------------------
1. ASME B31.4 / B31.3 (Pipeline Transportation Systems for Liquid Hydrocarbons):
   - Defines Maximum Allowable Operating Pressure (MAOP).
   - Safety trip envelope is typically set at 125% of nominal operating pressure.
   - Low pressure limit indicates pipe rupture or loss-of-containment.
2. API 610 / ISO 13709 (Centrifugal Pumps for Petroleum & Petrochemical Services):
   - Defines Minimum Continuous Stable Flow (MCSF) to prevent deadhead thermal buildup.
   - Mechanical overspeed trip threshold (+33% over maximum rated operational speed).
3. Hydraulic Institute Standards (HI 9.6.1 / HI 14.3):
   - Cavitation and water hammer rate-of-change (dP/dt) surge limits.
4. ISA-84 / IEC 61511 (Functional Safety: Safety Instrumented Systems):
   - High-High (HH), High (H), Low (L), and Low-Low (LL) trip boundaries.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class BoundarySeverity(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    TRIP = "CRITICAL"


class ViolationType(str, Enum):
    # Pressure
    OVER_PRESSURE_TRIP = "OVER_PRESSURE_TRIP"
    OVER_PRESSURE_WARN = "OVER_PRESSURE_WARN"
    UNDER_PRESSURE_TRIP = "UNDER_PRESSURE_TRIP"
    UNDER_PRESSURE_WARN = "UNDER_PRESSURE_WARN"
    PRESSURE_RUPTURE_LIMIT = "PRESSURE_RUPTURE_LIMIT"
    
    # Flow
    FLOW_SURGE_TRIP = "FLOW_SURGE_TRIP"
    DEADHEAD_BLOCKAGE = "DEADHEAD_BLOCKAGE"
    FLOW_REVERSE_ANOMALY = "FLOW_REVERSE_ANOMALY"
    
    # Temperature
    OVER_TEMPERATURE_TRIP = "OVER_TEMPERATURE_TRIP"
    OVER_TEMPERATURE_WARN = "OVER_TEMPERATURE_WARN"
    UNDER_TEMPERATURE_WARN = "UNDER_TEMPERATURE_WARN"
    
    # Pump Speed (Actuator)
    PUMP_OVERSPEED_TRIP = "PUMP_OVERSPEED_TRIP"
    PUMP_OVERSPEED_WARN = "PUMP_OVERSPEED_WARN"
    PUMP_UNDERSPEED_STALL = "PUMP_UNDERSPEED_STALL"
    
    # Dynamic Transients
    PRESSURE_SURGE_DELTA = "PRESSURE_SURGE_DELTA"
    FLOW_SURGE_DELTA = "FLOW_SURGE_DELTA"
    
    # Consistency / Cavitation
    CAVITATION_RISK = "CAVITATION_RISK"


@dataclass(frozen=True)
class SafetyLimits:
    """
    Physical engineering safety margins grounded in industrial standards.
    Nominal Baseline: P ≈ 120 PSI, Q ≈ 50 L/s, T ≈ 45 °C, Pump ≈ 1200 RPM, Valve ≈ 0.50.
    """
    # ── Pressure Limits (PSI) [ASME B31.4 MAOP Standard] ───────────────────
    # Nominal: 110 - 130 PSI
    P_NOMINAL_MIN: float = 110.0
    P_NOMINAL_MAX: float = 130.0
    P_WARN_MIN: float = 90.0
    P_WARN_MAX: float = 140.0
    P_TRIP_MIN: float = 50.0       # Loss of containment / major pipe breach
    P_TRIP_MAX: float = 150.0      # Physical Boundary Gate (125% of nominal 120 PSI)
    P_RUPTURE_LIMIT: float = 300.0 # Physical rupture limit of standard Schedule 40 pipe

    # ── Flow Rate Limits (L/s) [API 610 MCSF Standard] ─────────────────────
    # Nominal: 40 - 60 L/s at 50% valve position
    Q_NOMINAL_MIN: float = 40.0
    Q_NOMINAL_MAX: float = 60.0
    Q_SURGE_MAX: float = 75.0      # Pipe erosion / pump runout threshold
    Q_DEADHEAD_MIN: float = 5.0    # Minimum continuous stable flow (MCSF)
    Q_DEADHEAD_RPM: float = 800.0  # RPM above which Q < 5 L/s triggers deadhead trip

    # ── Temperature Limits (°C) [API 610 Thermal Dissipation] ───────────────
    # Nominal: 35 - 55 °C
    T_NOMINAL_MIN: float = 25.0
    T_NOMINAL_MAX: float = 55.0
    T_WARN_MAX: float = 65.0
    T_TRIP_MAX: float = 75.0       # Fluid vaporization & mechanical seal failure limit

    # ── Pump Speed Limits (RPM) [Motor Mechanical Limits] ───────────────────
    # Nominal: 1000 - 1500 RPM
    RPM_NOMINAL_MIN: float = 1000.0
    RPM_NOMINAL_MAX: float = 1500.0
    RPM_WARN_MAX: float = 1800.0
    RPM_TRIP_MAX: float = 2000.0   # Bearing damage & structural vibration limit
    RPM_STALL_MIN: float = 400.0   # Underspeed stall threshold when active

    # ── Dynamic Transient Rate-of-Change Limits (per second) ────────────────
    DELTA_P_SURGE_LIMIT: float = 25.0 # Water hammer limit (PSI/s)
    DELTA_Q_SURGE_LIMIT: float = 15.0 # Flow transient shock limit (L/s/s)

    # ── Cavitation / Physical Consistency Constraints ───────────────────────
    CAVITATION_RPM_MIN: float = 1800.0
    CAVITATION_VALVE_MAX: float = 0.15 # Valve mostly closed under high speed


DEFAULT_LIMITS = SafetyLimits()


@dataclass
class BoundaryViolation:
    violation_type: ViolationType
    severity: BoundarySeverity
    variable: str
    observed_value: float
    threshold_value: float
    message: str
    standard_ref: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "violation_type": self.violation_type.value,
            "severity": self.severity.value,
            "variable": self.variable,
            "observed_value": round(float(self.observed_value), 2),
            "threshold_value": round(float(self.threshold_value), 2),
            "message": self.message,
            "standard_ref": self.standard_ref,
        }


def evaluate_safety_boundaries(
    state: dict[str, float],
    prev_state: dict[str, float] | None = None,
    dt: float = 1.0,
    limits: SafetyLimits = DEFAULT_LIMITS,
) -> list[BoundaryViolation]:
    """
    Evaluates a telemetry state against the full suite of physical safety boundaries.
    
    Args:
        state: Dict containing 'pressure', 'flow_rate', 'temperature', 'pump_rpm', 'valve_pos'.
        prev_state: Optional prior state dict for computing dynamic transients.
        dt: Time delta between states (default 1.0s).
        limits: SafetyLimits configuration instance.
        
    Returns:
        List of BoundaryViolation objects detailing any tripped inequalities.
    """
    violations: list[BoundaryViolation] = []

    p = float(state.get("pressure", 0.0))
    q = float(state.get("flow_rate", 0.0))
    t = float(state.get("temperature", 25.0))
    rpm = float(state.get("pump_rpm", 0.0))
    valve = float(state.get("valve_pos", 0.5))

    # ─────────────────────────────────────────────────────────────────────────
    # 1. PRESSURE SAFETY BOUNDARIES (ASME B31.4 MAOP Standards)
    # ─────────────────────────────────────────────────────────────────────────
    if p > limits.P_RUPTURE_LIMIT:
        violations.append(BoundaryViolation(
            violation_type=ViolationType.PRESSURE_RUPTURE_LIMIT,
            severity=BoundarySeverity.TRIP,
            variable="pressure",
            observed_value=p,
            threshold_value=limits.P_RUPTURE_LIMIT,
            message=f"Catastrophic overpressure {p:.1f} PSI exceeds pipe rupture limit ({limits.P_RUPTURE_LIMIT} PSI)",
            standard_ref="ASME B31.4 Schedule 40 Rupture Limit",
        ))
    elif p > limits.P_TRIP_MAX:
        violations.append(BoundaryViolation(
            violation_type=ViolationType.OVER_PRESSURE_TRIP,
            severity=BoundarySeverity.TRIP,
            variable="pressure",
            observed_value=p,
            threshold_value=limits.P_TRIP_MAX,
            message=f"Critical overpressure {p:.1f} PSI breaches safety boundary ({limits.P_TRIP_MAX} PSI)",
            standard_ref="ASME B31.4 125% MAOP Safety Trip",
        ))
    elif p > limits.P_WARN_MAX:
        violations.append(BoundaryViolation(
            violation_type=ViolationType.OVER_PRESSURE_WARN,
            severity=BoundarySeverity.WARNING,
            variable="pressure",
            observed_value=p,
            threshold_value=limits.P_WARN_MAX,
            message=f"Warning: Pressure {p:.1f} PSI elevated above warning limit ({limits.P_WARN_MAX} PSI)",
            standard_ref="ASME B31.4 Normal Operating Margin",
        ))

    if p < limits.P_TRIP_MIN:
        violations.append(BoundaryViolation(
            violation_type=ViolationType.UNDER_PRESSURE_TRIP,
            severity=BoundarySeverity.TRIP,
            variable="pressure",
            observed_value=p,
            threshold_value=limits.P_TRIP_MIN,
            message=f"Critical underpressure {p:.1f} PSI indicates pipe rupture or loss-of-containment (< {limits.P_TRIP_MIN} PSI)",
            standard_ref="ASME B31.4 Containment Loss Standard",
        ))
    elif p < limits.P_WARN_MIN:
        violations.append(BoundaryViolation(
            violation_type=ViolationType.UNDER_PRESSURE_WARN,
            severity=BoundarySeverity.WARNING,
            variable="pressure",
            observed_value=p,
            threshold_value=limits.P_WARN_MIN,
            message=f"Warning: Pressure {p:.1f} PSI below nominal operating baseline (< {limits.P_WARN_MIN} PSI)",
            standard_ref="ASME B31.4 Hydraulic Efficiency Standard",
        ))

    # ─────────────────────────────────────────────────────────────────────────
    # 2. FLOW RATE SAFETY BOUNDARIES (API 610 MCSF Standards)
    # ─────────────────────────────────────────────────────────────────────────
    if q > limits.Q_SURGE_MAX:
        violations.append(BoundaryViolation(
            violation_type=ViolationType.FLOW_SURGE_TRIP,
            severity=BoundarySeverity.TRIP,
            variable="flow_rate",
            observed_value=q,
            threshold_value=limits.Q_SURGE_MAX,
            message=f"Flow surge {q:.1f} L/s exceeds maximum pipe erosion & pump runout velocity ({limits.Q_SURGE_MAX} L/s)",
            standard_ref="API 610 Pump Runout Limit",
        ))
    
    # Deadhead detection: Pump active at high speed but discharge blocked
    if rpm >= limits.Q_DEADHEAD_RPM and q <= limits.Q_DEADHEAD_MIN:
        violations.append(BoundaryViolation(
            violation_type=ViolationType.DEADHEAD_BLOCKAGE,
            severity=BoundarySeverity.TRIP,
            variable="flow_rate",
            observed_value=q,
            threshold_value=limits.Q_DEADHEAD_MIN,
            message=f"Deadhead hazard: Pump active at {rpm:.0f} RPM with near-zero flow ({q:.1f} L/s <= {limits.Q_DEADHEAD_MIN} L/s)",
            standard_ref="API 610 Minimum Continuous Stable Flow (MCSF)",
        ))

    # ─────────────────────────────────────────────────────────────────────────
    # 3. TEMPERATURE SAFETY BOUNDARIES (Thermodynamic Limits)
    # ─────────────────────────────────────────────────────────────────────────
    if t > limits.T_TRIP_MAX:
        violations.append(BoundaryViolation(
            violation_type=ViolationType.OVER_TEMPERATURE_TRIP,
            severity=BoundarySeverity.TRIP,
            variable="temperature",
            observed_value=t,
            threshold_value=limits.T_TRIP_MAX,
            message=f"Critical temperature {t:.1f} °C exceeds fluid vaporization & seal failure limit ({limits.T_TRIP_MAX} °C)",
            standard_ref="API 610 Mechanical Seal Temperature Limit",
        ))
    elif t > limits.T_WARN_MAX:
        violations.append(BoundaryViolation(
            violation_type=ViolationType.OVER_TEMPERATURE_WARN,
            severity=BoundarySeverity.WARNING,
            variable="temperature",
            observed_value=t,
            threshold_value=limits.T_WARN_MAX,
            message=f"Warning: Fluid temperature {t:.1f} °C elevated above warning baseline ({limits.T_WARN_MAX} °C)",
            standard_ref="API 610 Thermal Dissipation Baseline",
        ))

    # ─────────────────────────────────────────────────────────────────────────
    # 4. PUMP SPEED / ACTUATOR BOUNDARIES (Motor Mechanical Ratings)
    # ─────────────────────────────────────────────────────────────────────────
    if rpm > limits.RPM_TRIP_MAX:
        violations.append(BoundaryViolation(
            violation_type=ViolationType.PUMP_OVERSPEED_TRIP,
            severity=BoundarySeverity.TRIP,
            variable="pump_rpm",
            observed_value=rpm,
            threshold_value=limits.RPM_TRIP_MAX,
            message=f"Mechanical overspeed {rpm:.0f} RPM exceeds centrifugal pump rotor vibration limits ({limits.RPM_TRIP_MAX} RPM)",
            standard_ref="API 610 Maximum Continuous Rotor Speed",
        ))
    elif rpm > limits.RPM_WARN_MAX:
        violations.append(BoundaryViolation(
            violation_type=ViolationType.PUMP_OVERSPEED_WARN,
            severity=BoundarySeverity.WARNING,
            variable="pump_rpm",
            observed_value=rpm,
            threshold_value=limits.RPM_WARN_MAX,
            message=f"Warning: Pump RPM {rpm:.0f} operates above rated continuous duty ({limits.RPM_WARN_MAX} RPM)",
            standard_ref="API 610 Rated Operating Range",
        ))

    # ─────────────────────────────────────────────────────────────────────────
    # 5. DYNAMIC TRANSIENT SURGE BOUNDARIES (Water Hammer & Rate of Change)
    # ─────────────────────────────────────────────────────────────────────────
    if prev_state is not None and dt > 0:
        prev_p = float(prev_state.get("pressure", p))
        prev_q = float(prev_state.get("flow_rate", q))
        dp_dt = abs(p - prev_p) / dt
        dq_dt = abs(q - prev_q) / dt

        if dp_dt > limits.DELTA_P_SURGE_LIMIT:
            violations.append(BoundaryViolation(
                violation_type=ViolationType.PRESSURE_SURGE_DELTA,
                severity=BoundarySeverity.TRIP,
                variable="pressure_delta",
                observed_value=dp_dt,
                threshold_value=limits.DELTA_P_SURGE_LIMIT,
                message=f"Water hammer surge detected: dP/dt = {dp_dt:.1f} PSI/s exceeds transient surge limit ({limits.DELTA_P_SURGE_LIMIT} PSI/s)",
                standard_ref="Hydraulic Institute HI 9.6.1 Water Hammer Standard",
            ))

        if dq_dt > limits.DELTA_Q_SURGE_LIMIT:
            violations.append(BoundaryViolation(
                violation_type=ViolationType.FLOW_SURGE_DELTA,
                severity=BoundarySeverity.WARNING,
                variable="flow_delta",
                observed_value=dq_dt,
                threshold_value=limits.DELTA_Q_SURGE_LIMIT,
                message=f"Rapid flow transient: dQ/dt = {dq_dt:.1f} L/s/s exceeds steady-state gradient limit ({limits.DELTA_Q_SURGE_LIMIT} L/s/s)",
                standard_ref="Hydraulic Institute HI 14.3 Flow Transient Limit",
            ))

    # ─────────────────────────────────────────────────────────────────────────
    # 6. CAVITATION & MULTI-VARIABLE CONSISTENCY CONSTRAINTS
    # ─────────────────────────────────────────────────────────────────────────
    if rpm >= limits.CAVITATION_RPM_MIN and valve <= limits.CAVITATION_VALVE_MAX:
        violations.append(BoundaryViolation(
            violation_type=ViolationType.CAVITATION_RISK,
            severity=BoundarySeverity.TRIP,
            variable="cavitation_index",
            observed_value=rpm,
            threshold_value=limits.CAVITATION_RPM_MIN,
            message=f"Cavitation Hazard: High impeller speed ({rpm:.0f} RPM) against closed valve ({valve*100:.0f}%) causes localized vaporization & deadhead shock",
            standard_ref="Hydraulic Institute NPSH & Cavitation Criteria",
        ))

    return violations
