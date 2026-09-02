# ICS Honeypot — Physics-Aware Industrial Control System Deception & Cross-Layer Intrusion Detection Environment

A high-interaction, physics-grounded Industrial Cyber-Physical System (\ac{icps}) honeypot and cross-layer intrusion detection research environment. Designed to emulate realistic Operational Technology (\ac{ot}) infrastructure across 4 segmented Docker networks, continuous hydraulic physics simulation, Modbus/TCP, S7comm, and DNP3 services, automated 9-phase cyber-attack campaigns (including stealth drift, un-commanded telemetry replay, and authorized SCADA insider setpoint manipulation), and a 6-layer cross-layer detection architecture.

---

## 1. Executive Summary & Authoritative Benchmark Entry Point

> **Authoritative Evaluation Script:** `python scripts/canonical_evaluation.py`
> 
> **Summary Report:** [`results/CANONICAL_RESULTS.md`](results/CANONICAL_RESULTS.md)

Conventional intrusion detection systems suffer from a single-perspective monitoring limitation: network-level monitors are 100% blind to out-of-band telemetry spoofing (Phase 8 Replay) and authorized insider setpoint changes (Phase 9), while process-level monitors fail to distinguish malicious tampering from operational transients, causing precision collapse. Furthermore, naive multi-layer fusion rules (logical OR fusion / weighted voting) accumulate false alarms across independent process detectors, dropping precision down to 0.165–0.212 ($\text{F1} = 0.268$--$0.333$).

To overcome these vulnerabilities, this project implements:
1. **Domain Feature Separation:** $\mathbf{x}_{\text{net}}$ (protocol timing, write frequency, function code, length) for $\text{ML}_{\text{net}}$ ($0.982$--$0.989$ Precision) vs. $\mathbf{x}_{\text{proc}}$ (pressure, flow rate, temperature, pressure delta, mean deviation) for $\text{ML}_{\text{proc}}$.
2. **Narrow Mechanism Gate (NMG — Stealth Replay Gate):** $A_{\text{NMG}} = A_{\text{net}} \lor \left( |\delta_P| > \tau_{\text{NMG}} \land f_{\text{write\_10s}} == 0 \right)$, admitting process alerts *only* when network detection is silent AND physical mean deviations occur without Modbus write traffic.
3. **Dual-Gated Physical Mechanism Defense:** Pairing NMG's *Stealth Replay Gate* (Phase 8 replay, $87.6\%$ recall) with Layer 2's deterministic *Physical Boundary Gate* ($P > 150\text{ PSI}$, Phase 9 insider setpoint attack, $100.0\%$ recall).

### Reproducible Benchmark Results Across 3 Multi-Hour Campaigns

All numbers below are produced by `python scripts/canonical_evaluation.py` (`val_frac=0.45`, `SEED=42`, validation-only threshold calibration, recovery masking):

| Dataset | Configuration | Precision | Recall | F1 Score | TP | FP | FN |
|---|---|---:|---:|---:|---:|---:|---:|
| **Dataset 1** (`20260724_014825`, 6.5h) | Network-only Baseline ($\text{L1} + \text{ML}_{\text{net}}$) | 0.866 | 0.378 | **0.527** | 123 | 19 | 202 |
| | Combined Architecture (OR Fusion) | 0.212 | 0.778 | **0.333** | 253 | 942 | 72 |
| | ★ **Narrow Mechanism Gate (NMG)** | **0.485** | **0.760** | **0.592** | **247** | **262** | **78** |
| | | | | | | | |
| **Dataset 2** (`20260725_055634`, 6.5h) | Network-only Baseline ($\text{L1} + \text{ML}_{\text{net}}$) | 0.982 | 0.538 | **0.695** | 267 | 5 | 229 |
| | Combined Architecture (OR Fusion) | 0.173 | 0.829 | **0.286** | 411 | 1965 | 85 |
| | ★ **Narrow Mechanism Gate (NMG)** | **0.600** | **0.972** | **0.742** | **482** | **321** | **14** |
| | | | | | | | |
| **Dataset 3** (`20260801_052308`, 7.8h) | Network-only Baseline ($\text{L1} + \text{ML}_{\text{net}}$) | 0.989 | 0.601 | **0.748** | 366 | 4 | 243 |
| | Combined Architecture (OR Fusion) | 0.167 | 0.700 | **0.270** | 426 | 2124 | 183 |
| | ★ **Narrow Mechanism Gate (NMG)** | **0.881** | **0.901** | **0.891** | **549** | **74** | **60** |

---

## 2. Six-Layer Cross-Layer Detection Architecture

The framework processes synchronized network packets, PLC registers, and physical process telemetry through 6 reasoning layers:

```
[Layer 1: Protocol Semantic Verification] ──► Modbus write verification & forced-write rules
[Layer 2: Expert Safety Rules]            ──► Physical Boundary Gate (P > 150 PSI safety limit)
[Layer 3: Statistical Drift Monitor]       ──► EWMA & CUSUM on pressure dynamics (K=0.5, H=6.0)
[Layer 4: Cross-Layer Correlator]         ──► Command-to-consequence temporal verification
[Layer 5: Domain-Separated ML Ensemble]   ──► ML_net (5 network features) & ML_proc (5 process features)
[Layer 6: Decision Fusion & NMG]          ──► Narrow Mechanism Gate & Dual-Gated Physical Defense
```

- **Layer 1 (Raw Telemetry & Protocol Semantics):** Ingests 1~Hz synchronized telemetry; performs deep packet inspection on Modbus/TCP (FC3, FC4, FC6, FC16) to verify function codes and unauthorized write attempts.
- **Layer 2 (Expert Rule Engine & Multi-Variable Physical Safety Boundaries):** Evaluates deterministic engineering constraints across pressure, flow rate, temperature, pump speed, dynamic transient rates ($dP/dt$), and cavitation criteria grounded in industrial standards (ASME B31.4, API 610, HI 9.6.1). $P > 150\text{ PSI}$ acts as the primary Physical Boundary Gate for SCADA insider setpoint abuses (Phase 9).
- **Layer 3 (Temporal Statistical Detector):** Implements EWMA ($\lambda=0.1$) and CUSUM ($K=0.5, H=6.0$) to detect persistent stealth drift (Phase 5) before physical safety limits are breached.
- **Layer 4 (Cross-Layer Command-Consequence Correlator):** Verifies that physical process state changes correspond to authorized Modbus commands within $\Delta t_{\max}$.
- **Layer 5 (Machine Learning Ensemble & Domain Separation):** Trains dual Isolation Forest and LSTM Autoencoders ($20\text{ timesteps} \times 5\text{ features}$) on separate feature spaces to prevent normal process noise from bleeding into network scores.
- **Layer 6 (Selective Mechanism Gating & Dual-Gated Defense):** Combines network semantic alerts with NMG's Stealth Replay Gate ($|\delta_P| > \tau \land f_{\text{write\_10s}} == 0$) and Layer 2's Physical Boundary Gate ($P > 150\text{ PSI}$).

---

## 3. Deterministic Physical Safety Boundaries & Engineering Justifications

Rather than relying on a single pressure inequality, the architecture codifies a comprehensive multi-variable physical safety boundary system (`physics/safety_boundaries.py`) grounded in authoritative industrial standards:

| Physical Variable | Safety Threshold | Severity | Industrial Standard Grounding & Engineering Rationale |
|---|---|---|---|
| **Pressure ($P$)** | $P > 300.0\text{ PSI}$ | **Rupture Trip** | **ASME B31.4 Schedule 40 Pipe Rupture:** Catastrophic burst limit exceeding yield strength. |
| | $P > 150.0\text{ PSI}$ | **Critical Trip** | **ASME B31.4 / ISA-84 125% MAOP:** Safety Instrumented System (SIS) high-pressure trip. Catches Phase 9 insider attacks. |
| | $P > 140.0\text{ PSI}$ | Warning | **Normal Operating Margin (116%):** Upper operational boundary warning before emergency shutdown. |
| | $P < 50.0\text{ PSI}$ | **Critical Trip** | **ASME B31.4 Containment Loss:** Low-pressure trip indicating major pipe rupture or severe suction loss. |
| | $P < 90.0\text{ PSI}$ | Warning | **Hydraulic Efficiency Standard:** Pressure drop warning indicating pump performance degradation. |
| **Flow Rate ($Q$)** | $Q > 75.0\text{ L/s}$ | **Critical Trip** | **API 610 Pump Runout & Pipe Erosion:** Prevents fluid velocity exceeding maximum design limits and motor overloading. |
| | $Q \le 5.0\text{ L/s} \land R \ge 800\text{ RPM}$ | **Critical Trip** | **API 610 Minimum Continuous Stable Flow (MCSF):** Detects deadhead pumping against a closed valve, preventing explosive thermal fluid expansion. |
| **Temperature ($T$)** | $T > 75.0^\circ\text{C}$ | **Critical Trip** | **API 610 Mechanical Seal Limits:** Exceeds seal elastomer temperature thresholds, risking seal blowout and fluid vaporization. |
| | $T > 65.0^\circ\text{C}$ | Warning | **Thermodynamic Dissipation Warning:** Early indication of excessive friction, insufficient cooling, or deadhead operation. |
| **Pump Speed ($R$)** | $R > 2000\text{ RPM}$ | **Critical Trip** | **API 610 Continuous Rotor Limit:** Exceeds mechanical shaft critical speed and bearing vibration thresholds. |
| | $R > 1800\text{ RPM}$ | Warning | **Motor Duty Warning:** Continuous operation in intermittent/surge territory. |
| **Transient ($\Delta P / \Delta Q$)** | $\|dP/dt\| > 25.0\text{ PSI/s}$ | **Critical Trip** | **Hydraulic Institute HI 9.6.1 Water Hammer:** Detects steep hydraulic shockwaves caused by rapid actuator closure. |
| | $\|dQ/dt\| > 15.0\text{ L/s/s}$ | Warning | **Hydraulic Institute HI 14.3 Flow Shock:** Detects abrupt flow transients exceeding steady-state dissipation capacity. |
| **Cavitation Risk** | $R > 1800\text{ RPM} \land V \le 0.15$ | **Critical Trip** | **Hydraulic Institute NPSH Criteria:** High impeller velocity against throttled valve induces localized vaporization and cavitation erosion. |

---

## 4. Standardized ML-Ready JSONL Logging Schema

The unified audit log ([`general logs.jsonl`](general%20logs.jsonl)) provides a balanced, structured, multi-variable cyber-physical dataset where every single event embeds complete synchronized feature vectors and ML ground-truth labels:

```json
{
  "timestamp": "2026-09-02T15:30:00.000000Z",
  "event_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "event": {
    "type": "over_pressure_trip",
    "severity": "CRITICAL",
    "narrative": "Critical overpressure (325.0 PSI > 150 PSI) caused by pump overspeed to 2800 RPM against closed valve."
  },
  "context": {
    "sensor": "plc_simulator",
    "purdue_level": "Level 2",
    "journey_id": "unified_campaign_run",
    "session_id": "b8e5b21b"
  },
  "network": {
    "source": {
      "ip": "172.24.0.50",
      "port": 49152
    },
    "destination": {
      "ip": "172.24.0.8",
      "port": 502
    },
    "protocol": "Modbus",
    "inter_arrival_time": 0.052,
    "write_frequency_10s": 1.0,
    "is_write": 1,
    "function_code": 6,
    "length": 20
  },
  "process": {
    "pressure": 325.0,
    "flow_rate": 0.0,
    "temperature": 48.2,
    "pump_rpm": 2800.0,
    "valve_position": 0.0,
    "viscosity": 1.0,
    "pressure_delta": 45.0,
    "pressure_mean_deviation": 205.0
  },
  "ml_analysis": {
    "is_anomaly": 1,
    "anomaly_type": "OVER_PRESSURE_TRIP",
    "attack_phase": 9,
    "attack_category": "Insider Setpoint Overpressure",
    "boundary_violations": [
      {
        "violation_type": "OVER_PRESSURE_TRIP",
        "severity": "CRITICAL",
        "variable": "pressure",
        "observed_value": 325.0,
        "threshold_value": 150.0,
        "standard_ref": "ASME B31.4 125% MAOP Safety Trip"
      }
    ]
  },
  "mitre": {
    "technique_id": "T0828",
    "technique_name": "Loss of Safety",
    "tactic": "Damage to Property"
  },
  "security": {
    "kill_chain_stage": "Stage 2 - ICS Impact"
  }
}
```

### Direct Machine Learning Ingestion in Python
```python
import pandas as pd

# Load dataset
df = pd.read_json("general logs.jsonl", lines=True)

# Extract feature matrices and labels directly
X_proc = pd.json_normalize(df["process"])
X_net  = pd.json_normalize(df["network"])
y      = pd.json_normalize(df["ml_analysis"])["is_anomaly"]

print("Process Matrix:", X_proc.shape)  # (N, 8)
print("Network Matrix:", X_net.shape)   # (N, 10)
print("Anomaly Count: ", y.sum())
```

The physics engine (`physics/physics_engine.py`) models a continuously evolving oil pipeline process.

### State Relaxation Dynamics & Equations

Target equilibrium states for pressure $P^*$, volumetric flow rate $Q^*$, and fluid temperature $T$:
```
P*(t) = (pump_rpm / 10.0) × (1.5 - valve_pos × 0.8)
Q*(t) = (pump_rpm / 50.0) × valve_pos
```

Continuous state dynamics (matching Paper Eq. 2–4):
$$\dot{P}(t) = \kappa_p \left( P^*(t) - P(t) \right) + \eta_p(t)$$
$$\dot{Q}(t) = \kappa_q \left( Q^*(t) - Q(t) \right) + \eta_q(t)$$
$$\dot{T}(t) = \gamma_t R(t) - \delta_t Q(t) - \lambda_t (T(t) - T_{\text{ambient}}) + \eta_t(t)$$

where $R(t)$ is pump RPM (0–3000), $V(t)$ is valve position (0.0–1.0), and $\eta_p, \eta_q, \eta_t$ represent zero-mean Gaussian sensor noise.

**Physical Hard Constraint:** When valve position $V(t) \le 0.01$ (closed), flow rate $Q(t)$ is hard-clamped to $0.0\text{ L/s}$, and backpressure builds as a function of pump speed $R(t)$.

---

## 4. 9-Phase Cyber Attack Campaign

The environment supports automated 9-phase cyber-attack campaigns spanning initial network reconnaissance to physical process manipulation and authorized SCADA insider setpoint changes:

| Phase | Scenario / Attack Tactic | Operational Description | Detection Mechanism |
|---|---|---|---|
| 1 | Reconnaissance | Port scanning & network enumeration | Layer 1 Network Semantics |
| 2 | Information Gathering | Service & device fingerprinting | Layer 1 Network Semantics |
| 3 | Vulnerability Scan | Modbus/PLC service scanning | Layer 1 Network Semantics |
| 4 | Semantic Injection | High-frequency sub-second Modbus write toggles | Layer 1 Network Semantics (70.0% recall) |
| 5 | Stealth Pressure Drift | Gradual pressure setpoint drift ($2$--$3$ PSI/step over 129s) | Layer 3 EWMA/CUSUM & $\text{ML}_{\text{net}}$ (100.0% recall) |
| 6 | Discovery & Lateral Movement | Internal OT host pivoting | Layer 1 Network Semantics |
| 7 | Actuator Hijack | Forced valve closure at max pump RPM | Layer 1 $\text{ML}_{\text{net}}$ & Layer 4 (97.2% recall) |
| 8 | Telemetry Replay Attack | Out-of-band InfluxDB historical telemetry replay | Layer 6 NMG Stealth Replay Gate (87.6% recall) |
| 9 | SCADA Insider Setpoint | Authorized SSH/HMI setpoint changes (`ics_scada_ssh`) | Layer 2 Physics Boundary Gate ($P>150$, 100.0% recall) |

---

## 5. Quickstart & Evaluation Instructions

### Setup Environment
```bash
# Clone and enter workspace
git clone https://github.com/MohamedAyman04/Honeypot.git
cd Honeypot

# Activate virtual environment
source honeypot-venv/bin/activate  # or create venv: python3 -m venv honeypot-venv && source honeypot-venv/bin/activate
pip install -r requirements.txt
```

### Run Authoritative Benchmark Evaluation
```bash
# Executes 3-dataset benchmark under canonical methodology
python scripts/canonical_evaluation.py
```

### Run Docker Infrastructure
```bash
# Start Docker honeypot stack (IDMZ, OT network, Monitoring, Enterprise)
docker compose up -d
```

---

## 6. Deprecation Notice

- **`evaluate.py`**: Marked as a legacy exploratory script. For authoritative, reproducible multi-hour campaign benchmarks under strict validation calibration and Phase 9 insider scoring, use `scripts/canonical_evaluation.py`.
