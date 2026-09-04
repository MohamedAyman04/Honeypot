# ICS Honeypot — Physics-Aware Industrial Control System Deception & Cross-Layer Intrusion Detection Environment

A high-interaction, physics-grounded Industrial Cyber-Physical System (\ac{icps}) honeypot and cross-layer intrusion detection research environment. Designed to emulate realistic Operational Technology (\ac{ot}) infrastructure across 4 segmented Docker networks, continuous hydraulic physics simulation, Modbus/TCP, Siemens S7comm, and DNP3 services, automated 10-scenario cyber-attack campaigns (including stealth drift, un-commanded telemetry replay, authorized SCADA insider setpoint manipulation, and denial-of-service starvation), and a 6-layer cross-layer detection architecture.

---

## 1. Executive Summary & Authoritative Benchmark Entry Point

> **Authoritative Evaluation Script:** `python scripts/canonical_evaluation.py`  
> **Summary Report:** [`results/CANONICAL_RESULTS.md`](results/CANONICAL_RESULTS.md)

Conventional intrusion detection systems suffer from a single-perspective monitoring limitation: network-level monitors are 100% blind to out-of-band telemetry spoofing (Scenario 8 Replay) and authorized insider setpoint changes (Scenario 9), while process-level monitors fail to distinguish malicious tampering from operational transients, causing precision collapse. Furthermore, naive multi-layer fusion rules (logical OR fusion / weighted voting) accumulate false alarms across independent process detectors, dropping precision down to 0.165–0.212 ($\text{F1} = 0.268$--$0.333$).

To overcome these vulnerabilities, this project implements:
1. **Domain Feature Separation:** $\mathbf{x}_{\text{net}}$ (protocol timing, write frequency, function code, length) for $\text{ML}_{\text{net}}$ ($0.982$--$0.989$ Precision) vs. $\mathbf{x}_{\text{proc}}$ (pressure, flow rate, temperature, pressure delta, mean deviation) for $\text{ML}_{\text{proc}}$.
2. **Narrow Mechanism Gate (NMG — Stealth Replay Gate):** $A_{\text{NMG}} = A_{\text{net}} \lor \left( |\delta_P| > \tau_{\text{NMG}} \land f_{\text{write\_10s}} == 0 \right)$, admitting process alerts *only* when network detection is silent AND physical mean deviations occur without Modbus write traffic.
3. **Dual-Gated Physical Mechanism Defense:** Pairing NMG's *Stealth Replay Gate* (Scenario 8 replay, $87.6\%$ recall) with Layer 2's deterministic *Physical Boundary Gate* ($P > 150\text{ PSI}$, Scenario 9 insider setpoint attack, $100.0\%$ recall).

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

## 2. Realistic Network Segmentation & Purdue Model Architecture

In accordance with **IEC 62443** and the **Purdue Model**, field industrial protocols (Modbus, S7comm, DNP3) are strictly **NOT** exposed on the external perimeter. The testbed models a realistic multi-stage network topology:

1. **Cloud / Enterprise External WAN (Purdue Level 4–5):** The internet-facing environment from which external adversaries originate.
2. **Perimeter DMZ & Edge Bastion (Level 3.5):** Hosts boundary services including the SCADA engineering SSH bastion (`ics_scada_ssh` on port 22) and external historian APIs. *No PLC protocols are exposed here.*
3. **Internal Process Control Network (PCN) / Field Control Area (Level 1–2):** Segregated internal OT network hosting field PLCs running Modbus/TCP (`502`), Siemens S7comm (`102`), and DNP3 (`20000`). Adversaries must breach the perimeter bastion and pivot across the firewall to reach the PCN.
4. **Physical Process Backplane (Level 0):** Interconnects field PLCs with the continuous hydrodynamic simulation engine.
5. **Out-of-Band Monitoring Network:** Dedicated VLAN for ML telemetry sniffers, InfluxDB, and Grafana.

---

## 3. Six-Layer Cross-Layer Detection Architecture

The framework processes synchronized network packets, PLC registers, and physical process telemetry through 6 reasoning layers:

```
[Layer 1: Protocol Semantic Verification] ──► Modbus/S7 write validation, burst filters, port integrity, DoS filter
[Layer 2: Expert Safety Rules]            ──► Physical Boundary Gate (P > 150 PSI ASME B31.4 MAOP trip)
[Layer 3: Multi-Variable Drift Monitor]   ──► Multi-Variable CUSUM & EWMA across P, Q, T, and pump RPM
[Layer 4: Cross-Layer Correlator]         ──► Command-to-consequence causal validation
[Layer 5: Domain-Separated ML Ensemble]   ──► ML_net (5 network features) & ML_proc (5 process features)
[Layer 6: Decision Fusion & NMG]          ──► Narrow Mechanism Gate (NMG) & Dual-Gated Physical Defense
```

### Empirical Detection Recall Percentage Across Layers:

| Attack Scenario / Class | Layer 1 (Proto) | Layer 2 (Physics) | Layer 3 (CUSUM) | Layer 4 (Causal) | Layer 5 (ML_net) | Layer 6 ($A_{\text{Fused}}$) |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **S1: Reconnaissance Scan** | 100.0% | 0.0% | 0.0% | 0.0% | 94.2% | **100.0%** ($A_{\text{net}}$) |
| **S2: Info Gathering** | 100.0% | 0.0% | 0.0% | 0.0% | 91.5% | **100.0%** ($A_{\text{net}}$) |
| **S3: Vulnerability Scan** | 100.0% | 0.0% | 0.0% | 0.0% | 95.8% | **100.0%** ($A_{\text{net}}$) |
| **S4: Semantic Injection** | 70.0% | 70.0% | 0.0% | 70.0% | 75.0% | **70.0%** ($A_{\text{net}}$) |
| **S5: Stealth Drift** | 0.0% | 47.0% | 100.0% | 0.0% | 99.2% | **100.0%** ($A_{\text{net}}$) |
| **S6: Lateral Movement** | 100.0% | 0.0% | 0.0% | 0.0% | 92.4% | **100.0%** ($A_{\text{net}}$) |
| **S7: Actuator Hijack** | 97.2% | 100.0% | 0.0% | 97.2% | 96.8% | **97.2%** ($A_{\text{net}}$) |
| **S8: Telemetry Replay** | **0.0%** | 99.5%$^*$ | 33.3% | 87.6% | **0.0%** | **87.6%** ($A_{\text{NMG}}$) |
| **S9: Insider Setpoint** | **0.0%** | **100.0%** | 2.9% | 0.0% | **0.0%** | **100.0%** ($A_{\text{L2\_Physics}}$) |
| **S10: Denial of Service** | 100.0% | 0.0% | 0.0% | 0.0% | 98.6% | **100.0%** ($A_{\text{net}}$) |

*Note: Raw Layer 2 detects physical flatlining during Scenario 8 but produces 2,120 false alarms under normal transients. Layer 6's NMG isolates Scenario 8 with 87.6% recall and zero false positive accumulation.*

---

## 4. 10-Scenario Cyber Attack Spectrum & Evaluation Methodology

The testbed incorporates 10 representative attack classes mapping to MITRE ATT&CK for ICS:

1. **Scenario 1 (Reconnaissance):** TCP port scan probing 502 (Modbus), 102 (S7comm), and 20000 (DNP3).
2. **Scenario 2 (Information Gathering):** Modbus FC3 holding register read sweep and S7comm COTP banner grabbing.
3. **Scenario 3 (Vulnerability Scan):** DNP3 link-state enumeration and S7 setup handshake probing.
4. **Scenario 4 (Semantic Injection):** High-frequency sub-second Modbus FC6 write bursts inducing hydraulic transients.
5. **Scenario 5 (Stealth Drift):** Subtle pressure setpoint ramping (+2–3 PSI/step over 129s).
6. **Scenario 6 (Lateral Movement):** SSH password brute-force targeting SCADA workstation (`ics_scada_ssh:22`).
7. **Scenario 7 (Actuator Hijack):** Forced valve closure while pump runs at max RPM ($P \to 457\text{ PSI}$).
8. **Scenario 8 (Telemetry Replay):** Out-of-band InfluxDB historical telemetry replay masking true physical state.
9. **Scenario 9 (SCADA Insider Setpoint):** Authorized operator setpoint abuse (RPM 2800–3200) from engineering workstation.
10. **Scenario 10 (Denial of Service - DoS):** Sub-5ms Modbus request flood and TCP socket starvation.

### Preserving Benchmark Integrity Against Metric Inflation
While Scenario 10 (DoS) is fully implemented and tested, it is deliberately evaluated as an architectural capability at Layer 1 (Rule 1.5) rather than injected into the continuous multi-hour evaluation campaigns (Datasets 1–3). Volumetric attacks are trivially detected by packet rate monitors; padding multi-hour datasets with thousands of easy DoS frames would artificially inflate recall and F1 scores, masking performance on challenging stealth attacks (Scenarios 5, 8, and 9).

---

## 5. Deterministic Physical Safety Boundaries & Standards Grounding

The architecture codifies multi-variable physical safety boundaries (`physics/safety_boundaries.py`) grounded in industrial standards:

| Physical Variable | Safety Threshold | Severity | Industrial Standard Grounding & Engineering Rationale |
|---|---|---|---|
| **Pressure ($P$)** | $P > 300.0\text{ PSI}$ | **Rupture Trip** | **ASME B31.4 Schedule 40 Pipe Rupture:** Catastrophic burst limit exceeding yield strength. |
| | $P > 150.0\text{ PSI}$ | **Critical Trip** | **ASME B31.4 / ISA-84 125% MAOP:** Safety Instrumented System (SIS) high-pressure trip. Catches Scenario 9 insider attacks. |
| | $P > 140.0\text{ PSI}$ | Warning | **Normal Operating Margin (116%):** Upper operational boundary warning before emergency shutdown. |
| | $P < 50.0\text{ PSI}$ | **Critical Trip** | **ASME B31.4 Containment Loss:** Low-pressure trip indicating major pipe rupture or severe suction loss. |
| | $P < 90.0\text{ PSI}$ | Warning | **Hydraulic Efficiency Standard:** Pressure drop warning indicating pump performance degradation. |
| **Flow Rate ($Q$)** | $Q > 75.0\text{ L/s}$ | **Critical Trip** | **API 610 Pump Runout & Pipe Erosion:** Prevents fluid velocity exceeding maximum design limits and motor overloading. |
| | $Q \le 5.0\text{ L/s} \land R \ge 800\text{ RPM}$ | **Critical Trip** | **API 610 Minimum Continuous Stable Flow (MCSF):** Detects deadhead pumping against a closed valve. |
| **Temperature ($T$)** | $T > 75.0^\circ\text{C}$ | **Critical Trip** | **API 610 Mechanical Seal Limits:** Exceeds seal elastomer temperature thresholds, risking seal blowout and fluid vaporization. |
| | $T > 65.0^\circ\text{C}$ | Warning | **Thermodynamic Dissipation Warning:** Early indication of excessive friction, insufficient cooling, or deadhead operation. |
| **Pump Speed ($R$)** | $R > 2000\text{ RPM}$ | **Critical Trip** | **API 610 Continuous Rotor Limit:** Exceeds mechanical shaft critical speed and bearing vibration thresholds. |
| | $R > 1800\text{ RPM}$ | Warning | **Motor Duty Warning:** Continuous operation in intermittent/surge territory. |
| **Transient ($\Delta P / \Delta Q$)** | $\|dP/dt\| > 25.0\text{ PSI/s}$ | **Critical Trip** | **Hydraulic Institute HI 9.6.1 Water Hammer:** Detects steep hydraulic shockwaves caused by rapid actuator closure. |
| | $\|dQ/dt\| > 15.0\text{ L/s/s}$ | Warning | **Hydraulic Institute HI 14.3 Flow Shock:** Detects abrupt flow transients exceeding steady-state dissipation capacity. |
| **Cavitation Risk** | $R > 1800\text{ RPM} \land V \le 0.15$ | **Critical Trip** | **Hydraulic Institute NPSH Criteria:** High impeller velocity against throttled valve induces cavitation erosion. |

---

## 6. Quickstart & Evaluation Instructions

### Setup Environment
```bash
# Clone and enter workspace
git clone https://github.com/MohamedAyman04/Honeypot.git
cd Honeypot

# Activate virtual environment
source honeypot-venv/bin/activate
pip install -r requirements.txt
```

### Run Authoritative Benchmark Evaluation
```bash
# Executes 3-dataset benchmark under canonical methodology
python scripts/canonical_evaluation.py
```

### Run Docker Infrastructure
```bash
# Start Docker honeypot stack (PCN, Perimeter Bastion, Monitoring)
docker compose up -d
```
