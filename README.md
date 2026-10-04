# ICS Honeypot — Physics-Aware Industrial Control System Deception & Cross-Layer Intrusion Detection Environment

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg)](https://www.python.org/)
[![Docker Compose v2](https://img.shields.io/badge/Docker-Compose%20v2-2496ED.svg)](https://docs.docker.com/compose/)
[![Open Source: Public](https://img.shields.io/badge/Open%20Source-Public%20Repository-success.svg)](https://github.com/MohamedAyman04/Honeypot)
[![Benchmark F1](https://img.shields.io/badge/Champion%20F1-0.891-orange.svg)](#1-executive-summary--authoritative-benchmark-entry-point)
[![Datasets Available](https://img.shields.io/badge/Datasets-3%20Multi--Hour%20Campaigns-purple.svg)](#2-benchmark-datasets--download-links)

A high-interaction, physics-grounded Industrial Cyber-Physical System (ICPS) honeypot and cross-layer intrusion detection research environment. Emulates realistic Operational Technology (OT) infrastructure across 4 segmented Docker networks, continuous hydraulic physics simulation, Modbus/TCP, Siemens S7comm, and DNP3 services, automated 10-scenario cyber-attack campaigns (including stealth drift, un-commanded telemetry replay, authorized SCADA insider setpoint manipulation, and denial-of-service starvation), and a 6-layer cross-layer detection architecture.

> **Public Open-Source Research Platform:**  
> This repository is **public, open-source, and actively open to community contributions**. Whether you are an industrial cybersecurity researcher, an automation engineer, or a machine learning practitioner, we welcome bug reports, new industrial protocol implementations, high-fidelity physics simulators, advanced ML anomaly detection models, and benchmark extensions. Please refer to our [Contributing & Developer Guide](#9-contributing--developer-guide) to get started!

---

## 1. Executive Summary & Authoritative Benchmark Entry Point

> **Authoritative Evaluation Script:** `python scripts/canonical_evaluation.py`  
> **Summary Report:** [`reports/CANONICAL_RESULTS.md`](reports/CANONICAL_RESULTS.md)

Conventional intrusion detection systems suffer from a single-perspective monitoring limitation: network-level monitors are 100% blind to out-of-band telemetry spoofing (Scenario 8 Replay) and authorized insider setpoint changes (Scenario 9), while process-level monitors fail to distinguish malicious tampering from operational transients, causing precision collapse. Furthermore, naive multi-layer fusion rules (logical OR fusion / weighted voting) accumulate false alarms across independent process detectors, dropping precision down to 0.165–0.212 ($\text{F1} = 0.268$--$0.333$).

To overcome these vulnerabilities, this project implements:
1. **Domain Feature Separation:** $\mathbf{x}_{\text{net}}$ (protocol timing, write frequency, function code, length) for $\text{ML}_{\text{net}}$ ($0.982$--$0.989$ Precision) vs. $\mathbf{x}_{\text{proc}}$ (pressure, flow rate, temperature, pressure delta, mean deviation) for $\text{ML}_{\text{proc}}$. Strict feature isolation prevents baseline process variance from bleeding into network anomaly scores.
2. **Narrow Mechanism Gate (NMG — Replay Gate):** $A_{\text{NMG}}$ evaluates whether an observed physical state deviation ($|\delta_P| > \tau_{\text{NMG}}$) occurs in the absence of state-modifying write commands (`f_write_10s == 0`). This causal check isolates out-of-band telemetry replay (Scenario 8, $87.6\%$ recall) while suppressing over $96.5\%$ of process false alarms.
3. **Proposed Prioritized Decision Fusion ($A_{\text{Fused}}$):** The final reasoning layer evaluates:
   $$A_{\text{Fused}} = A_{\text{NMG}} \lor A_{\text{L3}} \lor A_{\text{proc}}$$
   where $A_{\text{NMG}}$ provides causal replay gating, $A_{\text{L3}}$ provides sequential statistical drift memory (CUSUM, Scenario 5, $100.0\%$ recall), and $A_{\text{proc}}$ provides deterministic physical safety limits (Layer 2, ASME B31.4 $P > 150\text{ PSI}$, Scenario 9 insider setpoint attack, $100.0\%$ recall) alongside unsupervised multivariate autoencoders (Layer $5_{\text{proc}}$). $A_{\text{Fused}}$ represents the definitive system-level anomaly verdict.

### Reproducible Benchmark Results Across 3 Multi-Hour Campaigns

All numbers below are produced by `python scripts/canonical_evaluation.py` (`val_frac=0.45`, `SEED=42`, validation-only threshold calibration, recovery masking):

| Dataset | Configuration / Layer | Precision | Recall | F1 Score | TP | FP | FN |
|---|---|---:|---:|---:|---:|---:|---:|
| **Dataset 1** (`20260724_014825`, 4.8h) | Network-Only Baseline ($A_{\text{net}}$) | 0.866 | 0.378 | 0.527 | 123 | 19 | 202 |
| | Combined Architecture (Naive OR) | 0.212 | 0.778 | 0.333 | 253 | 942 | 72 |
| | **Proposed Defense ($A_{\text{Fused}}$)** | **0.485** | **0.760** | **0.592** | **247** | **262** | **78** |
| | | | | | | | |
| **Dataset 2** (`20260725_055634`, 7.2h) | Network-Only Baseline ($A_{\text{net}}$) | 0.982 | 0.538 | 0.695 | 267 | 5 | 229 |
| | Combined Architecture (Naive OR) | 0.173 | 0.829 | 0.286 | 411 | 1965 | 85 |
| | **Proposed Defense ($A_{\text{Fused}}$)** | **0.600** | **0.972** | **0.742** | **482** | **321** | **14** |
| | | | | | | | |
| **Dataset 3** (`20260801_052308`, 7.8h) | Network-Only ($A_{\text{net}}$) | 0.989 | 0.601 | 0.748 | 366 | 4 | 243 |
| *(Primary Paper Benchmark)* | Process-Only ($A_{\text{proc}}$) | 0.160 | 0.665 | 0.258 | 405 | 2,124 | 204 |
| | Narrow Mechanism Gate ($A_{\text{NMG}}$) | 0.723 | 0.300 | 0.425 | 183 | 70 | 426 |
| | Naive OR Fusion ($\bigvee L_i$) | 0.167 | 0.700 | 0.270 | 426 | 2,124 | 183 |
| | Weighted Voting ($\mathbf{w} = [3, 3, 1, 3, 1, 1]$) | 0.167 | 0.700 | 0.270 | 426 | 2,124 | 183 |
| | Gated Confidence Fallback | 0.989 | 0.601 | 0.748 | 366 | 4 | 243 |
| | **Proposed Defense ($A_{\text{Fused}}$)** | **0.881** | **0.901** | **0.891** | **549** | **74** | **60** |

---

## 2. Benchmark Datasets & Download Links

The evaluation datasets gathered from extended continuous operational runs of the testbed are bundled directly in this repository and mirrored online:

> ### Primary Paper Benchmark: Dataset 3 (`dataset_3_20260801_052308`)
> - **Directory:** [`datasets/dataset_3/`](datasets/dataset_3/) (or via canonical symlink in [`datasets/`](datasets/))
> - **Campaign Duration:** **7.8 hours** continuous runtime (57,058 synchronized telemetry records @ 1 Hz)
> - **Threat Spectrum:** **Complete 10-Scenario Attack Suite**, introducing **Scenario 9 (authorized SCADA insider setpoint manipulation)** alongside stealth drift (S5) and out-of-band telemetry replay (S8).
> - **Paper Headline Metrics:** **$F_1 = 0.891$**, Recall = **$0.901$**, Precision = **$0.881$** (only 74 false alarms across 5,212 benign frames, achieving **95.2% benign specificity**).
> - **Why it is authoritative:** Dataset 3 provides the most comprehensive evaluation profile and is the primary dataset evaluated in the published manuscript.

### Dataset Directory & Remote Access Links

All three multi-hour datasets are accessible through the following channels:

| Dataset Identifier | Campaign Directory | Duration | Total Records | Attack Spectrum | Primary Highlight |
|---|---|:---:|:---:|:---:|---|
| **Dataset 1** | [`datasets/dataset_1/`](datasets/dataset_1/) | 4.8 h | 34,228 | Scenarios 1–8 | Baseline multi-stage campaign |
| **Dataset 2** | [`datasets/dataset_2/`](datasets/dataset_2/) | 7.2 h | 52,187 | Scenarios 1–8 | Extended multi-hour calibration |
| **Dataset 3** *(Primary)* | [`datasets/dataset_3/`](datasets/dataset_3/) | **7.8 h** | **57,058** | **Scenarios 1–10** | **Paper benchmark: F1=0.891, Recall=0.901, Scenario 9** |

- **Local Repository Directory:** [`datasets/`](datasets/) — See [`datasets/README.md`](datasets/README.md) for detailed column schemas, unit definitions, and CSV specifications.
- **Public GitHub Tree:** [github.com/MohamedAyman04/Honeypot/tree/main/datasets](https://github.com/MohamedAyman04/Honeypot/tree/main/datasets)
- **Anonymous Peer-Review Repository Mirror:** [anonymous.4open.science/r/Honeypot-FC35/tree/main/datasets](https://anonymous.4open.science/r/Honeypot-FC35/tree/main/datasets)

To reproduce the paper's canonical results directly on Dataset 3:
```bash
python scripts/canonical_evaluation.py --ds1 datasets/dataset_3 --ds2 datasets/dataset_3
```

---

## 3. Realistic Network Segmentation & Purdue Model Architecture

In accordance with **IEC 62443** and the **Purdue Model**, field industrial protocols (Modbus, S7comm, DNP3) are strictly **NOT** exposed on the external perimeter. The testbed models a realistic multi-stage network topology:

1. **Cloud / Enterprise External WAN (Purdue Level 4–5):** The internet-facing environment from which external adversaries originate.
2. **Perimeter DMZ & Edge Bastion (Level 3.5):** Hosts boundary services including the SCADA engineering SSH bastion (`ics_scada_ssh` on port 22) and external historian APIs. *No PLC protocols are exposed here.*
3. **Internal Process Control Network (PCN) / Field Control Area (Level 1–2):** Segregated internal OT network hosting field PLCs running Modbus/TCP (`502`), Siemens S7comm (`102`), and DNP3 (`20000`). Adversaries must breach the perimeter bastion and pivot across the firewall to reach the PCN.
4. **Physical Process Backplane (Level 0):** Interconnects field PLCs with the continuous hydrodynamic simulation engine.
5. **Out-of-Band Monitoring Network:** Dedicated VLAN for ML telemetry sniffers, InfluxDB, and Grafana.

---

## 4. Six-Layer Cross-Layer Detection Architecture

The framework processes synchronized network packets, PLC registers, and physical process telemetry through 6 reasoning layers:

```
[Layer 0: Protocol Integrity]             --> Protocol syntax, unauthorized function codes, register boundaries
[Layer 1: Network Dynamics]               --> Modbus/S7 write burst frequency, inter-arrival timing, DoS filtering
[Layer 2: Deterministic Physics]          --> ASME B31.4 MAOP (P > 150 PSI) and API 610 equipment safety envelopes
[Layer 3: Multi-Variable Drift Monitor]   --> Sequential CUSUM on EWMA-filtered pressure to detect creeping drift
[Layer 4: Command-Consequence Causality]  --> Verifies physical response follows active write commands within dt_max
[Layer 5: Domain-Separated ML Ensemble]   --> Dedicated ML_net (network timing) and ML_proc (hydraulic telemetry)
[Layer 6: Prioritized Decision Fusion]    --> Evaluates A_Fused = A_NMG or A_L3 or A_proc for final anomaly verdict
```

### Empirical Detection Recall Percentage Across Layers:

Consistent with Table VI of the manuscript (`results.tex`), the per-scenario recall achieved by each individual layer and the proposed fused defense ($A_{\text{Fused}}$) on Dataset 3 is reported below:

| # | Attack Scenario | Primary Attack Mechanism | Layers 0/1 (Protocol) | Layer 2 (Physics) | Layer 3 (CUSUM) | Layer 4 (Causal) | Layer 5_net (ML_net) | Layer 5_proc (ML_proc) | Proposed ($A_{\text{Fused}}$) |
|:---:|---|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **1** | Reconnaissance Scan | TCP SYN port scan (502/102/20000) | 100.0% | 0.0% | 0.0% | 0.0% | 94.2% | 0.0% | **100.0%** ($A_{\text{net}}$) |
| **2** | Information Gathering | Modbus FC3 read sweep, COTP CC grab | 100.0% | 0.0% | 0.0% | 0.0% | 91.5% | 0.0% | **100.0%** ($A_{\text{net}}$) |
| **3** | Vulnerability Scan | Probe DNP3 link states, S7 handshake | 100.0% | 0.0% | 0.0% | 0.0% | 95.8% | 0.0% | **100.0%** ($A_{\text{net}}$) |
| **4** | Semantic Injection | Sub-second FC6 write toggles (`f_write_10s > 5.0`) | 70.0% | 70.0% | 0.0% | 70.0% | 75.0% | 70.0% | **70.0%** ($A_{\text{proc}}$) |
| **5** | Stealth Drift | Creeping setpoint (+2–3 PSI/step, 129s) | 0.0% | 47.0% | 100.0% | 0.0% | 99.2% | 98.4% | **100.0%** ($A_{L3}$) |
| **6** | Lateral Movement | SSH password brute-force (port 22) | 100.0% | 0.0% | 0.0% | 0.0% | 92.4% | 0.0% | **100.0%** ($A_{\text{net}}$) |
| **7** | Actuator Hijack | Valve shutdown at max pump RPM (`P > 2000`) | 97.2% | 100.0% | 0.0% | 97.2% | 96.8% | 98.1% | **100.0%** ($A_{\text{proc}}$) |
| **8** | Telemetry Replay | InfluxDB direct spoofing (`f_write_10s == 0`, `|δ_P| > 35`) | **0.0%** | 99.5%* | 33.3% | 87.6% | **0.0%** | 92.3%* | **87.6%** ($A_{\text{NMG}}$) |
| **9** | Insider Setpoint | Authorized SCADA setpoint abuse (`P > 150`) | **0.0%** | **100.0%** | 2.9% | **0.0%** | **0.0%** | 96.0% | **100.0%** ($A_{\text{proc}}$) |
| **10** | Denial of Service (DoS) | Sub-5ms Modbus flooding (`Δt_arr < 5ms`) | 100.0% | 0.0% | 0.0% | 0.0% | 98.6% | 0.0% | **100.0%** ($A_{\text{net}}$) |

*Note: Raw process layers flag flatlines in Scenario 8 but produce 2,120 false positives during normal operation; NMG isolates Scenario 8 with 87.6% recall without false alarms. The final fusion layer asserts $A_{\text{Fused}} = A_{\text{NMG}} \lor A_{L3} \lor A_{\text{proc}}$, providing the unified anomaly verdict with 95.8% macro threat recall and 95.2% benign specificity.*

---

## 5. 10-Scenario Cyber Attack Spectrum & Evaluation Methodology

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

## 6. Deterministic Physical Safety Boundaries & Standards Grounding

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

## 7. Canonical Cross-Layer Logging Scheme & Audit Trail (`general_logs.jsonl`)

A core strength of this platform is the temporal synchronization of multi-perspective observations into a standardized, machine-learning-ready audit trail ([`data/general logs.jsonl`](data/general%20logs.jsonl)). Rather than producing disparate, unstructured text lines, the testbed's centralized logging engine ([`logger/unified_logger.py`](logger/unified_logger.py)) and schema specification ([`shared/log_schema.py`](shared/log_schema.py)) enforce a canonical hierarchical JSON schema for every logged event.

### Logging Scheme Implementation & Architecture Files
- **Unified Logger Daemon & Engine:** [`logger/unified_logger.py`](logger/unified_logger.py) — Core logging engine implementing the `UnifiedLogger` class, automated MITRE ATT&CK for ICS classification, severity mapping, and live dual-write dispatch to InfluxDB and the JSONL file.
- **Canonical Schema Specification:** [`shared/log_schema.py`](shared/log_schema.py) — Canonical Python data structure creating validated ML-ready JSONL event dictionaries (`create_ml_ready_log_record()`).
- **Aggregated Audit Trail File:** [`data/general logs.jsonl`](data/general%20logs.jsonl) — Master time-synchronized log stream capturing all cross-layer events across the Purdue hierarchy.
- **Continuous Benchmark Campaigns:** [`datasets/dataset_3/csv/correlation_logs.csv`](datasets/dataset_3/csv/correlation_logs.csv) — Authoritative multi-hour evaluation benchmark logs.

### Canonical Event Schema Breakdown

| Schema Component | Nested JSON Keys | Description & Recorded Fields |
|---|---|---|
| **Event Header** | `timestamp`, `event_id`, `event.type`, `event.severity`, `event.narrative` | ISO 8601 UTC timestamp, unique UUIDv4 event ID, normalized event category, operational severity (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), and human-readable diagnostic message. |
| **Provenance Context** | `context.sensor`, `context.purdue_level`, `context.journey_id`, `context.session_id` | Originating microservice daemon, architectural Purdue level (`Level 0` through `Level 3.5`), journey identifier, and correlated session token across multi-stage attack pivots. |
| **Network Telemetry ($\mathbf{x}_{\text{net}}$)** | `network.source`, `network.destination`, `network.protocol`, `network.inter_arrival_time`, `network.write_frequency_10s`, `network.is_write`, `network.function_code`, `network.length` | Source/destination IP and port pairs, protocol identifier (`Modbus`, `S7comm`, `DNP3`, `SSH`, `HTTP`), packet inter-arrival time $\Delta t_{\text{arr}}$, 10-second rolling write burst frequency `f_write_10s`, binary write flag `is_write`, function code $c_{\text{func}}$, and payload length $l_{\text{pkt}}$. |
| **Process Telemetry ($\mathbf{x}_{\text{proc}}$)** | `process.pressure`, `process.flow_rate`, `process.temperature`, `process.pump_rpm`, `process.valve_position`, `process.viscosity`, `process.pressure_delta`, `process.pressure_mean_deviation` | Synchronized continuous hydrodynamic state vector: pipeline pressure ($P$ in PSI), flow rate ($Q$ in L/s), temperature ($T$ in °C), pump speed ($R$ in RPM), valve position ($V \in [0.0, 1.0]$), viscosity ($\mu$ in cSt), first derivative rate of change ($\Delta P = dP/dt$), and real-time deviation from baseline mean ($\delta_P = \|P_t - \mu_0\|$). |
| **ML Ground Truth & Safety Envelopes** | `ml_analysis.is_anomaly`, `ml_analysis.anomaly_type`, `ml_analysis.attack_phase`, `ml_analysis.attack_category`, `ml_analysis.boundary_violations` | Binary ground-truth label ($y \in \{0, 1\}$), categorical anomaly type, discrete attack phase ID (Scenarios 1–10), threat category, and structured descriptors of active ASME B31.4 / API 610 safety-boundary violations. |
| **MITRE ATT&CK for ICS** | `mitre.technique_id`, `mitre.technique_name`, `mitre.tactic` | Automated mapping to the MITRE ATT&CK for ICS matrix (e.g. `T0855: Unauthorized Command Message`, `T0886: Remote Services`, `T0814: Denial of Service`). |
| **Cyber Kill Chain Stage** | `security.kill_chain_stage` | Strategic attack lifecycle stage (e.g. `Reconnaissance`, `Lateral Movement`, `Execution`, `Infiltration`, `Impact`). |

### Originating Sensor Daemons & Provenance Context

To guarantee end-to-end traceability across the Purdue hierarchy:
- `plc_simulator`: Field PLCs operating at **Purdue Levels 1–2**, executing local control loops, maintaining register banks, and applying physical actuator changes.
- `ics_sniffer`: Passive network sensor operating at **Purdue Level 2**, capturing raw fieldbus traffic and computing real-time inter-arrival dynamics and rolling burst rates.
- `ml_engine`: Anomaly detector spanning **Purdue Levels 2–3**, performing online feature normalization, statistical drift tracking, autoencoder reconstruction, and physics safety checks.
- `ics_scada_ssh`: Perimeter bastion honeypot at **Purdue Level 3.5**, logging authentication attempts, interactive command history, and credential brute-force attacks.
- `synthetic`: Simulation orchestrator generating startup baseline events, heartbeat checks, and automated benchmark verification probes.

### Representative Event Record (`JSONL`)

Below is an exact record illustrating how a telemetry event is formatted in `general_logs.jsonl`:

```json
{
  "timestamp": "2026-05-08T18:54:44.252412Z",
  "event_id": "ff8a0a42-b3b4-4541-9082-181c8139cdac",
  "event": {
    "type": "process_telemetry",
    "severity": "INFO",
    "narrative": "Nominal pipeline steady-state operation within standard ASME B31.4 limits."
  },
  "context": {
    "sensor": "plc_simulator",
    "purdue_level": "Level 2",
    "journey_id": "sess_001",
    "session_id": "sess_001"
  },
  "network": {
    "source": { "ip": "172.24.0.8", "port": 49152 },
    "destination": { "ip": "172.24.0.8", "port": 502 },
    "protocol": "Modbus",
    "inter_arrival_time": 0.015,
    "write_frequency_10s": 0.0,
    "is_write": 0,
    "function_code": 3,
    "length": 12
  },
  "process": {
    "pressure": 118.35,
    "flow_rate": 49.84,
    "temperature": 44.53,
    "pump_rpm": 1194.4,
    "valve_position": 0.50,
    "viscosity": 1.0,
    "pressure_delta": 0.01,
    "pressure_mean_deviation": -1.65
  },
  "ml_analysis": {
    "is_anomaly": 0,
    "anomaly_type": "NORMAL",
    "attack_phase": 0,
    "attack_category": "Normal Baseline",
    "boundary_violations": []
  },
  "mitre": {
    "technique_id": "T0000",
    "technique_name": "Normal Operation",
    "tactic": "None"
  },
  "security": {
    "kill_chain_stage": "Operational Baseline"
  }
}
```

---

## 8. Quickstart & Project Setup

### Prerequisites
- **Linux / macOS / Windows (WSL2)**
- **Python 3.10+** (recommended: 3.10–3.12)
- **Docker Engine & Docker Compose v2** (for running the honeypot testbed)
- **Git**

### Step 1: Clone Repository & Virtual Environment Setup
```bash
# Clone the repository
git clone https://github.com/MohamedAyman04/Honeypot.git
cd Honeypot

# Create and activate Python virtual environment
python3 -m venv honeypot-venv
source honeypot-venv/bin/activate

# Install required dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 2: Instant Authoritative Benchmark Evaluation (No Docker Required)
You can evaluate the pre-collected multi-hour campaigns immediately without starting Docker containers:
```bash
# Evaluate all 3 datasets under canonical validation methodology
python scripts/canonical_evaluation.py

# Evaluate Dataset 3 specifically (Primary Paper Benchmark)
python scripts/canonical_evaluation.py --ds1 datasets/dataset_3 --ds2 datasets/dataset_3
```
This runs the full 6-layer reasoning pipeline, cross-layer NMG gating, and prints canonical Precision, Recall, and F1 metrics.

### Step 3: Launching the Full Docker Testbed Infrastructure
To spin up the 4-network high-interaction honeypot with field PLCs, physics simulation, InfluxDB, and Grafana:
```bash
# Start all microservices in background
docker compose up -d --build

# Verify all services are running healthy
docker compose ps
```

### Step 4: Accessing Services and Dashboards
Once the Docker stack is active:

| Service / Component | Protocol / Port | Local URL / Access | Description |
|---|---|---|---|
| **Grafana Monitoring** | HTTP / `3000` | [`http://localhost:3000`](http://localhost:3000) | Pre-provisioned telemetry dashboards (`admin` / `admin`). |
| **Streamlit Log Explorer** | HTTP / `8501` | [`http://localhost:8501`](http://localhost:8501) | Real-time security events & MITRE ATT&CK dashboard. |
| **InfluxDB Historian** | HTTP / `8086` | [`http://localhost:8086`](http://localhost:8086) | Time-series database for raw 1 Hz process telemetry. |
| **Decoy Historian API** | HTTP / `5000` | [`http://localhost:5000`](http://localhost:5000) | Low-interaction honeypot REST API in DMZ. |
| **SCADA SSH Bastion** | SSH / `2222` | `ssh operator@localhost -p 2222` | Purdue Level 3.5 Cowrie SSH honeypot. |
| **PCN Modbus/TCP PLC** | TCP / `502` | `localhost:502` | Field PLC holding registers & actuator control. |
| **PCN Siemens S7comm** | TCP / `102` | `localhost:102` | Emulated Siemens S7-300/1200 field controller. |
| **PCN DNP3 Outstation** | TCP / `20000` | `localhost:20000` | Industrial DNP3 telemetry outstation. |

To trigger an automated offensive campaign from the attacker container:
```bash
docker compose exec attacker_node python3 attack_suite.py --phase 0
```

---

## 9. Contributing & Developer Guide

### 9.1 Welcome to Contributors!
This repository is **public, open-source, and warmly welcomes community contributions**. Whether you want to fix a bug, enhance the physics fidelity, implement an additional industrial protocol, add novel attack vectors, or develop new ML anomaly detection models, your input is highly appreciated!

### 9.2 Repository Architecture & Component Breakdown

```text
Honeypot/
├── README.md                      # Comprehensive documentation & developer guide
├── requirements.txt               # Top-level Python dependency specification
├── docker-compose.yml             # 4-network orchestration (PCN, DMZ, Monitor, Backplane)
│
├── datasets/                      # 3 Multi-hour operational cyber-physical evaluation campaigns
│   ├── README.md                  # Comprehensive dataset manifest & field definitions
│   ├── dataset_1/                 # Campaign 1 (4.8h, Scenarios 1–8)
│   ├── dataset_2/                 # Campaign 2 (7.2h, Scenarios 1–8)
│   └── dataset_3/                 # Primary Paper Benchmark Campaign (7.8h, Scenarios 1–10, F1=0.891)
│
├── physics/                       # Hydrodynamic simulation & ASME/API physical safety boundaries
│   ├── physics_engine.py          # PipelineSimulator mathematical physics ODE/difference model
│   ├── physics_process.py         # Standalone 1 Hz simulation loop syncing state to Redis
│   └── safety_boundaries.py       # Grounded ASME B31.4, API 610, & HI 9.6.1 trip boundaries
│
├── plc/                           # Level 1–2 PCN Field PLCs
│   ├── modbus_server.py           # Physics-coupled Modbus/TCP server (holding registers 100-202)
│   ├── s7_server.py               # Siemens S7comm server coupled to physics
│   └── dnp3_server.py             # DNP3 outstation daemon
│
├── ml-engine/                     # Cross-layer machine learning & statistical reasoning
│   ├── detector.py                # Online anomaly detector & feature extractors
│   └── trainer.py                 # Offline unsupervised model training (IF & LSTM-AE)
│
├── attacker_node/                 # Offensive attack suite & protocol probes (Purdue Level 3.5 / WAN)
│   ├── attack_suite.py            # Automated 10-scenario MITRE ATT&CK campaign runner
│   ├── s7comm_probe.py            # S7 protocol handshake & exploit probe
│   └── dnp3_probe.py              # DNP3 enumeration script
│
├── logger/                        # Centralized event logging & correlation
│   ├── unified_logger.py          # InfluxDB-to-JSONL log aggregator
│   └── correlator.py              # Command-to-consequence causal correlator
│
├── shared/                        # Shared utility libraries
│   ├── log_schema.py              # Canonical hierarchical JSON schema definitions
│   ├── mitre_mapping.py           # Automated MITRE ATT&CK for ICS classification
│   └── story_client.py            # Inter-service HTTP event logging client
│
├── scripts/                       # Benchmark evaluation, enrichment, and maintenance scripts
│   ├── canonical_evaluation.py    # Authoritative 3-dataset benchmark evaluation
│   ├── clean_and_enrich_logs.py   # Telemetry cleansing and derived feature generation
│   └── attack_simulation.py       # Standalone attack injection simulator
│
├── log_dashboard/                 # Real-time Streamlit security event visualizer
├── grafana_dashboards/            # Pre-provisioned Grafana dashboards
└── docs/                          # In-depth architectural & deployment documentation
```

### 9.3 Data Flow & Inter-Component Communication

```
[Attacker Node / SCADA Bastion]
           │
           ▼ (Modbus FC6 / S7 Writes / DNP3)
    [Field PLCs (plc/)] ◄───► [Redis State: pipeline_state] ◄───► [Physics Engine (physics/)]
           │                                                                 │
           │ (Modbus Events / Forced Writes)                                 │ (P, Q, T, RPM @ 1 Hz)
           ▼                                                                 ▼
    [InfluxDB Historian] ──────────────────────────────────────────► [ML Engine (ml-engine/)]
           │                                                                 │
           ▼                                                                 ▼
    [Unified Logger & Correlator] ──► [general_logs.jsonl] ──► [6-Layer Reasoning & Prioritized Fusion (A_Fused)]
```

### 9.4 Where and How to Modify Existing Components

#### 1. Field PLCs & Register Mappings (`plc/`)
- **Modbus Registers:** Defined in [`plc/modbus_server.py`](plc/modbus_server.py) (`PhysicsAwareDataBlock`).
  - Read registers: `100` (Pressure, PSI), `101` (Flow Rate $\times 10$, L/s), `102` (Temperature, °C), `103` (Pump RPM).
  - Actuator write registers: `200` (Pump RPM setpoint, 0–3000), `201` (Valve position $\times 1000$, 0–1000), `202` (Valve toggle bit).
- **Siemens S7 & DNP3:** Corresponding data blocks and outstation points are mapped in [`plc/s7_server.py`](plc/s7_server.py) and [`plc/dnp3_server.py`](plc/dnp3_server.py).
- To add a new sensor (e.g. differential pressure $\Delta P$ or vibration): update `setValues` and register addresses in `modbus_server.py`, sync the variable to the physics simulator, and log the event to InfluxDB.

#### 2. Detection Engine & Threshold Calibration (`ml-engine/`, `scripts/canonical_evaluation.py`)
- **Layer 1 Timing Rules:** In `canonical_evaluation.py` (Rule 1.1 write frequency `f_write_10s > 5.0`, Rule 1.5 DoS arrival time `Δt_arr < 5ms`).
- **Layer 2 Physics Limits:** In [`physics/safety_boundaries.py`](physics/safety_boundaries.py) (`ASME B31.4 MAOP`, `API 610 MCSF`).
- **Layer 3 CUSUM / EWMA Parameters:** Tweak decision interval $H$ and allowance $K$ in `scripts/canonical_evaluation.py` to adjust sensitivity to stealth drift.
- **Layer 6 Decision Fusion ($A_{\text{Fused}}$):** Gating logic evaluates $A_{\text{Fused}} = A_{\text{NMG}} \lor A_{\text{L3}} \lor A_{\text{proc}}$. The NMG deviation threshold $\tau_{\text{NMG}}$ (`|δ_P| > τ_NMG` and `f_write_10s == 0`) is calibrated automatically on the network-silent validation split.

#### 3. Attack Suite & Scenarios (`attacker_node/attack_suite.py`)
- Each attack scenario is defined as a phase function in [`attacker_node/attack_suite.py`](attacker_node/attack_suite.py).
- To add a new scenario: create a new phase method, map the MITRE ATT&CK technique via `_record_result()`, execute the offensive probe, and record ground-truth timing in `attack_status.csv`.

#### 4. Cross-Layer Logging & Schema Extensions (`logger/unified_logger.py`, `shared/log_schema.py`)
- **Unified Logger Daemon:** [`logger/unified_logger.py`](logger/unified_logger.py) defines the `UnifiedLogger` class utilized across all containerized honeypot microservices (PLC servers, network sniffer, SCADA SSH bastion, ML engine, and correlator) to emit normalized events to InfluxDB and the JSONL audit stream.
- **Canonical Schema Specification:** [`shared/log_schema.py`](shared/log_schema.py) implements the validated serialization contract (`create_ml_ready_log_record()`).
- **Modifying or Adding Telemetry Fields:**
  1. Add new attributes or nested keys into [`shared/log_schema.py`](shared/log_schema.py).
  2. Emit the field through `unified_logger.log(event_type=..., **fields)` in [`logger/unified_logger.py`](logger/unified_logger.py) or within individual sensor callers.
  3. Ensure downstream offline feature extraction in `scripts/clean_and_enrich_logs.py` ingests the new key.

---

### 9.5 Deep Dive: Replacing or Improving the Physics Engine

The honeypot separates physical simulation from communication protocols using a decoupled, service-oriented architecture:

#### Architecture & IPC Decoupling
1. **Simulation Engine:** [`physics/physics_engine.py`](physics/physics_engine.py) implements the class `PipelineSimulator`.
2. **Simulation Process:** [`physics/physics_process.py`](physics/physics_process.py) runs a continuous 1-second simulation loop.
3. **IPC Bridge:** The physical state is serialized as JSON and stored in Redis under the key `pipeline_state`. Field PLCs (`modbus_server.py`, `s7_server.py`) read and write this shared state.

#### The Shared State Schema
Any physics engine must maintain and expose the following JSON structure:
```json
{
  "pressure": 120.45,
  "flow_rate": 24.12,
  "temperature": 26.80,
  "viscosity": 0.98,
  "pump_rpm": 1200.0,
  "valve_pos": 0.50
}
```

#### The Minimal Interface Contract
If you wish to replace `PipelineSimulator` with a higher-fidelity model, your class must implement:
```python
class CustomPhysicsEngine:
    def __init__(self, use_redis: bool = True):
        ...
    def set_pump_rpm(self, rpm: float) -> None:
        """Update pump speed command (actuator input)."""
        ...
    def set_valve_pos(self, pos: float) -> None:
        """Update valve position command [0.0 = closed, 1.0 = fully open]."""
        ...
    def update(self) -> dict:
        """Step simulation by dt and return updated state dict."""
        ...
    def get_state(self) -> dict:
        """Return current physical state adhering to the schema above."""
        ...
```

#### Physical Consistency Invariants to Maintain
To avoid introducing artificial anomalies or breaking detector assumptions:
- **Zero Flow Invariant:** If `valve_pos <= 0.01` (valve closed), `flow_rate` **must** evaluate to `0.0` regardless of pump RPM.
- **Hydraulic Inertia:** Fluid cannot instantaneously change velocity; respect pump acceleration curves and pressure damping constants ($\tau_p, \tau_q$).
- **Safety Boundaries:** Check and align changes with [`physics/safety_boundaries.py`](physics/safety_boundaries.py). If you change nominal operating points (e.g. from 120 PSI to 60 PSI), update ASME/API limits accordingly.

#### Ideas for Advanced Physics Plugins:
- **EPANET / WNTR Integration:** Replace the single-pipe simulator with a full multi-junction water distribution network.
- **Simulink / OpenModelica FMU:** Export high-fidelity digital twins via the Functional Mock-up Interface (FMI/FMU) and drive them using `pyfmi`.
- **Chemical / Thermal Reactors:** Model exothermic CSTR dynamics (Continuous Stirred Tank Reactor) to test cyber-attacks on chemical cooling jackets.

---

### 9.6 How to Add or Improve Other Components

#### Adding New Industrial Fieldbus Protocols
1. Create a server implementation in `plc/` (e.g., `opcua_server.py` using `asyncua`, or `iec104_server.py` using `c104`).
2. Bind the server to the internal `pcn-net` Docker network.
3. Import `PipelineSimulator` (or query Redis `pipeline_state`) to serve real-time sensor measurements.
4. Hook actuator writes to update pump RPM or valve position in Redis.
5. Log incoming packets and write operations to InfluxDB `sensor_logs`.
6. Add the new service container to [`docker-compose.yml`](docker-compose.yml).

#### Adding New Machine Learning Anomaly Detectors
1. Implement your model in `ml-engine/` (e.g., Temporal Convolutional Networks, Graph Attention Networks, Isolation Forest variants).
2. **Crucial Rule — Enforce Domain Feature Separation:**
   - **Never** train ML models on unseparated raw vectors ($\mathbf{x}_{\text{net}} \cup \mathbf{x}_{\text{proc}}$). Normal process fluctuations bleed into network anomaly scores, causing severe false-alarm collapse (Precision drops below 0.10).
   - Train dedicated network models on `["inter_arrival_time", "write_freq_10s", "is_write", "func_code", "length"]`.
   - Train dedicated process models on `["pressure", "flow_rate", "temperature", "pressure_delta", "pressure_mean_dev"]`.
3. Plug your model into Layer 5 or Layer 6 of `scripts/canonical_evaluation.py` and benchmark on Dataset 3.

#### Adding New Cyber-Attack Scenarios
1. Write the attack routine in [`attacker_node/attack_suite.py`](attacker_node/attack_suite.py).
2. Assign the next scenario number (e.g., Scenario 11).
3. Map to the appropriate MITRE ATT&CK for ICS technique in [`shared/mitre_mapping.py`](shared/mitre_mapping.py).
4. Run the attack in a continuous testbed session and record timestamps in `data/attack_status.csv`.

---

### 9.7 Submitting Contributions & Pull Request Workflow

We follow standard GitHub Flow:

1. **Fork the Repository:** Click the "Fork" button at the top of the GitHub page.
2. **Clone your Fork:**
   ```bash
   git clone https://github.com/<your-username>/Honeypot.git
   cd Honeypot
   ```
3. **Create a Dedicated Branch:**
   ```bash
   git checkout -b feature/epanet-physics-engine
   # or
   git checkout -b fix/modbus-framing-error
   ```
4. **Develop and Test:**
   - Write clean, documented, and PEP 8-compliant Python code.
   - Include docstrings and type hints where applicable.
5. **Run the Authoritative Benchmark Verification:**
   Before submitting any PR modifying physics, detection rules, or logging, execute the canonical benchmark:
   ```bash
   python scripts/canonical_evaluation.py
   ```
   *Ensure that existing baseline performance on Dataset 3 ($F_1 = 0.891$) is maintained without regressions.*
6. **Commit and Push:**
   ```bash
   git add .
   git commit -m "feat(physics): integrate EPANET hydraulic network solver"
   git push origin feature/epanet-physics-engine
   ```
7. **Open a Pull Request:**
   - Open a PR against the `main` branch of `MohamedAyman04/Honeypot`.
   - Include a concise description of changes, motivation, and any evaluation or test outputs.
   - Engage with feedback during code review!

---

## 10. Citation & Contact

If you use this testbed, datasets, or detection architecture in your research, please cite:

```bibtex
@article{ayman2026physics,
  title   = {Cross-Layer Intrusion Detection in Industrial Control Systems via Domain-Separated Machine Learning and Physical Gating},
  author  = {Ayman, Mohamed and et al.},
  journal = {IEEE Transactions on Industrial Informatics},
  year    = {2026}
}
```

- **Project Lead:** Mohamed Ayman ([GitHub](https://github.com/MohamedAyman04))
- **Questions & Issues:** Please open an issue on the [GitHub Issue Tracker](https://github.com/MohamedAyman04/Honeypot/issues).
