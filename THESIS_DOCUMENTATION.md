# ICS Honeypot — Full Technical Documentation
## For Thesis Methodology Section

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [System Architecture](#2-system-architecture)
3. [Purdue Model Mapping](#3-purdue-model-mapping)
4. [Component Descriptions](#4-component-descriptions)
5. [Attack Simulation Subsystem](#5-attack-simulation-subsystem)
6. [ML Detection Engine — IsolationForest + LSTM Ensemble](#6-ml-detection-engine--isolationforest--lstm-ensemble)
7. [Rule-Based and Statistical Detectors](#7-rule-based-and-statistical-detectors)
8. [Data Pipeline and Telemetry](#8-data-pipeline-and-telemetry)
9. [Grafana Monitoring Dashboard](#9-grafana-monitoring-dashboard)
10. [Environment and Deployment](#10-environment-and-deployment)
11. [Security Design Decisions](#11-security-design-decisions)
12. [Evaluation Methodology](#12-evaluation-methodology)

---

## 1. Project Overview

This project implements a **multi-layer Industrial Control System (ICS) honeypot** designed to emulate a realistic oil-pipeline SCADA environment. The system simultaneously:

- Emulates physical process dynamics (pressure, flow, temperature, pump RPM) via a software physics engine.
- Exposes industrial protocols (Modbus TCP, Siemens S7comm, DNP3) to attract and fingerprint attackers.
- Applies multi-model anomaly detection combining classical machine learning (Isolation Forest) with deep-learning sequence models (two LSTM Autoencoders) to classify attack behaviours in real time.
- Logs all events to a time-series database (InfluxDB) and visualises them on a Grafana dashboard.

The research contribution is a **cross-layer detection architecture** that correlates network-layer protocol events with physical-process deviations, making it significantly harder for an attacker to evade detection by confining their activity to a single layer.

---

## 2. System Architecture

All services run inside Docker containers orchestrated by **Docker Compose**. A single `.env` file centralises all tokens, credentials, and connection strings; the Compose file references these via `${VARIABLE}` interpolation, so secrets are never hard-coded.

Four isolated Docker networks (`ot-net`, `dmz-net`, `monitor-net`, `enterprise-net`) enforce Purdue-level segmentation.

---

## 3. Purdue Model Mapping

| Purdue Level | Role | Services in This Project |
|---|---|---|
| **Level 0 / 1** | Field devices & physical processes | `physics_simulator` (pressure, flow, temperature, pump RPM) |
| **Level 2** | Control layer (PLCs/RTUs) | `plc_simulator` (Modbus), `ics_s7_plc` (S7comm), `ics_dnp3` (DNP3), `hmi`, `historian_bridge` |
| **Level 2 — Monitoring** | Passive observability | `ml_engine`, InfluxDB historian, Grafana, `network_sniffer`, `correlator` |
| **Level 3** | IT/OT integration | `historian_api`, `ics_scada_ssh` |
| **Level 3.5 / DMZ** | Demilitarised zone | Modbus port 502, S7 port 102, DNP3 port 20000, `honeypot_historian_api` |
| **External** | Simulated adversary | `attacker_node` |

---

## 4. Component Descriptions

### 4.1 Physics Simulator
Emulates the thermodynamic and fluid dynamics of an oil pipeline section.
State variables written to Redis every second:
- **Pressure** (PSI) — governed by pump RPM and valve state
- **Flow rate** (L/s) — derived from pressure differential
- **Temperature** (°C) — ambient + heat-of-compression model
- **Pump RPM** — controlled by the Modbus PLC

The physics engine is the ground-truth source for process state. Any discrepancy between what the physics engine computes and what the historian records is a key anomaly signal.

### 4.2 Modbus PLC Simulator
Implements a Modbus TCP server (port 502) backed by pyModbus.
- **Holding registers 0–99**: process outputs (read by HMI/SCADA)
- **Holding registers 100–103**: sensor inputs — writing to these directly is a **semantic injection attack**
- **Holding registers 200+**: actuator setpoints (legitimate operator writes)

Every Modbus transaction is published to InfluxDB as a `modbus_events` point for cross-layer correlation.

### 4.3 S7comm PLC Honeypot
Emulates a Siemens S7-300 PLC (ISO-TSAP port 102) to attract ICS-aware attackers.
All connection and read/write events are logged to `honeypot_events` with `protocol=S7comm`.

### 4.4 DNP3 Server / Honeypot
Emulates a DNP3 outstation (port 20000). Probes are logged to `recon_scan_events`.
**DNP3 is deliberately excluded from the ML feature pipeline** — its events do not affect anomaly scores — because the signal characteristics differ too much from pipeline telemetry without dedicated training data.

### 4.5 Fake PLC
A dead-end Modbus device on port 503 that reports plausible-looking but static data.
Purpose: slow down reconnaissance by giving an attacker a convincing (but useless) target.

### 4.6 SCADA SSH Workstation
An SSH server (port 2222) with two accounts:
- `operator / operator123` — referenced by the Historian API (legitimate target)
- `engineer / engineer456` — referenced by the Honeypot Historian API (deception)

### 4.7 HMI
Flask-based web HMI that reads live process values from the Modbus PLC and presents them on a browser dashboard (port 8060).

### 4.8 Historian Bridge
Continuously reads Modbus registers and writes the full pipeline telemetry (`pipeline_metrics` measurement) to InfluxDB at ~2 Hz.

### 4.9 ML Engine
Detailed in Section 6 below.

### 4.10 Historian API
FastAPI service (port 5001) acting as a Level-3 integration point for external reporting tools.

### 4.11 Honeypot Historian API
A deception copy of the Historian API (port 5002) deployed in the DMZ, providing subtly incorrect data and fingerprinting clients.

### 4.12 Network Sniffer + Correlator
- **logger.py**: Raw packet capture on the host network interface.
- **correlator.py**: Correlates Modbus write commands with process-state changes, writes `correlation_logs` to InfluxDB. These are consumed as network features by the ML engine.

### 4.13 InfluxDB Historian
Time-series database (InfluxDB v2) storing all measurements:

| Measurement | Contents |
|---|---|
| `pipeline_metrics` | pressure, flow, temperature, pump RPM |
| `modbus_events` | every Modbus transaction |
| `security_metrics` | ML anomaly scores (IF score, LSTM error, is_anomaly flag) |
| `security_alerts` | fired alert records |
| `honeypot_events` | S7/DNP3 probe events |
| `recon_scan_events` | DNP3 port scan detections |
| `correlation_logs` | cross-layer network events |
| `attack_status` | human-readable attack state |
| `grafana_events` | structured event log for annotations |
| `forced_writes` | semantic injection events |

### 4.14 Attacker Node
A container with a full Python attack suite capable of executing:
- **Reconnaissance scans** (Modbus FC3 enumerate, S7comm identity probe, DNP3 data link scan)
- **Semantic injection** (Modbus write to sensor registers 100–103)
- **Replay attacks** (capture + retransmit valid telemetry)
- **EWMA stealth drift** (slow monotonic pressure manipulation)

---

## 5. Attack Simulation Subsystem

### 5.1 Semantic Injection
The attacker writes fabricated sensor values directly to Modbus holding registers 100–103, bypassing the physics engine.

**Detection**: The correlator observes a write to a sensor register and logs a `forced_writes` event. The ML engine queries this every cycle and fires a `SEMANTIC_INJECTION` alert. To prevent alert fatigue from overlapping query windows, events are deduplicated in-memory using a timestamp-plus-value composite key.

### 5.2 Replay Attack
The attacker captures a window of valid process telemetry and retransmits it, masking real process changes.

**Detection**: The ML engine evaluates three complementary signals:
1. **Zero-Variance**: Sustained standard deviation < 0.1 PSI while deviating from baseline.
2. **Fingerprint Match**: A sliding window fuzzy match (0.5 PSI resolution) against recent historical signatures.
3. **Replay LSTM**: A dedicated LSTM Autoencoder trained on variance features (delta, rolling standard deviation, baseline deviation) detects the anomalously rigid patterns of replayed telemetry.

### 5.3 EWMA Stealth Drift
A very slow (sub-threshold PSI/s) pressure ramp — too slow for threshold-based rules but detectable by statistical process control.

**Detection**: The EWMA/CUSUM module tracks exponentially weighted deviations. A CUSUM accumulator fires when sustained drift exceeds a configurable threshold. Direction-consistent slope provides a second confirmatory signal.

### 5.4 Protocol Reconnaissance
Port scans, S7comm identity reads, and DNP3 probes are logged as honeypot events (visible in Grafana table panels).

---

## 6. ML Detection Engine — IsolationForest + LSTM Ensemble

### 6.1 Feature Set

Ten features are extracted from InfluxDB at each detection cycle (every 15 seconds):

| Feature | Source | Rationale |
|---|---|---|
| `pressure` | `pipeline_metrics` | Primary process variable |
| `flow_rate` | `pipeline_metrics` | Correlated with pressure |
| `temperature` | `pipeline_metrics` | Secondary process indicator |
| `pressure_delta` | Computed (1-step diff) | Rate of change — flags jumps |
| `pressure_mean_dev` | Computed (rolling 10-mean) | Sustained deviation from mean |
| `inter_arrival_time` | Computed (time diff) | Packet timing anomalies |
| `write_freq_10s` | `correlation_logs` join | Number of Modbus writes in 10 s |
| `is_write` | `correlation_logs` | Binary: was a write issued? |
| `func_code` | `correlation_logs` | Modbus function code |
| `length` | `correlation_logs` | Packet payload length |

### 6.2 Model 1 — Isolation Forest (IF)

**Algorithm**: `sklearn.ensemble.IsolationForest`

**Hyper-parameters**:

| Parameter | Value | Rationale |
|---|---|---|
| `n_estimators` | 200 | More trees = more stable scores |
| `contamination` | 0.01 | Very low → only unambiguous outliers |
| `random_state` | 42 | Reproducibility |
| Score threshold | −0.20 | Only score < −0.20 raises alert |

**Training**: 180-second warm-up on normal-only data. Serialised to `/data/model.pkl`.

**Rationale**: Isolation Forest requires no labelled anomaly examples and is robust to high-dimensional data. Its tree-based isolation of rare samples is well-suited to the sparse anomaly distribution typical in continuous process monitoring.

### 6.3 Model 2 — LSTM Autoencoder

**Algorithm**: Sequence-to-sequence LSTM autoencoder (TensorFlow/Keras)

**Architecture**:

```
Input  (seq_len=20, n_features=10)
 └── LSTM Encoder  (units=32, tanh, return_sequences=False)
      └── RepeatVector(20)
           └── LSTM Decoder (units=32, tanh, return_sequences=True)
                └── TimeDistributed Dense(10)
Output (seq_len=20, n_features=10)  ← reconstructed window
```

**Hyper-parameters**:

| Parameter | Value |
|---|---|
| Sequence length | 20 timesteps |
| Latent dimension | 32 |
| Epochs | 20 |
| Batch size | 32 |
| Optimiser | Adam (lr=1e-3) |
| Loss | MSE |
| Anomaly threshold | 95th percentile of training reconstruction errors |

**Training procedure**:
1. Feature matrix scaled to [0, 1] with `MinMaxScaler` (fit on training window only — never on test data).
2. Overlapping windows of length 20 are created from the normalised matrix.
3. Autoencoder trained to reconstruct each window (unsupervised).
4. The anomaly threshold is set post-training as the 95th percentile of training set reconstruction errors. All future samples with MSE > threshold are flagged.
5. Model and scaler persisted to `/data/lstm_model.keras`, `/data/scaler.pkl`, and `/data/scaler.pkl.threshold`.

**Rationale**: Pipeline processes are inherently temporal — pressure, flow, and temperature evolve along smooth physical trajectories. An LSTM autoencoder learns to reconstruct *normal temporal patterns*. Attacks (sudden jumps, frozen telemetry, monotonic ramps) violate these patterns and produce reconstruction errors significantly above the training distribution. This makes LSTM complementary to IF: IF catches point-in-time outliers while LSTM catches sequential pattern breaks that individually look normal.

### 6.4 Model 3 — Replay LSTM Autoencoder

**Algorithm**: Sequence-to-sequence LSTM autoencoder (TensorFlow/Keras)

**Features**: `[pressure_delta, rolling_std_5, baseline_dev]`
During a replay attack, these three features collapse to `[≈0, ≈0, constant≠0]` — a rigid pattern the model cannot reconstruct cheaply since it only learned normal process thermodynamics.

**Hyper-parameters**:
- Sequence length: 15
- Latent dimension: 16
- Threshold: 90th percentile of training reconstruction errors

**Rationale**: While the general LSTM detects broad dynamic anomalies, the replay LSTM is specifically scoped to variance characteristics, allowing it to reliably flag replayed or frozen telemetry even when the replayed values themselves fall within normal operating limits.

### 6.5 Ensemble Decision Logic

The generic models operate as an **OR-gate ensemble**:

```
is_anomaly = IF_anomaly  OR  LSTM_anomaly  OR  expert_rule_fired
```

- A single model flag is sufficient to set `is_anomaly = 1`.
- Both scores are published independently (`if_score` and `lstm_error` fields) so each model's contribution is separately attributable.
- Expert rules (Section 7) override model outputs upward but never suppress them.
- The effective score written to Grafana is `min(IF_score, −LSTM_error)` when LSTM fires.

**Why OR-gate over AND-gate**: Missed attacks (false negatives) carry higher operational risk in an ICS context than false alarms, which operators can acknowledge without process interruption.

### 6.5 Startup Grace Period and Model Persistence

- **120-second startup grace period** suppresses all alerts after container start.
- Models load from disk on startup and are **never retrained** unless `/reset-model` is called.
- During warm-up (first 180 s after training starts) no alerts are generated. The legacy "TRAINING" state (Grafana value = 2, blue) is fully removed — the ML Anomaly Status panel now only shows NORMAL or ANOMALY.

### 6.6 REST API

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Liveness + model readiness (both IF and LSTM) |
| `/alerts` | GET | Recent alert log (filterable by `alert_type`) |
| `/metrics` | GET | Live IF score, LSTM error, EWMA/CUSUM state |
| `/reset-model` | POST | Delete all model files and trigger retrain |

---

## 7. Rule-Based and Statistical Detectors

### 7.1 Expert Rules (Cross-Layer)

| Rule | Condition | Alert Type |
|---|---|---|
| Pressure jump, no write command | `|pressure_delta| > 20 PSI` AND `write_freq_10s == 0` | `CROSS_LAYER_ANOMALY` |
| Sustained mean deviation | `|pressure_mean_dev| > 35 PSI` | `STEALTH_DRIFT` |
| Over-pressure | `pressure > 300 PSI` | `OVER_PRESSURE` |

### 7.2 EWMA / CUSUM Stealth Drift Detector

EWMA update: `EWMA_t = 0.1 · P_t + 0.9 · EWMA_{t-1}`

CUSUM accumulators:
```
S⁺_t = max(0,  S⁺_{t-1} + (P_t − EWMA_t) − 1.0)
S⁻_t = max(0,  S⁻_{t-1} − (P_t − EWMA_t) − 1.0)
```
Alert when `S⁺ > 8.0` or `S⁻ > 8.0`.

Direction-aware slope detector: linear regression over 20-sample window → alert when ≥ 75% of recent slopes agree in sign AND magnitude > 0.3 PSI/sample.

### 7.3 Replay Attack Detector (Tri-Signal approach)

Alerts fire when any of three signals trigger:
1. **Zero-variance**: stdev < 0.1 PSI AND baseline deviation > 8%.
2. **Fingerprint match**: Current fingerprint (0.5 PSI resolution) matches any of 20 most recent fingerprints with ≥ 85% element match AND window mean deviates ≥ 5% from baseline AND stdev < 2.0.
3. **Replay LSTM**: Reconstruction error exceeds the 90th-percentile training threshold AND baseline deviation > 3%.
A 120-second cooldown is applied after each alert.

### 7.4 Semantic Injection Detector

Queries `forced_writes` measurement (populated by Modbus PLC on sensor-register writes) and raises `SEMANTIC_INJECTION`. Events are cached using a composite key `(register_id : rounded_value : 10s_timestamp_bucket)` for 120 seconds to guarantee exactly-once alerting per physical scan.

---

## 8. Data Pipeline and Telemetry

```
Physics Engine (Redis, 1 Hz)
        │
Modbus PLC Registers
        ├─── Historian Bridge ──────▶  pipeline_metrics     (InfluxDB, ~2 Hz)
        └─── Correlator ────────────▶  correlation_logs     (InfluxDB)
                                       modbus_events        (InfluxDB)
S7 / DNP3 servers ─────────────────▶  honeypot_events      (InfluxDB)
                                       recon_scan_events    (InfluxDB)
                │
         ML Engine reads all above
                │
        security_metrics  ──────────▶  Grafana (is_anomaly, scores)
        security_alerts   ──────────▶  Grafana (alert log)
        grafana_events    ──────────▶  Grafana (annotations)
```

All InfluxDB writes use nanosecond precision (`WritePrecision.NS`).

---

## 9. Grafana Monitoring Dashboard

### Row 1 — Pipeline Telemetry
- Pressure (PSI) — attacker series shown in red
- Flow Rate (L/s)
- Temperature (°C)
- Pump RPM

### Row 2 — Security & Anomaly Detection
- **ML Anomaly Status** (Stat) — NORMAL (green) | ANOMALY (red)
- ML Anomaly Score time-series (IF score; lower = more anomalous)
- Cross-Layer Correlation (write commands vs pressure overlay)
- Replay Attack – Pressure Delta time-series

### Row 3 — Attack Simulation Results
Stat panels: Semantic Injection, Replay Attack, DNP3 Probe, S7comm Probe, Reconnaissance Scan (FC3), EWMA Stealth Drift.

### Row 4 — Protocol Honeypot Events
Sortable table of 50 most recent `honeypot_events` records.

Dashboard refreshes every **5 seconds**; stat panels use `lastNotNull` reducer.

---

## 10. Environment and Deployment

### 10.1 Prerequisites
- Docker Engine ≥ 24.0
- Docker Compose v2
- ≥ 8 GB RAM (recommended — TensorFlow LSTM training inside container)

### 10.2 Configuration

All configuration managed through a single **`.env`** file at the project root (excluded from git):

```ini
INFLUX_URL=http://historian:8086
INFLUX_TOKEN=supersecrettoken
INFLUX_ORG=my_refinery
INFLUX_BUCKET=sensor_logs
REDIS_HOST=redis
ML_ENGINE_URL=http://ics_ml_engine:8000
SCADA_SSH_HOST=ics_scada_ssh
SCADA_SSH_PORT=2222
SCADA_SSH_USER=operator
SCADA_SSH_PASS=operator123
HONEYPOT_SSH_USER=engineer
HONEYPOT_SSH_PASS=engineer456
GF_SECURITY_ADMIN_PASSWORD=admin
GF_AUTH_ANONYMOUS_ENABLED=true
GF_AUTH_ANONYMOUS_ORG_ROLE=Viewer
PYTHONUNBUFFERED=1
```

The Compose file passes these as `environment: - VAR=${VAR}` to each service, which means service Python code reads them via `os.environ.get("VAR")`.

### 10.3 Startup
```bash
docker compose up --build -d
# Grafana: http://localhost:3000
# ML Engine health: http://localhost:8001/health
# Run attacks:
docker compose exec attacker_node python attack_suite.py --all
```

### 10.4 Network Segmentation

| Network | Services |
|---|---|
| `ot-net` | physics_simulator, plc_simulator, ics_s7_plc, hmi, historian_bridge, redis, historian |
| `dmz-net` | plc_simulator, ics_s7_plc, ics_dnp3, ics_scada_ssh, historian_bridge, correlator, attacker_node, honeypot_historian_api |
| `monitor-net` | plc_simulator, ics_s7_plc, ics_dnp3, hmi, historian_bridge, ml_engine, historian, grafana, correlator, attacker_node, honeypot_historian_api, historian_api |
| `enterprise-net` | historian_api, ics_scada_ssh, historian |

---

## 11. Security Design Decisions

### 11.1 Deception Depth
Three layers of deception:
1. **Protocol level** — authentic Modbus, S7, and DNP3 responses.
2. **Process level** — physics-backed sensor values consistent across pressure, flow, and temperature.
3. **API level** — a DMZ-facing historian REST API returning structurally valid but corrupted data.

### 11.2 Cross-Layer Correlation
The fundamental detection innovation: correlating **network-layer write commands** with **physical-layer process changes**.
- A legitimate pressure change *must* be preceded by a valid Modbus actuator write (register ≥ 200).
- Pressure change without such a write → `CROSS_LAYER_ANOMALY`.
- Write to sensor registers (100–103) → `SEMANTIC_INJECTION`.

### 11.3 Minimal Attack Surface
- The ML engine is on `monitor-net` only — no inbound connectivity from the DMZ.
- Redis is on `ot-net` only.
- The network sniffer uses `network_mode: host` rather than bridging into OT networks.

### 11.4 Post-Attack State Tracking
Global flags (`_semantic_injection_seen`, `_drift_attack_seen`) gate the replay detector to prevent the cooldown from masking overlapping attack phases.

---

## 12. Evaluation Methodology

### 12.1 Experimental Setup
Attacks executed from `attacker_node` using `attack_suite.py`. Each attack type is run independently and in combined compound scenarios.

### 12.2 Metrics Collected

| Metric | Definition |
|---|---|
| **TPR (Recall)** | Fraction of executed attacks producing at least one correct-type alert within 60 s |
| **FPR** | Alerts fired during quiescent periods per hour |
| **Detection Latency** | Seconds from attack onset to first alert |
| **IF contribution** | Alerts where only IF fired |
| **LSTM contribution** | Alerts where only LSTM fired |
| **Ensemble lift** | Additional attacks caught by OR-gate vs single model |

### 12.3 Ground Truth Alignment
All attack executions write timestamped markers to InfluxDB (`attack_status`, `forced_writes`). Detection latency is computed as `alert_timestamp − attack_onset_timestamp` using nanosecond-precision records — Grafana provides a fully aligned visual ground-truth timeline.

### 12.4 Baseline Establishment
Models are trained during a 180-second window of **normal operation only** (no attacks injected). The LSTM threshold at the 95th percentile of training reconstruction errors ensures a theoretical ≤ 5% FPR on normal data.

### 12.5 Ensemble vs Single Model Trade-offs

| Model | Strength | Weakness |
|---|---|---|
| Isolation Forest | Fast, no temporal context needed, handles multi-variate point outliers | Misses gradual drift — each sample may look normal individually |
| LSTM Autoencoder | Captures sequential process dynamics, detects pattern breaks across time | Requires sufficient training data; slower to retrain |
| **Ensemble (OR-gate)** | Highest recall — either model fires on its corresponding attack class | Slightly higher FPR than either alone (mitigated by expert-rule gating) |

The OR-gate ensemble is preferred because missed attacks (false negatives) carry higher operational risk in an ICS context than false alarms, which operators can acknowledge without process interruption.

---

*This document covers the system as implemented in Docker Compose v4 with the IsolationForest + LSTM Autoencoder ensemble ML engine (trainer.py v4).*
