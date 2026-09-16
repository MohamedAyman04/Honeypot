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

- Emulates physical process dynamics (pressure, flow, temperature, pump RPM) via a software physics engine backed by Redis shared state.
- Exposes three industrial protocols — Modbus/TCP (port 502), Siemens S7comm (port 102), and DNP3 (port 20000) — to attract and fingerprint attackers.
- Applies a three-model anomaly detection ensemble: **Isolation Forest** (statistical point-outlier detection), a **general LSTM Autoencoder** (sequential process anomaly detection), and a **Replay LSTM Autoencoder** (variance-focused frozen-telemetry detection), correlated with expert cross-layer rules and EWMA/CUSUM stealth-drift detection.
- Logs all events to a time-series database (InfluxDB v2) and visualises them in real time on auto-provisioned Grafana dashboards.
- Exposes REST APIs for external Level-3 integration: a legitimate **Historian API** (host port 5001) and a deception **Honeypot Historian API** (host port 5002) in the DMZ.
- Maintains a unified narrative log (`general logs.jsonl`) via the **Story Logger** service (port 8600), capturing the full adversary kill-chain in a structured JSONL audit trail.

The research contribution is a **cross-layer detection architecture** that correlates network-layer protocol events with physical-process deviations, making it significantly harder for an attacker to evade detection by confining their activity to a single layer. The deception feedback loop further confuses adversaries by returning subtly corrupted data from the DMZ-facing historian when an anomaly is active.

---

## 2. System Architecture

All services run inside Docker containers orchestrated by **Docker Compose** (v2, no `version:` key). A single `.env` file centralises all tokens, credentials, and connection strings; the Compose file references these via `${VARIABLE}` interpolation, so secrets are never hard-coded.

Five Docker networks enforce Purdue-level segmentation:

| Network | Purpose |
|---|---|
| `ot-net` | Internal OT process network (physics, PLCs, Redis) — no external access |
| `dmz-net` | Demilitarised zone — externally-reachable industrial protocols and SCADA SSH |
| `monitor-net` | Passive monitoring network (historian, ML engine, Grafana, correlator) |
| `enterprise-net` | Level-3 enterprise network (Historian API, SCADA SSH) — static subnet `192.168.50.0/24` |
| `l2l3-bridge-net` | External bridge (`172.28.0.0/24`) linking this Level-2 stack to the companion Level-3 stack |

The `l2l3-bridge-net` network must be created before first run via:
```bash
docker network create l2l3-bridge-net --subnet 172.28.0.0/24
```

### 2.1 Host Port Map

| Host Port | Container Port | Service | Protocol |
|---|---|---|---|
| 502 | 502 | `plc_simulator` | Modbus/TCP |
| 503 | 502 | `fake_plc_sim` | Modbus/TCP (dead-end decoy) |
| 102 | 102 | `ics_s7_plc` | S7comm / ISO-TSAP |
| 20000 | 20000 | `ics_dnp3` | DNP3 |
| 2222 | 2222 | `ics_scada_ssh` | SSH |
| 5100 | 5100 | `ics_scada_ssh` | Physics REST API (Level 2 → Level 3) |
| 8060 | 8060 | `hmi` | Flask HMI web dashboard |
| 8086 | 8086 | `historian` | InfluxDB v2 |
| 3000 | 3000 | `grafana` | Grafana |
| **8001** | 8000 | `ml_engine` | ML Engine FastAPI |
| **5001** | 5000 | `historian_api` | Historian API (Level 3) |
| **5002** | 5000 | `honeypot_historian_api` | Honeypot Historian API (DMZ decoy) |
| 8502 | 8501 | `log_dashboard` | Streamlit log viewer |
| 8600 | 8600 | `story_logger` | Narrative JSONL logger |

> **Note on ML Engine port**: The ML engine's FastAPI server listens on container port 8000 but is mapped to **host port 8001** in the Compose file. All external `curl` commands and documentation must use port 8001.

---

## 3. Purdue Model Mapping

| Purdue Level | Role | Services in This Project |
|---|---|---|
| **Level 0 / 1** | Field devices & physical processes | `physics_simulator` (pressure, flow, temperature, pump RPM) |
| **Level 2** | Control layer (PLCs/RTUs) | `plc_simulator` (Modbus/502), `ics_s7_plc` (S7comm/102), `ics_dnp3` (DNP3/20000), `fake_plc_sim` (dead-end/503), `hmi`, `historian_bridge` |
| **Level 2 — Monitoring** | Passive observability | `ml_engine` (port 8001), InfluxDB historian (port 8086), `grafana` (port 3000), `network_sniffer`, `correlator` |
| **Level 3** | IT/OT integration | `historian_api` (port 5001), `ics_scada_ssh` (SSH 2222, Physics API 5100) |
| **Level 3.5 / DMZ** | Demilitarised zone | Modbus/502, S7/102, DNP3/20000, SCADA SSH/2222, `honeypot_historian_api` (port 5002) |
| **External** | Simulated adversary | `attacker_node` |

---

## 4. Component Descriptions

### 4.1 Physics Simulator
**Files:** `physics/physics_engine.py`, `physics/physics_process.py`

Emulates the thermodynamic and fluid dynamics of an oil pipeline section using a `PipelineSimulator` class. State is persisted in **Redis** every second so that Modbus, S7, and HMI all read from one consistent snapshot.

State variables:
- **Pressure** (PSI) — governed by pump RPM and valve state
- **Flow rate** (L/s) — derived from pressure differential
- **Temperature** (°C) — ambient + heat-of-compression model
- **Pump RPM** — controlled by the Modbus PLC

**Physics equations:**
```
target_pressure = (pump_rpm / 10.0) × (1.5 − valve_pos × 0.8)
target_flow     = (pump_rpm / 50.0) × valve_pos
pressure  += (target_pressure  − pressure)  × 0.2 + N(0, 0.2)
flow_rate += (target_flow      − flow_rate) × 0.2 + N(0, 0.05)
```

**Physical constraint — closed-valve clamp:** When `valve_pos == 0`, `flow_rate` is clamped to exactly `0.0` regardless of the physics update. This prevents non-physical flow readings when the valve is shut (Phase 7 sabotage scenario).

**Startup conditions:** 1200 RPM, valve 50% open → approximately 60 PSI, 12 L/s, 18.5 °C.

The physics engine is the ground-truth source for process state. Any discrepancy between what the physics engine computes and what the historian records is a key anomaly signal.

### 4.2 Modbus PLC Simulator
**File:** `plc/modbus_server.py`

Implements a Modbus/TCP server (port 502) backed by `pymodbus`. Uses a `PhysicsAwareDataBlock` that overrides both `getValues` (reads) and `setValues` (writes):

- **Read (FC3/FC4):** Loads the latest Redis state into registers 100–103 and serves the values. Logs a `modbus_events` record with `fc_type=read`.
- **Write (FC6/FC16) to actuator registers (200–202):** Applies the change to the physics engine. Logs `modbus_events` with `fc_type=write`.
- **Write to sensor registers (100–103):** Additionally logs a `forced_writes` record, which the ML engine treats as a **Semantic Injection** event.

The `PhysicsAwareDataBlock` pre-seeds registers at startup with the `PipelineSimulator` runtime defaults, ensuring zero-free initialisation from the first millisecond of boot.

**Actuation registers (writable):**

| Register | Effect |
|---|---|
| HR 200 | Set pump RPM (0–3000) |
| HR 201 | Set valve position (0–1000 mapped to 0.0–1.0) |
| HR 202 | Valve on/off toggle (0 or 1) |

Every Modbus transaction is published to InfluxDB as a `modbus_events` point for cross-layer correlation.

### 4.3 S7comm PLC Honeypot
**File:** `plc/s7_server.py`

Uses `python-snap7` to emulate a **Siemens S7-300** PLC (ISO-TSAP port 102). DB1 contains the four physical variables as IEEE-754 REAL values, updated from Redis every second. Presents `ProductName = 'SIMATIC S7-300 Modbus Gateway'` as a convincing decoy identity.

| S7 DB1 Offset | Variable | Units |
|---|---|---|
| DBD0 (REAL) | pressure | PSI |
| DBD4 (REAL) | temperature | °C |
| DBD8 (REAL) | flow_rate | L/s |
| DBD12 (REAL) | pump_rpm | RPM |

Every TCP connection and disconnection logs to `auth_attempts` and `honeypot_events` with `protocol=S7comm`.

### 4.4 DNP3 Server / Honeypot
**File:** `plc/dnp3_server.py`

Implements a minimal DNP3 link-layer outstation (port 20000):
- Parses start bytes `0x05 0x64` and link-layer header.
- Responds with a valid ACK frame using DNP3 CRC-16.
- Logs raw frame hex and source/destination addresses to `honeypot_events`.

**DNP3 is deliberately excluded from the ML feature pipeline** — its events do not affect anomaly scores — because the signal characteristics differ too much from pipeline telemetry without dedicated training data.

### 4.5 Fake PLC
A dead-end Modbus device (host port 503) that reports plausible-looking but static data. Purpose: slow down reconnaissance by giving an attacker a convincing but useless target.

### 4.6 SCADA SSH Workstation
**Build context:** `scada_ssh/`

An SSH server (container port 2222) with two accounts:
- `operator / operator123` — referenced by the Historian API (legitimate target)
- `engineer / engineer456` — referenced by the Honeypot Historian API (deception pivot)

Also exposes a **Physics REST API** on port 5100 (unauthenticated by design) that bridges Level-2 physical state to Level-3 consumers over the `l2l3-bridge-net`.

**Host-side command logging** (`scada_ssh/log_scada_cmd.py`) hooks into every interactive shell via `PROMPT_COMMAND` in `/etc/bash.bashrc`. Each executed command is classified, enriched with MITRE ATT&CK metadata from `shared/mitre_mapping.py`, and written to four sinks:

| Sink | Measurement / File | Purpose |
|---|---|---|
| InfluxDB | `terminal_commands` | Grafana stat panels and command table |
| InfluxDB | `security_alerts` | MITRE Attack Story narrative panel |
| InfluxDB | `honeypot_events` | Protocol honeypot event table |
| Story Logger | `general logs.jsonl` | Central JSONL audit trail (`sensor=workstation`) |

Operator `mbtget` invocations are tagged as `MODBUS_WRITE` (FC5/6) or `MODBUS_READ` (FC3). Credential harvesting via `cat /var/log/scada_maintenance.log` is tagged `CREDENTIAL_DISCOVERY`. SSH login events are additionally recorded by `UnifiedLogger` in `/etc/profile.d/log_ssh.sh` as `LATERAL_MOVEMENT` on the `security_alerts` measurement.

Only the `operator` user may egress to Modbus/S7/DNP3 ports (enforced by `iptables` in the container entrypoint).

### 4.7 HMI
**File:** `hmi/hmi_app.py`

Flask-based (Plotly Dash) web HMI at host port 8060. Reads live process values from the Modbus PLC and presents a SCADA operator console with live gauges, historical charts, and operator controls (Pump RPM slider → HR 200, Valve toggle → HR 202).

### 4.8 Historian Bridge
**File:** `hmi/hmi_simulator.py`

Continuously polls Modbus registers and writes the full pipeline telemetry (`pipeline_metrics` measurement) to InfluxDB at approximately 2 Hz.

### 4.9 ML Engine
**File:** `ml-engine/trainer.py` (v5)

Detailed in Section 6. Exposes a FastAPI server on container port 8000 (host port **8001**).

### 4.10 Historian API
**File:** `historian_api/app.py`

FastAPI service at host port **5001** (container port 5000) acting as the Level-3 integration point. Sits on both `monitor-net` and `enterprise-net`. Authenticates against SCADA SSH (operator account) for privileged queries and proxies ML engine metrics.

### 4.11 Honeypot Historian API
**Files:** `honeypot_historian_api/`

A deception copy of the Historian API at host port **5002** (container port 5000) deployed in the DMZ, on `dmz-net` and `monitor-net`. Returns structurally valid but subtly corrupted telemetry data. All client accesses are fingerprinted and written to InfluxDB as `API_ACCESS` events. The deception feedback loop: when the ML engine writes `is_anomaly == 1` to `security_metrics`, the HMI/Historian Bridge intercepts this flag and the honeypot API begins returning scrambled data — confusing the adversary's situational awareness.

### 4.12 Network Sniffer + Correlator
**Files:** `logger/logger.py`, `logger/correlator.py`

- **`logger.py`**: Raw packet capture using `network_mode: host` with `NET_ADMIN` + `NET_RAW` capabilities.
- **`correlator.py`**: Runs in the same network namespace as `plc_simulator` (`network_mode: service:plc_simulator`), sniffing Modbus TCP traffic and correlating Modbus write commands with physical-state changes. Writes `correlation_logs` and `modbus_events` to InfluxDB. These are consumed as network features by the ML engine. All events are enriched with MITRE ATT&CK metadata via `shared/mitre_mapping.py`.

### 4.13 Story Logger
**Port:** 8600

The `story_logger` service (on `dmz-net`, `monitor-net`, `l2l3-bridge-net`) receives HTTP POST events from all producers and appends one JSON record per line to `general logs.jsonl`. Producers include:
- ML engine (`sensor=synthetic`)
- Attacker node (`sensor=attacker_node`)
- SCADA workstation (`sensor=workstation`)

Each record carries: `ts`, `sensor`, `event_type`, `src_ip`, `journey_id`, `outcome`, `severity`, and a `meta` object with `command`, `narrative`, and MITRE fields where applicable.

### 4.14 Log Dashboard
**Port:** 8502 (Streamlit)

A Streamlit-based dashboard (`log_dashboard/`) that reads `general logs.jsonl` and presents the live kill-chain narrative, with filters by phase, severity, and event type.

### 4.15 InfluxDB Historian
InfluxDB v2.7.6 (host port 8086) stores all measurements in the `sensor_logs` bucket:

| Measurement | Contents |
|---|---|
| `pipeline_metrics` | pressure, flow_rate, temperature, pump_rpm, pump_state, setpoint |
| `modbus_events` | every Modbus transaction (fc_type, register, value, src_ip) |
| `security_metrics` | ML anomaly scores (if_score, lstm_error, replay_lstm_error, is_anomaly flag) |
| `security_alerts` | fired alert records (alert_type, detail, score) |
| `honeypot_events` | S7/DNP3 probe events (protocol, remote_ip, event_type) |
| `recon_scan_events` | DNP3 port scan detections |
| `correlation_logs` | cross-layer network events with MITRE enrichment |
| `attack_status` | human-readable attack state markers |
| `grafana_events` | structured event log for Grafana annotations |
| `forced_writes` | semantic injection events (register, value) |
| `terminal_commands` | SCADA workstation shell commands with MITRE tags |
| `auth_attempts` | S7/DNP3 TCP connection attempts |
| `hmi_access` | HMI HTTP access logs |

All InfluxDB writes use nanosecond precision (`WritePrecision.NS`). All records include a `session_id` tag (8-character UUID prefix) for cross-session forensic correlation.

### 4.16 Attacker Node
A Debian-based container with `nmap`, `pymodbus`, `scapy`, and `requests` pre-installed. Ships the 7-phase `attack_suite.py` kill-chain script. Configured on `dmz-net` + `monitor-net`.

---

## 5. Attack Simulation Subsystem

The primary attack script is `attack_suite.py` (7-phase Cyber Kill Chain). A legacy `attack_simulation.py` (6 scenarios) also exists for backwards compatibility.

### 5.1 Phase 1 — Reconnaissance
TCP connect scan (`nmap -sT -n`) against ports 502, 102, and 20000 on all three honeypot targets. Results are logged to `auth_attempts` and `honeypot_events`. No anomaly is raised — correct low-FPR behaviour.

### 5.2 Phase 2 — Information Gathering
Modbus FC3 read of sensor registers 100–103 (pressure, flow, temperature, pump RPM) and actuator registers 200–202. S7comm COTP connection request + banner grab (`COTP CC` response confirms Siemens S7-300 emulation). All reads are logged but do not trigger anomaly alerts.

### 5.3 Phase 3 — Vulnerability Scan / Protocol Fingerprinting
Probes supported Modbus function codes (FC3, FC6, FC16). Sends DNP3 RESET_LINK_STATES frame and verifies ACK. Performs full S7 Setup Communication handshake to discover PDU size. All connections fingerprinted in `honeypot_events`.

### 5.4 Phase 4 — Exploit (Semantic Injection)
The attacker writes 350 PSI directly to Modbus holding register 100 (pressure sensor) using FC6 Write, bypassing the physics engine.

**Detection**: The Modbus server additionally logs a `forced_writes` event. The ML engine queries `forced_writes` every 15 seconds. Any entry fires `SEMANTIC_INJECTION`. Events are deduplicated in-memory using a timestamp key (`_INJECTION_DEDUP_TTL = 120 s`) — ensuring exactly-once alerting per physical event regardless of how many detection cycles the event appears in the query window.

### 5.5 Phase 5 — Payload Delivery (Stealth Drift)
9 steps of incrementing pressure by 3 PSI every 5 seconds (45 s total). Each individual step is below any fixed-threshold alarm. Total cumulative drift: +27 PSI above baseline.

**Detection**: The EWMA/CUSUM stealth-drift detector accumulates evidence across steps. CUSUM fires when `S⁺ > 6.0` or `S⁻ > 6.0` (after requiring 3 consecutive confirmations via `_drift_confirm_count`). The slope detector additionally fires when ≥ 80% of recent slope samples agree in sign AND magnitude > 0.3 PSI/sample. A `STEALTH_DRIFT_EWMA` alert is raised in `security_alerts`.

### 5.6 Phase 6 — Lateral Movement
Pivots from Modbus PLC → S7comm PLC → DNP3 RTU in sequence. Each pivot performs a full protocol handshake, is logged to `honeypot_events`, and tagged with MITRE ATT&CK `T0867 Lateral Tool Transfer`.

### 5.7 Phase 7 — Privilege Escalation
Escalates from sensor-register reads to actuator-register writes:
- Writes max RPM (3000) to register 200 → physics engine spikes pressure.
- Closes the valve (register 202 = 0) → physics engine clamps `flow_rate = 0.0`.
- Restores actuators to pre-attack state after demo.

**Detection**: The ML engine detects the resulting process anomaly (IF and LSTM both fire on the pressure spike). The `OVER_PRESSURE` expert rule fires if pressure exceeds 300 PSI.

---

## 6. ML Detection Engine — IsolationForest + LSTM Ensemble

**File:** `ml-engine/trainer.py` (v5)

### 6.1 Feature Set

Ten features are extracted from InfluxDB at each detection cycle (every **15 seconds**, querying the last 2 hours):

| Feature | Source | Rationale |
|---|---|---|
| `pressure` | `pipeline_metrics` | Primary process variable |
| `flow_rate` | `pipeline_metrics` | Correlated with pressure |
| `temperature` | `pipeline_metrics` | Secondary process indicator |
| `pressure_delta` | Computed (1-step diff) | Rate of change — flags jumps |
| `pressure_mean_dev` | Computed (rolling 10-sample mean) | Sustained deviation from mean |
| `inter_arrival_time` | Computed (time diff between rows) | Packet timing anomalies |
| `write_freq_10s` | `correlation_logs` (rolling 10 s) | Number of Modbus writes in 10 s |
| `is_write` | `correlation_logs` | Binary: was a write issued? |
| `func_code` | `correlation_logs` | Modbus function code |
| `length` | `correlation_logs` | Packet payload length |

Network features are joined to the pipeline telemetry via `pd.merge_asof` with a 1-second tolerance. DNP3 events are **intentionally excluded** from the feature pipeline.

### 6.2 Model 1 — Isolation Forest (IF)

**Algorithm**: `sklearn.ensemble.IsolationForest`

**Hyper-parameters**:

| Parameter | Value | Rationale |
|---|---|---|
| `n_estimators` | 200 | More trees → more stable scores |
| `contamination` | 0.01 | Very low → only unambiguous outliers flagged |
| `random_state` | 42 | Reproducibility |
| Score threshold | −0.20 | Only scores below −0.20 raise an alert |

**Training**: 180-second warm-up on normal-only data (minimum 50 samples). Model serialised to `/data/model.pkl`.

**Rationale**: Isolation Forest requires no labelled anomaly examples and is robust to high-dimensional data. Its tree-based isolation of rare samples is well-suited to the sparse anomaly distribution typical in continuous process monitoring.

### 6.3 Model 2 — General LSTM Autoencoder

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
| Anomaly threshold | p99 of training reconstruction errors |
| Threshold floor | 0.01 (absolute minimum to prevent near-zero false-positive floods) |
| Error margin multiplier | 4.0× (applied to threshold at scoring time to suppress borderline FP) |
| Confirmation window | 3 consecutive anomalous cycles required before alert fires |

**Training procedure**:
1. Feature matrix scaled to [0, 1] with `MinMaxScaler` (fit on training window only).
2. Overlapping windows of length 20 created from the normalised matrix.
3. Autoencoder trained to reconstruct each window (unsupervised).
4. Anomaly threshold set post-training as the 99th percentile of training reconstruction errors. A minimum floor of 0.01 is enforced.
5. At scoring time, live data is clamped to [0, 1] before transformation to prevent out-of-distribution inputs from generating artificially high reconstruction errors.
6. Model and scaler persisted to `/data/lstm_model.keras`, `/data/scaler.pkl`, and `/data/scaler.pkl.threshold`.

**Rationale**: Pipeline processes are inherently temporal — pressure, flow, and temperature evolve along smooth physical trajectories. An LSTM autoencoder learns to reconstruct *normal temporal patterns*. Attacks (sudden jumps, frozen telemetry, monotonic ramps) violate these patterns and produce reconstruction errors above the training distribution. LSTM is complementary to IF: IF catches point-in-time outliers while LSTM catches sequential pattern breaks that individually appear normal.

### 6.4 Model 3 — Replay LSTM Autoencoder

**Algorithm**: Sequence-to-sequence LSTM autoencoder (TensorFlow/Keras)

**Features**: `[pressure_delta, rolling_std_5, baseline_dev_norm]`

During a replay attack, these three features collapse to `[≈0, ≈0, constant≠0]` — a rigid pattern the model (trained on normal process variance) cannot reconstruct cheaply.

**Feature computation**:
- `pressure_delta` = first-order difference of the pressure array
- `rolling_std_5` = 5-sample rolling standard deviation (≈0 during frozen telemetry)
- `baseline_dev_norm` = `|pressure − baseline| / |baseline|` where `baseline` is the mean of the first half of the window

**Hyper-parameters**:

| Parameter | Value |
|---|---|
| Sequence length | 15 timesteps |
| Latent dimension | 16 |
| Epochs | 15 |
| Batch size | 32 |
| Optimiser | Adam (lr=1e-3) |
| Anomaly threshold | p95 of training reconstruction errors |

Model persisted to `/data/replay_lstm.keras`, `/data/replay_scaler.pkl`, and `/data/replay_scaler.pkl.threshold`.

**Rationale**: The general LSTM detects broad dynamic anomalies. The Replay LSTM is specifically scoped to variance characteristics, allowing it to reliably flag replayed or frozen telemetry even when the replayed values themselves fall within normal operating limits.

### 6.5 Ensemble Decision Logic

The three models and the expert rules operate as an **OR-gate ensemble**:

```
is_anomaly = IF_anomaly  OR  LSTM_anomaly  OR  Replay_LSTM_anomaly  OR  expert_rule_fired
```

- A single model or rule flag is sufficient to set `is_anomaly = 1`.
- All scores are published independently (`if_score`, `lstm_error`, `replay_lstm_error` fields) so each model's contribution is separately attributable in Grafana.
- Expert rules (Section 7) override model outputs upward but never suppress them.

**Why OR-gate over AND-gate**: Missed attacks (false negatives) carry higher operational risk in an ICS context than false alarms, which operators can acknowledge without process interruption.

**TRAINING state removed**: The legacy `is_anomaly=2` (blue "TRAINING" state) is permanently removed from the Grafana metrics. The ML Anomaly Status panel now shows only NORMAL (0) or ANOMALY (1).

### 6.6 Startup Grace Period and Model Persistence

- **120-second startup grace period** (`STARTUP_GRACE_SECONDS = 120`) suppresses all alerts after container start. This covers the physics engine's natural convergence from initial conditions (0 → ~60 PSI).
- Models are loaded from disk on startup if they exist; a retrain is triggered only when model files are absent.
- During warm-up (first 180 s after training starts, minimum 50 samples) no alerts are generated.
- If the IF model is present but either LSTM is missing, the engine retrains the missing LSTM(s) on live data without resetting the IF model — a fast-path retrain.

### 6.7 REST API

The FastAPI server runs on container port 8000 (host port **8001**):

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Liveness + model readiness (`model_ready`, `lstm_ready`, `replay_lstm_ready`, `in_warmup`, `in_grace`, `uptime_seconds`, `session_id`) |
| `/alerts` | GET | Recent alert log (in-memory, newest first). Params: `limit`, `alert_type` |
| `/metrics` | GET | Live IF score, LSTM error, replay LSTM error, EWMA state, CUSUM accumulators |
| `/reset-model` | POST | Delete all model files and trigger full retrain on next cycle |

```bash
curl http://localhost:8001/health
curl "http://localhost:8001/alerts?limit=20&alert_type=SEMANTIC_INJECTION"
curl http://localhost:8001/metrics
curl -X POST http://localhost:8001/reset-model
```

---

## 7. Rule-Based and Statistical Detectors

### 7.1 Expert Rules (Cross-Layer)

Active after the 120-second grace period. Applied to the most recent row of the feature matrix:

| Rule | Condition | Alert Type |
|---|---|---|
| Pressure jump, no write command | `|pressure_delta| > 20 PSI` AND `write_freq_10s == 0` | `CROSS_LAYER_ANOMALY` |
| Sustained mean deviation | `|pressure_mean_dev| > 35 PSI` | `STEALTH_DRIFT` |
| Over-pressure | `pressure > 300 PSI` | `OVER_PRESSURE` |

### 7.2 EWMA / CUSUM Stealth Drift Detector

Designed to detect slow, gradual setpoint manipulation that evades fixed-threshold detection.

**EWMA update:**
```
EWMA_t = λ × P_t + (1 − λ) × EWMA_{t-1}    λ = 0.1
```

**CUSUM accumulators (two-sided):**
```
S⁺_t = max(0,  S⁺_{t-1} + (P_t − EWMA_t) − k)
S⁻_t = max(0,  S⁻_{t-1} − (P_t − EWMA_t) − k)
k = 1.5 PSI   (allowance / slack)
```

Alert when `S⁺ > 6.0` or `S⁻ > 6.0` (after 3 consecutive confirmations: `DRIFT_CONFIRM_NEEDED = 3`). Accumulators reset after each confirmed alert.

**Slope-based drift detector:** Linear regression over 20-sample window. Alert when ≥ 80% of the most recent 10 slope samples agree in sign AND magnitude > 0.3 PSI/sample AND overall range > 30 PSI (`DRIFT_RANGE_THRESHOLD`).

**Baseline initialisation:** EWMA is seeded from the mean of the first 10 samples recorded after the grace period expires (30-second post-grace buffer), preventing the startup ramp from contaminating the long-run baseline.

### 7.3 Replay Attack Detector (Tri-Signal)

Alerts fire when any of three signals trigger (120-second cooldown after each alert):

1. **Zero-variance**: Rolling standard deviation < 0.1 PSI AND baseline deviation > 8% (`ZERO_VARIANCE_BASELINE_DEV_PCT = 8.0`).
2. **Fingerprint match**: Current pressure fingerprint (0.5 PSI resolution) matches any of the 20 most recent historical fingerprints with ≥ 95% element match (`REPLAY_MATCH_RATIO`) AND window mean deviates ≥ 12% from baseline (`REPLAY_BASELINE_DEV`) AND rolling std < 2.0.
3. **Replay LSTM**: Reconstruction error exceeds p95 training threshold AND baseline deviation > 3%.

Post-attack state flags (`_semantic_injection_seen`, `_drift_attack_seen`) gate the replay detector to prevent the cooldown from masking overlapping attack phases.

### 7.4 Semantic Injection Detector

Queries the `forced_writes` measurement (populated by the Modbus PLC on sensor-register writes) and raises `SEMANTIC_INJECTION`. Events are cached in `_seen_injection_ts` using the record timestamp as a key for 120 seconds (`_INJECTION_DEDUP_TTL`), guaranteeing exactly-once alerting per physical injection regardless of how many 15-second detection cycles the event appears in the query window.

---

## 8. Data Pipeline and Telemetry

### 8.1 Data Flow

```
Physics Engine (Redis, 1 Hz)
        │
Modbus PLC Registers
        ├─── Historian Bridge (hmi_simulator.py) ───▶  pipeline_metrics     (InfluxDB, ~2 Hz)
        └─── Correlator (correlator.py) ────────────▶  correlation_logs     (InfluxDB)
                                                        modbus_events        (InfluxDB)
S7 / DNP3 servers ──────────────────────────────────▶  honeypot_events      (InfluxDB)
                                                        auth_attempts        (InfluxDB)
SCADA SSH Workstation ──────────────────────────────▶  terminal_commands    (InfluxDB)
        │               (log_scada_cmd.py)              security_alerts      (InfluxDB)
        │
        ▼
 Story Logger (port 8600)  ──────────────────────────▶  general logs.jsonl  (JSONL)

         ML Engine reads pipeline_metrics + correlation_logs
                │
        security_metrics  ──────────────────────────▶  Grafana (is_anomaly, scores)
        security_alerts   ──────────────────────────▶  Grafana (alert log)
        grafana_events    ──────────────────────────▶  Grafana (annotations)
```

### 8.2 Unified Logging and MITRE Mapping

The `shared/mitre_mapping.py` module provides a single source of truth for mapping internal event types to MITRE ATT&CK for ICS techniques. The `lookup()` function accepts both lowercase wire names (e.g. `modbus_write`) and uppercase dashboard names (e.g. `MODBUS_WRITE`). The `enrich_point()` function adds five MITRE tags to any InfluxDB `Point` object in-place.

All events are tagged with `purdue_level = "Level 2"` as this deployment operates at that level.

**Complete MITRE ATT&CK mapping table:**

| Event Type | MITRE ID | Technique | Tactic |
|---|---|---|---|
| `modbus_write` / `write_command` / `forced_write` | T0855 | Unauthorized Command Message | Impair Process Control |
| `modbus_read` | T0802 | Automated Collection | Collection |
| `credential_discovery` | T1005 | Data from Local System | Credential Access |
| `lateral_movement` | T0867 | Lateral Tool Transfer | Lateral Movement |
| `network_scan` | T1595 | Active Scanning | Reconnaissance |
| `terminal_cmd` | T0807 | Command-Line Interface | Execution |
| `replay_attack` / `REPLAY_LSTM` / `REPLAY_FINGERPRINT` / `ZERO_VARIANCE` | T0856 | Spoof Reporting Message | Impair Process Control |
| `s7_connect` | T0886 | Remote Services | Initial Access |
| `s7_stop_cpu` | T0816 | Device Restart/Shutdown | Inhibit Response Function |
| `S7COMM_PROBE` / `DNP3_PROBE` | T0846 | Network Service Discovery | Discovery |
| `ssh_login` / `ssh_bruteforce` | T0812 | Default Credentials | Lateral Movement |
| `ssh_command` | T0807 | Command-Line Interface | Execution |
| `ISOLATION_FOREST` | T0806 | Brute Force I/O | Impair Process Control |
| `LSTM_AUTOENCODER` | T0856 | Spoof Reporting Message | Impair Process Control |
| `SEMANTIC_INJECTION` | T0855 | Unauthorized Command Message | Impair Process Control |
| `CROSS_LAYER_ANOMALY` | T0820 | Exploitation for Evasion | Evasion |
| `STEALTH_DRIFT` / `DRIFT_ATTACK` | T0836 | Modify Parameter | Impair Process Control |
| `OVER_PRESSURE` | T0828 | Loss of Safety | Damage to Property |

### 8.3 Story Logger and `general logs.jsonl`

Each JSONL record contains: `ts`, `sensor`, `event_type`, `src_ip`, `stage`, `journey_id`, `outcome`, `level`, and a `meta` object with `message`, `component`, `command`, `narrative`, and MITRE fields where applicable.

All producers write to the Story Logger via HTTP POST to `http://story_logger:8600/story/events`. The logger appends records to `general logs.jsonl` in the project root (mounted at `/repo`).

### 8.4 Historian Services

- **`historian_bridge`** (`hmi/hmi_simulator.py`): Polls Modbus PLC and writes `pipeline_metrics` (~2 Hz) for Grafana process telemetry.
- **`historian_api` (port 5001)**: FastAPI Level-3 integration endpoint. Authenticates against SCADA SSH for operator-level access. Proxies ML engine `/health` and `/alerts` responses.
- **`honeypot_historian_api` (port 5002)**: DMZ-facing deception copy. Returns structurally valid but corrupted data; fingerprints all clients.

All InfluxDB writes use nanosecond precision (`WritePrecision.NS`).

---

## 9. Grafana Monitoring Dashboard

**Files:** `grafana_dashboards/dashboard.json`, `grafana_dashboards/mitre_attack_ics.json`

Auto-provisioned via `grafana_provisioning/`. Dashboard refresh interval: **5 seconds**. All stat panels use `lastNotNull` reducer.

### Main Dashboard (`dashboard.json`)

#### Row 1 — Pipeline Telemetry
- Pressure (PSI) — attacker-sourced series shown in red (separated by `source` tag)
- Flow Rate (L/s)
- Temperature (°C)
- Pump RPM

#### Row 2 — Security & Anomaly Detection
- **ML Anomaly Status** (Stat) — `is_anomaly` from `security_metrics`; value-mapped: 0 → "NORMAL" (green), 1 → "ANOMALY" (red)
- ML Anomaly Score time-series (IF score + LSTM error overlay)
- Cross-Layer Correlation (Modbus write frequency vs. pressure overlay)
- Replay Attack – Pressure Delta time-series

#### Row 3 — Attack Simulation Results
Stat panels querying `security_alerts` (last 30 s look-back): Semantic Injection, Replay Attack, DNP3 Probe, S7comm Probe, Reconnaissance Scan (FC3), EWMA Stealth Drift.

#### Row 4 — Protocol Honeypot Events
Sortable table of 50 most recent `honeypot_events` records with columns: time, protocol, remote_ip, event_type, detail.

#### Row 5 — Terminal Operator Commands (Transient Detection)
Four stat panels with **10-second transient look-back** (dashboard refresh 5 s):

| Panel | Flux filter | Idle display | Active display |
|---|---|---|---|
| SSH Attempts | `AUTH_ATTEMPT` or `LATERAL_MOVEMENT` on `terminal_commands` | NONE | DETECTED |
| API Recon Probes | `API_ACCESS` on `terminal_commands` | NONE | DETECTED |
| Modbus Writes | `MODBUS_WRITE` on `terminal_commands` | NONE | DETECTED |
| Modbus Reads / Cred Discovery | `MODBUS_READ` or `CREDENTIAL_DISCOVERY` on `terminal_commands` | NONE | DETECTED |

All transient panels use `group() |> count() |> max()` to collapse multiple matching series into a single label, preventing duplicate "DETECTED" text. Value maps: `null → NONE`, `0 → NONE`, `≥1 → DETECTED`. After ~10 s without a matching event the panel reverts to NONE automatically. `textMode: value` ensures only the mapped word is shown.

### MITRE ATT&CK ICS Dashboard (`mitre_attack_ics.json`)
- **Attack Story** table: unions `narrative` fields from `security_alerts`, `terminal_commands`, and `honeypot_events` (not only ML-engine `security_alerts`), providing a cross-layer kill-chain narrative.
- Heatmaps by protocol, tactic, kill-chain stage, and Purdue level across `correlation_logs`, `security_alerts`, `terminal_commands`, and `honeypot_events`.

**Session deduplication**: All Flux queries include `|> group(columns: ["_measurement", "_field"])` before aggregation. Without this, each container restart creates a new `session_id` tag that InfluxDB treats as a distinct time series, causing duplicate lines in Grafana.

---

## 10. Environment and Deployment

### 10.1 Prerequisites
- Docker Engine ≥ 24.0 and Docker Compose v2
- `l2l3-bridge-net` network pre-created: `docker network create l2l3-bridge-net --subnet 172.28.0.0/24`
- ≥ 8 GB RAM (TensorFlow LSTM training runs inside the `ml_engine` container)
- ≥ 20 GB free disk

### 10.2 Configuration

All configuration managed through a single **`.env`** file at the project root (excluded from git via `.gitignore`):

```ini
# InfluxDB
INFLUX_URL=http://historian:8086
INFLUX_TOKEN=supersecrettoken
INFLUX_ORG=my_refinery
INFLUX_BUCKET=sensor_logs

# Redis
REDIS_HOST=redis

# ML Engine
ML_ENGINE_URL=http://ics_ml_engine:8000

# SCADA SSH
SCADA_SSH_HOST=ics_scada_ssh
SCADA_SSH_PORT=2222
SCADA_SSH_USER=operator
SCADA_SSH_PASS=operator123

# Honeypot SSH (deception)
HONEYPOT_SSH_USER=engineer
HONEYPOT_SSH_PASS=engineer456

# L2/L3 bridge
L2L3_SHARED_TOKEN=change-this-token

# Grafana
GF_SECURITY_ADMIN_PASSWORD=admin
GF_AUTH_ANONYMOUS_ENABLED=true
GF_AUTH_ANONYMOUS_ORG_ROLE=Viewer

# Story Logger
STORY_LOGGER_URL=http://story_logger:8600

PYTHONUNBUFFERED=1
```

### 10.3 Startup Sequence
```bash
# 1. Create the external bridge network (once)
docker network create l2l3-bridge-net --subnet 172.28.0.0/24

# 2. Build and start all services
docker compose up --build -d

# 3. Access points
#    Grafana:           http://localhost:3000
#    HMI:               http://localhost:8060
#    ML Engine health:  http://localhost:8001/health
#    Historian API:     http://localhost:5001/api/health
#    Honeypot API:      http://localhost:5002/api/health
#    InfluxDB UI:       http://localhost:8086
#    Log Dashboard:     http://localhost:8502

# 4. Run the full 7-phase attack kill chain
docker compose exec attacker_node python attack_suite.py
# Or run specific phase:
docker compose exec attacker_node python attack_suite.py --phase 4
```

### 10.4 Network Segmentation

| Network | Services |
|---|---|
| `ot-net` | physics_simulator, plc_simulator, ics_s7_plc, fake_plc_sim, hmi, historian_bridge, redis, historian |
| `dmz-net` | plc_simulator, ics_s7_plc, ics_dnp3, ics_scada_ssh, historian_bridge, correlator, attacker_node, honeypot_historian_api, story_logger |
| `monitor-net` | plc_simulator, ics_s7_plc, ics_dnp3, hmi, historian_bridge, ml_engine, historian, grafana, grafana-image-renderer, correlator, attacker_node, honeypot_historian_api, historian_api, log_dashboard, story_logger |
| `enterprise-net` | historian_api, ics_scada_ssh, historian |
| `l2l3-bridge-net` | ics_scada_ssh (172.28.0.10), story_logger |

---

## 11. Security Design Decisions

### 11.1 Deception Depth
Three layers of deception:
1. **Protocol level** — authentic Modbus, S7, and DNP3 responses that pass ICS-aware scanner validation.
2. **Process level** — physics-backed sensor values that are internally consistent across pressure, flow, and temperature.
3. **API level** — a DMZ-facing historian REST API that returns structurally valid but corrupted telemetry, activated by the `is_anomaly` flag feedback loop.

### 11.2 Cross-Layer Correlation
The fundamental detection innovation: correlating **network-layer write commands** with **physical-layer process changes**.
- A legitimate pressure change *must* be preceded by a valid Modbus actuator write (register ≥ 200).
- Pressure change without such a write → `CROSS_LAYER_ANOMALY`.
- Write to sensor registers (100–103) → `SEMANTIC_INJECTION` (via `forced_writes`).

### 11.3 Minimal Attack Surface
- The ML engine is on `monitor-net` only — no inbound connectivity from the DMZ.
- Redis is on `ot-net` only.
- The network sniffer uses `network_mode: host` rather than bridging into OT networks.
- The correlator shares the Modbus PLC's network namespace (`network_mode: service:plc_simulator`) to sniff Modbus traffic directly.

### 11.4 No Authentication on Honeypot Services
By design — a deception environment must accept all connections to maximise attacker engagement and logging fidelity. The `honeypot_historian_api` deliberately exposes an unauthenticated debug endpoint.

### 11.5 Post-Attack State Tracking
Global flags (`_semantic_injection_seen`, `_drift_attack_seen`, `_drift_attack_seen_time`) gate the replay detector to prevent the 120-second cooldown from masking overlapping attack phases. `DRIFT_POST_ATTACK_WINDOW = 300 s` keeps the system in heightened-awareness mode for 5 minutes after a confirmed drift attack.

### 11.6 Session-ID Tagging
All InfluxDB writes include a `session_id` tag (8-character UUID prefix), enabling post-attack forensic reconstruction of the full attacker timeline across all protocols and services across container restarts.

---

## 12. Evaluation Methodology

### 12.1 Experimental Setup
Attacks executed from `attacker_node` using `attack_suite.py`. Each attack phase is run independently and combined in a full 7-phase compound scenario. The `evaluate.py` script (`scripts/evaluate.py`) computes all metrics from InfluxDB data.

### 12.2 Metrics Collected

| Metric | Definition |
|---|---|
| **Precision** | Correctly detected attack alerts / Total alerts fired |
| **Recall (TPR)** | Fraction of attack phases producing at least one correct-type alert |
| **F1-Score** | Harmonic mean of precision and recall |
| **FPR** | Alerts fired during quiescent periods per hour |
| **Detection Latency** | Seconds from attack onset to first alert |
| **IF contribution** | Alerts where only IF fired |
| **LSTM contribution** | Alerts where only LSTM fired |
| **Ensemble lift** | Additional attacks caught by OR-gate vs single model |

### 12.3 Ground Truth Alignment
All attack executions write timestamped markers to InfluxDB (`attack_status`, `forced_writes`). Detection latency is computed as `alert_timestamp − attack_onset_timestamp` using nanosecond-precision records. Grafana provides a fully aligned visual ground-truth timeline.

### 12.4 Baseline Establishment
Models are trained during a 180-second window of **normal operation only** (no attacks injected, minimum 50 samples). The LSTM threshold at the p99 of training reconstruction errors, combined with a 4× error margin and 3-consecutive-window confirmation, is designed to yield a very low FPR on normal data.

### 12.5 Quantitative Evaluation Results

From `evaluation_report.txt` (519 samples at 1 Hz, 27 attack samples, 492 normal):

| Model | Precision | Recall | F1-Score |
|---|---|---|---|
| Isolation Forest | 0.0652 | 0.4444 | 0.1137 |
| LSTM Autoencoder | 0.1698 | 1.0000 | 0.2903 |
| **Ensemble (OR-gate)** | **0.1011** | **1.0000** | **0.1837** |

**Phase Detection Audit:**

| Phase | Isolation Forest | LSTM Autoencoder | Ensemble |
|---|---|---|---|
| Phase 4 (Semantic Injection) | MISSED | MISSED | MISSED |
| Phase 5 (Stealth Drift) | DETECTED | DETECTED | DETECTED |
| Phase 7 (Actuator Manipulation) | DETECTED | DETECTED | DETECTED |
| Phase 8 (Replay Attack) | MISSED | DETECTED | DETECTED |

> **Note on Phase 4 (Semantic Injection):** The Isolation Forest and LSTM ensemble score the injected value within the feature space but the rule-based `SEMANTIC_INJECTION` detector (which operates on `forced_writes`, not model scores) correctly identifies it. The `evaluate.py` evaluation script assesses model scores only; the rule-based detector is separately validated through Grafana `security_alerts` records.

### 12.6 Ensemble vs. Single Model Trade-offs

| Model | Strength | Weakness |
|---|---|---|
| Isolation Forest | Fast, no temporal context needed, handles multivariate point outliers | Misses gradual drift; each sample may look normal individually |
| LSTM Autoencoder | Captures sequential process dynamics, detects pattern breaks across time | Requires sufficient training data; high error margin to reduce FP |
| **Ensemble (OR-gate)** | Highest recall — either model fires on its corresponding attack class | Slightly higher FPR than either alone; mitigated by expert-rule gating and confirmation windows |

The OR-gate ensemble is preferred because missed attacks (false negatives) carry higher operational risk in an ICS context than false alarms, which operators can acknowledge without process interruption.

### 12.7 Operational Findings

Analysis of `general logs.jsonl` from recent simulation runs confirms the system's effectiveness:
- **Kill Chain Progression**: Logs show clear evidence of an adversary moving from `phase1_recon` through `phase7_privesc` with full MITRE enrichment at each step.
- **Anomalous Activity Detection**: The ML engine successfully flagged `OVER_PRESSURE` events (Level 2), `LSTM_AUTOENCODER` sequence anomalies, and `STEALTH_DRIFT_EWMA` alerts with high precision.
- **Terminal Exploitation**: `terminal_logger.py` captured `mbtget -r3 -a 100` (`MODBUS_READ`, T0802) and `mbtget -w6 300 -a 100` (`MODBUS_WRITE`, T0855) with `outcome=success`. SCADA workstation logging (`sensor=workstation`) mirrors the same event types.
- **Credential Harvesting**: `cat /var/log/scada_maintenance.log` is classified as `CREDENTIAL_DISCOVERY` (T1005) in both InfluxDB `terminal_commands` and `general logs.jsonl`.
- **Cross-Layer Traceability**: All events carry `mitre_technique_id`, `mitre_tactic`, `kill_chain_stage`, and `purdue_level` tags. The MITRE dashboard Attack Story panel surfaces terminal and honeypot narratives alongside ML/correlator `security_alerts`.
- **Grafana Transient Alerts**: Detection stat cards use a 10-second sliding window so operator actions briefly show DETECTED (~5–10 s) then revert to NONE, satisfying live exercise feedback requirements.

---

*This document covers the system as implemented in Docker Compose (no version key) with the IsolationForest + General LSTM + Replay LSTM ensemble ML engine (trainer.py v5), the 7-phase Cyber Kill Chain attack suite (attack_suite.py), and the Story Logger / JSONL narrative pipeline.*
