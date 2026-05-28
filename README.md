# ICS Honeypot – Physics-Aware Industrial Control System Deception Environment

> **Bachelor Thesis Implementation**
> Full Purdue Model emulation (Levels 0–3) with Modbus/TCP, S7comm, and DNP3 protocols,
> cross-layer anomaly detection, a three-model ML ensemble (Isolation Forest + two LSTM Autoencoders),
> EWMA/CUSUM stealth-drift detection, and Level-3 REST APIs for external integration.

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Architecture](#2-architecture)
3. [Physical Process Simulation](#3-physical-process-simulation)
4. [Protocol Honeypots](#4-protocol-honeypots)
5. [Logging Schema](#5-logging-schema)
6. [ML Anomaly Detection Engine](#6-ml-anomaly-detection-engine)
7. [Level-3 REST APIs](#7-level-3-rest-apis)
8. [HMI Dashboard](#8-hmi-dashboard)
9. [Grafana Monitoring](#9-grafana-monitoring)
10. [Deployment](#10-deployment)
11. [Attack Scenarios — 7-Phase Cyber Kill Chain](#11-attack-scenarios--7-phase-cyber-kill-chain)
12. [Manual Attack Commands](#12-manual-attack-commands)
13. [Evaluation Metrics](#13-evaluation-metrics)
14. [Demo Sequence for Exhibition](#14-demo-sequence-for-exhibition)
15. [File Structure](#15-file-structure)
16. [Key Design Decisions](#16-key-design-decisions)

---

## 1. System Overview

This project implements a **high-interaction ICS honeypot** modelled after the Purdue Reference Architecture. The system:

- Emulates a **pressure-regulated oil pipeline** with realistic physics (pressure, flow rate, temperature, viscosity, pump RPM) via a Redis-backed `PipelineSimulator`.
- Exposes three industrial protocols: **Modbus/TCP** (port 502), **Siemens S7comm** (port 102), and **DNP3** (port 20000).
- Applies **cross-layer anomaly detection** correlating network-level write commands with physical process state.
- Uses a **three-model ML ensemble** (Isolation Forest + General LSTM Autoencoder + Replay LSTM Autoencoder) supplemented by expert cross-layer rules and an **EWMA/CUSUM** stealth-drift detector, with a 120-second startup grace period to eliminate false positives.
- Logs every attacker interaction to **InfluxDB v2** and visualises everything in **Grafana** (auto-provisioned dashboards).
- Exposes REST APIs: **ML Engine** on host `:8001`, **Historian API** on host `:5001`, and a deception **Honeypot Historian API** on host `:5002`.
- Maintains a unified narrative audit trail in `general logs.jsonl` via the **Story Logger** (port 8600) with full MITRE ATT&CK for ICS enrichment.
- Includes a **Debian-based attacker node** container pre-loaded with `nmap`, `pymodbus`, `scapy`, and the 7-phase `attack_suite.py` kill-chain script.

The honeypot is entirely containerised with Docker Compose and requires no special hardware.

---

## 2. Architecture

### 2.1 Network Segmentation

Five Docker bridge networks emulate the full Purdue Model:

| Network | Docker Name | Connected Services | Purdue Level |
|---|---|---|---|
| OT / Process | `ot-net` | `physics_simulator`, `plc_simulator`, `ics_s7_plc`, `fake_plc_sim`, `hmi`, `historian_bridge`, `redis`, `historian` | L1–L2 |
| DMZ | `dmz-net` | `plc_simulator`, `ics_s7_plc`, `ics_dnp3`, `ics_scada_ssh`, `correlator`, `attacker_node`, `honeypot_historian_api`, `story_logger` | L3.5 |
| Monitoring | `monitor-net` | `ml_engine`, `historian`, `grafana`, `grafana-image-renderer`, `correlator`, `historian_api`, `attacker_node`, `honeypot_historian_api`, `log_dashboard`, `story_logger` | L2–L3 passive |
| Enterprise | `enterprise-net` | `historian_api`, `ics_scada_ssh`, `historian` | L3 |
| L2/L3 Bridge | `l2l3-bridge-net` | `ics_scada_ssh` (172.28.0.10), `story_logger` | L2↔L3 |

> **Pre-requisite:** Create the external bridge before first run:
> ```bash
> docker network create l2l3-bridge-net --subnet 172.28.0.0/24
> ```

An attacker entering via `dmz-net` can reach the PLCs but **cannot** directly reach InfluxDB (monitor-net only), the ML engine (monitor-net only), or Redis (ot-net only).

### 2.2 Service Map

```
┌─────────────────────────────────────────────────────────────────────┐
│  LEVEL 3 — Enterprise / Historian (enterprise-net)                 │
│  • historian_api       :5001  ← Legitimate Level-3 REST API        │
│  • ics_historian       :8086  ← InfluxDB v2 data store             │
│  • ics_scada_ssh       :2222  ← SSH (operator/engineer accounts)   │
│                        :5100  ← Physics REST API (L2→L3 bridge)    │
├─────────────────────────────────────────────────────────────────────┤
│  LEVEL 2 — SCADA / Monitoring (monitor-net)                        │
│  • ics_ml_engine       :8001  ← ML anomaly FastAPI (host port)     │
│  • ics_grafana         :3000  ← Dashboards                         │
│  • ics_hmi             :8060  ← Operator HMI (Plotly Dash)         │
│  • story_logger        :8600  ← Narrative JSONL logger             │
│  • ics_log_dashboard   :8502  ← Streamlit log viewer               │
├─────────────────────────────────────────────────────────────────────┤
│  LEVEL 3.5 — DMZ (dmz-net - externally reachable)                 │
│  • plc_simulator       :502   ← Modbus/TCP                         │
│  • ics_s7_plc          :102   ← S7comm (Siemens S7-300 emulation)  │
│  • ics_dnp3            :20000 ← DNP3                               │
│  • fake_plc_sim        :503   ← Dead-end Modbus decoy              │
│  • honeypot_historian  :5002  ← Deception API (corrupted data)     │
│  • attacker_node              ← Debian (nmap, pymodbus, scapy)     │
├─────────────────────────────────────────────────────────────────────┤
│  LEVEL 1/0 — Field Devices (ot-net - internal only)               │
│  • ics_physics_engine         ← Physics simulator (Redis-backed)   │
│  • ics_state_store            ← Redis shared process state         │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.3 Host Port Reference

| Host Port | Service | Purpose |
|---|---|---|
| 502 | `plc_simulator` | Modbus/TCP |
| 503 | `fake_plc_sim` | Dead-end Modbus decoy |
| 102 | `ics_s7_plc` | S7comm / ISO-TSAP |
| 20000 | `ics_dnp3` | DNP3 |
| 2222 | `ics_scada_ssh` | SSH (operator/engineer) |
| 5100 | `ics_scada_ssh` | Physics REST API |
| 8060 | `hmi` | Operator HMI |
| 8086 | `historian` | InfluxDB v2 |
| 3000 | `grafana` | Grafana dashboards |
| **8001** | `ml_engine` | ML Engine API (container: 8000) |
| **5001** | `historian_api` | Historian API (container: 5000) |
| **5002** | `honeypot_historian_api` | Deception API (container: 5000) |
| 8502 | `log_dashboard` | Streamlit log viewer |
| 8600 | `story_logger` | Story Logger HTTP endpoint |

---

## 3. Physical Process Simulation

**Files:** `physics/physics_engine.py`, `physics/physics_process.py`

The `PipelineSimulator` class models an oil refinery pipeline. State is persisted in **Redis** every second so that Modbus, S7, and HMI all read from one consistent snapshot.

### 3.1 State Variables

| Variable | Units | Modbus Register | S7 DB1 Offset |
|---|---|---|---|
| `pressure` | PSI | HR 100 | DBD0 (REAL) |
| `flow_rate` | L/s | HR 101 | DBD8 (REAL) |
| `temperature` | °C | HR 102 | DBD4 (REAL) |
| `pump_rpm` | RPM | HR 103 | DBD12 (REAL) |
| `valve_pos` | 0.0–1.0 | Writeable: HR 201 | — |

### 3.2 Physics Equations

```
target_pressure = (pump_rpm / 10.0) × (1.5 − valve_pos × 0.8)
target_flow     = (pump_rpm / 50.0) × valve_pos
temp_gain       = (pump_rpm / 3000)  × 0.5 × dt
viscosity       = max(0.2, 1.0 − (temperature − 25) × 0.02)

# Each variable converges toward its target with process noise:
pressure  += (target_pressure  − pressure)  × 0.2 + N(0, 0.2)
flow_rate += (target_flow      − flow_rate) × 0.2 + N(0, 0.05)

# Physical constraint: closed-valve clamp
if valve_pos == 0:
    flow_rate = 0.0
```

**Startup conditions:** 1200 RPM, valve 50% open → ~60 PSI, ~12 L/s, 18.5 °C.

---

## 4. Protocol Honeypots

### 4.1 Modbus/TCP (Port 502)

**File:** `plc/modbus_server.py`

Uses `pymodbus`. The `PhysicsAwareDataBlock` overrides both `getValues` (reads) and `setValues` (writes). Registers are pre-seeded at boot with `PipelineSimulator` defaults (zero-free from millisecond one).

- **Read (FC3/FC4):** Loads Redis state → registers 100–103. Logs a `modbus_events` record.
- **Write (FC6/FC16) to actuators (HR 200–202):** Updates physics engine. Logs `modbus_events`.
- **Write to sensor registers (100–103):** Additionally logs a `forced_writes` record → triggers `SEMANTIC_INJECTION` in the ML engine.

**Actuation registers (writable):**

| Register | Effect |
|---|---|
| HR 200 | Set pump RPM (0–3000) |
| HR 201 | Set valve position (0–1000 → 0.0–1.0) |
| HR 202 | Valve on/off toggle (0 or 1) |

### 4.2 S7comm / ISO-on-TCP (Port 102)

**File:** `plc/s7_server.py`

Uses `python-snap7` to emulate a **Siemens S7-300** PLC. DB1 contains four physical variables as IEEE-754 REAL values, updated from Redis every second. Presents `ProductName = 'SIMATIC S7-300 Modbus Gateway'` as a convincing decoy identity. Every TCP connection logs to `auth_attempts` and `honeypot_events`.

### 4.3 DNP3 (Port 20000)

**File:** `plc/dnp3_server.py`

Implements a minimal DNP3 link-layer outstation:
- Parses start bytes `0x05 0x64` and link-layer header.
- Responds with a valid ACK frame using DNP3 CRC-16.
- Logs raw frame hex and source/destination addresses to `honeypot_events`.

DNP3 events are **intentionally excluded** from the ML feature pipeline.

### 4.4 Fake PLC (Port 503)

Dead-end Modbus device returning plausible-looking but static data. Slows down reconnaissance by giving the attacker a convincing but useless target.

---

## 5. Logging Schema

All services write to InfluxDB v2 bucket `sensor_logs`. All writes include a **`session_id`** tag (8-character UUID prefix) for cross-session forensic correlation.

| Measurement | Key Tags | Key Fields | Written By |
|---|---|---|---|
| `pipeline_metrics` | `location`, `source`, `session_id` | `pressure`, `flow_rate`, `temperature`, `pump_rpm`, `pump_state`, `setpoint` | `historian_bridge` |
| `modbus_events` | `session_id`, `fc_type`, `src_ip` | `func_code`, `register`, `value` | `modbus_server` |
| `forced_writes` | `session_id`, `source` | `register`, `value` | `modbus_server` |
| `hmi_access` | `session_id`, `src_ip`, `endpoint` | `http_code` | `hmi_app` |
| `auth_attempts` | `session_id`, `src_ip`, `service` | `detail` | modbus, s7, dnp3 |
| `honeypot_events` | `session_id`, `protocol`, `remote_ip` | `event_type`, `detail`, `raw_data` | dnp3, s7 |
| `correlation_logs` | `session_id`, `src_ip` | `func_code`, `value`, `phys_pressure`, `is_anomalous` | `correlator` |
| `security_metrics` | `session_id`, `sensor` | `anomaly_score`, `lstm_error`, `replay_lstm_error`, `is_anomaly` | `ml_engine` |
| `security_alerts` | `session_id`, `alert_type` | `detail`, `score`, `narrative` | `ml_engine` |
| `terminal_commands` | `session_id`, `event_type`, `sensor` | `command`, `narrative`, MITRE tags | `log_scada_cmd.py` |
| `grafana_events` | `session_id`, `event_type`, `severity` | `value`, `detail` | `ml_engine` |
| `attack_status` | `session_id` | `phase`, `status` | `attack_suite.py` |

All `correlation_logs` and `security_alerts` entries include MITRE tags from `shared/mitre_mapping.py`:
`mitre_tactic`, `mitre_technique_id`, `mitre_technique_name`, `kill_chain_stage`, `purdue_level`, `protocol`.

---

## 6. ML Anomaly Detection Engine

**File:** `ml-engine/trainer.py` (v5)

### 6.1 Three-Model Ensemble Architecture

The engine runs **four detection layers** simultaneously every **15 seconds** on the last 2 hours of telemetry:

**Layer 1 — Isolation Forest** (statistical point-outlier):
- Warm-up: 180 seconds, minimum 50 samples of clean baseline.
- Feature vector (10 dimensions): `pressure`, `flow_rate`, `temperature`, `pressure_delta`, `pressure_mean_dev`, `inter_arrival_time`, `write_freq_10s`, `is_write`, `func_code`, `length`.
- Contamination: `0.01`. Alert threshold: score < `−0.20`.
- Model: `sklearn.ensemble.IsolationForest` with 200 estimators.

**Layer 2 — General LSTM Autoencoder** (sequential pattern anomaly):
- Sequence-to-sequence LSTM autoencoder on all 10 features.
- Architecture: `Input(20, 10) → LSTM(32) → RepeatVector(20) → LSTM(32) → TimeDistributed Dense(10)`.
- Threshold: p99 of training reconstruction errors, floor 0.01, multiplied by 4× error margin at scoring.
- Confirmation: 3 consecutive anomalous windows required before alert fires.
- Clamping: live data clipped to [0, 1] before MinMaxScaler transform to prevent out-of-distribution inflation.

**Layer 3 — Replay LSTM Autoencoder** (variance-focused frozen-telemetry):
- Sequence-to-sequence LSTM on 3 variance features: `[pressure_delta, rolling_std_5, baseline_dev_norm]`.
- Architecture: `Input(15, 3) → LSTM(16) → RepeatVector(15) → LSTM(16) → TimeDistributed Dense(3)`.
- Threshold: p95 of training reconstruction errors.
- During replay, features collapse to `[≈0, ≈0, constant≠0]` — a pattern the model cannot reconstruct cheaply.

**Layer 4 — Expert Rules + EWMA/CUSUM** (see Section 6.3).

**Ensemble OR-gate:**
```
is_anomaly = IF_anomaly OR LSTM_anomaly OR Replay_LSTM_anomaly OR expert_rule_fired
```

### 6.2 False-Positive Hardening

| Mechanism | Value | Effect |
|---|---|---|
| `STARTUP_GRACE_SECONDS` | 120 s | All detectors silenced during physics startup transient |
| IF contamination | 0.01 (1%) | Only unambiguous outliers flagged |
| IF score threshold | −0.20 | Higher bar than default |
| LSTM threshold | p99 + 4× margin | Very conservative; borderline reconstruction errors not flagged |
| LSTM confirmation | 3 consecutive windows | Filters transient spikes |
| LSTM input clamping | clip [0, 1] | Prevents stale scaler from inflating reconstruction errors |
| LSTM threshold floor | 0.01 | Prevents near-zero thresholds on low-variance startup data |
| CUSUM threshold | 6.0 | Only sustained drift triggers |
| CUSUM confirmation | 3 consecutive signals | Filters CUSUM noise |

### 6.3 EWMA / CUSUM Drift Detector

Designed specifically to detect **slow, gradual setpoint manipulation** that evades fixed-threshold detection.

**EWMA update:**
```
EWMA_t = λ × x_t + (1 − λ) × EWMA_{t−1}
λ = 0.1   (slow response — accumulates evidence over minutes)
```

**Cumulative Sum (CUSUM), two-sided:**
```
S+_t = max(0, S+_{t−1} + (x_t − EWMA_t) − k)
S−_t = max(0, S−_{t−1} − (x_t − EWMA_t) − k)
k = 1.5 PSI   (allowance / slack, ignores micro-fluctuations)
h = 6.0        (alert threshold)
```

Alert fires when `S+_t > h` or `S−_t > h` AND confirmed for 3 consecutive cycles. Accumulators reset after each confirmed alert.

**Why this matters:** Phase 5 (Stealth Drift) increments pressure by only 3 PSI every 5 seconds. Each step is individually invisible. CUSUM accumulates all 9 steps and fires after sustained drift — the only mechanism designed to catch this specific attack pattern.

### 6.4 Replay Attack Detector (Tri-Signal)

Alerts fire when any of three signals trigger (120-second cooldown):

1. **Zero-variance**: rolling std < 0.1 PSI AND baseline deviation > 8%.
2. **Fingerprint match**: fingerprint (0.5 PSI resolution) matches any of 20 recent fingerprints with ≥ 95% match AND baseline deviation ≥ 12% AND std < 2.0.
3. **Replay LSTM**: reconstruction error exceeds p95 threshold AND baseline deviation > 3%.

### 6.5 Model Persistence

Models are saved to a Docker volume at `/data/`:
- `/data/model.pkl` — Isolation Forest
- `/data/lstm_model.keras` + `/data/scaler.pkl` + `/data/scaler.pkl.threshold` — General LSTM
- `/data/replay_lstm.keras` + `/data/replay_scaler.pkl` + `/data/replay_scaler.pkl.threshold` — Replay LSTM

On startup, all three models are loaded from disk if present. Retraining is triggered only when model files are absent. If the IF model is present but LSTM files are missing, the engine retrains only the LSTMs on current live data (fast-path retrain).

### 6.6 REST API (host port 8001, container port 8000)

| Method | Endpoint | Description |
|---|---|---|
| GET | `/health` | `{status, session_id, model_ready, lstm_ready, replay_lstm_ready, in_warmup, in_grace, uptime_seconds}` |
| GET | `/alerts` | Recent anomaly alerts (in-memory, newest first). Params: `limit`, `alert_type` |
| GET | `/metrics` | `{anomaly_score, lstm_error, replay_lstm_error, ewma_pressure, cusum_pos, cusum_neg, last_anomaly}` |
| POST | `/reset-model` | Delete all model files → full retrain on next cycle |

```bash
curl http://localhost:8001/health
curl "http://localhost:8001/alerts?limit=20&alert_type=SEMANTIC_INJECTION"
curl http://localhost:8001/metrics
curl -X POST http://localhost:8001/reset-model
```

---

## 7. Level-3 REST APIs

### 7.1 Historian API (host port 5001)

**Container:** `ics_historian_api` — FastAPI service on `monitor-net` + `enterprise-net`.

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/health` | Service health + ML engine health proxied |
| GET | `/api/alerts` | Paginated alerts from InfluxDB. Params: `lookback`, `limit`, `alert_type`, `source` |
| GET | `/api/metrics` | Physical telemetry snapshot + ML engine metrics |
| GET | `/api/summary` | High-level dashboard: alert counts by type, latest alert, ML status |
| POST | `/api/external-event` | Push an event from a Level-3 IDS into InfluxDB |

```bash
curl http://localhost:5001/api/health
curl http://localhost:5001/api/alerts
curl "http://localhost:5001/api/alerts?alert_type=STEALTH_DRIFT_EWMA&lookback=-6h"
curl http://localhost:5001/api/summary

# Push an external IDS event:
curl -X POST http://localhost:5001/api/external-event \
  -H 'Content-Type: application/json' \
  -d '{"event_type":"IDS_ALERT","source":"snort","detail":"SYN flood on 502","severity":"HIGH"}'
```

### 7.2 Honeypot Historian API (host port 5002)

**Container:** `honeypot_historian_api` — Deception copy on `dmz-net` + `monitor-net`. Returns structurally valid but subtly corrupted telemetry. Designed to fingerprint adversaries. No authentication required (deception by design). All accesses logged to InfluxDB as `API_ACCESS` events tagged with the attacker's source IP.

Credentials harvested from `cat /var/log/scada_maintenance.log` on the SCADA SSH workstation point to this API (`engineer/engineer456`).

```bash
# Adversary accesses (all logged):
curl http://localhost:5002/api/health
curl http://localhost:5002/api/metrics    # returns corrupted data
```

---

## 8. HMI Dashboard

**File:** `hmi/hmi_app.py` — Access at `http://localhost:8060`

A Plotly Dash web application simulating a Purdue Level-2 SCADA operator console:

- **Live gauges:** Pressure (PSI), Flow Rate (L/s), Temperature (°C), Pump RPM.
- **Historical chart:** Rolling 60-point time-series of pressure and flow with area fill.
- **Controls:**
  - Pump RPM slider (0–3000) — writes to Modbus HR 200 on change.
  - Valve toggle button — writes to Modbus HR 202 (0/1).
- **Access logging:** Every page access is written to `hmi_access` in InfluxDB.

---

## 9. Grafana Monitoring

**URL:** `http://localhost:3000` (admin/admin, anonymous Viewer access enabled)

Two auto-provisioned dashboards (from `grafana_dashboards/`). Dashboard refresh: **5 seconds**. All stat panels use `lastNotNull` reducer.

### Main Dashboard — "ICS Honeypot — Full Monitoring"

| Panel | Type | Source |
|---|---|---|
| Pressure (PSI) | Time series | `pipeline_metrics.pressure` (attacker source = red series) |
| Flow Rate (L/s) | Time series | `pipeline_metrics.flow_rate` |
| Temperature (°C) | Time series | `pipeline_metrics.temperature` |
| Pump RPM | Time series | `pipeline_metrics.pump_rpm` |
| ML Anomaly Status | Stat (0=NORMAL/green, 1=ANOMALY/red) | `security_metrics.is_anomaly` |
| Anomaly Score Timeline | Time series | `security_metrics` (IF score + LSTM error) |
| Cross-Layer Correlation | Time series | `correlation_logs` (write freq vs. pressure) |
| Replay Attack Delta | Time series | `security_alerts.delta` |
| Semantic Injection / Replay / DNP3 / S7 Results | Stat | `security_alerts` |
| Protocol Honeypot Events | Table (50 rows) | `honeypot_events` |
| SSH Attempts (transient) | Stat (10 s look-back) | `terminal_commands` (`AUTH_ATTEMPT`/`LATERAL_MOVEMENT`) |
| API Recon Probes (transient) | Stat (10 s look-back) | `terminal_commands` (`API_ACCESS`) |
| Modbus Writes (transient) | Stat (10 s look-back) | `terminal_commands` (`MODBUS_WRITE`) |
| Modbus Reads / Cred Discovery (transient) | Stat (10 s look-back) | `terminal_commands` (`MODBUS_READ`/`CREDENTIAL_DISCOVERY`) |

**Session deduplication:** All Flux queries include `|> group(columns: ["_measurement", "_field"])` before aggregation. Without this, a container restart creates a new `session_id` tag that InfluxDB treats as a distinct time series, appearing as a duplicate line in Grafana.

### MITRE ATT&CK ICS Dashboard — `mitre_attack_ics.json`
- **Attack Story** table: unions `narrative` fields from `security_alerts`, `terminal_commands`, and `honeypot_events` — full cross-layer kill-chain narrative.
- Heatmaps by protocol, MITRE tactic, kill-chain stage, and Purdue level.

---

## 10. Deployment

### Prerequisites

- Docker Engine ≥ 24.0 with Docker Compose v2
- Minimum **8 GB RAM**, 4 CPU cores, 20 GB free disk
- External bridge network (one-time setup):
  ```bash
  docker network create l2l3-bridge-net --subnet 172.28.0.0/24
  ```

### Commands

```bash
# First boot — build all images and start
docker compose up --build -d

# Subsequent starts (no code changes)
docker compose up -d

# Follow live logs from all services
docker compose logs -f

# Single service logs
docker compose logs -f ml_engine
docker compose logs -f physics_simulator
docker compose logs -f plc_simulator

# Stop (preserve data volumes)
docker compose down

# Full reset — wipe all stored telemetry and model files
docker compose down -v
```

> **Note:** Use `docker compose` (v2, no hyphen). The Compose file has no `version:` key (v2 standard).

### Access Points

| Service | URL | Notes |
|---|---|---|
| HMI Dashboard | http://localhost:8060 | Operator SCADA console |
| Grafana | http://localhost:3000 | admin / admin |
| InfluxDB UI | http://localhost:8086 | admin / password123 |
| ML Engine API | http://localhost:8001/health | FastAPI docs: `/docs` |
| Historian API | http://localhost:5001/api/health | Level-3 integration |
| Honeypot Historian API | http://localhost:5002/api/health | Deception (corrupted data) |
| Log Dashboard | http://localhost:8502 | Streamlit narrative viewer |
| Story Logger | http://localhost:8600 | HTTP JSONL endpoint |
| Modbus PLC | localhost:502 | pymodbus / mbpoll / nmap |
| Fake PLC | localhost:503 | Dead-end decoy |
| S7comm PLC | localhost:102 | s7comm_probe.py / nmap |
| DNP3 Outstation | localhost:20000 | dnp3_probe.py |
| SCADA SSH | localhost:2222 | operator/operator123 or engineer/engineer456 |

### InfluxDB Credentials

| Parameter | Value |
|---|---|
| Organization | `my_refinery` |
| Bucket | `sensor_logs` |
| API Token | `supersecrettoken` |
| Admin login | admin / password123 |

---

## 11. Attack Scenarios — 7-Phase Cyber Kill Chain

The primary attack script is `attack_suite.py`, a 7-phase Cyber Kill Chain run from the `attacker_node` container.

```bash
# Open an interactive shell into the attacker container
docker exec -it attacker_node bash

# Run the full 7-phase kill chain
python3 attack_suite.py

# Run a specific phase only
python3 attack_suite.py --phase 4

# Override target host
python3 attack_suite.py --target plc_simulator
```

| Phase | Name | Technique | Expected Detection |
|---|---|---|---|
| 1 | **Reconnaissance** | TCP connect scan (nmap -sT -n) on ports 502, 102, 20000 | `auth_attempts` + `honeypot_events` logged; **no anomaly** (correct low-FPR behaviour) |
| 2 | **Information Gathering** | Modbus FC3 read of registers 100–103, 200–202; S7 banner grab (COTP CC) | Reads logged; no anomaly |
| 3 | **Vulnerability Scan** | Probe FC3/FC6/FC16 support; DNP3 RESET_LINK_STATES; full S7 Setup handshake | Fingerprinted in `honeypot_events` |
| 4 | **Exploit (Semantic Injection)** | Modbus FC6 write of 350 PSI to register 100 (sensor) | `forced_writes` → `SEMANTIC_INJECTION` in < 15 s |
| 5 | **Payload Delivery (Stealth Drift)** | 9 × 3 PSI increments every 5 s (45 s total) | CUSUM fires `STEALTH_DRIFT_EWMA` after ~45 s |
| 6 | **Lateral Movement** | Pivot: Modbus → S7comm → DNP3 (all three handshakes) | `honeypot_events` + MITRE T0867 tagged |
| 7 | **Privilege Escalation** | Write max RPM (3000) to HR 200; close valve (HR 202=0); restore | `modbus_events` FC6 writes; IF+LSTM fire on pressure spike; `OVER_PRESSURE` expert rule |

---

## 12. Manual Attack Commands

All commands can be run from the `attacker_node` bash shell:
```bash
docker exec -it attacker_node bash
```

### 12.1 Reconnaissance (Phase 1)

```bash
# Fast TCP connect scan (no DNS)
nmap -sT -n -p 502,102,20000 --open -T4 plc_simulator ics_s7_plc ics_dnp3

# S7comm fingerprinting
nmap --script s7-info -p 102 ics_s7_plc

# Modbus device enumeration
nmap --script modbus-discover -p 502 plc_simulator
```

### 12.2 Information Gathering (Phase 2)

```bash
python3 -c "
from pymodbus.client import ModbusTcpClient
c = ModbusTcpClient('plc_simulator', port=502)
c.connect()
r = c.read_holding_registers(100, 4, slave=1)
print(f'Pressure: {r.registers[0]} PSI')
print(f'Flow:     {r.registers[1]/10.0:.1f} L/s')
print(f'Temp:     {r.registers[2]} °C')
print(f'RPM:      {r.registers[3]}')
c.close()
"
```

### 12.3 Semantic Injection (Phase 4)

```bash
# Inject 350 PSI to pressure sensor register (triggers SEMANTIC_INJECTION in < 15 s)
python3 -c "
from pymodbus.client import ModbusTcpClient
c = ModbusTcpClient('plc_simulator', port=502)
c.connect()
c.write_register(100, value=350, slave=1)
print('Injected 350 PSI to register 100')
c.close()
"
```

### 12.4 Stealth Drift (Phase 5)

```bash
python3 -c "
from pymodbus.client import ModbusTcpClient; import time
c = ModbusTcpClient('plc_simulator', port=502)
c.connect()
r = c.read_holding_registers(100, 1, slave=1)
base = r.registers[0]
print(f'Base pressure: {base} PSI')
for step in range(9):
    new_val = base + (step + 1) * 3
    c.write_register(100, value=new_val, slave=1)
    print(f'Step {step+1}/9: pressure → {new_val} PSI')
    time.sleep(5)
print('Attack complete. Watch CUSUM fire STEALTH_DRIFT_EWMA in Grafana.')
c.close()
"
```

### 12.5 Privilege Escalation (Phase 7)

```bash
# Force pump to maximum RPM → physics engine spikes pressure
python3 -c "
from pymodbus.client import ModbusTcpClient
c = ModbusTcpClient('plc_simulator', port=502)
c.connect()
c.write_register(200, value=3000, slave=1)
print('Overclocked Pump to 3000 RPM')
c.close()
"

# Close the valve → physics engine clamps flow_rate to 0.0
python3 -c "
from pymodbus.client import ModbusTcpClient
c = ModbusTcpClient('plc_simulator', port=502)
c.connect()
c.write_register(202, value=0, slave=1)
print('Valve closed (0)')
c.close()
"
```

### 12.6 S7comm Probe (raw socket)

```python
import socket

# TPKT + COTP Connection Request (standard S7 handshake)
cotp_cr = bytes([
    0x03, 0x00, 0x00, 0x16,        # TPKT header (length=22)
    0x11, 0xe0,                     # COTP CR
    0x00, 0x00, 0x00, 0x01, 0x00,  # dst/src ref, class
    0xc1, 0x02, 0x01, 0x00,        # source TSAP
    0xc2, 0x02, 0x01, 0x02,        # destination TSAP
    0xc0, 0x01, 0x09,              # TPDU size = 512
])

s = socket.socket()
s.connect(('ics_s7_plc', 102))
s.sendall(cotp_cr)
resp = s.recv(256)
print(f'S7 Response ({len(resp)} bytes): {resp.hex()}')
s.close()
```

### 12.7 DNP3 Probe (raw socket)

```python
import socket, struct

def dnp3_crc(data):
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
        table.append(crc)
    crc = 0
    for b in data:
        crc = table[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return (~crc) & 0xFFFF

# DNP3 link-layer Reset Link States frame
frame = bytes([0x05, 0x64, 0x05, 0x40, 0x01, 0x00, 0x03, 0x00])
frame += struct.pack('<H', dnp3_crc(frame))

s = socket.socket()
s.connect(('ics_dnp3', 20000))
s.sendall(frame)
print(f'DNP3 Response: {s.recv(256).hex()}')
s.close()
```

---

## 13. Evaluation Metrics

**File:** `evaluate.py`

```bash
# Run inside the project root (uses InfluxDB data)
python evaluate.py
```

### Quantitative Results (from `evaluation_report.txt`)

Dataset: 519 samples at 1 Hz (27 attack, 492 normal).

| Model | Precision | Recall | F1-Score |
|---|---|---|---|
| Isolation Forest | 0.0652 | 0.4444 | 0.1137 |
| LSTM Autoencoder | 0.1698 | 1.0000 | 0.2903 |
| **Ensemble (OR-gate)** | **0.1011** | **1.0000** | **0.1837** |

**Phase Detection Audit:**

| Phase | IF | LSTM | Ensemble |
|---|---|---|---|
| Phase 4 (Semantic Injection) | MISSED | MISSED | MISSED* |
| Phase 5 (Stealth Drift) | DETECTED | DETECTED | DETECTED |
| Phase 7 (Actuator Manipulation) | DETECTED | DETECTED | DETECTED |
| Phase 8 (Replay Attack) | MISSED | DETECTED | DETECTED |

> *Phase 4 is caught by the rule-based `SEMANTIC_INJECTION` detector (queries `forced_writes` measurement), which is separate from the ML model scoring evaluated here. The Grafana `security_alerts` panel confirms correct detection.

### Evaluation Metric Definitions

| Metric | Formula | Interpretation |
|---|---|---|
| **Precision** | Correct alerts / Total alerts × 100 | How accurate are the alerts? |
| **Recall (TPR)** | Detected phases / Total attack phases × 100 | How many attacks were caught? |
| **F1-Score** | 2 × P × R / (P + R) | Harmonic mean of precision and recall |
| **Detection Latency** | Mean time: attack start → first alert (s) | System response speed |
| **Attacker Dwell Time** | Last attack event − First attack event (s) | Campaign duration |

---

## 14. Demo Sequence for Exhibition

### Step 1 — Show Normal Operations (2 min)

1. Open **Grafana** at `http://localhost:3000`.
2. Navigate to *"ICS Honeypot — Full Monitoring"* dashboard.
3. Point out: stable pressure ~60 PSI, consistent flow ~12 L/s, temperature rising slowly.
4. Open **HMI** at `http://localhost:8060`.
5. Move the **Pump RPM slider** — show pressure and flow updating in both HMI and Grafana within 5 seconds.

### Step 2 — Reconnaissance (1 min)

```bash
docker exec -it attacker_node nmap -sT -n -p 502,102,20000 plc_simulator
```

6. Switch to Grafana → **Protocol Honeypot Events** table panel.
7. Show `auth_attempts` entries appearing.
8. **Key point:** ML Anomaly Status stays NORMAL — reconnaissance is logged but not alarmed (demonstrates correct low-FPR behaviour).

### Step 3 — Semantic Injection (2 min)

```bash
docker exec -it attacker_node python3 -c "
from pymodbus.client import ModbusTcpClient
c = ModbusTcpClient('plc_simulator', port=502); c.connect()
c.write_register(100, value=350, slave=1)
print('Injected 350 PSI'); c.close()
"
```

9. Watch the **Pressure gauge in Grafana** spike to 350 PSI (red attacker series).
10. In Grafana, **ML Anomaly Status** flips from NORMAL → **ANOMALY**.
11. Show the `security_alerts` row in InfluxDB Explorer with `alert_type=SEMANTIC_INJECTION`.

### Step 4 — Stealth Drift (3 min)

Run the stealth drift command from Section 12.4.

12. Each step is only 3 PSI — individually invisible to any fixed alarm.
13. In Grafana, the pressure graph shows a slow, gradual slope upward.
14. After ~45 s, `STEALTH_DRIFT_EWMA` appears in the `security_alerts` panel.
15. **Key point:** *"Standard threshold alarms miss this completely. CUSUM accumulates 9 small deviations and fires when cumulative evidence exceeds the threshold — this is the novel EWMA/CUSUM contribution."*

### Step 5 — Lateral Movement (1 min)

```bash
docker exec -it attacker_node python3 attack_suite.py --phase 6
```

16. Show `honeypot_events` table: S7comm + DNP3 entries appearing with MITRE tags.
17. Navigate to **MITRE ATT&CK ICS Dashboard** → Attack Story panel: cross-layer narrative.

### Step 6 — Evaluation Results (1 min)

```bash
python evaluate.py
```

18. Show Precision, Recall, F1-Score, and per-phase detection results.
19. *"Ensemble OR-gate achieves 100% recall — every attack phase was caught by at least one model or rule."*

---

## 15. File Structure

```
Honeypot/
├── docker-compose.yml              Full service orchestration (no version: key)
├── .env                            Secrets and config (git-ignored)
├── attack_suite.py                 7-phase Cyber Kill Chain attack script
├── attack_simulation.py            Legacy 6-scenario script (backwards compat)
├── evaluate.py                     Evaluation metric calculator
├── evaluation_report.txt           Latest evaluation results (text)
├── general logs.jsonl              Unified JSONL narrative audit trail
├── THESIS_DOCUMENTATION.md         Full technical thesis documentation
├── DEPLOYMENT_GUIDE.md             Deployment and booth testing guide
│
├── physics/
│   ├── physics_engine.py           PipelineSimulator class (Redis-backed state)
│   └── physics_process.py          Physics update service (1 s loop)
│
├── plc/
│   ├── Dockerfile                  Shared image for all PLC + physics services
│   ├── modbus_server.py            Modbus/TCP honeypot (pymodbus, port 502)
│   ├── s7_server.py                S7comm honeypot (python-snap7, port 102)
│   └── dnp3_server.py              DNP3 honeypot (raw socket, port 20000)
│
├── fake_plc/
│   └── ...                         Dead-end Modbus decoy (port 503)
│
├── hmi/
│   ├── hmi_app.py                  Plotly Dash SCADA HMI (port 8060)
│   └── hmi_simulator.py            Historian bridge: Modbus → InfluxDB (~2 Hz)
│
├── ml-engine/
│   ├── Dockerfile                  Includes tensorflow + fastapi + uvicorn
│   └── trainer.py                  IF + 2×LSTM + EWMA/CUSUM engine + FastAPI :8001 (v5)
│
├── historian_api/
│   └── app.py                      FastAPI REST API — Level-3 bridge (port 5001)
│
├── honeypot_historian_api/
│   └── ...                         Deception API — DMZ-facing decoy (port 5002)
│
├── scada_ssh/
│   ├── Dockerfile                  SSH server + physics REST API
│   ├── log_scada_cmd.py            PROMPT_COMMAND hook → InfluxDB + Story Logger
│   └── ...                         iptables rules, profile hooks
│
├── attacker_node/
│   ├── Dockerfile                  Debian slim + nmap + pymodbus + scapy
│   ├── attack_suite.py             7-phase kill chain (symlinked from root)
│   ├── s7comm_probe.py             Raw COTP+S7 handshake probe
│   └── dnp3_probe.py               DNP3 link-layer probe
│
├── logger/
│   ├── correlator.py               Cross-layer Modbus correlation logger
│   └── logger.py                   Network packet sniffer (host mode)
│
├── log_dashboard/
│   └── ...                         Streamlit log viewer (port 8502)
│
├── shared/
│   └── mitre_mapping.py            MITRE ATT&CK for ICS technique mapping (single source of truth)
│
├── scripts/
│   └── export_results.py           Legacy evaluation metric calculator
│
├── grafana_dashboards/
│   ├── dashboard.json              Main ICS monitoring dashboard
│   └── mitre_attack_ics.json       MITRE ATT&CK ICS heatmap dashboard
│
├── grafana_provisioning/
│   ├── datasources/                InfluxDB datasource auto-config
│   └── dashboards/                 Dashboard provisioning config
│
└── results/                        Persisted CSV evaluation results (Docker volume)
```

---

## 16. Key Design Decisions

| Decision | Rationale |
|---|---|
| **Redis for shared physics state** | Allows Modbus, S7, and HMI to read a single consistent physics snapshot without each running an independent simulation loop, preventing state drift between protocols. |
| **Three-model ML ensemble (IF + 2× LSTM)** | IF handles point-in-time outliers; General LSTM handles temporal pattern breaks; Replay LSTM specifically targets variance-collapse signatures of frozen/replayed telemetry. No single model catches all attack types. |
| **OR-gate ensemble** | Missed attacks (false negatives) carry higher operational risk in ICS than false alarms, which operators can acknowledge without process interruption. |
| **120-second startup grace period** | Physics engine needs ~60 s to converge from initial conditions. Grace period suppresses all detectors during this transient, giving zero startup false positives. |
| **CUSUM for stealth drift** | Phase 5 increments pressure by only 3 PSI every 5 s. Each step is individually below any threshold. CUSUM accumulates 9 steps and fires on the cumulative evidence — the only detection layer designed for this. |
| **LSTM 3-confirmation window** | A single anomalous LSTM window may result from sensor noise. Requiring 3 consecutive anomalous windows filters transient spikes, reducing FPR significantly. |
| **Closed-valve physics clamp** | When valve_pos == 0, flow_rate is clamped to exactly 0.0. Prevents non-physical flow readings during Phase 7 sabotage and ensures physics consistency. |
| **`session_id` tagging** | All InfluxDB writes include a session UUID prefix, enabling post-attack forensic reconstruction of the full attacker timeline across all protocols across container restarts. |
| **`group()` in all Grafana queries** | Without grouping, InfluxDB returns one time series per unique tag combination. A new `session_id` on restart creates a new series, appearing as a duplicate line in Grafana. |
| **Deception Historian API (port 5002)** | DMZ-facing API returns corrupted telemetry when `is_anomaly==1` is active, confusing adversary situational awareness while logging all their queries for analysis. |
| **MITRE ATT&CK enrichment on every event** | `shared/mitre_mapping.py` is the single source of truth. Every InfluxDB write and Story Logger record carries `mitre_technique_id`, `mitre_tactic`, `kill_chain_stage`, and `purdue_level` — enabling the MITRE ICS dashboard heatmaps and cross-layer kill-chain narrative. |
| **`network_mode: host` for sniffer** | Raw packet capture requires host-mode networking. The correlator uses `network_mode: service:plc_simulator` to share the Modbus PLC's network namespace — the minimal footprint needed for packet inspection without full host access. |
| **Five-network Purdue topology** | `ot-net`, `dmz-net`, `monitor-net`, `enterprise-net`, `l2l3-bridge-net` mirror real industrial network segmentation. The ML engine and Redis are unreachable from the DMZ, demonstrating defence-in-depth. |
| **No authentication on honeypot services** | By design — a deception environment must accept all connections to maximise attacker engagement and logging fidelity. |
| **Physics-aware semantic validation** | The cross-layer correlator joins write events with the physical state at the time of the write. This enables detection of commands that are syntactically valid Modbus packets but semantically dangerous. |
