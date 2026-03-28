# ICS Honeypot – Physics-Aware Industrial Control System Deception Environment

> **Bachelor Thesis Implementation**
> Emulating Purdue Model Level 0–3.5 with Modbus/TCP, S7comm, and DNP3 protocols,
> cross-layer anomaly detection, and ML-based attacker profiling.

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Architecture](#2-architecture)
3. [Physical Process Simulation](#3-physical-process-simulation)
4. [Protocol Honeypots](#4-protocol-honeypots)
5. [Logging Schema](#5-logging-schema)
6. [ML Anomaly Detection Engine](#6-ml-anomaly-detection-engine)
7. [HMI Dashboard](#7-hmi-dashboard)
8. [Grafana Monitoring](#8-grafana-monitoring)
9. [Deployment](#9-deployment)
10. [Attack Scenarios and Exhibition Guide](#10-attack-scenarios-and-exhibition-guide)
11. [Evaluation Metrics](#11-evaluation-metrics)
12. [Demo Sequence for Exhibition](#12-demo-sequence-for-exhibition)
13. [File Structure](#13-file-structure)
14. [Key Design Decisions](#14-key-design-decisions)

---

## 1. System Overview

This project implements a **high-interaction ICS honeypot** modelled after the Purdue Reference Architecture. The system:

- Emulates a **pressure-regulated oil pipeline** with realistic physics (pressure, flow rate, temperature, viscosity, pump RPM).
- Exposes three industrial protocols: **Modbus/TCP**, **Siemens S7comm**, and **DNP3**.
- Applies **cross-layer anomaly detection** correlating network-level commands with physical process state.
- Uses an **Isolation Forest** ML model supplemented by expert rules and an **EWMA/CUSUM** stealth drift detector.
- Logs every attacker interaction to **InfluxDB** and visualises everything in **Grafana**.

The honeypot is entirely containerised with Docker Compose and requires no special hardware.

---

## 2. Architecture

### 2.1 Network Segmentation

Three Docker bridge networks emulate the Purdue Model DMZ principle:

| Network | Docker Name | Connected Services | Purdue Level |
|---|---|---|---|
| DMZ / Attacker-Facing | `dmz-net` | `plc_simulator`, `ics_s7_plc`, `ics_dnp3`, `correlator` | L3.5 |
| OT / Process Network | `ot-net` | `plc_simulator`, `ics_s7_plc`, `hmi`, `historian_bridge`, `redis`, `physics_simulator` | L1–L2 |
| Monitoring / Secure | `monitor-net` | `ml_engine`, `historian` (InfluxDB), `grafana`, `correlator` | L3 passive |

An attacker entering via `dmz-net` can reach the PLCs but **cannot** directly reach InfluxDB or Grafana, which are isolated on `monitor-net`. This mirrors a real corporate DMZ and prevents the attacker from tampering with the audit trail.

### 2.2 Service Map

```
ATTACKER ──► plc_simulator  (Modbus  :502)   [dmz-net]
         ──► ics_s7_plc     (S7comm  :102)   [dmz-net]
         ──► ics_dnp3       (DNP3  :20000)   [dmz-net]

                   │ (ot-net)
         physics_simulator  ◄── updates Redis every 1 s
         redis              ◄── shared process state store
         hmi (:8060)        ◄── reads Modbus, exposes operator controls
         historian_bridge   ◄── reads Modbus, writes InfluxDB every 5 s

                   │ (monitor-net — passive observer only)
         ml_engine          ◄── reads InfluxDB, writes anomaly alerts
         historian (:8086)  ◄── InfluxDB v2 data store
         grafana   (:3000)  ◄── real-time dashboards
```

---

## 3. Physical Process Simulation

**Files:** `physics/physics_engine.py`, `physics/physics_process.py`

The `PipelineSimulator` class models an oil refinery pipeline. State is persisted in **Redis** so that Modbus, S7, and HMI all read from one consistent snapshot. The `physics_process.py` service runs the update loop every 1 second.

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
```

**Startup conditions:** 1200 RPM, valve 50% open → ~60 PSI, ~12 L/s, 18.5 °C.

---

## 4. Protocol Honeypots

### 4.1 Modbus/TCP (Port 502)

**File:** `plc/modbus_server.py`

Uses `pymodbus`. The `PhysicsAwareDataBlock` overrides both `getValues` (reads) and `setValues` (writes):

- **Read (FC3/FC4):** Loads the latest Redis state into registers 100–103 and serves the values. Logs a `modbus_events` record with `fc_type=read`.
- **Write (FC6/FC16):** Applies the register change to the physics engine (HR200 = pump RPM, HR201 = valve position, HR202 = valve on/off). Logs `modbus_events` with `fc_type=write`.
- **Write to sensor registers (100–103):** Additionally logs a `forced_writes` record, which the ML engine treats as a **Semantic Injection** event.

**Actuation registers (writable):**

| Register | Effect |
|---|---|
| HR 200 | Set pump RPM (0–3000) |
| HR 201 | Set valve position (0–1000 mapped to 0.0–1.0) |
| HR 202 | Valve on/off toggle (0 or 1) |

### 4.2 S7comm / ISO-on-TCP (Port 102)

**File:** `plc/s7_server.py`

Uses `python-snap7` to emulate a **Siemens S7-300** PLC. DB1 contains the four physical variables as IEEE-754 REAL values, updated from Redis every second. Every TCP connection and disconnection logs to `auth_attempts` and `honeypot_events`.

The S7 server presents `ProductName = 'SIMATIC S7-300 Modbus Gateway'` as a convincing decoy identity to enumerating attackers.

### 4.3 DNP3 (Port 20000)

**File:** `plc/dnp3_server.py`

Implements a minimal DNP3 link-layer outstation:

- Parses start bytes `0x05 0x64` and link-layer header.
- Responds with a valid ACK frame using DNP3 CRC-16.
- Logs raw frame hex, source/destination addresses to `honeypot_events`.
- Every TCP connection logs to `auth_attempts`.

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
| `security_metrics` | `session_id`, `sensor` | `anomaly_score`, `is_anomaly` | `ml_engine` |
| `security_alerts` | `session_id`, `alert_type` | `detail`, `score` | `ml_engine` |
| `attack_results` | `attack_type` | `success`, `detail` | `attack_simulation.py` |

---

## 6. ML Anomaly Detection Engine

**File:** `ml-engine/trainer.py`

### 6.1 Detection Layers

The engine runs three independent detection layers simultaneously, every 10 seconds:

**Layer 1 — Isolation Forest** (statistical, post-warmup):
- Warmup: 180 seconds of baseline telemetry, minimum 30 samples.
- Feature vector (10 dimensions): `pressure`, `flow_rate`, `temperature`, `pressure_delta`, `pressure_mean_dev`, `inter_arrival_time`, `write_freq_10s`, `is_write`, `func_code`, `length`.
- Contamination factor: 5%. Scores below −0.5 are flagged as anomalous.

**Layer 2 — Expert Rules** (immediate, no warmup):
- `CROSS_LAYER_ANOMALY`: Large pressure jump (`|Δp| > 5 PSI`) with zero write commands in the last 10 s — physics change without a command.
- `STEALTH_DRIFT`: Sustained deviation > 15 PSI from the 10-sample rolling mean.
- `SEMANTIC_INJECTION`: Pressure value > 200 PSI (above maximum safe operating limit).

**Layer 3 — EWMA/CUSUM Drift Detector** (always running):
- See Section 6.2 below.

**Layer 4 — Forced Write Check** (immediate):
- Queries `forced_writes` every 10 seconds.
- Any direct write to sensor registers (HR 100–103) triggers `SEMANTIC_INJECTION`.

### 6.2 EWMA / CUSUM Drift Detector

Designed specifically to detect **slow, gradual setpoint manipulation** that evades fixed-threshold detection.

**Exponentially Weighted Moving Average (EWMA):**

```
EWMA_t = λ × x_t + (1 − λ) × EWMA_{t−1}
λ = 0.1   (slow response — accumulates evidence over minutes)
```

**Cumulative Sum (CUSUM), two-sided:**

```
C+_t = max(0, C+_{t−1} + (x_t − EWMA_t) − k)
C−_t = max(0, C−_{t−1} − (x_t − EWMA_t) − k)
k = 2.0 PSI   (allowance / slack, ignores micro-fluctuations)
h = 25.0      (alert threshold)
```

Alert fires when `C+_t > h` or `C−_t > h`. Accumulators reset after each alert.

**Why this matters:** The `ewma_stealth_drift` attack increments pump RPM by only 50 every 3 seconds over 15 steps. Each step is individually invisible (≈ 3–4 PSI change). CUSUM accumulates all 15 steps and fires after sustained drift — the only layer designed to catch this.

---

## 7. HMI Dashboard

**File:** `hmi/hmi_app.py` — Access at `http://localhost:8060`

A Plotly Dash web application simulating a Purdue Level 2 SCADA operator console:

- **Live gauges:** Pressure (PSI), Flow Rate (L/s), Temperature (°C), Pump RPM.
- **Historical chart:** Rolling 60-point time-series of pressure and flow with area fill.
- **Controls:**
  - Pump RPM slider (0–3000) — writes to Modbus HR 200 on change.
  - Valve toggle button — writes to Modbus HR 202 (0/1).
- **Access logging:** Every page access (URL path, source IP, HTTP status) is written to `hmi_access` in InfluxDB via a Flask `before_request` hook.

---

## 8. Grafana Monitoring

**URL:** `http://localhost:3000` (admin/admin, anonymous Viewer access enabled)

**Dashboard:** "ICS Honeypot — Full Monitoring"

| Panel | Type | Source |
|---|---|---|
| Pressure (PSI) | Time series | `pipeline_metrics.pressure` |
| Flow Rate (L/s) | Time series | `pipeline_metrics.flow_rate` |
| Temperature (°C) | Time series | `pipeline_metrics.temperature` |
| Pump RPM | Time series | `pipeline_metrics.pump_rpm` |
| ML Anomaly Status | Stat (0 = NORMAL, 1 = ANOMALY) | `security_metrics.is_anomaly` |
| Anomaly Score Timeline | Time series | `security_metrics.is_anomaly` |
| Cross-Layer Correlation | Time series | `correlation_logs` |
| Replay Attack Delta | Time series | `security_alerts.delta` |
| Semantic Injection / Replay / DNP3 / S7 Results | Stat | `attack_results` |
| Protocol Honeypot Events | Table | `honeypot_events` |

**Note on session deduplication:** All Flux queries include `|> group(columns: ["_measurement", "_field"])` before aggregation. Without this, restarting any service creates a new `session_id` tag, which InfluxDB treats as a distinct time series — resulting in duplicate lines in Grafana. Grouping collapses all sessions into a single series per metric.

---

## 9. Deployment

### Prerequisites

- Docker Desktop (Windows/Mac) or Docker Engine + Compose (Linux)

### Commands

```powershell
# First boot — build all images and start
docker-compose up --build -d

# Subsequent starts (no code changes)
docker-compose up -d

# Follow live logs from all services
docker-compose logs -f

# Single service logs
docker-compose logs -f ml_engine
docker-compose logs -f physics_simulator
docker-compose logs -f plc_simulator

# Stop (preserve data volumes)
docker-compose down

# Full reset — wipe all stored telemetry
docker-compose down -v
```

### Access Points

| Service | URL |
|---|---|
| HMI Dashboard | http://localhost:8060 |
| Grafana | http://localhost:3000 |
| InfluxDB UI | http://localhost:8086 |
| Modbus PLC | localhost:502 |
| S7comm PLC | localhost:102 |
| DNP3 Outstation | localhost:20000 |

### InfluxDB Credentials

| Parameter | Value |
|---|---|
| Organization | `my_refinery` |
| Bucket | `sensor_logs` |
| API Token | `supersecrettoken` |
| Admin login | admin / password123 |

---

## 10. Attack Scenarios and Exhibition Guide

### 10.1 Built-in Attack Script

Run from the **host machine** (not inside Docker):

```powershell
pip install pymodbus requests influxdb-client
python attack_simulation.py
```

| # | Attack Name | Technique | Expected Detection |
|---|---|---|---|
| 1 | **Semantic Injection** | Modbus FC6: write HR100 = 5000 PSI | `forced_writes` → `SEMANTIC_INJECTION` alert |
| 2 | **Historian Replay** | HTTP POST fake telemetry directly to InfluxDB | Replay detector in `hmi_simulator` |
| 3 | **DNP3 Probe** | Raw link-layer frame to port 20000 | `honeypot_events` + `auth_attempts` logged |
| 4 | **S7comm Probe** | Raw COTP Connection Request to port 102 | `honeypot_events` + `auth_attempts` logged |
| 5 | **Reconnaissance Only** | Modbus FC3 read scan (read HR 100–103, no writes) | Logged but **no anomaly** (correct FPR behaviour) |
| 6 | **EWMA Stealth Drift** | 15 × RPM increment, +50 RPM every 3 s | CUSUM fires after ~45 s of cumulative drift |

---

### 10.2 nmap Reconnaissance (Run from host)

```bash
# Service and version discovery across all three honeypot ports
nmap -sV -p 502,102,20000 localhost

# S7comm fingerprinting (Nmap NSE script)
nmap --script s7-info -p 102 localhost

# Modbus device enumeration
nmap --script modbus-discover -p 502 localhost

# Aggressive OS + version + script scan on all ports
nmap -A -p 502,102,20000 localhost
```

Each nmap probe generates entries in `auth_attempts` and `honeypot_events` — visible immediately in the Grafana Protocol Events table.

---

### 10.3 Manual Modbus Attacks

Using **`mbpoll`** (Linux/WSL):

```bash
# Read current process state (reconnaissance, no anomaly)
mbpoll -1 -r 100 -c 4 localhost -p 502

# Write dangerous pressure value (semantic injection)
mbpoll -1 -r 100 -0 -1 5000 localhost -p 502

# Slow pump-down (setpoint manipulation)
mbpoll -1 -r 200 -0 -1 500 localhost -p 502
```

Using **Python** (no extra tools):

```python
from pymodbus.client import ModbusTcpClient

c = ModbusTcpClient('localhost', port=502)
c.connect()

# Read current state
r = c.read_holding_registers(100, 4)
print(f"Pressure: {r.registers[0]} PSI")
print(f"Flow:     {r.registers[1]/10} L/s")
print(f"Temp:     {r.registers[2]} C")
print(f"RPM:      {r.registers[3]}")

# Semantic injection — spike pressure to 5000 PSI
c.write_register(100, 5000)

# Pump override — set RPM to 0 (process shutdown)
c.write_register(200, 0)

c.close()
```

Using **Metasploit**:

```
use auxiliary/scanner/scada/modbusdetect
set RHOSTS localhost
run

use auxiliary/scanner/scada/modbus_findunitid
set RHOSTS localhost
run
```

---

### 10.4 DNP3 Probe (Python raw socket)

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
s.connect(('localhost', 20000))
s.sendall(frame)
print(f'DNP3 Response: {s.recv(256).hex()}')
s.close()
```

---

### 10.5 S7comm Fingerprint (Python raw socket)

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
s.connect(('localhost', 102))
s.sendall(cotp_cr)
resp = s.recv(256)
print(f'S7 Response ({len(resp)} bytes): {resp.hex()}')
s.close()
```

Or with Nmap (automated):

```bash
nmap --script s7-info -p 102 localhost
```

---

### 10.6 Manual Stealth Drift Attack

```python
import time
from pymodbus.client import ModbusTcpClient

c = ModbusTcpClient('localhost', port=502)
c.connect()
print("Starting stealth drift — 15 steps, +50 RPM every 3 s")
for i in range(15):
    rpm = 1200 + (i + 1) * 50
    c.write_register(200, rpm)
    state = c.read_holding_registers(100, 2)
    print(f"  Step {i+1:02d}: RPM={rpm}  Pressure={state.registers[0]} PSI")
    time.sleep(3)
c.close()
print("Attack complete. Watch CUSUM fire in Grafana security_alerts.")
```

---

## 11. Evaluation Metrics

**File:** `scripts/export_results.py`

```powershell
pip install influxdb-client pandas numpy
python scripts/export_results.py
```

| Metric | Formula | Interpretation |
|---|---|---|
| **TPR** (True Positive Rate) | Detected attacks / Total attacks × 100 | Overall detection effectiveness |
| **FPR** (False Positive Rate) | Anomalies during benign ops / Total samples × 100 | False alarm rate (target: < 10%) |
| **Detection Latency** | Mean time from attack start → first alert (s) | System response speed |
| **Attacker Dwell Time** | Last attack event − First attack event (s) | Campaign duration in the system |
| **Correlation Accuracy** | Valid cross-layer records / Total write records × 100 | Network-to-physics link quality |

Output is printed to the console and saved to `thesis_evaluation_summary.csv`.

---

## 12. Demo Sequence for Exhibition

### Step 1 — Show Normal Operations (2 min)

1. Open **Grafana** at `http://localhost:3000`.
2. Navigate to *"ICS Honeypot — Full Monitoring"* dashboard.
3. Point out: stable pressure ~60 PSI, consistent flow ~12 L/s, temperature rising slowly.
4. Open **HMI** at `http://localhost:8060`.
5. Move the **Pump RPM slider** — show pressure and flow updating in both HMI and Grafana within 5 seconds.

### Step 2 — Reconnaissance (2 min)

```bash
nmap -sV -p 502,102,20000 localhost
nmap --script s7-info -p 102 localhost
```

6. Switch to Grafana → **Protocol Honeypot Events** table panel.
7. Show `auth_attempts` entries appearing for S7 and DNP3.
8. **Key point:** The ML Anomaly Status stays NORMAL — reconnaissance is logged but not alarmed (demonstrates low FPR and correct classification).

### Step 3 — Semantic Injection (2 min)

```python
from pymodbus.client import ModbusTcpClient
c = ModbusTcpClient('localhost', port=502)
c.connect()
c.write_register(100, 5000)   # 5000 PSI injection
c.close()
```

9. Watch the **Pressure gauge in HMI** spike to 5000 PSI instantly.
10. In Grafana, **ML Anomaly Status** flips from NORMAL → **ANOMALY**.
11. Show the `security_alerts` row in InfluxDB Explorer with `alert_type=SEMANTIC_INJECTION`.

### Step 4 — Stealth Drift (3 min)

Run the manual stealth drift script from Section 10.6.

12. Each step is only 50 RPM — individually invisible to any fixed alarm.
13. In Grafana, the pressure graph shows a slow, gradual slope upward.
14. After ~45 s, `STEALTH_DRIFT_EWMA` appears in the `security_alerts` table.
15. **Key point:** "Standard threshold alarms miss this completely. CUSUM accumulates 15 small deviations and fires when the cumulative evidence exceeds the threshold — this is the novel contribution."

### Step 5 — Evaluation Results (1 min)

```powershell
python scripts/export_results.py
```

16. Show live TPR, FPR, Detection Latency, and Dwell Time values.
17. "These numbers will be the basis of the evaluation chapter."

---

## 13. File Structure

```
Honeypot/
├── docker-compose.yml           Full service orchestration
├── attack_simulation.py         6 attack scenarios (run on host)
│
├── physics/
│   ├── physics_engine.py        PipelineSimulator class (Redis-backed state)
│   └── physics_process.py       Standalone physics update service (1 s loop)
│
├── plc/
│   ├── Dockerfile               Shared image for all PLC + physics services
│   ├── modbus_server.py         Modbus/TCP honeypot (pymodbus, port 502)
│   ├── s7_server.py             S7comm honeypot (python-snap7, port 102)
│   └── dnp3_server.py           DNP3 honeypot (raw socket, port 20000)
│
├── hmi/
│   ├── Dockerfile
│   ├── hmi_app.py               Plotly Dash SCADA HMI (port 8060)
│   └── hmi_simulator.py         Historian bridge: Modbus → InfluxDB (5 s poll)
│
├── ml-engine/
│   ├── Dockerfile
│   └── trainer.py               Isolation Forest + EWMA/CUSUM engine (10 s loop)
│
├── logger/
│   ├── Dockerfile
│   ├── correlator.py            Cross-layer correlation logger
│   └── logger.py                Network packet sniffer
│
├── scripts/
│   └── export_results.py        Evaluation metric calculator
│
├── grafana_dashboards/
│   └── dashboard.json           Grafana dashboard (auto-provisioned on startup)
│
└── grafana_provisioning/
    └── ...                      Grafana datasource configuration
```

---

## 14. Key Design Decisions

| Decision | Rationale |
|---|---|
| **Redis for shared physics state** | Allows Modbus, S7, and HMI to read a single consistent physics snapshot without each running an independent simulation loop, preventing state drift between protocols. |
| **`session_id` tagging** | All InfluxDB writes include a session UUID prefix, enabling post-attack forensic reconstruction of the full attacker timeline across all protocols and services. |
| **Isolation Forest + EWMA/CUSUM** | Isolation Forest handles statistical outliers (injection, replay, sudden anomalies); EWMA/CUSUM handles slow drift attacks that evade single-point thresholds. The two layers are complementary. |
| **CUSUM reset on alert** | After a CUSUM trigger, accumulators reset to zero. This prevents repeated alerts on the same drift event and keeps `security_alerts` readable. |
| **No authentication on honeypot services** | By design — a deception environment must accept all connections to maximise attacker engagement and logging fidelity. |
| **`group()` in all Grafana queries** | Without grouping, InfluxDB returns one time series per unique tag combination. A new `session_id` on restart creates a new series, appearing as a duplicate line in Grafana. Grouping by `_measurement` + `_field` collapses all sessions into a single continuous line per metric. |
| **Physics-aware semantic validation** | The cross-layer correlator joins write events with the physical state at the time of the write. This enables detection of commands that are syntactically valid Modbus packets but semantically dangerous (e.g., writing 5000 PSI to a sensor register). |
