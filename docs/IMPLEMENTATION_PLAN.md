# ICS Honeypot — Master Implementation Plan

## Overview of the 5 Requested Changes

| # | Request | Status |
|---|---------|--------|
| 1 | Fix ML engine false positives (anomaly on startup) | 🔨 Implementing |
| 2 | Integrate Purdue Level 1, 3, and 3.5 | 🔨 Implementing |
| 3 | REST API for Level 3 alert consumption | 🔨 Implementing |
| 4 | Real attack surface (nmap-visible open ports) | 🔨 Implementing |
| 5 | Deployment guide + thesis testing strategy | 📝 Documented Below |

---

## 1. ML Engine — Root Cause of False Positives on Startup

### Why it fires immediately on startup

The **EWMA/CUSUM** detector (`run_drift_cycle`) starts on every loop iteration **before any warm-up guard**. When the container starts:
- `_ewma_state` is `None`, so it initialises to the first pressure sample.
- The physics engine starts from `pressure ≈ 50 PSI` but the **IsolationForest model** was trained on historical data with a different distribution.
- The model is loaded from the **previous session's `/data/model.pkl`** (Docker volume `shared-data`), which was fit on different data — instant anomaly.
- The `apply_expert_rules` check fires if `pressure_delta > 5.0` with no write activity. On startup, the first two readings naturally produce a large delta as the simulator converges.

### Fixes applied

1. **Startup Grace Period** — suppress all detections for the first `STARTUP_GRACE_SECONDS` (120 s by default).
2. **Model Versioning** — delete stale model on startup if session flags a fresh boot.
3. **IsolationForest contamination** — lower `contamination=0.05 → 0.02` to reduce false positive rate.
4. **Expert rules tuning** — raise `pressure_delta` threshold from `5.0 → 15.0` PSI and `pressure_mean_dev` from `15.0 → 25.0`.
5. **CUSUM threshold** — raise from `25.0 → 40.0` to avoid triggering on normal startup transients.
6. **Warm-up now still collects, only suppresses writes** to InfluxDB during warm-up.
7. **API server added** (see §3).

---

## 2. Purdue Level Integration

### Level 1 (Field Devices / PLCs) — Already Working
- `physics_simulator` + `plc_simulator` already simulate Level 1 sensors and actuators via Redis.

### Level 3.5 (DMZ) — Already Working
- Ports 502, 102, 20000 are exposed in the DMZ via `dmz-net`.

### Level 3 (Historian / Enterprise) — **New: `historian_api` service**
A new Flask REST service that:
- Exposes `GET /api/alerts` — paginated JSON feed of recent `security_alerts` from InfluxDB.
- Exposes `GET /api/health` — liveness check.
- Exposes `POST /api/external-event` — allows Level 3 systems to push events back.
- Runs on port **5000** on the `monitor-net` and new `enterprise-net`.

---

## 3. ML Engine REST API (Alert Logs Only)

Embedded **FastAPI/uvicorn** server on port **8000**.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Liveness — `{status, session_id, model_ready}` |
| GET | `/alerts` | Paginated recent anomalies |
| GET | `/metrics` | Latest score, sample count, EWMA state |
| POST | `/reset-model` | Force model retrain |

---

## 4. Real Attack Surface

All three ICS ports already exposed:
- **502/TCP** — Modbus (plc_simulator) ✅
- **102/TCP** — S7comm (ics_s7_plc) ✅  
- **20000/TCP** — DNP3 (ics_dnp3) ✅

**Added:** `attacker_node` service — an nmap + Python container for booth demos.

---

## 5. Deployment Guide

### Prerequisites
- Docker Desktop (Windows) with WSL2 backend
- Minimum 8 GB RAM, 4 CPU cores, 20 GB disk

### Deploy
```bash
docker compose up --build -d
```

### Verify ports (from attacker_node)
```bash
docker exec -it attacker_node nmap -sV -p 502,102,20000 plc_simulator
docker exec -it attacker_node nmap -sV -p 502,102,20000 ics_s7_plc
docker exec -it attacker_node nmap -sV -p 20000 ics_dnp3
```

### Access Points
| Service | URL |
|---------|-----|
| Grafana | http://localhost:3000 (admin/admin) |
| HMI | http://localhost:8060 |
| InfluxDB | http://localhost:8086 |
| ML API | http://localhost:8000/health |
| Historian API | http://localhost:5000/api/alerts |

### Thesis Test Scenarios
1. **Baseline** — run 10 min, verify 0 anomalies in Grafana.
2. **Port scan** — nmap; verify honeypot_events increases.
3. **Modbus write** — `attack_simulation.py` overrides pump RPM.
4. **Semantic injection** — write to read-only sensor registers.
5. **Stealth drift** — gradual pressure manipulation; EWMA/CUSUM triggers ~30s later.
6. **S7comm probe** — from attacker_node.
7. **DNP3 flood** — raw DNP3 frames; auth_attempts spike.

### Drawing Conclusions
- Export Grafana panels as PNG/CSV per scenario.
- Compare anomaly score time-series between baseline and attacks.
- Measure **True Positive Rate** and **False Positive Rate**.
- The `historian_api /api/alerts` JSON is the clean dataset for your thesis table.
