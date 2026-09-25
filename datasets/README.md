# Operational Cyber-Physical Benchmark Datasets

This directory contains the three multi-hour cyber-physical benchmark datasets collected from the physics-grounded industrial oil-pipeline honeypot testbed.

---

## 🌟 Primary Benchmark Dataset: Dataset 3 (`dataset_3_20260801_052308`)

> **IMPORTANT NOTE FOR RESEARCHERS & REVIEWERS:**  
> **Dataset 3 is the primary held-out benchmark upon which the paper is written.**  
> It represents the complete 10-scenario attack campaign, introducing **Scenario 9 (authorized SCADA insider setpoint manipulation)** alongside stealth drift (Scenario 5) and out-of-band telemetry replay (Scenario 8).
>
> **Paper Headline Results Achieved on Dataset 3:**
> - **Overall F1-Score:** **0.891** (Champion performance among all evaluated fusion methods)
> - **Attack Recall:** **0.901** (549 out of 609 stealth cyber-physical attack frames detected)
> - **Operational Precision:** **0.881** (Only 74 false alarms across 5,212 normal frames, achieving 95.2% benign specificity)
> - **Total Campaign Duration:** **7.8 hours** (27,926 continuous 1 Hz telemetry cycles / 57,058 logged records)

---

## Dataset Overview Across All Three Campaigns

| Dataset Identifier | Directory | Duration | Total Records | Attack Injections | Key Threats Evaluated |
|---|---|:---:|:---:|:---:|---|
| **Dataset 1** | `dataset_1_20260724_014825/` | 4.8 h | 34,228 | Scenarios 1–8 | Perimeter scan, semantic injection, stealth drift, replay |
| **Dataset 2** | `dataset_2_20260725_055634/` | 7.2 h | 52,187 | Scenarios 1–8 | Extended multi-stage attack campaign |
| **Dataset 3** *(Primary)* | `dataset_3_20260801_052308/` | **7.8 h** | **57,058** | **Scenarios 1–10** | **Complete spectrum + Scenario 9 (SCADA Insider Setpoint Abuse)** |

---

## Directory Structure Per Dataset

Each dataset directory (`dataset_1_...`, `dataset_2_...`, `dataset_3_...`) contains:

```text
dataset_X/
├── csv/
│   ├── pipeline_metrics.csv       # Primary 1 Hz telemetry: pressure, flow rate, temperature, RPM, valve position
│   ├── process_state.csv          # Internal hydrodynamic simulator physics variables
│   ├── attack_status.csv          # Ground-truth injection start/stop timestamps, attack types, and phase IDs
│   ├── modbus_events.csv          # Industrial Modbus/TCP packet transactions, function codes, and register offsets
│   ├── forced_writes.csv          # Unauthorized Modbus write attempts (FC5, FC6, FC16)
│   ├── correlation_logs.csv       # Command-to-consequence correlation logs
│   ├── security_alerts.csv        # Real-time multi-layer intrusion detection alerts
│   ├── security_metrics.csv       # Rolling network arrival rates and sliding-window statistics
│   ├── honeypot_events.csv        # Perimeter honeypot interaction records
│   └── auth_attempts.csv          # SCADA SSH bastion authentication attempts (Scenario 6)
├── logs/                          # Microservice runtime logs (PLC simulator, ML engine, sniffer, correlator)
├── attack_results_extended.csv    # Extended phase-level attack recall breakdown
└── summary.txt                    # Operational campaign execution manifest and parameters
```

---

## Key Telemetry Fields (`pipeline_metrics.csv`)

| Column Name | Unit / Range | Description |
|---|:---:|---|
| `timestamp` | ISO 8601 UTC | Synchronized measurement timestamp (1 Hz telemetry rate). |
| `pressure` | PSI (0–500) | Pipeline fluid pressure (nominal operating mean ~120.0 PSI). |
| `flow_rate` | L/s (0–100) | Discharge flow rate (nominal steady state ~50.0 L/s). |
| `temperature` | °C (20–80) | Fluid temperature. |
| `pump_rpm` | RPM (0–3500) | Centrifugal pump rotational speed (nominal ~1200 RPM). |
| `valve_position` | [0.0, 1.0] | Control valve opening fraction (0.0 = closed, 1.0 = fully open). |
| `viscosity` | cSt | Fluid kinematic viscosity (crude oil simulation). |
| `pressure_delta` | PSI/s | First derivative rate of change (dP/dt). |
| `pressure_mean_dev` | PSI | Real-time deviation from baseline mean (|P_t - mu_0|). |

---

## Reproducing Paper Results

To execute the authoritative canonical evaluation across the datasets:

```bash
# Evaluate Datasets 1 & 2
python scripts/canonical_evaluation.py --ds1 datasets/dataset_1 --ds2 datasets/dataset_2

# Evaluate Dataset 3 (Primary Paper Benchmark)
python scripts/canonical_evaluation.py --ds1 datasets/dataset_3 --ds2 datasets/dataset_3
```
