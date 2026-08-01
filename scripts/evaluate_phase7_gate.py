#!/usr/bin/env python3
"""
Phase 7 Mechanism Gate Evaluation Script
========================================
Diagnoses Phase 7 failures and evaluates a targeted, physics-informed Phase 7 gate
(Flow-Rate Deviation during Actuator Writes) combined with NMG across Dataset 1 and Dataset 2.
"""

import os
import sys
import numpy as np
import pandas as pd
from pathlib import Path

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT_DIR, "scripts"))

from architecture_validation import (
    load_campaign, NETWORK_FEATURES, PROCESS_FEATURES,
    detect_semantic_injection, detect_ewma_cusum
)
from full_architecture_realistic import repair_features, metrics
from canonical_evaluation import set_seed, calibrate_domain_ml, narrow_mechanism_gate, SEED

set_seed()

def phase_stratified_split(df, val_frac=0.45):
    val_indices = []
    for phase_id in df['attack_phase'].unique():
        phase_idxs = df[df['attack_phase'] == phase_id].index.values
        n_val = int(len(phase_idxs) * val_frac)
        val_indices.extend(phase_idxs[:n_val])
    return df.index.isin(val_indices)

def calibrate_p7_gate(df, val_mask, max_fpr=0.005):
    y_val = df.loc[val_mask, 'ground_truth'].to_numpy()
    p7_val = (df.loc[val_mask, 'attack_phase'] == 7).to_numpy()
    norm_val = (df.loc[val_mask, 'attack_phase'] == 0).to_numpy()
    
    cand_scores = []
    
    for W in [15, 30, 45, 60, 90, 120]:
        flow_mean = df['flow_rate'].rolling(W, min_periods=1).mean()
        flow_dev = (df['flow_rate'] - flow_mean).abs()
        
        for tau in np.arange(1.0, 6.1, 0.2):
            gate_cand = ((df['write_freq_10s'] > 0) & (flow_dev > tau)).astype(int).to_numpy()
            gate_val = gate_cand[val_mask]
            
            fpr = gate_val[norm_val].sum() / max(norm_val.sum(), 1)
            rec_p7 = gate_val[p7_val].sum() / max(p7_val.sum(), 1) if p7_val.sum() > 0 else 0.0
            
            if fpr <= max_fpr:
                score = rec_p7 - 5.0 * fpr
                cand_scores.append((score, W, float(tau)))
            else:
                cand_scores.append((-999.0, W, float(tau)))
                
    max_cand_score = max(cand_scores, key=lambda x: x[0])[0]
    best_tuple = max(cand_scores, key=lambda x: x[0])
    best_score = best_tuple[0]
    
    assert best_score == max_cand_score, f'Max selection assertion failed: {best_score} != {max_cand_score}'
    
    W_opt, tau_opt = best_tuple[1], best_tuple[2]
    flow_mean_full = df['flow_rate'].rolling(W_opt, min_periods=1).mean()
    flow_dev_full = (df['flow_rate'] - flow_mean_full).abs()
    gate_full = ((df['write_freq_10s'] > 0) & (flow_dev_full > tau_opt)).astype(int).to_numpy()
    
    return gate_full, (W_opt, tau_opt)

def run_eval_for_dataset(data_dir, label):
    data_raw = load_campaign(data_dir)
    data = repair_features(data_raw)
    df = data.df
    y_full = df['ground_truth'].to_numpy()
    
    results = {}
    mean_dev_cands = list(np.arange(5.0, 50.0, 1.0))
    
    for split_type in ['chrono', 'stratified']:
        if split_type == 'chrono':
            val_mask = df.index < int(len(df) * 0.45)
        else:
            val_mask = phase_stratified_split(df, val_frac=0.45)
            
        test_mask = ~val_mask
        y_test = y_full[test_mask]
        
        csv_dir = Path(data_dir) / 'csv'
        fw_path = str(csv_dir / 'forced_writes.csv')
        l1_pred = detect_semantic_injection(df, fw_path, data.campaign_start).pred
        
        ml_net_preds, _, _ = calibrate_domain_ml(df, val_mask, NETWORK_FEATURES)
        net_only_full = (l1_pred.astype(bool) | ml_net_preds['if'].astype(bool) | ml_net_preds['lstm'].astype(bool)).astype(int)
        
        nmg_full, nmg_meta = narrow_mechanism_gate(net_only_full, df, val_mask, y_full, mean_dev_cands)
        
        p7_gate_full, params = calibrate_p7_gate(df, val_mask, max_fpr=0.005)
        comb_p7_nmg_full = (nmg_full.astype(bool) | p7_gate_full.astype(bool)).astype(int)
        
        net_m = metrics(y_test, net_only_full[test_mask])
        nmg_m = metrics(y_test, nmg_full[test_mask])
        comb_m = metrics(y_test, comb_p7_nmg_full[test_mask])
        
        p7_test_mask = (df.loc[test_mask, 'attack_phase'] == 7).to_numpy()
        n_p7_test = p7_test_mask.sum()
        
        p7_rec_net = net_only_full[test_mask][p7_test_mask].sum() / max(n_p7_test, 1)
        p7_rec_nmg = nmg_full[test_mask][p7_test_mask].sum() / max(n_p7_test, 1)
        p7_rec_comb = comb_p7_nmg_full[test_mask][p7_test_mask].sum() / max(n_p7_test, 1)
        
        results[split_type] = {
            'net_only': net_m,
            'nmg': nmg_m,
            'comb_p7': comb_m,
            'p7_rec_net': p7_rec_net,
            'p7_rec_nmg': p7_rec_nmg,
            'p7_rec_comb': p7_rec_comb,
            'params': params,
            'nmg_threshold': nmg_meta.get('best_t', nmg_meta.get('gate_threshold', 15.0)),
            'n_p7_test': n_p7_test
        }
        
    return results

def main():
    print("Executing Phase 7 Gate Evaluation across Dataset 1 and Dataset 2 ...")
    d1_dir = os.path.join(PROJECT_DIR, "results", "20260724_014825")
    d2_dir = os.path.join(PROJECT_DIR, "results", "20260725_055634")
    
    d1_res = run_eval_for_dataset(d1_dir, "Dataset 1")
    d2_res = run_eval_for_dataset(d2_dir, "Dataset 2")
    
    print("\n" + "="*80)
    print("  PHASE 7 MECHANISM GATE EVALUATION SUMMARY")
    print("="*80)
    
    for label, res in [("Dataset 1 (20260724_014825)", d1_res), ("Dataset 2 (20260725_055634)", d2_res)]:
        print(f"\n▶ {label}:")
        for stype, sname in [("chrono", "Canonical Chronological Split (frac=0.45)"), ("stratified", "Phase-Stratified Split")]:
            r = res[stype]
            print(f"  • {sname} (NMG t={r['nmg_threshold']}, P7 Gate Params: W={r['params'][0]}s, tau={r['params'][1]:.1f} L/s):")
            print(f"    - Network-only Baseline : P={r['net_only']['Precision']:.3f}, R={r['net_only']['Recall']:.3f}, F1={r['net_only']['F1']:.3f} | Phase 7 Recall={r['p7_rec_net']*100:5.1f}%")
            print(f"    - NMG Alone             : P={r['nmg']['Precision']:.3f}, R={r['nmg']['Recall']:.3f}, F1={r['nmg']['F1']:.3f} | Phase 7 Recall={r['p7_rec_nmg']*100:5.1f}%")
            print(f"    - NMG + Phase 7 Gate    : P={r['comb_p7']['Precision']:.3f}, R={r['comb_p7']['Recall']:.3f}, F1={r['comb_p7']['F1']:.3f} | Phase 7 Recall={r['p7_rec_comb']*100:5.1f}%")

if __name__ == "__main__":
    main()
