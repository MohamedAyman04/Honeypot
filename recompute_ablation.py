#!/usr/bin/env python3
import os
import sys
import numpy as np
import pandas as pd
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix

# Add scripts directory to path
sys.path.append(os.path.abspath("scripts"))
from architecture_validation import (
    load_campaign,
    build_all_detectors,
    combine_detectors,
    ALL_DET,
    DEFAULT_DATA_DIR
)

def main():
    print(f"Loading campaign data from: {DEFAULT_DATA_DIR}")
    data = load_campaign(DEFAULT_DATA_DIR)
    
    print("Building all detectors...")
    detectors = build_all_detectors(data)
    
    eval_mask = (data.df["split"] == "test").values
    y_true = data.df.loc[eval_mask, "ground_truth"].values
    
    # Define configurations and their corresponding detector subsets
    # We match the configurations from the user prompt:
    # - Full Architecture: all detectors
    # - Without Layer 1: without forced-write (semantic_injection)
    # - Without Layer 2: without threshold rules (stealth_drift, over_pressure)
    # - Without Layer 3: without EWMA/CUSUM (stealth_drift_ewma)
    # - Without Layer 4: without Cross-layer (cross_layer)  (Wait, this matches "Full − Cross-layer")
    # - Without Layer 5: without ML ensemble (if, lstm)      (Wait, this matches "Full − ML ensemble")
    
    configs = {
        "Full Architecture": ALL_DET,
        "Without Layer 1": [d for d in ALL_DET if d != "semantic_injection"],
        "Without Layer 2": [d for d in ALL_DET if d not in ("stealth_drift", "over_pressure")],
        "Without Layer 3": [d for d in ALL_DET if d != "stealth_drift_ewma"],
        "Without Layer 4": [d for d in ALL_DET if d != "cross_layer"],
        "Without Layer 5": [d for d in ALL_DET if d not in ("if", "lstm")]
    }
    
    rows = []
    for config_name, active_detectors in configs.items():
        pred = combine_detectors(detectors, active_detectors)
        y_pred = pred[eval_mask]
        
        # Calculate confusion matrix
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
        
        # Calculate precision, recall, F1 using sklearn.metrics
        p = precision_score(y_true, y_pred, zero_division=0)
        r = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        
        print(f"{config_name:25s}: TP={tp:3d}, FP={fp:4d}, FN={fn:3d}, TN={tn:4d}, P={p:.6f}, R={r:.6f}, F1={f1:.6f}")
        
        rows.append({
            "Configuration": config_name,
            "TP": int(tp),
            "FP": int(fp),
            "TN": int(tn),
            "FN": int(fn),
            "Precision": float(p),
            "Recall": float(r),
            "F1": float(f1)
        })
        
    df = pd.DataFrame(rows)
    
    # Write to project root
    out_csv = "table_ablation_complete.csv"
    df.to_csv(out_csv, index=False)
    print(f"\nSaved results to: {out_csv}")
    
    # Write to results/architecture_validation/ as well
    out_csv_alt = os.path.join("results", "architecture_validation", "table_ablation_complete.csv")
    df.to_csv(out_csv_alt, index=False)
    print(f"Saved results also to: {out_csv_alt}")

if __name__ == "__main__":
    main()
