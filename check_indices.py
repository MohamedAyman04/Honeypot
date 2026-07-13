import pandas as pd
from evaluate import reconstruct_data, load_phases, label_ground_truth
df = reconstruct_data()
phases = load_phases()
df = label_ground_truth(df, phases)
for idx, row in phases.iterrows():
    mask = (df["timestamp"] >= row["start"]) & (df["timestamp"] <= row["end"])
    indices = df[mask].index.tolist()
    if len(indices) > 0:
        print(f"Phase {row['phase']} ({row['name']}): expects_alert={row['expects_alert']} -> Indices {indices[0]} to {indices[-1]} ({len(indices)} samples)")
