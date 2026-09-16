#!/usr/bin/env python3
"""v7 Investigation of Active Attack Split TN=0 and transitional states."""
import pandas as pd, numpy as np, warnings, os
warnings.filterwarnings("ignore")
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import MinMaxScaler
from evaluate import reconstruct_data, load_phases, label_ground_truth
import tensorflow as tf
tf.get_logger().setLevel("ERROR")

df = reconstruct_data()
phases = load_phases()
df = label_ground_truth(df, phases)

FEATURE_COLS = [
    "pressure", "flow_rate", "temperature",
    "pressure_delta", "pressure_mean_dev",
    "inter_arrival_time", "write_freq_10s",
    "is_write", "func_code", "length",
]
X = df[FEATURE_COLS].values
scaler = MinMaxScaler()
Xs = scaler.fit_transform(X)

df["split"] = "train"
df.loc[360:390, "split"] = "val"
df.loc[391:, "split"] = "test"

X_train = Xs[df["split"] == "train"]
y_val = df[df["split"] == "val"]["ground_truth"].values

# Fit Isolation Forest using best val params
m_if = IsolationForest(contamination=0.005, n_estimators=100, max_samples=256, random_state=42)
m_if.fit(X_train)
if_scores = m_if.decision_function(Xs)
if_thresh = 0.184193  # Best val threshold
if_preds = (if_scores < if_thresh).astype(int)

# Fit LSTM
seq_len = 10
def make_seqs(data):
    return np.array([data[i:i+seq_len] for i in range(len(data)-seq_len+1)])

X_train_seq = make_seqs(X_train)
X_full_seq = make_seqs(Xs)
inp = tf.keras.layers.Input(shape=(seq_len, len(FEATURE_COLS)))
enc = tf.keras.layers.LSTM(16, activation="relu")(inp)
rep = tf.keras.layers.RepeatVector(seq_len)(enc)
dec = tf.keras.layers.LSTM(16, activation="relu", return_sequences=True)(rep)
out = tf.keras.layers.TimeDistributed(tf.keras.layers.Dense(len(FEATURE_COLS)))(dec)
model_lstm = tf.keras.models.Model(inp, out)
model_lstm.compile(optimizer="adam", loss="mse")
model_lstm.fit(X_train_seq, X_train_seq, epochs=30, verbose=0, batch_size=16)

full_preds_lstm = model_lstm.predict(X_full_seq, verbose=0)
full_errs = np.mean(np.square(X_full_seq - full_preds_lstm), axis=(1,2))
padded = np.concatenate([np.full(seq_len-1, full_errs[0]), full_errs])
smoothed = pd.Series(padded).rolling(3, min_periods=1).mean().values
lstm_thresh = 0.009427  # Best val threshold
lstm_preds = (smoothed > lstm_thresh).astype(int)

df["if_score"] = if_scores
df["if_anomaly"] = if_preds
df["lstm_error"] = smoothed
df["lstm_anomaly"] = lstm_preds
df["or_anomaly"] = (if_preds | lstm_preds).astype(int)

# 1. Inspect the 12 normal samples in the active window (360-398)
sub_active = df.iloc[360:399]
normals_active = sub_active[sub_active["ground_truth"] == 0]

print("=" * 80)
print("1. DETAILED PROFILING OF THE 12 'NORMAL' SAMPLES IN THE ACTIVE ATTACK WINDOW")
print("=" * 80)
print(f"IF Threshold  : {if_thresh:.6f}")
print(f"LSTM Threshold: {lstm_thresh:.6f}")
print("-" * 80)

# Print columns: index, ground_truth, if_score, if_pred, lstm_error, lstm_pred, pressure, temperature, flow_rate, write_freq_10s
cols_to_show = ["pressure", "temperature", "flow_rate", "write_freq_10s", "is_write"]
for idx, row in normals_active.iterrows():
    print(f"Index {idx}:")
    print(f"  [Model Scores] IF Score={row['if_score']:.6f} (Flagged={row['if_anomaly']}) | LSTM Error={row['lstm_error']:.6f} (Flagged={row['lstm_anomaly']})")
    print(f"  [Features]     Pressure={row['pressure']:.2f} | Temp={row['temperature']:.2f} | Flow={row['flow_rate']:.2f} | WriteFreq={row['write_freq_10s']:.2f} | IsWrite={row['is_write']}")
    # Compare with training baseline averages
    print("-" * 50)

# Calculate training baseline average features
baseline_means = df.iloc[0:360][cols_to_show].mean()
print("\nTraining Baseline (0-359) Mean Reference Values:")
for col in cols_to_show:
    print(f"  {col}: {baseline_means[col]:.4f}")

# 2. Test models against a separate block of normal telemetry outside baseline and active attack window
# Wait, where is there normal telemetry outside baseline (0-359) and active attack window (360-398)?
# Let's check indices 399-518 (post-attack aftermath split). Are there any labeled normal samples there?
# Yes, indices 399-518 are ALL labeled normal (ground_truth = 0). Let's see how many samples there are, and their scores.
# Wait, are there any other segments? Let's check.
print("\n" + "=" * 80)
print("2. TESTING AGAINST SEPARATE BLOCKS OF NORMAL TELEMETRY")
print("=" * 80)

# Let's check the confusion matrix counts for a purely normal block of telemetry (e.g. indices 200-359 from the training set, just as an sanity check)
train_subset = df.iloc[200:360]
print(f"Sanity Check: Training subset (indices 200-359) [All ground_truth = 0]")
print(f"  Total={len(train_subset)}")
print(f"  IF Solo False Alarms: {train_subset['if_anomaly'].sum()} / {len(train_subset)}")
print(f"  LSTM Solo False Alarms: {train_subset['lstm_anomaly'].sum()} / {len(train_subset)}")
print(f"  Ensemble OR False Alarms: {train_subset['or_anomaly'].sum()} / {len(train_subset)}")

# Now check the post-attack aftermath period (indices 399 to 518) where ground_truth is 0.
aftermath = df.iloc[399:519]
print(f"\nPost-Attack Aftermath period (indices 399-518) [All ground_truth = 0]")
print(f"  Total={len(aftermath)}")
print(f"  IF Solo flagged (FP)     : {aftermath['if_anomaly'].sum()} (TN = {len(aftermath) - aftermath['if_anomaly'].sum()})")
print(f"  LSTM Solo flagged (FP)   : {aftermath['lstm_anomaly'].sum()} (TN = {len(aftermath) - aftermath['lstm_anomaly'].sum()})")
print(f"  Ensemble OR flagged (FP) : {aftermath['or_anomaly'].sum()} (TN = {len(aftermath) - aftermath['or_anomaly'].sum()})")

# Let's check why they are flagged in the aftermath.
print("\nAverage aftermath feature values vs Baseline:")
aftermath_means = aftermath[cols_to_show].mean()
for col in cols_to_show:
    print(f"  {col}: Aftermath={aftermath_means[col]:.4f}  |  Baseline={baseline_means[col]:.4f}")

# Let's check if there are any specific TNs in the aftermath period for IF Solo.
# Indeed, IF Solo has 12 TNs (132 - 120 = 12 TNs) in the aftermath period! Let's print some of these TN sample indices and features.
tn_indices = aftermath.index[aftermath["if_anomaly"] == 0].tolist()
print(f"\nIF Solo correctly classified Normal samples (TNs) in the aftermath: {tn_indices}")
if tn_indices:
    sample_tn = df.loc[tn_indices[0]]
    print(f"Example TN sample at Index {tn_indices[0]}:")
    print(f"  IF Score={sample_tn['if_score']:.6f} | LSTM Error={sample_tn['lstm_error']:.6f}")
    print(f"  Pressure={sample_tn['pressure']:.2f} | Temp={sample_tn['temperature']:.2f} | Flow={sample_tn['flow_rate']:.2f}")

# 3. Analyze transitional/ambiguous conditions
print("\n" + "=" * 80)
print("3. ANALYSIS OF THE 'NORMAL' SAMPLES WITHIN THE ACTIVE ATTACK WINDOW")
print("=" * 80)
print("Let's look at the chronological sequence of indices 360-375 to understand attack phase transitions:")
for idx in range(360, 376):
    row = df.loc[idx]
    phase_label = "NORMAL" if row["ground_truth"] == 0 else "ATTACK"
    print(f"Index {idx:3d} ({phase_label}): Pressure={row['pressure']:6.2f} | Temp={row['temperature']:5.2f} | IF Score={row['if_score']:8.5f} | LSTM Error={row['lstm_error']:8.5f}")
