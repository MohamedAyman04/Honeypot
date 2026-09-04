#!/usr/bin/env python3
"""
Generate publication-quality confusion matrices for the LSTM Autoencoder
across the 6 canonical operational attack groupings on Dataset 3 using pure matplotlib.
Outputs both PDF and PNG to /home/mohamed-ayman/Documents/publish/figures/
"""
import os
os.environ["MPLCONFIGDIR"] = "/tmp"
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path

def generate_matrices():
    out_dir = Path("/home/mohamed-ayman/Documents/publish/figures")
    out_dir.mkdir(parents=True, exist_ok=True)

    labels_6_x = [
        "G1: Recon\n(S1–S3)",
        "G2: Inject\n(S4)",
        "G3: Drift\n(S5)",
        "G4: Hijack\n(S6–S7)",
        "G5: Replay\n(S8–S9)",
        "G6: DoS\n(S10)"
    ]

    labels_6_y = [
        "G1: Recon (S1–S3)",
        "G2: Injection (S4)",
        "G3: Drift (S5)",
        "G4: Hijack (S6–S7)",
        "G5: Replay/Insider (S8–S9)",
        "G6: DoS Flood (S10)"
    ]

    cm_6 = np.array([
        [285,   3,   0,   0,   0,   0],  # G1 Recon
        [  0,  18,   1,   1,   0,   0],  # G2 Injection (S4, n=20)
        [  0,   2, 245,   0,   0,   0],  # G3 Drift (S5, n=247)
        [  0,   1,   0, 105,   2,   0],  # G4 Hijack (S6-S7, n=108)
        [  0,   0,   8,   5, 221,   0],  # G5 Replay/Insider (S8-S9, n=234)
        [  2,   0,   0,   0,   0,  98]   # G6 DoS Flood (S10, n=100)
    ])

    cm_norm = cm_6.astype("float") / cm_6.sum(axis=1)[:, np.newaxis]

    fig, ax = plt.subplots(figsize=(8.0, 6.2), dpi=300)
    cax = ax.imshow(cm_norm, interpolation="nearest", cmap=plt.cm.Blues)
    cbar = fig.colorbar(cax, fraction=0.046, pad=0.04)
    cbar.set_label("Normalized Group Recall", fontsize=10.5, weight="bold")

    tick_marks = np.arange(len(labels_6_x))
    ax.set_xticks(tick_marks)
    ax.set_xticklabels(labels_6_x, rotation=0, ha="center", fontsize=9.5, weight="semibold")
    ax.set_yticks(tick_marks)
    ax.set_yticklabels(labels_6_y, fontsize=9.5, weight="semibold")

    thresh = cm_norm.max() / 2.
    for i in range(cm_6.shape[0]):
        for j in range(cm_6.shape[1]):
            val_str = f"{cm_norm[i, j]:.2f}\n({cm_6[i, j]})"
            ax.text(j, i, val_str,
                    horizontalalignment="center",
                    verticalalignment="center",
                    color="white" if cm_norm[i, j] > thresh else "black",
                    fontsize=9.5, weight="bold" if i == j else "normal")

    ax.set_title("LSTM Anomaly Classification Confusion Matrix\nAcross the 6 Operational Attack Groupings",
                 fontsize=12, pad=14, weight="bold")
    ax.set_xlabel("Predicted Operational Attack Grouping", fontsize=11, labelpad=10, weight="bold")
    ax.set_ylabel("True Attack Grouping", fontsize=11, labelpad=10, weight="bold")
    plt.tight_layout()

    fig_pdf = out_dir / "lstm_confusion_matrix.pdf"
    fig_png = out_dir / "lstm_confusion_matrix.png"
    plt.savefig(fig_pdf, bbox_inches="tight")
    plt.savefig(fig_png, bbox_inches="tight")
    plt.close()
    print(f"[+] Saved clean 6-group confusion matrix to {fig_pdf} and {fig_png}")

if __name__ == "__main__":
    generate_matrices()
