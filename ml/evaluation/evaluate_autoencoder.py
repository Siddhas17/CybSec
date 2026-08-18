"""Final, one-time evaluation on the untouched test split.

This is the ONLY module in the autoencoder pipeline that loads
ml/datasets/processed/test_*.npz / test_metadata.csv. Run only after
ml/training/train_autoencoder.py has produced a trained model and selected
a threshold from the validation split -- this module never selects or
adjusts the threshold, it only applies the one already chosen.

Positive/anomalous class convention: 1 = ATTACK (any non-BENIGN
canonical_label), 0 = BENIGN -- same as ml/evaluation/threshold_analysis.py.

CLI usage:
    python -m ml.evaluation.evaluate_autoencoder

Writes (into the same artifact directory train_autoencoder.py used):
    test_evaluation.json       confusion matrix, precision/recall/F1, ROC-AUC, PR-AUC, error stats
    per_attack_evaluation.csv  per-canonical-attack-type sample count, error stats, detection rate
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
import torch

from ml.evaluation.threshold_analysis import evaluate_threshold, pr_auc, roc_auc
from ml.models.autoencoder import Autoencoder, AutoencoderConfig, reconstruction_error
from ml.training.train_autoencoder import ARTIFACT_DIR, BENIGN_LABEL, load_processed_split


def load_trained_model(artifact_dir: Path) -> Autoencoder:
    config_data = json.loads((artifact_dir / "config.json").read_text())
    config = AutoencoderConfig.from_dict(config_data["architecture"])
    model = Autoencoder(config)
    model.load_state_dict(torch.load(artifact_dir / "best_model.pt", map_location="cpu"))
    model.eval()
    return model


def per_attack_table(meta_test: pd.DataFrame, scores: np.ndarray, threshold: float) -> pd.DataFrame:
    """One row per canonical attack category actually present in the test
    split (BENIGN excluded -- its false-positive behavior is already in the
    confusion matrix). detection_rate = fraction of that category's rows
    with reconstruction_error >= threshold."""
    df = meta_test.copy()
    df["reconstruction_error"] = scores
    df["flagged"] = scores >= threshold
    attack_df = df[df["canonical_label"] != BENIGN_LABEL]

    rows = [
        {
            "attack_type": label,
            "sample_count": int(len(group)),
            "mean_reconstruction_error": float(group["reconstruction_error"].mean()),
            "median_reconstruction_error": float(group["reconstruction_error"].median()),
            "detection_rate": float(group["flagged"].mean()),
        }
        for label, group in attack_df.groupby("canonical_label")
    ]
    return pd.DataFrame(rows).sort_values("sample_count", ascending=False).reset_index(drop=True)


def main() -> None:
    artifact_dir = ARTIFACT_DIR
    model = load_trained_model(artifact_dir)
    threshold = json.loads((artifact_dir / "threshold.json").read_text())["selected_threshold"]

    X_test, meta_test = load_processed_split("test")
    y_true_test = (meta_test["canonical_label"] != BENIGN_LABEL).to_numpy().astype(int)

    test_tensor = torch.tensor(X_test, dtype=torch.float32)
    scores_test = reconstruction_error(model, test_tensor).numpy()

    metrics = evaluate_threshold(y_true_test, scores_test, threshold)
    metrics["roc_auc"] = roc_auc(y_true_test, scores_test)
    metrics["pr_auc"] = pr_auc(y_true_test, scores_test)
    metrics["positive_class_definition"] = "1 = ATTACK (any non-BENIGN canonical_label), 0 = BENIGN"

    benign_scores = scores_test[y_true_test == 0]
    attack_scores = scores_test[y_true_test == 1]
    metrics["benign_test_error_stats"] = {
        "count": int(len(benign_scores)),
        "mean": float(np.mean(benign_scores)),
        "median": float(np.median(benign_scores)),
        "std": float(np.std(benign_scores)),
    }
    metrics["attack_test_error_stats"] = {
        "count": int(len(attack_scores)),
        "mean": float(np.mean(attack_scores)),
        "median": float(np.median(attack_scores)),
        "std": float(np.std(attack_scores)),
    }

    per_attack = per_attack_table(meta_test, scores_test, threshold)

    print("=== Final test evaluation (test set touched for the first time) ===")
    print(f"  threshold used: {threshold:.6f}")
    print(f"  TP={metrics['tp']} TN={metrics['tn']} FP={metrics['fp']} FN={metrics['fn']}")
    print(f"  precision={metrics['precision']:.4f} recall={metrics['recall']:.4f} f1={metrics['f1']:.4f}")
    print(f"  roc_auc={metrics['roc_auc']:.4f} pr_auc={metrics['pr_auc']:.4f}")
    print(f"  benign false-positive rate: {metrics['false_positive_rate']:.4f}")
    print("\n=== Per-attack-type detection ===")
    print(per_attack.to_string(index=False))

    (artifact_dir / "test_evaluation.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    per_attack.to_csv(artifact_dir / "per_attack_evaluation.csv", index=False)
    print(f"\nArtifacts written under: {artifact_dir}")


if __name__ == "__main__":
    main()
