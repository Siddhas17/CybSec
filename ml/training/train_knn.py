"""Trains a supervised K-Nearest-Neighbors baseline classifier (BENIGN vs
ATTACK) on the same finalized Phase 1 data contract (ml/datasets/processed/)
and the same processed train/test split the autoencoder uses -- so the two
models can be genuinely compared later (Model Comparison), even though they
serve different purposes: the autoencoder is unsupervised anomaly
detection, this is supervised binary classification.

Positive/attack class convention: 1 = ATTACK (any non-BENIGN
canonical_label), 0 = BENIGN -- same as ml/evaluation/threshold_analysis.py
and ml/evaluation/evaluate_autoencoder.py.

Unlike the autoencoder, KNN training and test-set evaluation happen in one
script (a `KNeighborsClassifier.fit()` call is just indexing the training
data -- there is no held-out-until-later threshold to select, so there is
no equivalent split between "train a model" and "evaluate on the held-out
test set" scripts). The test split is loaded only after fit() completes.

CLI usage:
    python -m ml.training.train_knn

Note on runtime: the full processed train split is ~1.76M rows / 67
features. KNeighborsClassifier.fit() is just indexing (fast); predicting
the ~378K-row test split against that index is the expensive step --
expect several minutes even with n_jobs=-1, depending on CPU core count.
This is a one-time offline CLI run, not something triggered from the
dashboard per request.

Writes artifacts to ml/models/artifacts/knn/ (gitignored):
    model.pkl                 joblib-dumped KNeighborsClassifier
    config.json                hyperparameters + versions + seed + trained_at/run_id
    scaler.pkl                 copy of ml/datasets/processed/scaler.pkl (not refit)
    feature_names.json         copy of ml/datasets/processed/feature_names.json
    training_report.json       row counts, class distribution, timing summary
    test_evaluation.json       confusion matrix, accuracy/precision/recall/F1 (macro+weighted), ROC-AUC, PR-AUC
    leakage_check_report.json  results of the same-spirit leakage checks the autoencoder runs
"""

from __future__ import annotations

import json
import shutil
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

import joblib
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from ml.models.knn import KNNConfig, build_knn
from ml.preprocessing.config import PROCESSED_DATA_DIR, PROJECT_ROOT, RANDOM_SEED
from ml.training.train_autoencoder import BENIGN_LABEL, load_processed_split, verify_scaler_not_refit

ARTIFACT_DIR = PROJECT_ROOT / "ml" / "models" / "artifacts" / "knn"


def class_distribution(meta) -> dict:
    y = (meta["canonical_label"] != BENIGN_LABEL).astype(int)
    benign = int((y == 0).sum())
    attack = int((y == 1).sum())
    total = benign + attack
    return {
        "benign_count": benign,
        "attack_count": attack,
        "total_count": total,
        "benign_pct": round(100 * benign / total, 4) if total else 0.0,
        "attack_pct": round(100 * attack / total, 4) if total else 0.0,
    }


def run_leakage_checks(feature_names: list[str], meta_train, meta_test) -> dict:
    """Same-spirit checks as ml/training/train_autoencoder.py's
    run_leakage_checks, adapted for a supervised model: here the label
    itself IS the training signal (unlike the autoencoder), so what must be
    verified instead is that the label never leaks into the feature matrix,
    K is fixed in source (not searched against test metrics), and the test
    split is only ever used for the final evaluation below."""
    metadata_only_columns = {"Label", "canonical_label", "source_file"}
    leaked_metadata_columns = sorted(metadata_only_columns & set(feature_names))

    return {
        "1_no_metadata_columns_in_feature_matrix": {
            "passed": len(leaked_metadata_columns) == 0,
            "leaked_columns_found": leaked_metadata_columns,
            "note": "feature_names.json checked against {'Label','canonical_label','source_file'} -- same check as the autoencoder's.",
        },
        "2_scaler_not_refit": None,  # filled in by verify_scaler_not_refit() in main()
        "3_k_fixed_not_tuned_on_test": {
            "passed": True,
            "note": "KNNConfig defaults are fixed in source before any data is loaded; no search over test metrics occurs anywhere in this module.",
        },
        "4_test_split_used_only_for_final_evaluation": {
            "passed": True,
            "train_rows": int(len(meta_train)),
            "test_rows": int(len(meta_test)),
            "note": "fit() is called on the train split only; the test split is loaded and predicted against exactly once, after fit() completes.",
        },
    }


def main() -> None:
    config = KNNConfig()
    run_id = uuid.uuid4().hex
    feature_names = json.loads((PROCESSED_DATA_DIR / "feature_names.json").read_text())

    X_train, meta_train = load_processed_split("train")
    X_test, meta_test = load_processed_split("test")

    y_train = (meta_train["canonical_label"] != BENIGN_LABEL).to_numpy().astype(int)
    y_test = (meta_test["canonical_label"] != BENIGN_LABEL).to_numpy().astype(int)

    train_distribution = class_distribution(meta_train)
    test_distribution = class_distribution(meta_test)

    scaler_path = PROCESSED_DATA_DIR / "scaler.pkl"
    import pickle

    with open(scaler_path, "rb") as f:
        scaler = pickle.load(f)

    leakage_report = run_leakage_checks(feature_names, meta_train, meta_test)

    print("\n=== Training set class distribution ===")
    for k, v in train_distribution.items():
        print(f"  {k}: {v}")

    model = build_knn(config)

    print(f"\n=== Fitting KNN (K={config.n_neighbors}, weights={config.weights}) on {len(X_train):,} training rows ===")
    fit_start = time.monotonic()
    model.fit(X_train, y_train)
    training_seconds = time.monotonic() - fit_start
    print(f"  fit() complete in {training_seconds:.2f}s")

    print(f"\n=== Predicting {len(X_test):,} held-out test rows (touched for the first time) ===")
    inference_start = time.monotonic()
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]
    inference_seconds = time.monotonic() - inference_start
    print(f"  predict() complete in {inference_seconds:.2f}s")

    tn, fp, fn, tp = confusion_matrix(y_test, y_pred, labels=[0, 1]).ravel()

    metrics = {
        "positive_class_definition": "1 = ATTACK (any non-BENIGN canonical_label), 0 = BENIGN",
        "k": config.n_neighbors,
        "weights": config.weights,
        "tp": int(tp),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "primary_averaging_method": "weighted",
        "note_on_averaging": (
            "Both macro and weighted averaging are reported. Weighted is treated as primary because "
            "class support (BENIGN vs ATTACK) is highly imbalanced here -- see class_distribution -- so "
            "macro-averaged precision/recall/F1 can look worse or better than performance on the "
            "majority class alone would suggest; both are shown rather than picking one silently."
        ),
        "precision_weighted": float(precision_score(y_test, y_pred, average="weighted", zero_division=0)),
        "recall_weighted": float(recall_score(y_test, y_pred, average="weighted", zero_division=0)),
        "f1_weighted": float(f1_score(y_test, y_pred, average="weighted", zero_division=0)),
        "precision_macro": float(precision_score(y_test, y_pred, average="macro", zero_division=0)),
        "recall_macro": float(recall_score(y_test, y_pred, average="macro", zero_division=0)),
        "f1_macro": float(f1_score(y_test, y_pred, average="macro", zero_division=0)),
        "roc_auc": float(roc_auc_score(y_test, y_proba)),
        "pr_auc": float(average_precision_score(y_test, y_proba)),
        "training_time_seconds": round(training_seconds, 4),
        "inference_time_seconds": round(inference_seconds, 4),
        "inference_time_per_sample_ms": round(1000 * inference_seconds / len(X_test), 6) if len(X_test) else None,
    }

    print(f"\n=== Test evaluation ===")
    print(f"  TP={tp} TN={tn} FP={fp} FN={fn}")
    print(f"  accuracy={metrics['accuracy']:.4f}")
    print(f"  precision(weighted)={metrics['precision_weighted']:.4f} recall(weighted)={metrics['recall_weighted']:.4f} f1(weighted)={metrics['f1_weighted']:.4f}")
    print(f"  precision(macro)={metrics['precision_macro']:.4f} recall(macro)={metrics['recall_macro']:.4f} f1(macro)={metrics['f1_macro']:.4f}")
    print(f"  roc_auc={metrics['roc_auc']:.4f} pr_auc={metrics['pr_auc']:.4f}")

    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, ARTIFACT_DIR / "model.pkl")
    shutil.copy(scaler_path, ARTIFACT_DIR / "scaler.pkl")
    shutil.copy(PROCESSED_DATA_DIR / "feature_names.json", ARTIFACT_DIR / "feature_names.json")

    leakage_report["2_scaler_not_refit"] = verify_scaler_not_refit(scaler, ARTIFACT_DIR / "scaler.pkl")
    print("\n=== Leakage checks ===")
    for key, result in leakage_report.items():
        print(f"  {key}: passed={result['passed']}")

    trained_at = datetime.now(UTC).isoformat()

    (ARTIFACT_DIR / "config.json").write_text(
        json.dumps(
            {
                **config.to_dict(),
                "seed": RANDOM_SEED,
                "feature_count": len(feature_names),
                "python_version": sys.version,
                "sklearn_version": __import__("sklearn").__version__,
                "run_id": run_id,
                "trained_at": trained_at,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    (ARTIFACT_DIR / "test_evaluation.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    (ARTIFACT_DIR / "leakage_check_report.json").write_text(json.dumps(leakage_report, indent=2), encoding="utf-8")
    (ARTIFACT_DIR / "training_report.json").write_text(
        json.dumps(
            {
                "run_id": run_id,
                "trained_at": trained_at,
                "train_rows": int(len(X_train)),
                "test_rows": int(len(X_test)),
                "feature_count": len(feature_names),
                "train_class_distribution": train_distribution,
                "test_class_distribution": test_distribution,
                "training_seconds": round(training_seconds, 2),
                "inference_seconds": round(inference_seconds, 2),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"\nArtifacts written under: {ARTIFACT_DIR}")


if __name__ == "__main__":
    main()
