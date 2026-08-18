"""Anomaly-threshold selection and evaluation.

Convention used throughout: the anomalous/positive class is ATTACK (1);
BENIGN is the negative class (0) -- the autoencoder is trained to
reconstruct BENIGN behavior well, so higher reconstruction error indicates
greater deviation from normal, i.e. more likely ATTACK.

Four candidate strategies are implemented so the final choice can be
compared and justified rather than picked blind (see
docs/autoencoder.md "Threshold selection"):

- percentile: a percentile of the BENIGN validation error distribution.
  The project's primary strategy, since the model's purpose is learning
  normal behavior and flagging deviation from it.
- mean_std: BENIGN mean + k * BENIGN standard deviation.
- roc: the threshold maximizing Youden's J statistic (tpr - fpr) on
  labeled validation data.
- pr: the threshold maximizing F1 on labeled validation data.

All strategy selection happens on the validation split only -- callers
must never pass test-set errors/labels into these functions before final
evaluation (see ml/evaluation/evaluate_autoencoder.py, which is the only
module that touches the test split).
"""

from __future__ import annotations

import numpy as np
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    precision_recall_curve,
    roc_auc_score,
    roc_curve,
)


def threshold_from_percentile(benign_errors: np.ndarray, percentile: float = 95.0) -> float:
    return float(np.percentile(benign_errors, percentile))


def threshold_from_mean_std(benign_errors: np.ndarray, k: float = 3.0) -> float:
    return float(np.mean(benign_errors) + k * np.std(benign_errors))


def threshold_from_roc(y_true: np.ndarray, scores: np.ndarray) -> float:
    """Threshold maximizing Youden's J statistic (tpr - fpr)."""
    fpr, tpr, thresholds = roc_curve(y_true, scores)
    j = tpr - fpr
    return float(thresholds[np.argmax(j)])


def threshold_from_pr(y_true: np.ndarray, scores: np.ndarray) -> float:
    """Threshold maximizing F1 on the precision-recall curve."""
    precision, recall, thresholds = precision_recall_curve(y_true, scores)
    denom = precision[:-1] + recall[:-1]
    with np.errstate(invalid="ignore", divide="ignore"):
        f1 = np.where(denom > 0, 2 * precision[:-1] * recall[:-1] / denom, 0.0)
    return float(thresholds[np.argmax(f1)])


def evaluate_threshold(y_true: np.ndarray, scores: np.ndarray, threshold: float) -> dict:
    """Confusion matrix and precision/recall/F1/FPR at a fixed threshold.
    predicted anomaly (1) iff scores >= threshold."""
    y_pred = (scores >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return {
        "threshold": float(threshold),
        "tp": int(tp),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "false_positive_rate": float(fpr),
    }


def compare_threshold_strategies(
    benign_val_errors: np.ndarray,
    y_true_val: np.ndarray,
    scores_val: np.ndarray,
    percentile: float = 95.0,
    k: float = 3.0,
) -> dict:
    """Compute all four candidate thresholds and their resulting metrics on
    the (labeled) validation set, so the choice actually used can be
    justified by comparison rather than picked without evidence."""
    candidates = {
        "percentile": threshold_from_percentile(benign_val_errors, percentile),
        "mean_std": threshold_from_mean_std(benign_val_errors, k),
        "roc": threshold_from_roc(y_true_val, scores_val),
        "pr": threshold_from_pr(y_true_val, scores_val),
    }
    return {
        name: {"threshold": t, **evaluate_threshold(y_true_val, scores_val, t)}
        for name, t in candidates.items()
    }


def roc_auc(y_true: np.ndarray, scores: np.ndarray) -> float:
    return float(roc_auc_score(y_true, scores))


def pr_auc(y_true: np.ndarray, scores: np.ndarray) -> float:
    return float(average_precision_score(y_true, scores))
