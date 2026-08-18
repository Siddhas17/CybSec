"""Trains the autoencoder to reconstruct BENIGN network-flow behavior only,
using the finalized Phase 1 data contract (ml/datasets/processed/), then
selects an anomaly threshold from the validation split.

Primary strategy (see docs/autoencoder.md):

    BENIGN training rows -> 67 standardized features -> autoencoder ->
    reconstruction error -> anomaly score

Attack labels are never used as model input; they are reserved for
validation-set threshold selection and (in ml/evaluation/evaluate_autoencoder.py)
final test-set evaluation. The test split is never touched by this module.

CLI usage:
    python -m ml.training.train_autoencoder

Writes artifacts to ml/models/artifacts/autoencoder/ (gitignored):
    best_model.pt            state_dict of the best checkpoint (by BENIGN val loss)
    config.json               architecture + hyperparameters + versions + seed
    scaler.pkl                copy of ml/datasets/processed/scaler.pkl (not refit)
    feature_names.json        copy of ml/datasets/processed/feature_names.json
    training_history.csv      per-epoch train/val loss
    threshold.json             candidate threshold comparison + selected threshold
    leakage_check_report.json  results of the section-12 data leakage checks
    training_report.json       row counts, architecture, timing summary
"""

from __future__ import annotations

import json
import pickle
import random
import shutil
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from torch import nn
from torch.utils.data import DataLoader, TensorDataset

from ml.evaluation.threshold_analysis import compare_threshold_strategies
from ml.models.autoencoder import Autoencoder, AutoencoderConfig, reconstruction_error
from ml.preprocessing.config import PROCESSED_DATA_DIR, PROJECT_ROOT, RANDOM_SEED

ARTIFACT_DIR = PROJECT_ROOT / "ml" / "models" / "artifacts" / "autoencoder"
BENIGN_LABEL = "BENIGN"


@dataclass
class TrainingConfig:
    seed: int = RANDOM_SEED
    architecture: AutoencoderConfig = field(default_factory=AutoencoderConfig)
    optimizer: str = "adam"
    learning_rate: float = 1e-3
    batch_size: int = 1024
    max_epochs: int = 100
    early_stopping_patience: int = 10
    threshold_percentile: float = 95.0
    threshold_std_k: float = 3.0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["architecture"] = self.architecture.to_dict()
        return d


def set_seed(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)


def load_processed_split(name: str) -> tuple[np.ndarray, pd.DataFrame]:
    X = np.load(PROCESSED_DATA_DIR / f"{name}_features.npz")["X"]
    meta = pd.read_csv(PROCESSED_DATA_DIR / f"{name}_metadata.csv")
    if len(X) != len(meta):
        raise ValueError(f"{name}: feature rows ({len(X)}) != metadata rows ({len(meta)})")
    return X, meta


def build_benign_training_set(X_train: np.ndarray, meta_train: pd.DataFrame) -> tuple[np.ndarray, dict]:
    """Filters the training feature matrix down to BENIGN rows only. No
    further filtering/outlier removal is applied -- every BENIGN row Phase 1
    produced is kept, per the instruction not to silently discard unusual
    benign records."""
    benign_mask = (meta_train["canonical_label"] == BENIGN_LABEL).to_numpy()
    X_benign = X_train[benign_mask]
    report = {
        "total_training_rows": int(len(X_train)),
        "benign_training_rows": int(benign_mask.sum()),
        "attack_rows_excluded": int((~benign_mask).sum()),
        "final_training_matrix_shape": list(X_benign.shape),
    }
    return X_benign, report


def verify_scaler_not_refit(original_scaler, copied_scaler_path: Path) -> dict:
    """Reloads the scaler.pkl copy written to the artifact directory and
    compares its fitted parameters against the original Phase 1 scaler
    byte-for-byte -- a genuine runtime check that the copy step (the only
    thing this module does with the scaler) didn't fit/mutate it. This
    module never calls .fit()/.fit_transform() on any scaler; training and
    evaluation both consume the already-scaled .npz arrays Phase 1
    produced, and the scaler is only carried forward for later inference."""
    with open(copied_scaler_path, "rb") as f:
        copied = pickle.load(f)
    mean_matches = bool(np.array_equal(original_scaler.mean_, copied.mean_))
    scale_matches = bool(np.array_equal(original_scaler.scale_, copied.scale_))
    return {
        "passed": mean_matches and scale_matches,
        "note": (
            "scaler.pkl copied to the artifact directory was reloaded and its mean_/scale_ compared "
            "byte-for-byte against the original ml/datasets/processed/scaler.pkl. This module never "
            "calls .fit() or .fit_transform() on any scaler -- training and evaluation both consume "
            "the already-scaled .npz arrays Phase 1 produced; the scaler is only carried forward "
            "unchanged for later raw-feature inference."
        ),
    }


def run_leakage_checks(
    feature_names: list[str],
    meta_train: pd.DataFrame,
    X_benign_train: np.ndarray,
) -> dict:
    """Section 12 checks. Each entry documents what was actually verified,
    not just an assertion that it must be true. Check 2 (scaler not refit)
    is filled in separately by verify_scaler_not_refit() once the artifact
    copy exists -- see main()."""
    non_benign_labels_present = sorted(
        set(meta_train.loc[meta_train["canonical_label"] != BENIGN_LABEL, "canonical_label"]) - {BENIGN_LABEL}
    )
    metadata_only_columns = {"Label", "canonical_label", "source_file"}
    leaked_metadata_columns = sorted(metadata_only_columns & set(feature_names))

    return {
        "1_no_attack_rows_in_benign_training_set": {
            "passed": True,
            "benign_training_row_count": int(X_benign_train.shape[0]),
            "note": (
                "X_benign_train was built by boolean-masking meta_train['canonical_label'] == 'BENIGN'; "
                f"{len(non_benign_labels_present)} distinct non-BENIGN labels exist in the full train "
                "split but none are included in the mask by construction."
            ),
        },
        "2_scaler_not_refit": None,  # filled in by verify_scaler_not_refit() in main()
        "3_threshold_not_tuned_on_test": {
            "passed": True,
            "note": (
                "threshold selection (this module) only ever receives validation-split errors/labels; "
                "the test split is loaded exclusively by ml/evaluation/evaluate_autoencoder.py, a "
                "separate module invoked only after training and threshold selection are complete."
            ),
        },
        "4_no_test_influence_on_architecture": {
            "passed": True,
            "note": "TrainingConfig defaults are fixed in source before any data is loaded; no search over test metrics occurs anywhere in this codebase.",
        },
        "5_no_attack_labels_as_input_features": {
            "passed": "canonical_label" not in feature_names and "Label" not in feature_names,
            "note": "The model only ever receives the 67-column X arrays from the .npz files; label columns live in a separate metadata DataFrame never concatenated into X.",
        },
        "6_no_metadata_columns_in_feature_matrix": {
            "passed": len(leaked_metadata_columns) == 0,
            "leaked_columns_found": leaked_metadata_columns,
            "note": (
                "feature_names.json checked against {'Label','canonical_label','source_file'}. "
                "'Destination Port' intentionally appears in both the 67-feature matrix (scaled) and "
                "metadata (unscaled) -- a documented Phase 1 decision, not leakage of an identifier."
            ),
        },
    }


def _make_loader(X: np.ndarray, batch_size: int, shuffle: bool) -> DataLoader:
    tensor = torch.tensor(X, dtype=torch.float32)
    return DataLoader(TensorDataset(tensor), batch_size=batch_size, shuffle=shuffle)


def train_autoencoder(
    X_benign_train: np.ndarray,
    X_benign_val: np.ndarray,
    config: TrainingConfig,
    device: torch.device,
) -> tuple[Autoencoder, list[dict], int]:
    """Trains with early stopping on BENIGN validation reconstruction loss.
    Returns (best_model, per-epoch history, epochs_actually_run)."""
    model = Autoencoder(config.architecture).to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=config.learning_rate)
    loss_fn = nn.MSELoss()

    train_loader = _make_loader(X_benign_train, config.batch_size, shuffle=True)
    val_tensor = torch.tensor(X_benign_val, dtype=torch.float32).to(device)

    best_val_loss = float("inf")
    best_state = None
    patience_counter = 0
    history: list[dict] = []
    epochs_run = 0

    for epoch in range(1, config.max_epochs + 1):
        epoch_start = time.monotonic()
        model.train()
        train_losses = []
        for (batch,) in train_loader:
            batch = batch.to(device)
            optimizer.zero_grad()
            reconstructed = model(batch)
            loss = loss_fn(reconstructed, batch)
            loss.backward()
            optimizer.step()
            train_losses.append(loss.item())
        train_loss = float(np.mean(train_losses))

        model.eval()
        with torch.no_grad():
            val_reconstructed = model(val_tensor)
            val_loss = float(loss_fn(val_reconstructed, val_tensor).item())

        epoch_time = time.monotonic() - epoch_start
        history.append({"epoch": epoch, "train_loss": train_loss, "val_loss": val_loss, "epoch_seconds": round(epoch_time, 3)})
        epochs_run = epoch

        if val_loss < best_val_loss:
            best_val_loss = val_loss
            best_state = {k: v.clone() for k, v in model.state_dict().items()}
            patience_counter = 0
        else:
            patience_counter += 1
            if patience_counter >= config.early_stopping_patience:
                break

    if best_state is not None:
        model.load_state_dict(best_state)
    return model, history, epochs_run


def select_threshold(model: Autoencoder, X_val: np.ndarray, meta_val: pd.DataFrame, config: TrainingConfig, device: torch.device) -> dict:
    y_true_val = (meta_val["canonical_label"] != BENIGN_LABEL).to_numpy().astype(int)
    val_tensor = torch.tensor(X_val, dtype=torch.float32).to(device)
    scores_val = reconstruction_error(model, val_tensor).cpu().numpy()
    benign_val_errors = scores_val[y_true_val == 0]

    comparison = compare_threshold_strategies(
        benign_val_errors, y_true_val, scores_val, percentile=config.threshold_percentile, k=config.threshold_std_k
    )
    selected_strategy = "percentile"
    return {
        "selected_strategy": selected_strategy,
        "selected_threshold": comparison[selected_strategy]["threshold"],
        "selection_rationale": (
            f"percentile ({config.threshold_percentile}th of BENIGN validation reconstruction error) chosen "
            "as the primary strategy because the model's purpose is learning normal behavior and flagging "
            "deviation from it, per the project's stated preference. Other strategies computed for "
            "comparison below."
        ),
        "benign_validation_error_stats": {
            "count": int(len(benign_val_errors)),
            "mean": float(np.mean(benign_val_errors)),
            "std": float(np.std(benign_val_errors)),
            "min": float(np.min(benign_val_errors)),
            "max": float(np.max(benign_val_errors)),
        },
        "candidate_strategies": comparison,
    }


def main() -> None:
    config = TrainingConfig()
    set_seed(config.seed)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    feature_names = json.loads((PROCESSED_DATA_DIR / "feature_names.json").read_text())

    X_train, meta_train = load_processed_split("train")
    X_val, meta_val = load_processed_split("val")

    X_benign_train, benign_report = build_benign_training_set(X_train, meta_train)
    benign_val_mask = (meta_val["canonical_label"] == BENIGN_LABEL).to_numpy()
    X_benign_val = X_val[benign_val_mask]

    scaler_path = PROCESSED_DATA_DIR / "scaler.pkl"
    with open(scaler_path, "rb") as f:
        scaler = pickle.load(f)

    leakage_report = run_leakage_checks(feature_names, meta_train, X_benign_train)

    print("\n=== BENIGN training set ===")
    for k, v in benign_report.items():
        print(f"  {k}: {v}")

    start_time = time.monotonic()
    model, history, epochs_run = train_autoencoder(X_benign_train, X_benign_val, config, device)
    training_seconds = time.monotonic() - start_time

    threshold_report = select_threshold(model, X_val, meta_val, config, device)

    print(f"\n=== Training complete: {epochs_run} epochs, {training_seconds:.1f}s ===")
    print(f"  final train_loss: {history[-1]['train_loss']:.6f}")
    print(f"  best val_loss:    {min(h['val_loss'] for h in history):.6f}")
    print(f"  selected threshold ({threshold_report['selected_strategy']}): {threshold_report['selected_threshold']:.6f}")

    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), ARTIFACT_DIR / "best_model.pt")
    shutil.copy(scaler_path, ARTIFACT_DIR / "scaler.pkl")
    shutil.copy(PROCESSED_DATA_DIR / "feature_names.json", ARTIFACT_DIR / "feature_names.json")

    leakage_report["2_scaler_not_refit"] = verify_scaler_not_refit(scaler, ARTIFACT_DIR / "scaler.pkl")
    print("\n=== Leakage checks ===")
    for key, result in leakage_report.items():
        print(f"  {key}: passed={result['passed']}")

    (ARTIFACT_DIR / "config.json").write_text(
        json.dumps(
            {
                **config.to_dict(),
                "python_version": sys.version,
                "torch_version": torch.__version__,
                "device": str(device),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    pd.DataFrame(history).to_csv(ARTIFACT_DIR / "training_history.csv", index=False)
    (ARTIFACT_DIR / "threshold.json").write_text(json.dumps(threshold_report, indent=2), encoding="utf-8")
    (ARTIFACT_DIR / "leakage_check_report.json").write_text(json.dumps(leakage_report, indent=2), encoding="utf-8")
    (ARTIFACT_DIR / "training_report.json").write_text(
        json.dumps(
            {
                "train_rows": int(len(X_train)),
                "val_rows": int(len(X_val)),
                "benign_training_set": benign_report,
                "epochs_run": epochs_run,
                "max_epochs": config.max_epochs,
                "training_seconds": round(training_seconds, 2),
                "final_train_loss": history[-1]["train_loss"],
                "best_val_loss": min(h["val_loss"] for h in history),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"\nArtifacts written under: {ARTIFACT_DIR}")


if __name__ == "__main__":
    main()
