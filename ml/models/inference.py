"""Reusable inference API for the persisted autoencoder.

Loads the trained model, the persisted (never refit) scaler, the exact
Phase 1 feature order, and the selected anomaly threshold from a saved
artifact directory (see ml/training/train_autoencoder.py). Not wired to
FastAPI or any live service -- this is a plain Python class callable from
a script or another module.
"""

from __future__ import annotations

import json
import pickle
from pathlib import Path

import numpy as np
import pandas as pd
import torch

from ml.models.autoencoder import Autoencoder, AutoencoderConfig, reconstruction_error


class AutoencoderPredictor:
    """predict(X) -> reconstruction error, anomaly score, and anomaly flag
    for one or more raw (unscaled) flow feature vectors.

    anomaly_score is defined identically to reconstruction_error (mean
    squared error between input and reconstruction, per feature-vector) --
    see ml/models/autoencoder.reconstruction_error. Both names are exposed
    so callers can use whichever is clearer in context; this class never
    applies a risk-score transform (that belongs to a later phase).
    """

    def __init__(self, model: Autoencoder, scaler, feature_names: list[str], threshold: float):
        self.model = model
        self.model.eval()
        self.scaler = scaler
        self.feature_names = list(feature_names)
        self.threshold = float(threshold)

    @classmethod
    def load(cls, artifact_dir: Path) -> "AutoencoderPredictor":
        artifact_dir = Path(artifact_dir)
        config = AutoencoderConfig.from_dict(json.loads((artifact_dir / "config.json").read_text())["architecture"])
        model = Autoencoder(config)
        model.load_state_dict(torch.load(artifact_dir / "best_model.pt", map_location="cpu"))
        model.eval()

        with open(artifact_dir / "scaler.pkl", "rb") as f:
            scaler = pickle.load(f)

        feature_names = json.loads((artifact_dir / "feature_names.json").read_text())
        threshold = json.loads((artifact_dir / "threshold.json").read_text())["selected_threshold"]

        return cls(model=model, scaler=scaler, feature_names=feature_names, threshold=threshold)

    def _validate_and_order(self, X) -> np.ndarray:
        """Accepts a pandas DataFrame (validated and reordered against
        self.feature_names -- raises if any required column is missing) or
        a raw numpy array/list (trusted to already be in self.feature_names
        order; only the column count is checked)."""
        if isinstance(X, pd.DataFrame):
            missing = [c for c in self.feature_names if c not in X.columns]
            if missing:
                raise ValueError(f"Missing required feature column(s): {missing}")
            return X[self.feature_names].to_numpy(dtype="float64")

        arr = np.asarray(X, dtype="float64")
        if arr.ndim == 1:
            arr = arr.reshape(1, -1)
        if arr.shape[1] != len(self.feature_names):
            raise ValueError(f"Expected {len(self.feature_names)} features, got {arr.shape[1]}")
        return arr

    def predict_batch(self, X) -> dict:
        """Vectorized prediction. Returns a dict of equal-length arrays,
        one entry per input row."""
        arr = self._validate_and_order(X)
        scaled = self.scaler.transform(arr)
        tensor = torch.tensor(scaled, dtype=torch.float32)
        errors = reconstruction_error(self.model, tensor).numpy()
        is_anomaly = errors >= self.threshold
        return {
            "reconstruction_error": errors,
            "anomaly_score": errors.copy(),
            "is_anomaly": is_anomaly,
        }

    def predict(self, X) -> dict:
        """Single-sample convenience wrapper: a 1D array, a pandas Series,
        or a single-row DataFrame returns scalar values; anything else
        (2D array, multi-row DataFrame) returns predict_batch()'s arrays."""
        single = isinstance(X, pd.Series) or (isinstance(X, np.ndarray) and X.ndim == 1)
        if isinstance(X, pd.DataFrame) and len(X) == 1:
            single = True

        result = self.predict_batch(X)
        if single:
            return {
                "reconstruction_error": float(result["reconstruction_error"][0]),
                "anomaly_score": float(result["anomaly_score"][0]),
                "is_anomaly": bool(result["is_anomaly"][0]),
            }
        return result
