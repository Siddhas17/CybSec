"""Reusable inference API for the persisted KNN classifier -- mirrors
ml/models/inference.py's AutoencoderPredictor, but for the supervised KNN
baseline. Kept in a separate module (rather than folded into inference.py)
because that module's docstring and imports are autoencoder/torch-specific;
KNN inference needs no torch dependency. Not wired to FastAPI or any live
service -- KNN is offline-evaluation-only (see
backend/app/services/model_registry.get_knn_predictor()'s docstring for why
it's never called from the live per-event scoring path).
"""

from __future__ import annotations

import json
import pickle
from pathlib import Path

import joblib
import numpy as np
import pandas as pd


class KNNPredictor:
    """predict(X) -> predicted class (0=BENIGN, 1=ATTACK), predicted label,
    and attack probability for one or more raw (unscaled) flow feature
    vectors. Same positive-class convention as the autoencoder pipeline:
    1 = ATTACK, 0 = BENIGN."""

    def __init__(self, model, scaler, feature_names: list[str]):
        self.model = model
        self.scaler = scaler
        self.feature_names = list(feature_names)

    @classmethod
    def load(cls, artifact_dir: Path) -> "KNNPredictor":
        artifact_dir = Path(artifact_dir)
        # model.pkl was written with joblib.dump() (ml/training/train_knn.py) --
        # joblib's on-disk format for large numpy-array-backed estimators like a
        # fitted KNeighborsClassifier is not plain-pickle-compatible, so it must
        # be loaded with joblib.load(), not pickle.load(). scaler.pkl is a plain
        # copy of Phase 1's scaler (written via shutil.copy), which IS plain
        # pickle, same as the autoencoder's inference module already assumes.
        model = joblib.load(artifact_dir / "model.pkl")
        with open(artifact_dir / "scaler.pkl", "rb") as f:
            scaler = pickle.load(f)
        feature_names = json.loads((artifact_dir / "feature_names.json").read_text())
        return cls(model=model, scaler=scaler, feature_names=feature_names)

    def _validate_and_order(self, X) -> np.ndarray:
        """Same contract as AutoencoderPredictor._validate_and_order: a
        DataFrame is validated and reordered against self.feature_names; a
        raw array/list is trusted to already be in that order."""
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
        arr = self._validate_and_order(X)
        scaled = self.scaler.transform(arr)
        predicted_class = self.model.predict(scaled)
        attack_probability = self.model.predict_proba(scaled)[:, 1]
        return {
            "predicted_class": predicted_class,
            "predicted_label": np.where(predicted_class == 1, "ATTACK", "BENIGN"),
            "attack_probability": attack_probability,
        }

    def predict(self, X) -> dict:
        single = isinstance(X, pd.Series) or (isinstance(X, np.ndarray) and X.ndim == 1)
        if isinstance(X, pd.DataFrame) and len(X) == 1:
            single = True

        result = self.predict_batch(X)
        if single:
            return {
                "predicted_class": int(result["predicted_class"][0]),
                "predicted_label": str(result["predicted_label"][0]),
                "attack_probability": float(result["attack_probability"][0]),
            }
        return result
