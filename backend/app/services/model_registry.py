"""Loads the Phase 1/3/4 analytical artifacts once per process and keeps
them cached -- the backend never retrains, refits, or duplicates any of
this logic (section 3/6 of the phase instructions). Also assigns the
version identifiers persisted in the `model_versions` table.

Phases 1-3 didn't define explicit version strings of their own (Phase 4's
risk_engine did: "risk-engine-v1"). This module introduces one constant
per component so every detection/risk row can record exactly which
artifacts produced it, per section 6.
"""

from __future__ import annotations

import json
from functools import lru_cache

from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.models.model_version import ModelVersion
from ml.models.inference import AutoencoderPredictor
from risk_engine.config import RiskEngineConfig

PREPROCESSING_VERSION = "cicids2017-67feature-v1"  # ml/datasets/processed/feature_names.json contract
AUTOENCODER_VERSION = "autoencoder-v1"  # ml/models/artifacts/autoencoder/
ATTACK_GRAPH_VERSION = "attack-graph-v1"  # attack_graph/ output


@lru_cache(maxsize=1)
def get_predictor() -> AutoencoderPredictor:
    return AutoencoderPredictor.load(settings.model_path_absolute)


@lru_cache(maxsize=1)
def get_risk_config() -> RiskEngineConfig:
    path = settings.risk_config_path_absolute
    if not path.exists():
        raise FileNotFoundError(
            f"Risk engine config not found at {path}. Run `python -m risk_engine.run_pipeline` first "
            "(see docs/risk_engine.md) to generate it."
        )
    return RiskEngineConfig.load(path)


def get_or_create_model_version(db: Session, component: str, version: str, config_snapshot: dict | None = None) -> ModelVersion:
    """Idempotent: returns the existing row for (component, version) if one
    exists, else creates it. Called by ingestion/scoring so every
    detection/risk row can reference exactly which config produced it."""
    existing = (
        db.query(ModelVersion)
        .filter(ModelVersion.component == component, ModelVersion.version == version)
        .order_by(ModelVersion.id.desc())
        .first()
    )
    if existing is not None:
        return existing

    row = ModelVersion(component=component, version=version, config_snapshot=config_snapshot)
    db.add(row)
    db.flush()
    return row


def ensure_all_model_versions(db: Session) -> dict[str, ModelVersion]:
    predictor = get_predictor()
    risk_config = get_risk_config()

    autoencoder_config = json.loads((settings.model_path_absolute / "config.json").read_text())

    return {
        "preprocessing": get_or_create_model_version(db, "preprocessing", PREPROCESSING_VERSION),
        "autoencoder": get_or_create_model_version(
            db,
            "autoencoder",
            AUTOENCODER_VERSION,
            {"threshold": predictor.threshold, "architecture": autoencoder_config.get("architecture")},
        ),
        "attack_graph": get_or_create_model_version(db, "attack_graph", ATTACK_GRAPH_VERSION),
        "risk_engine": get_or_create_model_version(db, "risk_engine", risk_config.version, risk_config.to_dict()),
    }
