from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class TrainingRunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    component: str
    run_id: str
    model_version_id: int | None
    artifact_dir: str
    content_hash: str
    trained_at: datetime | None
    training_duration_seconds: float | None
    feature_count: int | None
    dataset_info: dict
    hyperparameters: dict
    preprocessing_version: str | None
    threshold: float | None
    metrics: dict
    confusion_matrix: dict
    class_distribution: dict | None
    created_at: datetime
