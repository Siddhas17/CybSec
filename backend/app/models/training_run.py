from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.db.base import Base


class TrainingRun(Base):
    """Append-only historical snapshot of a trained model's on-disk
    artifacts (ml/models/artifacts/{autoencoder,knn}/) -- never edited, only
    inserted, mirroring PreventionAction's "new row, not an edit" convention.

    Written exclusively by model_eval_service.sync_training_run(), which
    hashes the current artifact JSON and only inserts a new row when the
    hash differs from the latest row for that component -- so this table is
    a real history of distinct training runs, not a row per API request.
    "Current" metrics shown by default elsewhere are read straight off disk
    (same pattern as model_registry.get_predictor()); this table exists for
    the training-history/browse-old-versions requirement and to give the
    PDF/CSV report exporters one consistent MySQL source of truth."""

    __tablename__ = "training_runs"
    __table_args__ = (UniqueConstraint("component", "content_hash", name="uq_training_run_component_hash"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    component: Mapped[str] = mapped_column(String(32), nullable=False, index=True)  # "autoencoder" | "knn"
    run_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)  # uuid4 hex, human-shareable
    model_version_id: Mapped[int | None] = mapped_column(ForeignKey("model_versions.id", ondelete="SET NULL"), nullable=True)

    artifact_dir: Mapped[str] = mapped_column(String(255), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    trained_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    training_duration_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    feature_count: Mapped[int | None] = mapped_column(Integer, nullable=True)

    dataset_info: Mapped[dict] = mapped_column(JSON, nullable=False)
    hyperparameters: Mapped[dict] = mapped_column(JSON, nullable=False)
    preprocessing_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    threshold: Mapped[float | None] = mapped_column(Float, nullable=True)  # autoencoder only

    metrics: Mapped[dict] = mapped_column(JSON, nullable=False)
    confusion_matrix: Mapped[dict] = mapped_column(JSON, nullable=False)
    class_distribution: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), nullable=False, index=True)
