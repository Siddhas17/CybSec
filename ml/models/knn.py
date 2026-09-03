"""Config + factory for the KNN supervised baseline classifier (BENIGN vs
ATTACK), trained on the same 67 standardized CICIDS2017 features and the
same processed train/val/test split as the autoencoder
(ml/training/train_autoencoder.py). Unlike the autoencoder this is a plain
sklearn estimator -- no custom model class is needed, so this module is
just the configuration contract (KNNConfig) and a factory (build_knn).

K is fixed in source, not tuned against any split -- same "fixed config,
not searched" convention the autoencoder's TrainingConfig already uses for
its threshold_percentile.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

from sklearn.neighbors import KNeighborsClassifier


@dataclass
class KNNConfig:
    n_neighbors: int = 5
    weights: str = "distance"
    metric: str = "minkowski"
    p: int = 2
    n_jobs: int = -1

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "KNNConfig":
        return cls(
            n_neighbors=data.get("n_neighbors", 5),
            weights=data.get("weights", "distance"),
            metric=data.get("metric", "minkowski"),
            p=data.get("p", 2),
            n_jobs=data.get("n_jobs", -1),
        )


def build_knn(config: KNNConfig) -> KNeighborsClassifier:
    return KNeighborsClassifier(n_neighbors=config.n_neighbors, weights=config.weights, metric=config.metric, p=config.p, n_jobs=config.n_jobs)
