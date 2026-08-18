"""Compact fully-connected autoencoder for the 67 standardized CICIDS2017
flow features (ml/datasets/processed/feature_names.json).

Architecture is configurable via AutoencoderConfig rather than hard-coded:
`dims` lists [input_dim, ...encoder hidden sizes..., latent_dim]; the
decoder is the exact mirror of `dims`. A ReLU activation follows every
Linear layer except the final decoder layer, which is left linear so the
reconstruction can take any real value (inputs are StandardScaler output,
not bounded to [0, 1] or [-1, 1]).

Trained by reconstructing only BENIGN traffic (see ml/training/train_autoencoder.py)
so that reconstruction error measures deviation from learned normal
behavior -- the anomaly score. This module has no knowledge of attack
labels, the attack graph, or risk scoring; it is a plain feature-vector
model (see docs/architecture.md section 2 and docs/attack_graph.md
section 13 for why the autoencoder and the attack graph stay independent
until the risk-scoring phase).
"""

from __future__ import annotations

from dataclasses import dataclass, field

import torch
from torch import nn

_ACTIVATIONS: dict[str, type[nn.Module]] = {
    "relu": nn.ReLU,
    "tanh": nn.Tanh,
    "leaky_relu": nn.LeakyReLU,
}


@dataclass
class AutoencoderConfig:
    dims: list[int] = field(default_factory=lambda: [67, 32, 16])
    activation: str = "relu"
    dropout: float = 0.0

    @property
    def input_dim(self) -> int:
        return self.dims[0]

    @property
    def latent_dim(self) -> int:
        return self.dims[-1]

    def to_dict(self) -> dict:
        return {"dims": list(self.dims), "activation": self.activation, "dropout": self.dropout}

    @classmethod
    def from_dict(cls, data: dict) -> "AutoencoderConfig":
        return cls(dims=list(data["dims"]), activation=data.get("activation", "relu"), dropout=data.get("dropout", 0.0))


def _build_mlp(dims: list[int], activation: str, dropout: float, final_activation: bool) -> nn.Sequential:
    if activation not in _ACTIVATIONS:
        raise ValueError(f"Unknown activation {activation!r}, choose from {sorted(_ACTIVATIONS)}")
    act_cls = _ACTIVATIONS[activation]

    layers: list[nn.Module] = []
    num_pairs = len(dims) - 1
    for i in range(num_pairs):
        layers.append(nn.Linear(dims[i], dims[i + 1]))
        is_last_pair = i == num_pairs - 1
        if not is_last_pair or final_activation:
            layers.append(act_cls())
            if dropout > 0:
                layers.append(nn.Dropout(dropout))
    return nn.Sequential(*layers)


class Autoencoder(nn.Module):
    """Symmetric encoder/decoder MLP. forward() returns the reconstruction;
    use reconstruction_error() for the per-sample anomaly score."""

    def __init__(self, config: AutoencoderConfig):
        super().__init__()
        self.config = config
        self.encoder = _build_mlp(config.dims, config.activation, config.dropout, final_activation=True)
        self.decoder = _build_mlp(list(reversed(config.dims)), config.activation, config.dropout, final_activation=False)

    def encode(self, x: torch.Tensor) -> torch.Tensor:
        return self.encoder(x)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.decoder(self.encoder(x))


def reconstruction_error(model: Autoencoder, x: torch.Tensor) -> torch.Tensor:
    """Per-sample mean squared reconstruction error: mean((x - x_hat)^2)
    over the feature dimension. This is the anomaly score -- see
    docs/autoencoder.md "Anomaly score definition". Higher = greater
    deviation from learned normal (BENIGN) behavior."""
    model.eval()
    with torch.no_grad():
        reconstructed = model(x)
        return torch.mean((x - reconstructed) ** 2, dim=1)
