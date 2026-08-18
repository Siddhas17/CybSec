"""Unit tests for ml.models.autoencoder: input/output shapes, forward pass,
and the reconstruction-error (anomaly score) calculation. Uses a tiny
synthetic config, never the real 67-feature dataset."""

import torch

from ml.models.autoencoder import Autoencoder, AutoencoderConfig, reconstruction_error


def test_config_input_and_latent_dim():
    config = AutoencoderConfig(dims=[10, 6, 3])
    assert config.input_dim == 10
    assert config.latent_dim == 3


def test_forward_pass_preserves_input_shape():
    config = AutoencoderConfig(dims=[10, 6, 3])
    model = Autoencoder(config)
    x = torch.randn(5, 10)

    reconstructed = model(x)
    assert reconstructed.shape == (5, 10)


def test_encode_produces_latent_shape():
    config = AutoencoderConfig(dims=[10, 6, 3])
    model = Autoencoder(config)
    x = torch.randn(5, 10)

    latent = model.encode(x)
    assert latent.shape == (5, 3)


def test_reconstruction_error_shape_and_nonnegativity():
    config = AutoencoderConfig(dims=[10, 6, 3])
    model = Autoencoder(config)
    x = torch.randn(8, 10)

    errors = reconstruction_error(model, x)
    assert errors.shape == (8,)
    assert torch.all(errors >= 0)


def test_reconstruction_error_is_zero_for_perfect_reconstruction():
    config = AutoencoderConfig(dims=[4, 4])
    model = Autoencoder(config)

    # Force the decoder to exactly reproduce its input (identity-like weights).
    with torch.no_grad():
        for layer in model.encoder:
            if isinstance(layer, torch.nn.Linear):
                layer.weight.zero_()
                layer.weight.fill_diagonal_(1.0)
                layer.bias.zero_()
        for layer in model.decoder:
            if isinstance(layer, torch.nn.Linear):
                layer.weight.zero_()
                layer.bias.zero_()

    x = torch.zeros(3, 4)  # zeros pass through ReLU(identity) unchanged, decoder maps to zero bias
    errors = reconstruction_error(model, x)
    assert torch.allclose(errors, torch.zeros(3), atol=1e-6)


def test_unknown_activation_raises():
    config = AutoencoderConfig(dims=[10, 6, 3], activation="not-a-real-activation")
    try:
        Autoencoder(config)
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_config_round_trip_to_dict_from_dict():
    config = AutoencoderConfig(dims=[67, 32, 16], activation="relu", dropout=0.1)
    restored = AutoencoderConfig.from_dict(config.to_dict())
    assert restored.dims == config.dims
    assert restored.activation == config.activation
    assert restored.dropout == config.dropout
