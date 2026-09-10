from __future__ import annotations

import json

from victim_agent.identity import load_or_create_identity, save_token


def test_creates_new_identity_when_file_missing(make_config):
    config = make_config()
    identity = load_or_create_identity(config)
    assert identity.agent_id
    assert identity.token is None
    assert config.identity_file_path.exists()


def test_identity_stable_across_multiple_loads(make_config):
    config = make_config()
    first = load_or_create_identity(config)
    second = load_or_create_identity(config)
    assert first.agent_id == second.agent_id


def test_uses_explicit_agent_id_when_no_file_exists(make_config):
    config = make_config(agent_id="victim-99")
    identity = load_or_create_identity(config)
    assert identity.agent_id == "victim-99"


def test_persisted_identity_wins_over_a_later_config_change(make_config):
    config = make_config()
    original = load_or_create_identity(config)

    changed_config = make_config(agent_id="a-different-id", identity_file_path=config.identity_file_path)
    reloaded = load_or_create_identity(changed_config)

    assert reloaded.agent_id == original.agent_id


def test_save_token_persists_across_reload(make_config):
    config = make_config()
    identity = load_or_create_identity(config)
    save_token(config, identity, "super-secret-token")

    reloaded = load_or_create_identity(config)
    assert reloaded.token == "super-secret-token"


def test_identity_file_contains_no_extra_fields(make_config):
    config = make_config()
    identity = load_or_create_identity(config)
    save_token(config, identity, "tok")

    data = json.loads(config.identity_file_path.read_text())
    assert set(data.keys()) == {"agent_id", "token"}
