"""Packaging/validation checks for deploy/victim_agent/ -- the standalone
bundle meant to be copied to a separate Victim Windows laptop that does
NOT have the rest of this repository.

These tests never build or execute the deploy package (no venv, no pip
install, no capture, no HTTP) -- they only check that the files placed
under deploy/victim_agent/ are exactly the intended lightweight runtime
subset of victim_agent/, stay byte-identical to the source of truth (so a
future change to victim_agent/*.py can't silently drift from what actually
ships), and never leak a secret or pull in the Admin's ML/backend/DB
stack.
"""

from __future__ import annotations

import ast
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SOURCE_PACKAGE_DIR = PROJECT_ROOT / "victim_agent"
DEPLOY_ROOT = PROJECT_ROOT / "deploy" / "victim_agent"
DEPLOY_PACKAGE_DIR = DEPLOY_ROOT / "victim_agent"

# Exactly the modules victim_agent's own runtime import graph needs:
# agent.py -> telemetry, config, identity, queue, sender; flow_worker.py ->
# capture, flow, sender. Nothing outside this set is required to run
# `python -m victim_agent.agent` or FlowScoringWorker.run_once().
EXPECTED_RUNTIME_FILES = {
    "__init__.py",
    "agent.py",
    "capture.py",
    "config.py",
    "flow.py",
    "flow_worker.py",
    "identity.py",
    "queue.py",
    "sender.py",
    "telemetry.py",
}

EXPECTED_REQUIREMENTS = {"psutil", "httpx", "python-dotenv", "scapy"}

FORBIDDEN_IMPORT_PREFIXES = (
    "backend", "risk_engine", "ml", "attack_graph", "sqlalchemy",
    "torch", "numpy", "pandas", "sklearn", "fastapi", "pydantic",
    "pymysql", "mysql", "uvicorn",
)


def test_deploy_package_dir_contains_exactly_the_required_runtime_files():
    actual = {p.name for p in DEPLOY_PACKAGE_DIR.iterdir() if p.is_file()}
    assert actual == EXPECTED_RUNTIME_FILES


def test_deploy_package_files_are_byte_identical_to_source():
    """Guards against drift: if victim_agent/*.py changes but deploy/
    isn't re-synced, this fails loudly instead of silently shipping stale
    logic to the Victim laptop."""
    for name in EXPECTED_RUNTIME_FILES:
        source_bytes = (SOURCE_PACKAGE_DIR / name).read_bytes()
        deployed_bytes = (DEPLOY_PACKAGE_DIR / name).read_bytes()
        assert deployed_bytes == source_bytes, f"deploy/victim_agent/victim_agent/{name} has drifted from victim_agent/{name}"


def test_deploy_package_excludes_tests_and_local_secrets():
    assert not (DEPLOY_PACKAGE_DIR / "tests").exists()
    assert not (DEPLOY_PACKAGE_DIR / ".agent_identity.json").exists()
    assert not (DEPLOY_PACKAGE_DIR / ".env").exists()
    # Belt-and-suspenders: no file named .agent_identity.json or .env
    # anywhere under the deploy tree at all.
    assert list(DEPLOY_ROOT.rglob(".agent_identity.json")) == []
    assert list(DEPLOY_ROOT.rglob(".env")) == []


def test_deploy_env_example_has_placeholders_not_real_values():
    content = (DEPLOY_ROOT / ".env.example").read_text(encoding="utf-8")
    # Only non-comment lines matter here -- the file legitimately mentions
    # "127.0.0.1"/"localhost" inside an explanatory comment warning that
    # neither is a valid ADMIN_BASE_URL value.
    value_lines = {line.split("#", 1)[0].strip() for line in content.splitlines() if not line.strip().startswith("#")}
    value_lines.discard("")
    assert "ADMIN_BASE_URL=" in value_lines  # present, but with no value after "="
    assert "AGENT_ENROLLMENT_KEY=" in value_lines
    # The real project .env (if one exists on this dev machine) must never
    # have been copied in verbatim -- no assigned value should look like a
    # live token/IP:port.
    for line in value_lines:
        if line.startswith("ADMIN_BASE_URL="):
            assert line == "ADMIN_BASE_URL=", f"ADMIN_BASE_URL must be blank in the template, got: {line!r}"
        if line.startswith("AGENT_ENROLLMENT_KEY="):
            assert line == "AGENT_ENROLLMENT_KEY=", f"AGENT_ENROLLMENT_KEY must be blank in the template, got: {line!r}"


def test_deploy_requirements_has_only_the_expected_lightweight_dependencies():
    content = (DEPLOY_ROOT / "requirements.txt").read_text(encoding="utf-8")
    names = set()
    for line in content.splitlines():
        stripped = line.split("#", 1)[0].strip()
        if not stripped:
            continue
        names.add(stripped.split("==")[0].strip())
    assert names == EXPECTED_REQUIREMENTS


def test_deploy_requirements_matches_source_requirements_exactly():
    source = (SOURCE_PACKAGE_DIR / "requirements.txt").read_text(encoding="utf-8")
    deployed = (DEPLOY_ROOT / "requirements.txt").read_text(encoding="utf-8")
    assert deployed == source


def _imported_names_from_source(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.append(node.module)
            names.extend(alias.name for alias in node.names)
    return names


def test_deploy_package_files_import_no_backend_ml_or_db_dependencies():
    for name in EXPECTED_RUNTIME_FILES:
        imported = _imported_names_from_source(DEPLOY_PACKAGE_DIR / name)
        offending = [n for n in imported if any(n == p or n.startswith(p + ".") for p in FORBIDDEN_IMPORT_PREFIXES)]
        assert offending == [], f"{name} imports forbidden module(s): {offending}"


def test_deploy_package_top_level_files_exist():
    assert (DEPLOY_ROOT / "README.md").is_file()
    assert (DEPLOY_ROOT / "requirements.txt").is_file()
    assert (DEPLOY_ROOT / ".env.example").is_file()
    assert (DEPLOY_PACKAGE_DIR / "__init__.py").is_file()
