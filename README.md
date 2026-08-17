# Intelligent Cybersecurity System Using Attack Graphs

Final-year engineering project (Dept. of CSE) — a detection-and-analysis
cybersecurity pipeline that combines attack-graph generation with
autoencoder-based anomaly detection and explainable risk scoring.

## Objective

Given network flow data, this system:

1. Preprocesses raw flow records into clean, model-ready features.
2. Generates an attack graph from connection topology (attacker → target →
   service relationships).
3. Detects anomalous / zero-day-style traffic using a PyTorch autoencoder
   trained on normal traffic.
4. Produces an explainable risk score (1-10) by combining the anomaly
   score with graph context.
5. Visualizes results and raises alerts.

This is the **core academic deliverable**, matching the scope of the
submitted Phase 1 report: single machine, offline datasets, detection and
analysis only. See [`docs/architecture.md`](docs/architecture.md) for the
full pipeline design and the documented plan for how this later extends
into a live multi-host system with a backend API, database, and controlled
prevention — none of which is implemented yet.

## Architecture (current scope)

```
Network flow records (dataset)
        |
        +-------------------+-------------------+
        |                                       |
        v                                       v
  Preprocessing                        Attack graph generation
        |                                       |
        v                                       |
  Autoencoder (anomaly score)                   |
        |                                       |
        +-------------------+-------------------+
                             |
                             v
                   Risk scoring (1-10)
                             |
                             v
              Visualization dashboard + alerts
```

Full detail, including why the autoencoder and the attack graph are
deliberately kept as separate branches that merge at risk scoring, is in
[`docs/architecture.md`](docs/architecture.md).

## Prerequisites

- **WSL2 with an Ubuntu distribution.** All Python/ML work runs there, not
  in native Windows Python — this dev machine has Windows Smart App
  Control enabled, which blocks the native compiled-extension DLLs that
  numpy/pandas/PyTorch/scikit-learn depend on. Ubuntu is also the report's
  documented alternate OS, so this doesn't deviate from the project's
  stated stack.
- Python 3.10 (inside WSL2 Ubuntu).
- Git (for version control of this repository).

### Installing WSL2 Ubuntu

Verified state on this machine: WSL2 itself is installed and enabled
(`wsl --status` reports Default Version 2), but **no distribution is
installed yet**. Install Ubuntu from an elevated Windows terminal with:

```powershell
wsl --install -d Ubuntu
```

This downloads and installs Ubuntu, then prompts you (inside the new
Ubuntu window) to create a UNIX username and password — that part is
interactive and has to be done by you directly, not via an automated
script. A reboot may be requested afterward. After setup, confirm it
worked with:

```powershell
wsl -l -v
```

which should list `Ubuntu` as `Running` or `Stopped` with `VERSION 2`.

## Python environment setup (inside WSL2 Ubuntu)

Once Ubuntu is installed, open it (`wsl` from PowerShell, or the Ubuntu
Start Menu entry) and run:

```bash
# from the project root, accessed via /mnt/e/MP inside WSL
cd /mnt/e/MP

python3 --version   # confirm 3.10.x
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip --version
```

## Dependency installation

```bash
pip install -r requirements.txt
```

`requirements.txt` intentionally excludes PyTorch — install it separately
once the WSL2 environment is confirmed, using the CPU or CUDA command from
<https://pytorch.org/get-started/locally/> matched to whatever GPU (or lack
of one) is actually available inside WSL2. Don't install a CUDA build
blindly on a machine without a compatible NVIDIA GPU/WSL CUDA support.

## Project structure

```
ml/
  datasets/raw/         raw dataset files (gitignored, not committed)
  datasets/processed/   cleaned/feature-engineered output (gitignored)
  preprocessing/        cleaning, feature selection, scaling, splitting
  training/             autoencoder training scripts
  evaluation/           metrics, threshold selection, confusion matrix etc.
  models/               saved model artifacts (binaries gitignored)
attack_graph/
  generation/           builds the graph from flow records (NetworkX)
  analysis/             graph queries/metrics (paths, centrality, etc.)
  visualization/        graph rendering
notebooks/               exploratory analysis
tests/                   automated tests
docs/                    architecture.md, dataset_selection.md, etc.
config/                  configuration files
scripts/                 utility scripts (e.g. verify_environment.py)
requirements.txt
.env.example
```

`backend/`, `frontend/`, `sensor/`, and `database/` are intentionally not
created yet — they belong to the future live-system layer described in
`docs/architecture.md` §3, and will be added only when that phase starts.

## Dataset policy

Datasets are **not** committed to this repository (`ml/datasets/raw/` and
`ml/datasets/processed/` are gitignored). See
[`docs/dataset_selection.md`](docs/dataset_selection.md) for the full
comparison of CICIDS2017 vs UNSW-NB15 vs KDD Cup 99 and the recommendation
(CICIDS2017 — primarily because it's the only one of the three with real
source/destination IP fields, which the attack-graph module requires).

Download instructions and required files are documented there. Place
downloaded files under `ml/datasets/raw/` before starting Phase 1.

## Environment verification

Once the WSL2 Python environment and dependencies from above are in place:

```bash
python scripts/verify_environment.py
```

This checks the Python version, each required library (numpy, pandas,
scikit-learn, networkx, matplotlib, scipy, python-dotenv), PyTorch/CUDA if
installed, and CPU count, then prints a PASS/FAIL line per check plus an
overall result.

## Development roadmap

| Phase | Scope |
|---|---|
| 0 (this phase) | WSL2/Python environment, project scaffolding, git, dataset comparison, architecture docs |
| 1 | Data preprocessing (CICIDS2017) |
| 2 | Attack graph generation (NetworkX) |
| 3 | Autoencoder anomaly/zero-day detection (PyTorch) |
| 4 | Risk scoring (anomaly score + graph context → 1-10) |
| 5 | Visualization dashboard, alerts/reports, testing |
| Stretch (post-core, time permitting) | FastAPI backend, MySQL, live sensor, WebSocket push, React dashboard, controlled lab-only prevention — see `docs/architecture.md` §3 |

## Safety

This project only targets machines/networks explicitly owned or authorized
for testing (an isolated lab). No attack/exploitation scripts are part of
this repository — only detection, analysis, graph generation, anomaly
scoring, and (later, lab-only) defensive response.
