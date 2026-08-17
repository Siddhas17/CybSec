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
- **Python 3.12** (inside WSL2 Ubuntu) — the report's stack was documented
  against Python 3.10, but Ubuntu 24.04 LTS (the version `wsl --install -d
  Ubuntu` provisions today) ships 3.12 as its system default, and getting
  exact 3.10 would require adding the third-party `deadsnakes` PPA. 3.12
  was verified directly (see `docs/architecture.md` for the check) to
  install and import every required library — numpy, pandas, scipy,
  scikit-learn, matplotlib, networkx, python-dotenv, jupyter, and PyTorch
  (CPU build) — cleanly, so it's used instead rather than pulling in an
  unofficial repo for a version-number match alone.
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

Ubuntu 24.04's default Python is 3.12, and creating an isolated environment
the standard way (`python3 -m venv`) needs the `python3.12-venv` and
`python3-pip` OS packages, which require `sudo` — an interactive step this
setup can't do for you. To avoid that dependency entirely, this project
uses **Miniconda** instead, installed into user space with no root access
required:

```bash
# from anywhere inside WSL2 Ubuntu (not /mnt/e — keep the env on the native
# Linux filesystem for speed; only the project code lives on /mnt/e/MP)
curl -sSf -o /tmp/miniconda.sh https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh
bash /tmp/miniconda.sh -b -p $HOME/miniconda3

$HOME/miniconda3/bin/conda create -y -n attack-graph-ids -c conda-forge --override-channels python=3.12
```

(`--override-channels -c conda-forge` avoids Anaconda's default-channel
Terms of Service prompt, which isn't scriptable non-interactively.)

Activate it whenever you work on the project:

```bash
source $HOME/miniconda3/bin/activate attack-graph-ids
cd /mnt/e/MP   # the project code itself still lives on the Windows drive
python --version   # confirm 3.12.x
```

## Dependency installation

With the `attack-graph-ids` environment activated:

```bash
pip install -r requirements.txt
```

`requirements.txt` pins exact versions (not ranges) verified together on
this Python 3.12 / WSL2 Ubuntu 24.04 setup on 2026-08-17, including a
CPU-only PyTorch build (`--extra-index-url` line in the file) — this
machine has no NVIDIA GPU / no CUDA passthrough in WSL2. If you're on
different hardware with a working CUDA setup, swap the PyTorch line for the
matching command from <https://pytorch.org/get-started/locally/> instead of
assuming CPU.

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

With the `attack-graph-ids` conda environment activated and dependencies
installed:

```bash
python scripts/verify_environment.py
```

This checks the Python version, each required library (numpy, pandas,
scikit-learn, networkx, matplotlib, scipy, python-dotenv), PyTorch/CUDA if
installed, and CPU count, then prints a PASS/FAIL line per check plus an
overall result. Last run on this machine (2026-08-17): **PASS**, all 11
checks — Python 3.12.13, numpy 1.26.4, pandas 2.3.3, scikit-learn 1.9.0,
networkx 3.6.1, matplotlib 3.11.1, scipy 1.17.1, python-dotenv, torch
2.13.0+cpu, 8 CPUs, CUDA not available (CPU-only training).

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
