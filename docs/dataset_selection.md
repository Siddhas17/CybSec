# Dataset Selection

Three datasets are named in the Phase 1 report: CICIDS2017, UNSW-NB15, and
KDD Cup 99. This document compares them against this project's specific
needs (autoencoder anomaly detection + attack-graph generation) and
recommends one primary dataset. No dataset is downloaded yet — this is a
comparison only, per Phase 0 scope.

## Comparison

| Criterion | CICIDS2017 | UNSW-NB15 | KDD Cup 99 |
|---|---|---|---|
| Size (as scoped in report) | ~2.8M flow records, 78 features | ~2.5M records, 49 features | ~4.9M records, 41 features |
| Era / realism | 2017, modern traffic + attacks (CICFlowMeter output) | 2015, synthetic testbed traffic (IXIA PerfectStorm), broader attack taxonomy | 1998-99 DARPA-derived, widely considered outdated |
| Attack diversity | Brute force, DoS/DDoS, web attacks, infiltration, botnet, port scan, Heartbleed | 9 categories: Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode, Worms | 4 broad categories (DoS, R2L, U2R, Probe); many attack types no longer representative of current threats |
| Host identifiers (source/dest IP, port, protocol) | **Yes** — real 5-tuple flow fields | Yes — real 5-tuple flow fields | **No** — released feature set omits IP addresses (anonymized out); only derived/aggregated stats remain |
| Attack-graph suitability | Good — can build attacker→target graphs directly from flow 5-tuples | Good — same reason | **Poor** — without host identifiers, an attack graph can't be built from the released data at all |
| Autoencoder suitability | Good — large benign-traffic volume for normal-baseline training, continuous numeric features | Good — comparable feature richness | Usable but dated; features are already heavily pre-aggregated, and ~78% of the original train records are duplicates (well-documented; motivated the NSL-KDD cleanup) |
| Known data-quality issues | NaN/Infinity values in a few derived columns (Flow Bytes/s, Flow Packets/s), some column-name inconsistencies across the 8 CSVs, class imbalance (a few attack classes like Heartbleed have very few samples), and documented label-quality issues in follow-up research (Engelen et al., 2021) | Comparatively cleaner; provided as pre-split train/test CSVs by the authors | Heavy record duplication in original release; NSL-KDD exists specifically to fix this |
| Academic credibility (current literature) | De facto modern IDS benchmark, extremely widely cited 2018-2024 | Widely cited, especially where broader attack-category taxonomy matters | Historically dominant, but increasingly flagged in modern papers as outdated for benchmarking |
| Preprocessing complexity | Moderate — cleaning NaN/Inf, standardizing column names across files, handling imbalance | Moderate — already fairly clean | Low-to-moderate if using NSL-KDD; but fundamentally missing what this project needs (host identifiers) |
| Compatibility with eventual live-detection goal | **Strong** — CICFlowMeter (the tool used to generate this dataset) is still maintained and can extract the *same* feature schema live from captured lab traffic, so the trained model's feature pipeline could later run on real lab pcaps largely unchanged | Weaker — no equivalent maintained live-extraction tool matching this exact schema | Weak — feature schema doesn't correspond to any current live-capture tool |

## Recommendation: CICIDS2017

**Primary reason:** this is the only one of the three that includes real
source/destination IP and port fields, which the attack-graph module
absolutely needs (attacker → target → service relationships are built
from exactly those fields). KDD Cup 99 doesn't ship IP data at all, which
rules it out regardless of its size or historical prominence.

Secondary reasons:
- Modern, diverse attack coverage relevant to what an examiner would
  expect from a 2025/26 project (vs. 1998-era attack types in KDD99).
- Large volume of labeled benign traffic, which fits the autoencoder's
  "train on normal, flag deviation" approach.
- CICFlowMeter (the feature-extraction tool behind this dataset) is a real,
  still-maintained tool — meaning the same feature schema can, in a later
  phase, be regenerated from live-captured lab traffic instead of only
  from the static CSVs. This directly supports the long-term live-detection
  goal without a feature-schema redesign later.
- Already the dataset explicitly named in the Phase 1 report, so this
  doesn't introduce scope drift.

**Honest caveats (not hidden):** CICIDS2017's CSVs have known NaN/Infinity
values in a couple of derived columns and some published label-quality
issues (see Engelen, Niels, et al., "Troubleshooting an Intrusion Detection
Dataset," 2021). These will need explicit handling in Phase 1
preprocessing — documented there, not glossed over in the results.

## Where to obtain it

Official source: Canadian Institute for Cybersecurity (University of New
Brunswick) — the "IDS 2017" dataset page:
`https://www.unb.ca/cic/datasets/ids-2017.html`

The page provides both raw PCAPs and the pre-extracted, labeled CICFlowMeter
CSVs (`MachineLearningCSV` / `GeneratedLabelledFlows` folder, split across
one file per day/time-window, covering Monday through Friday). **Exact
filenames and folder layout should be verified against the live download
page at acquisition time** — do not assume the names below are current;
confirm them before writing any preprocessing code, per the project rule
against assuming column/file structure.

Required action before Phase 1 can start:
1. Download the labeled flow CSVs (not just raw PCAPs) from the official
   page above.
2. Place them under `ml/datasets/raw/` (already `.gitignore`d — these files
   should not be committed).
3. Confirm actual column names/row counts by opening the files directly —
   Phase 1 preprocessing will inspect them programmatically before writing
   any transformation logic, per project rules.

Phase 1 will not begin until these files are physically present in
`ml/datasets/raw/`.
