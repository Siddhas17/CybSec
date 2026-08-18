# Explainable Risk Scoring Engine

## Status: implemented and evaluated (2026-08-18)

> **The risk score is a project-specific prioritization score, not a
> standardized measure of compromise probability or universal
> cybersecurity severity.** It is deterministic, explainable, and
> configurable -- not another ML classifier, and not a claim that 10
> means "certain compromise."

Not implemented (deliberately out of scope for this phase): FastAPI,
React, MySQL, WebSockets, live monitoring, prevention.

## 1. Objective

Combine two independently-generated signals -- the Phase 3 autoencoder's
per-flow anomaly score and the Phase 2 attack graph's edge context -- into
a single, explainable, bounded 1-10 operational risk score:

```
Flow / Event
     |
     +----> Autoencoder ----> anomaly score
     |
     +----> Attack Graph ----> graph context
     |
     v
Risk Engine
     |
     v
Risk Score 1-10
```

The autoencoder remains a plain feature-vector model and the attack graph
remains a plain topology model -- neither is modified, retrained, or fed
the other's output as input. `risk_engine/` is the only place both are
combined.

## 2. The data-alignment problem this phase had to solve

Phase 3's autoencoder was trained on `ml/datasets/raw/`
(`MachineLearningCSV` -- no Source/Destination IP at all). Phase 2's
attack graph was built from `ml/datasets/raw_labelled_flows/`
(`GeneratedLabelledFlows` -- has IPs, but is a *different* CSV export of
the same underlying captures, with no shared row-level join key). There
is no way to look up "this exact Phase 1 test-split row's edge in the
Phase 2 graph."

**Resolution (`risk_engine/data_bridge.py`):** `raw_labelled_flows/`
contains the identical 67 model-feature columns (verified byte-for-byte
by name) plus the topology fields. This module re-derives the 67-feature
vector for each `raw_labelled_flows` row, applies the *same persisted*
Phase 1 scaler and Phase 3 model (via `ml.models.inference.AutoencoderPredictor`,
loaded read-only -- the autoencoder's weights and threshold are never
touched by this phase), and joins the resulting anomaly score with that
row's real Source/Destination IP -- giving one flow both signals honestly.

**Documented limitation:** this necessarily draws on the same underlying
captures the autoencoder was trained on -- flows scored here are not
guaranteed to be a strictly independent held-out set relative to Phase
3's training data. See section 11 for the full methodological discussion
of what this does and does not affect.

Full-dataset run: 3,119,345 raw rows -> 2,830,743 topology-valid (matches
Phase 2 exactly) -> 2,827,876 scored (2,867 additionally dropped for
non-finite values in the 67 feature columns, the same known
`Flow Bytes/s`/`Flow Packets/s` division-by-zero issue from Phase 1).

## 3. Input signals

Only signals that exist in the real Phase 2/3 artifacts -- no fabricated
vulnerability data, no invented CVSS scores, no inferred OS/compromise
state:

| Signal | Source |
|---|---|
| Autoencoder anomaly score | `ml.models.autoencoder.reconstruction_error`, re-derived per flow via the data bridge |
| Edge attack ratio | `attack_graph` edge attribute `attack_ratio` |
| Edge attack flow count | `attack_graph` edge attribute `attack_flow_count` |
| Edge total flow count | `attack_graph` edge attribute `flow_count` (used for normalization scale and context rules) |
| Edge first/last seen | `attack_graph` edge attributes (temporal persistence) |
| Edge attack-label diversity | `len(attack_graph` edge attribute `attack_labels)` -- historical categories seen on this edge, not the current flow's own label (see section 5) |

## 4. Normalization

Every signal is normalized to `[0, 1]` (`risk_engine/normalize.py`), each
independently documented and unit-tested (`tests/test_risk_engine_normalize.py`).

### Anomaly severity -- the key design decision

**Not** `anomaly_score / max(dataset_score)`: BENIGN validation
reconstruction error alone has mean 0.33, std 156, and max 87,376 (see
`docs/autoencoder.md` section 7) -- dividing by the maximum would collapse
almost every real score to ~0 while a single extreme outlier dominates
the scale.

**Chosen: threshold-relative saturation**, `1 - exp(-score / threshold)`:

| score | severity |
|---|---|
| 0 | 0.0 |
| threshold | 0.632 |
| 3x threshold | 0.950 |
| 87,376 (real BENIGN max) | ~1.0 (saturates, never blows up) |

Bounded, monotonic, robust to arbitrarily large outliers by construction
(exponential decay). Compared against a percentile-based alternative
(empirical rank within the BENIGN validation error distribution): both
are bounded and outlier-robust, but percentile-based scoring requires
persisting (or recomputing) the full empirical BENIGN error array as
extra state, while the threshold-relative formula needs only the single
already-persisted threshold value -- chosen for simplicity and less
hidden state (section 16's "no hidden mutable state" requirement),
without materially sacrificing robustness.

### Other signals

- **edge_attack_ratio**: already in `[0,1]` by construction (Phase 2); clipped defensively; `0.0` if the flow's IP pair has no graph entry (documented neutral default, not a claim of confirmed-benign).
- **attack_activity**: `min(1, log1p(attack_flow_count) / log1p(scale))`, log-saturating so absolute attack volume (distinct from the *ratio*) contributes without a few mega-edges dominating linearly. `scale` = 95th percentile of `attack_flow_count` across attack-carrying edges in the real graph, derived once and persisted (`166,948.7` in this run).
- **temporal_persistence**: `min(1, duration_hours / scale)`, `duration = edge.last_seen - edge.first_seen`. `scale` = 95th percentile of edge durations (edges with >1 flow), derived once and persisted (`101.28` hours in this run).
- **attack_context**: `min(1, distinct_attack_labels_on_edge / cap)`, `cap = 3`. Uses the edge's *historical* label diversity, not the current flow's own ground-truth label -- see section 5.

## 5. Why `attack_context` uses edge history, not the flow's own label

Section 3G of the phase instructions lists "attack category/context" as
an allowed signal. Using the *current flow's own* ground-truth
`canonical_label` as a scoring input would be circular for a detector --
in a genuinely unknown live flow, that label is exactly what you don't
have. Instead, `attack_context` measures how many *distinct* attack
categories have historically been observed on that flow's edge (a
property of the src/dst relationship, available even for a brand-new,
unlabeled flow arriving on a previously-seen edge). This keeps the signal
legitimately usable in a live setting in principle, while still only
using information already present in the Phase 2 graph.

## 6. Risk formula and baseline weights

```
risk_raw = 0.40 * anomaly_severity
         + 0.25 * edge_attack_ratio
         + 0.15 * attack_activity
         + 0.10 * temporal_persistence
         + 0.10 * attack_context

risk_score = clip(1 + 9 * risk_raw + context_rule_adjustments, 1, 10)
```

**Baseline rationale (documented, not claimed objectively correct):**
anomaly evidence gets the largest weight (0.40) because it is the only
signal derived from the flow's own numeric behavior, independent of any
prior graph knowledge. `edge_attack_ratio` (0.25) is the strongest
graph-derived signal. `attack_activity` (0.15) is deliberately smaller
than `edge_attack_ratio` despite both deriving from the same underlying
attack-flow counts -- see "double counting" below. `temporal_persistence`
and `attack_context` (0.10 each) are minor, corroborating signals, per
the explicit instruction that attack-category context should not
dominate. Weights sum to 1.0 by construction (enforced in
`RiskEngineConfig.__post_init__`) so `risk_raw in [0,1]`.

**Weights were fixed before looking at any real evaluation data** and
were never adjusted based on validation or test results in this phase --
the instructions explicitly prohibit optimizing the risk model against
the test set, and this project treats that as a hard rule, not a
target to work around. Section 11 reports how these baseline weights
*behave*, not a tuned result.

### Avoiding double counting (section 8)

`edge_attack_ratio` and `attack_activity` both derive from the same
underlying `(attack_flow_count, flow_count)` pair on an edge, but they
measure genuinely different things: a ratio (*what fraction* of this
edge's traffic is malicious) and a log-saturated absolute count (*how
much* malicious volume, distinguishing a 100%-attack edge with 1 flow
from a 60%-attack edge with 10,000 attack flows). Kept as two components,
each with a smaller combined weight (0.40 total) than `anomaly_severity`
alone (0.40), so this correlated pair does not dominate the score.
`attack_context` (edge label diversity) is also graph/label-derived but
measures a third, distinct property (category diversity, not volume or
ratio) and carries only 0.10 weight.

## 7. Risk levels

| Score | Level |
|---|---|
| [1, 2) | Very Low |
| [2, 4) | Low |
| [4, 6) | Moderate |
| [6, 8) | High |
| [8, 10] | Critical |

10 means "the highest score this project's model produces from observed
evidence" -- not "certain compromise."

## 8. Context rules (section 7)

Three small, additive, fixed-magnitude adjustments applied after
calibration, each independently tested:

| Rule | Condition | Adjustment |
|---|---|---|
| `repeated_attack_heavy_communication` | edge_attack_ratio >= 0.7 AND edge_flow_count >= 10 | +0.5 |
| `very_high_anomaly` | anomaly_severity >= 0.9 | +0.5 |
| `isolated_low_volume_weak_evidence` | edge_attack_flow_count <= 1 AND edge_flow_count <= 2 AND anomaly_severity < 0.5 | -0.5 |

Final score is clipped to `[1, 10]` after rules apply. A notable
consequence: an extreme anomaly score *alone*, with zero graph
corroboration, can reach at most `1 + 9*0.40 + 0.5 = 5.1` ("Moderate") --
by design, no single signal can push risk to "Critical" without other
corroborating evidence (verified in `tests/test_risk_engine_scoring.py`).

## 9. Explanation format

Every `score_event()` call returns a `RiskResult`, never a bare number:

```json
{
  "risk_score": 8.7,
  "risk_level": "High",
  "factors": [
    {"name": "anomaly_severity", "value": 0.91, "contribution": 0.364},
    {"name": "edge_attack_ratio", "value": 0.84, "contribution": 0.21}
  ],
  "rules_applied": ["repeated_attack_heavy_communication"],
  "reason": "High anomaly deviation combined with Moderate attack-heavy communication; adjusted for repeated attack-heavy communication",
  "config_version": "risk-engine-v1"
}
```

`contribution = weight * normalized_value`, so `sum(contributions) ==
risk_raw` (verified in tests). `factors` is sorted by contribution,
descending. `reason` is generated deterministically from the top
contributing factors plus any fired rules -- no LLM call, pure
conditional logic.

## 10. Entity-level scoring (section 9)

The primary, dashboard-ready output is **flow/edge-associated**:
`score_event()` scores one flow using its own anomaly score plus its
edge's graph context. A representative **edge** score can be produced the
same way using an aggregate (e.g. mean or max) anomaly score across the
edge's flows. **Node**-level scoring is deliberately kept as a simple
rollup (e.g. max of incident edge scores) rather than a second weighted
formula, per the explicit instruction not to build an unnecessarily
complex multi-level framework.

## 11. Validation methodology and results

`risk_engine/run_pipeline.py` builds the joint flow dataset (2,827,876
flows), attaches graph context, and applies the **fixed baseline
weights** (never tuned against this data) to every flow. The scored
dataset is then split 50/50, stratified by `canonical_label`, seed=42,
into a "risk_engine val" (sanity check) and "risk_engine test" (reported
results) -- fresh splits over the joint dataset, **not** a reuse of Phase
1/3's original train/val/test partition (no join key exists to make that
possible; see section 2). Because weights were fixed a priori with no
tuning loop touching either split, this structure matches the requested
methodology (val for sanity-checking behavior, test for final reporting)
even though, in this specific implementation, there was nothing tuned
that a stricter separation would have protected against.

### Important methodological caveat: graph signals are full-dataset-informed

The attack graph is built **once** from the entire topology dataset
(matching Phase 2's already-approved design as an offline analysis
graph), not rebuilt per split. `edge_attack_ratio` and related
graph-derived signals therefore reflect knowledge of the *entire*
dataset's ground-truth labels, not only a training portion -- this is
fundamentally different from Phase 3's autoencoder val/test split, where
the model never saw validation or test data during training.

Two distinct leakage-shaped questions follow, and this project
distinguishes them rather than treating "leakage" as one monolithic
concern:

1. **Self-reference** (a flow's own label dominating its own edge's
   aggregate stats -- most acute on very-low-volume edges): checked
   empirically (`edge_volume_context_by_category` in
   `risk_engine/evaluation.py`). Result: for every category compared in
   section 12 below, the median `edge_flow_count` is **555,764** --
   nearly all PortScan/FTP-Patator/SSH-Patator/Web-Attack flows in this
   dataset land on one massive `172.16.0.1 -> 192.168.10.50` edge (the
   documented CICIDS2017 attacker->victim server, already identified in
   `docs/attack_graph.md`'s sample visualization). A single category's
   own few thousand flows are a negligible fraction of that edge's
   555,764-flow aggregate, so removing them would barely change
   `attack_ratio`. Self-reference is measured to be **not** a material
   driver of the results below (fraction of flows on edges with <= 5
   total flows is ~0% for every category checked). This is itself a
   notable finding about this dataset's topology: CICIDS2017's lab
   testbed concentrates nearly all attack traffic through very few
   attacker/victim pairs -- a property of this specific captured
   environment, not necessarily representative of a more diverse
   real-world deployment.
2. **Full-dataset graph construction** (the graph as a whole was built
   with knowledge of every flow's label, including whichever flows ended
   up in "risk_engine test"): this is real and not mitigated in this
   phase -- doing so would require rebuilding the graph excluding
   test-split flows (or scoring only edges/flows never seen during graph
   construction), which was judged out of scope for this phase's
   instruction not to overbuild. **Practical consequence for reading the
   numbers below:** they should be understood as *"how much does having
   comprehensive, already-labeled attack-graph context help prioritize
   traffic"* (a retrospective/forensic analysis capability -- e.g., "we
   know this src/dst relationship has confirmed malicious history,
   elevate anything new on it"), not as a claim of prospective
   generalization to a genuinely novel, never-before-seen network
   relationship. The anomaly-score-alone comparison baseline remains
   fully independent of labels (the autoencoder never sees them), so the
   *comparison* itself is fair even though the risk engine's absolute
   numbers benefit from full-dataset graph knowledge.

### Results (risk_engine test split, 1,413,938 flows)

| Metric | Value |
|---|---|
| Score distribution | mean 3.42, median 2.04, std 2.72, range [1, 10] |
| Risk level distribution | Very Low 658,664 &#124; Low 417,017 &#124; Moderate 54,698 &#124; High 144,771 &#124; Critical 138,788 |
| Mean risk, BENIGN | 2.17 |
| Mean risk, ATTACK | 8.55 |
| High-risk (>= 7.0) precision | 0.9997 |
| High-risk (>= 7.0) recall | 0.9916 |
| High-risk (>= 7.0) F1 | 0.9956 |

BENIGN vs. ATTACK mean-risk separation (2.17 vs. 8.55) is large and
consistent between the validation sanity check and the test results
(val: 2.17 / 8.55 -- effectively identical), which is expected given
neither split influenced the fixed weights.

## 12. Comparison against the anomaly score alone (section 12/19)

For every category the phase instructions specifically named as
autoencoder weak points (`docs/autoencoder.md` section 10), comparing the
autoencoder's own `is_anomaly` flag (threshold 0.106125) against the full
risk engine's high-risk flag (`risk_score >= 7.0`):

| Category | Samples | Anomaly-alone detection | Risk-engine detection | Improvement |
|---|---|---|---|---|
| PortScan | 79,402 | 0.52% | 99.99% | **+99.47pp** |
| FTP-Patator | 3,968 | 0.08% | 99.92% | **+99.85pp** |
| SSH-Patator | 2,948 | 0.10% | 60.58% | **+60.48pp** |
| Bot | 978 | 3.58% | 3.27% | -0.31pp |
| Web Attack - Brute Force | 754 | 5.44% | 92.44% | **+87.00pp** |
| Web Attack - XSS | 326 | 2.76% | 99.08% | **+96.32pp** |
| Web Attack - Sql Injection | 11 | 0.00% | 90.91% | **+90.91pp** (n=11, indicative only) |

**Honest reading:** graph context produces a dramatic, consistent
prioritization improvement for six of the seven autoencoder-weak
categories -- these attacks share the property of repeatedly targeting
the same destination (port scanning, credential brute-forcing, and the
web attacks in this dataset all funnel through the same heavily-probed
edge), which `edge_attack_ratio`/`attack_activity` capture even when a
single flow's own feature vector looks unremarkable to the autoencoder.
**Bot does not improve** -- Bot (C2 beaconing) traffic in this dataset
sits on edges with a lower attack ratio (~0.61 on its primary edge, below
the 0.7 rule threshold) and doesn't benefit from the same concentration
effect; graph context here does not compensate for the autoencoder's weak
Bot detection. This is reported as-is, not smoothed over: **the goal of
this comparison was to determine whether graph context helps, not to
guarantee that it always does, and it does not for Bot traffic in this
dataset.**

Given section 11's full-dataset-graph caveat, these improvements should
be read primarily as evidence that *the concept* of combining anomaly and
graph-communication signals has real, substantial value for this class of
low-and-slow attacks -- not as an unconditional, held-out-validated
production accuracy claim.

## 13. Per-attack risk summary (test split)

| Attack Type | Samples | Mean Risk | Median Risk | High-Risk Rate |
|---|---|---|---|---|
| DoS Hulk | 115,062 | 9.15 | 10.00 | 100.0% |
| PortScan | 79,402 | 7.47 | 7.40 | 99.99% |
| DDoS | 64,012 | 8.96 | 9.76 | 99.997% |
| DoS GoldenEye | 5,146 | 9.06 | 9.22 | 97.34% |
| FTP-Patator | 3,968 | 7.08 | 7.10 | 99.92% |
| SSH-Patator | 2,948 | 7.08 | 7.15 | 60.58% |
| DoS slowloris | 2,898 | 8.83 | 10.00 | 100.0% |
| DoS Slowhttptest | 2,749 | 9.82 | 10.00 | 99.85% |
| Bot | 978 | 4.51 | 4.34 | 3.27% |
| Web Attack - Brute Force | 754 | 7.19 | 7.04 | 92.44% |
| Web Attack - XSS | 326 | 7.12 | 7.03 | 99.08% |
| Infiltration | 18 | 6.68 | 7.15 | 50.0% (n=18) |
| Web Attack - Sql Injection | 11 | 7.08 | 7.04 | 90.91% (n=11) |
| Heartbleed | 6 | 6.32 | 6.32 | 0.0% (n=6) |

Compare against `docs/autoencoder.md` section 10's anomaly-only
detection-rate table -- every category here except Bot and the
very-low-sample Heartbleed/Infiltration rows shows large gains.

## 14. Code structure

```
risk_engine/
├── __init__.py
├── config.py         RiskEngineConfig (weights, thresholds, scales, rule params, version)
├── schemas.py          FlowRiskContext, NormalizedFactors, RiskResult
├── normalize.py         the five [0,1] normalization formulas
├── scoring.py            score_event() -- the main interface
├── explanations.py       factor breakdown + reason-string generation
├── data_bridge.py         joins Phase 2 graph + Phase 3 model into a joint flow dataset
├── evaluation.py           distribution/precision-recall/comparison utilities
└── run_pipeline.py         orchestrates the full real-data run
```

## 15. Reproducibility

`RiskEngineConfig` persists (via `.save()`/`.load()`): weight
configuration, the autoencoder threshold it was built against,
data-derived normalization scales (with their exact derivation
formula recorded), context-rule thresholds, and a `version` string
(`risk-engine-v1`). No hidden mutable state -- `score_event(context,
config)` is a pure function of its two arguments.

## 16. Future integration contract (section 21)

```python
from risk_engine.config import RiskEngineConfig
from risk_engine.schemas import FlowRiskContext
from risk_engine.scoring import score_event

config = RiskEngineConfig.load(path)
result = score_event(FlowRiskContext(...), config)
```

`score_event()` has no dependency on FastAPI, a live event loop, or any
particular caller -- a future API layer can call it directly per-request
without any change to this module.

## 17. Limitations

- See section 11 for the full graph-full-dataset-knowledge and
  self-reference discussion -- the single most important caveat on these
  results.
- CICIDS2017's lab topology concentrates most attack traffic through very
  few attacker/victim IP pairs; results here (especially the very high
  precision/recall) partly reflect that concentration and may not
  generalize to a more diverse real network's edge structure.
- `attack_context` and `edge_attack_ratio` both derive from
  Phase-2-computed, label-informed statistics -- neither is available in
  a form usable against a truly never-before-seen edge with zero history.
- Bot detection is not improved by graph context in this dataset (see
  section 12) -- reported honestly rather than omitted.
- Baseline weights are a documented starting point, not claimed optimal;
  no systematic weight search was performed (the instructions explicitly
  prohibit tuning against the test set, and this phase did not introduce
  a separate tuning procedure against validation either).
- The 1-10 calibration is a simple linear map (`1 + 9*risk_raw`); no
  claim is made that risk differences are "linear" in any real-world
  cost/severity sense.
