# Autoencoder Anomaly Detection

## Status: implemented and evaluated (2026-08-18)

Training, validation-based threshold selection, and one final test
evaluation are complete. Not implemented (deliberately out of scope for
this phase): risk scoring, FastAPI/React/MySQL/WebSockets, live detection,
prevention.

## 1. Objective

Learn normal (BENIGN) network-flow behavior from the Phase 1 standardized
feature vectors, then flag flows whose reconstruction error deviates from
that learned normal as anomalous:

```
BENIGN training data -> 67 standardized features -> autoencoder ->
reconstruction error -> anomaly score
```

The autoencoder is never trained by reconstructing attack traffic. Attack
labels are reserved for validation-set threshold selection and one final
test-set evaluation -- never for model input.

## 2. Data used

The already-finalized Phase 1 data contract (see
[cleaning_pipeline_cicids2017.md] / `docs/cleaning_decision_report.md`) is
the sole model input, reused without modification:

- **Model features**: 67 features, exact order from `ml/datasets/processed/feature_names.json`.
- **Preprocessing artifact**: `ml/datasets/processed/scaler.pkl` (sklearn `StandardScaler`, `n_features_in_=67`, fit on the training split only) -- never refit anywhere in this phase.
- **Splits**: `train_features.npz` / `val_features.npz` / `test_features.npz` (float32, already scaled) with matching `*_metadata.csv` (`Label`, `canonical_label`, `source_file`, `Destination Port`).

| Split | Rows | BENIGN | Attack |
|---|---|---|---|
| Train | 1,764,558 | 1,466,539 | 298,019 |
| Validation | 378,120 | 314,259 | 63,861 |
| Test | 378,120 | 314,259 | 63,861 |

## 3. BENIGN-only training strategy

`ml/training/train_autoencoder.py:build_benign_training_set` filters the
training feature matrix to `canonical_label == "BENIGN"` rows only, with
no further outlier removal -- every BENIGN row Phase 1 produced is kept:

- Total training rows: **1,764,558**
- BENIGN training rows: **1,466,539**
- Attack rows excluded from autoencoder training: **298,019**
- Final training matrix shape: **(1,466,539, 67)**

Early-stopping validation during training uses the BENIGN subset of the
**validation** split (314,259 rows) -- not a held-out slice of train, and
not the test split.

## 4. Architecture

Compact, approximately symmetric fully-connected autoencoder
(`ml/models/autoencoder.py`), configurable via `AutoencoderConfig` rather
than hard-coded:

| | |
|---|---|
| Input dimension | 67 |
| Encoder | Linear(67->32) + ReLU -> Linear(32->16) + ReLU |
| Latent dimension | 16 |
| Decoder | Linear(16->32) + ReLU -> Linear(32->67) |
| Output layer | Linear, no activation (reconstruction must take any real value -- inputs are StandardScaler output, not bounded) |
| Loss function | Mean squared error (`torch.nn.MSELoss`) |

`AutoencoderConfig.dims = [67, 32, 16]` is the single place this shape is
defined; changing it does not require touching the training loop.

## 5. Training configuration (reproducibility)

| | |
|---|---|
| Python | 3.12.13 (conda-forge) |
| PyTorch | 2.13.0+cpu |
| Device | CPU (`torch.cuda.is_available()` is `False` on this machine; no CUDA dependencies installed) |
| Random seed | 42 (`ml.preprocessing.config.RANDOM_SEED`, reused from Phase 1 for consistency) |
| Optimizer | Adam, lr = 1e-3 |
| Batch size | 1024 |
| Max epochs | 100 (early stopping, patience = 10 epochs on BENIGN validation loss) |
| Training subset size | 1,466,539 BENIGN training rows (full set -- no sampling; see "Performance" below) |

Full config, including versions, is persisted at
`ml/models/artifacts/autoencoder/config.json`.

## 6. Training results

- Training stopped early at **epoch 15** of a maximum 100 (patience of 10
  epochs after the best validation loss at epoch 5).
- Wall-clock training time: **96.2s** on CPU.
- Final training loss (epoch 15): **0.03921**
- Best validation loss (epoch 5, the checkpoint actually saved): **0.32574**

The persistent gap between train and validation loss (full history in
`ml/models/artifacts/autoencoder/training_history.csv`) is driven by
extreme outliers in the BENIGN validation error distribution (see
below), not by early-stopping failing to catch overfitting -- the
checkpoint used is the epoch-5 minimum, not the final epoch.

## 7. Threshold selection

Four candidate strategies were computed and compared on the **validation
split only** (`ml/evaluation/threshold_analysis.py`); the test split was
not touched at this stage:

| Strategy | Threshold | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|
| **percentile (selected)** | **0.1061** | **0.704** | **0.585** | **0.639** | **0.050** |
| mean_std (BENIGN mean + 3*std) | 468.73 | 0.500 | 0.0000 | 0.0001 | 0.0000 |
| roc (Youden's J) | 0.0133 | 0.403 | 0.953 | 0.566 | 0.287 |
| pr (F1-maximizing) | 0.1366 | 0.733 | 0.569 | 0.641 | 0.042 |

**Selected: the 95th percentile of the BENIGN validation reconstruction
error**, per the project's stated preference for a threshold derived from
learned-normal behavior.

**Why `mean_std` failed and was rejected:** BENIGN validation
reconstruction error is extremely heavy-tailed --

```
count=314,259  mean=0.326  std=156.14  min=0.00013  max=87,376.8
```

-- a handful of BENIGN flows with very large reconstruction error inflate
the mean and especially the standard deviation by orders of magnitude, so
`mean + 3*std` (468.73) sits far above virtually all attack traffic too,
catching only 3 of 63,861 validation attacks. This is a real, verified
property of the data (not a bug in the threshold code -- `evaluate_threshold`
was independently checked against a hand-computed synthetic case, see
`tests/test_threshold_analysis.py`) and is the concrete evidence for
preferring `percentile` over `mean_std` in this project, rather than
assuming it upfront.

`roc` reaches much higher recall (0.953) but at an operationally
impractical false-positive rate (28.7% of all benign traffic flagged).
`pr` performs almost identically to `percentile` (both threshold near
~0.11-0.14, F1 within 0.003 of each other) -- reinforcing that the chosen
region is a robust, non-arbitrary choice rather than a coincidence of one
metric.

## 8. Anomaly score definition

```
anomaly_score(x) = reconstruction_error(x) = mean((x - decoder(encoder(x)))^2)
```

Mean squared error between the standardized input vector and its
reconstruction, averaged over the 67 feature dimensions -- computed by
`ml.models.autoencoder.reconstruction_error`. Higher score = greater
deviation from learned normal (BENIGN) behavior. The raw continuous score
is preserved as-is; it is **not** converted to the project's 1-10 risk
score in this phase (that belongs to the risk-scoring phase).

`is_anomaly = anomaly_score >= 0.106125` (the selected threshold).

## 9. Final test evaluation

Performed once, after the model and threshold were finalized using
training + validation data only (`ml/evaluation/evaluate_autoencoder.py`
is the only module in this phase that reads
`ml/datasets/processed/test_*`). Positive/anomalous class: **1 = ATTACK**
(any non-BENIGN `canonical_label`); negative class: **0 = BENIGN**.

| Metric | Value |
|---|---|
| TP | 37,458 |
| TN | 298,701 |
| FP | 15,558 |
| FN | 26,403 |
| Precision | 0.7065 |
| Recall | 0.5866 |
| F1 | 0.6410 |
| ROC-AUC | 0.9160 |
| PR-AUC | 0.7410 |
| Benign false-positive rate | 4.95% |

Test-set results are close to validation-set results (F1 0.641 vs 0.639,
precision/recall within 0.003) -- consistent with a threshold that
generalizes rather than one overfit to the validation split. Given
CICIDS2017's severe class imbalance (test set is 83.1% BENIGN), accuracy
alone would be a misleading headline metric and is intentionally not
reported as a primary result; PR-AUC (0.741) is a more informative
imbalance-aware summary than ROC-AUC alone.

BENIGN test reconstruction error: mean 0.141, median 0.0061, std 48.7
(again heavy-tailed). ATTACK test reconstruction error: mean 0.574, median
0.345, std 1.76 -- attack errors are on average higher and less
outlier-dominated than BENIGN, consistent with the model reconstructing
typical BENIGN traffic well while attack traffic more consistently
deviates.

## 10. Per-attack-type results (test set)

| Attack Type | Sample Count | Mean Reconstruction Error | Median Reconstruction Error | Detection Rate |
|---|---|---|---|---|
| DoS Hulk | 25,927 | 0.935 | 0.968 | 91.4% |
| DDoS | 19,202 | 0.534 | 0.195 | 59.8% |
| PortScan | 13,604 | 0.027 | 0.022 | 0.8% |
| DoS GoldenEye | 1,543 | 0.385 | 0.122 | 56.8% |
| FTP-Patator | 890 | 0.011 | 0.011 | 0.1% |
| DoS slowloris | 808 | 0.509 | 0.302 | 63.9% |
| DoS Slowhttptest | 784 | 0.444 | 0.324 | 96.2% |
| SSH-Patator | 483 | 0.013 | 0.013 | 0.0% |
| Bot | 292 | 0.092 | 0.020 | 4.1% |
| Web Attack - Brute Force | 220 | 0.016 | 0.009 | 3.2% |
| Web Attack - XSS | 98 | 0.016 | 0.009 | 3.1% |
| Infiltration | 6 | 71.44 | 0.105 | 50.0% (n=6, not statistically meaningful) |
| Web Attack - Sql Injection | 3 | 0.009 | 0.008 | 0.0% (n=3, not statistically meaningful) |
| Heartbleed | 1 | 1.147 | 1.147 | 100% (n=1, not statistically meaningful) |

**Reading these results honestly:** high-volume flooding attacks (DoS
Hulk, DoS Slowhttptest, DDoS, DoS GoldenEye, DoS slowloris) are detected
well to very well -- their flow statistics genuinely deviate from typical
BENIGN traffic in ways this feature set captures. Low-and-slow /
credential-based / single-connection attacks (PortScan, FTP-Patator,
SSH-Patator, Bot, both Web Attack categories) are detected poorly --
their per-flow statistics resemble ordinary BENIGN connections closely
enough that a plain reconstruction-error autoencoder on this feature set
does not separate them well. This is evidence about *this* model and
feature set, not a general claim about autoencoders or about CICIDS2017.

This project uses the term **"unsupervised anomaly-detection capability"**
to describe these results. It does **not** claim the model "detects all
zero-day attacks" or has been proven against attacks not represented in
this dataset -- the model has only been evaluated against CICIDS2017's
own attack categories, all of which the literature already documents as
detectable by various means; nothing here demonstrates generalization to
genuinely novel attack behavior.

## 11. Data leakage checks (section 12 of the phase instructions)

All six checks passed; full detail (including the exact verification
method for each) in `ml/models/artifacts/autoencoder/leakage_check_report.json`:

1. **No attack rows in BENIGN training set** -- verified by construction (boolean mask on `canonical_label == "BENIGN"`).
2. **Scaler not refit** -- the `scaler.pkl` copy written to the artifact directory was reloaded and its `mean_`/`scale_` compared byte-for-byte against the original; this module never calls `.fit()`/`.fit_transform()` anywhere.
3. **Threshold not tuned on test** -- threshold selection only ever runs against validation-split errors/labels; the test split is loaded exclusively by a separate module (`evaluate_autoencoder.py`) invoked after training and threshold selection complete.
4. **No test influence on architecture** -- `TrainingConfig` defaults are fixed in source before any data loads; no hyperparameter search against test metrics exists anywhere in this codebase.
5. **No attack labels as input features** -- the model only ever receives the 67-column `X` arrays; label columns live in a separate metadata DataFrame never concatenated into `X`.
6. **No metadata columns in the feature matrix** -- `feature_names.json` checked against `{'Label', 'canonical_label', 'source_file'}`; none present. (`Destination Port` intentionally appears in both the scaled feature matrix and unscaled metadata -- a documented Phase 1 decision, not identifier leakage.)

## 12. Model artifacts

`ml/models/artifacts/autoencoder/` (gitignored -- regenerate via the
commands below rather than committing):

| File | Contents |
|---|---|
| `best_model.pt` | state_dict of the best checkpoint (lowest BENIGN validation loss) |
| `config.json` | architecture, hyperparameters, seed, Python/PyTorch versions, device |
| `scaler.pkl` | copy of the Phase 1 scaler (verified unchanged, never refit) |
| `feature_names.json` | copy of the Phase 1 67-feature order |
| `training_history.csv` | per-epoch train/val loss |
| `threshold.json` | all four candidate thresholds + selected threshold + rationale |
| `leakage_check_report.json` | results of the six leakage checks |
| `training_report.json` | row counts, timing summary |
| `test_evaluation.json` | confusion matrix, precision/recall/F1, ROC-AUC, PR-AUC, error stats |
| `per_attack_evaluation.csv` | the per-attack-type table above |

Regenerate with:
```
python -m ml.training.train_autoencoder
python -m ml.evaluation.evaluate_autoencoder
```

The model is loadable without retraining via
`ml.models.inference.AutoencoderPredictor.load(artifact_dir)` -- verified
against the real trained artifacts (not just synthetic test fixtures):
predictions from a freshly loaded predictor matched directly-computed
reconstruction error to float32 precision on real test-split rows.

## 13. Inference API

`ml.models.inference.AutoencoderPredictor`:

```python
predictor = AutoencoderPredictor.load(artifact_dir)
predictor.predict(X)  # -> {"reconstruction_error": ..., "anomaly_score": ..., "is_anomaly": ...}
```

- Accepts raw (unscaled) feature vectors -- a 1D/2D numpy array (trusted
  to already be in `feature_names.json` order) or a pandas DataFrame
  (validated and reordered to match `feature_names.json`; raises on any
  missing required column).
- Applies the persisted scaler internally (`scaler.transform`, never
  `.fit()`).
- `anomaly_score` is identical to `reconstruction_error` by definition
  (see section 8) -- both keys are exposed for API clarity.
- Not wired to FastAPI or any live service.

## 14. Performance / memory

The full BENIGN training matrix (1,466,539 x 67 float32) was loaded and
trained on directly -- no sampling, no streaming pipeline was needed:

- Peak memory for the whole training run (`/usr/bin/time -v`, includes
  Python/PyTorch/pandas import overhead): **~2.26 GB**.
- Training wall-clock time: **96.2s** for 15 epochs (~6.3s/epoch) on CPU.

This was well within the environment's available memory, so no reduced
training subset was necessary and none was used -- 100% of the available
1,466,539 BENIGN training rows trained the model.

## 15. Relationship to the attack graph

```
            Network Flow
                 |
      +----------+----------+
      |                     |
      v                     v
Feature Vector        Topology Metadata
      |                     |
      v                     v
 Autoencoder           Attack Graph
      |                     |
      | Anomaly Score       | Graph Context
      |                     |
      +----------+----------+
                 v
            Risk Engine
```

The autoencoder never receives NetworkX objects, graph metrics, or
topology data as input, and the attack graph (`attack_graph/`, Phase 2)
never depends on the autoencoder. Both remain independent until the
risk-scoring phase, which will combine the autoencoder's anomaly score
with the attack graph's context (node/edge statistics) -- not implemented
here.

## 16. Limitations

- Detection performance is highly uneven across attack categories (see
  section 10) -- strong on volumetric DoS/DDoS, weak on stealthy/low-volume
  attacks (PortScan, credential brute-forcing, Bot, Web Attack). A single
  global threshold cannot be simultaneously well-tuned for both regimes;
  per-category or ensemble thresholds were not implemented in this phase
  (out of scope -- "do not overbuild").
- BENIGN reconstruction error is extremely heavy-tailed (max 87,376 vs.
  median far below 1 on validation) -- a small number of BENIGN flows the
  model reconstructs very poorly. These were not investigated
  individually in this phase; they may reflect genuinely unusual (but
  still benign) traffic, or feature values at the edge of what
  `StandardScaler` handles gracefully (see Phase 1's zero-variance-column
  and duplicate-column decisions in `docs/cleaning_decision_report.md`).
- Very-low-sample categories (Infiltration n=6, Web Attack - Sql Injection
  n=3, Heartbleed n=1) have detection rates that are not statistically
  meaningful and are reported only for completeness.
- Evaluated exclusively against CICIDS2017's own documented attack
  categories. No claim is made about detection of attack behavior outside
  this dataset ("zero-day" in the literal sense of unseen-during-training
  attack *types*, not unseen-during-training attack *instances*) -- this
  project describes the model's capability as **unsupervised
  anomaly-detection**, evaluated empirically against known attack labels
  for validation purposes only.
- `attack_flow_count` on the attack graph and this model's anomaly score
  are not yet combined; nothing in this phase asserts that a high anomaly
  score at a node corresponds to that node's attack-graph activity --
  that join is explicitly deferred to the risk-scoring phase.
