# Attack Graph Module

## Status: implemented (2026-08-18)

Graph construction, aggregation, analysis, and visualization are
implemented and have been run end-to-end against the full real dataset.
Not implemented (deliberately out of scope for this phase): autoencoder
training, risk scoring, FastAPI/React/MySQL/WebSockets, live detection,
prevention.

## 1. Data source

Raw data: `ml/datasets/raw_labelled_flows/` (gitignored, not committed) --
the CICIDS2017 `GeneratedLabelledFlows` distribution, 8 CSV files (one per
capture day/window), acquired from the same official source as the Phase 1
`MachineLearningCSV` distribution
(https://www.unb.ca/cic/datasets/ids-2017.html). Never modified by this
module; all cleaning happens in memory, per chunk, at read time.

## 2. Verified topology fields

Confirmed present, identically named, in all 8 files (full detail:
[dataset_inspection_labelled_flows.md](dataset_inspection_labelled_flows.md)):
`Flow ID`, `Source IP`, `Source Port`, `Destination IP`, `Destination
Port`, `Protocol`, `Timestamp`, `Label`, plus the same 77 CICFlowMeter
statistical columns as Phase 1. `attack_graph.schemas.REQUIRED_RAW_COLUMNS`
lists exactly the 10 columns this module reads (the 8 topology fields plus
`Total Length of Fwd Packets` / `Total Length of Bwd Packets` for byte
totals) -- the other ~75 statistical columns are skipped at read time
(`usecols`) since they aren't needed for topology and would otherwise
triple-plus memory use for no benefit.

## 3. Blank-row handling

`Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` contains 288,602
fully-blank trailing rows (verified distribution-specific artifact, not
present in Phase 1's `MachineLearningCSV` version of the same file).
`attack_graph.generation.cleaner.drop_blank_rows` drops any row where
every selected column is empty, before any other processing -- confirmed
by the full-dataset run:

| | Count |
|---|---|
| Total raw rows (8 files) | 3,119,345 |
| Blank rows dropped | 288,602 (100% from the WebAttacks file) |
| Real flows remaining | 2,830,743 |

2,830,743 matches Phase 1's total cleaned-dataset row count exactly --
strong cross-validation that no other rows were incorrectly included or
excluded.

## 4. Timestamp handling

Format is day-first (`D/M/YYYY H:MM[:SS]`), inconsistently zero-padded
across files -- verified by cross-referencing known capture dates (e.g.
the Monday file's dates read `03/07/2017` = 3 July 2017 = Monday).
`attack_graph.generation.cleaner.clean_chunk` parses with
`pd.to_datetime(..., format="mixed", dayfirst=True, errors="coerce")`;
anything that fails to parse becomes `NaT`, is dropped, and is counted in
`CleaningStats.invalid_timestamp_rows` (0 across the full real dataset).
Internally, timestamps are `pandas.Timestamp` objects; on edges they are
stored as ISO 8601 strings (`first_seen` / `last_seen`).

## 5. Graph schema

Directed graph (`networkx.DiGraph`). One node per distinct IP address seen
as a source or destination; one edge per distinct *(source IP,
destination IP)* pair, aggregated across every flow observed between that
pair (repeated flows are never represented as separate edges or objects).

### Node definition

| Field | Set by | Meaning |
|---|---|---|
| `ip` | generation | node identity |
| `total_flow_count` | generation | flows where this node is source or destination (see caveat below) |
| `benign_flow_count` / `attack_flow_count` | generation | same, split by `traffic_class` |
| `attack_ratio` | generation | `attack_flow_count / total_flow_count` |
| `in_degree` / `out_degree` / `degree` | analysis (`annotate_degree_metrics`) | pure graph-topology counts |
| `unique_source_count` / `unique_destination_count` | analysis | aliases of `in_degree` / `out_degree` -- see below |

`unique_source_count == in_degree` and `unique_destination_count ==
out_degree` **by construction**: because edges are aggregated per unique
(src, dst) pair, each distinct predecessor/successor contributes exactly
one edge. Both names are set so either is directly available as a node
attribute without the caller needing to know the equivalence.

**Documented caveat:** if `src_ip == dst_ip` (a self-loop) ever occurred,
those flows would be counted once as outgoing and once as incoming,
double-counting them in `total_flow_count`. Verified **not to occur** in
the real dataset (0 self-loop edges in the 113,769-edge full-dataset
graph).

### Edge definition

| Field | Meaning |
|---|---|
| `flow_count` | total flows aggregated onto this edge |
| `benign_flow_count` / `attack_flow_count` / `attack_ratio` | traffic_class split |
| `unique_source_ports` / `unique_destination_ports` | count of distinct ports seen (not the raw port list, to stay compact) |
| `protocols_seen` | sorted list of numeric protocol values seen (subset of `{0, 6, 17}`) |
| `first_seen` / `last_seen` | ISO 8601 timestamps, min/max across all aggregated flows |
| `total_forward_bytes` / `total_backward_bytes` | sum of `Total Length of Fwd/Bwd Packets` |
| `attack_labels` | sorted list of distinct `canonical_label` values seen on this edge, excluding `BENIGN` -- the specific attack category is never discarded in favor of the binary class |

None of these fields are risk scores.

## 6. Aggregation method

Two-stage pipeline (`attack_graph.generation.build_graph.build_graph_from_directory`):

```
CSV chunks (usecols-limited, chunksize=100,000)
        |
        v
drop blank rows -> validate/parse IP, port, protocol, timestamp
        |
        v
normalize labels -> canonical_label, traffic_class
        |
        v
accumulate into plain-dict EdgeAccumulator objects, keyed by (src_ip, dst_ip)
        |
        v
derive NodeAccumulator objects from the completed edge accumulators
        |
        v
construct one compact nx.DiGraph from the accumulators
```

Aggregation happens entirely in `attack_graph.schemas.EdgeAccumulator` /
`NodeAccumulator` (plain dataclasses, not NetworkX objects) *before* the
graph is built, so memory scales with the number of unique (src, dst)
pairs -- 113,769 on the real dataset -- not with the 2.8M raw flow
records.

## 7. Attack/benign mapping

`attack_graph.schemas.traffic_class(canonical_label)`: `canonical_label ==
"BENIGN"` maps to `"BENIGN"`; every other canonical label (`DDoS`,
`PortScan`, `Bot`, `Infiltration`, `FTP-Patator`, `SSH-Patator`, `DoS
Hulk`/`GoldenEye`/`slowloris`/`Slowhttptest`, `Heartbleed`, `Web Attack -
Brute Force`/`XSS`/`Sql Injection`) maps to `"ATTACK"`. This is a coarse
binary used only for aggregate counts; the specific attack category is
always preserved separately via `original_label` / `canonical_label`
(row level) and `attack_labels` (edge level).

**Label-encoding finding specific to this distribution:** the three "Web
Attack" labels are corrupted with a raw **0x96** byte as the category
separator (`Web Attack \x96 Brute Force`), decoded as U+0096 once the
file falls back to latin1 encoding
(`attack_graph.generation.loader._detect_encoding` -- this distribution's
`Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` is not valid
UTF-8). This is a **different** corruption than Phase 1's
`MachineLearningCSV` distribution, which used a UTF-8-encoded U+FFFD
replacement character for the same three labels
(`ml/preprocessing/labels.py`). Rather than modify Phase 1's
already-committed module, `attack_graph.generation.cleaner` reuses its
`CLEAN_LABELS` and `MOJIBAKE_TO_CANONICAL` constants directly and merges
in its own `TOPOLOGY_MOJIBAKE_TO_CANONICAL` mapping to the identical
canonical spelling. Verified: all 2,180 occurrences of the 0x96 byte in
the raw file are confined to the Label column.

## 8. Graph metrics (`attack_graph.analysis.graph_metrics`)

- `summarize_graph`: node/edge counts, total/benign/attack flow counts,
  attack-flow ratio, average degree, weakly-connected-component structure.
- `annotate_degree_metrics`: in/out/total degree, unique source/destination
  counts, written onto node attributes.
- `nodes_involved_in_attack_traffic`, `high_activity_nodes`,
  `top_attack_sources`, `top_attack_destinations`,
  `sources_with_many_destinations`, `high_attack_ratio_edges` (requires a
  minimum flow count *and* a nonzero attack ratio -- a single-flow
  100%-attack edge, or padding the list with 0%-ratio edges just to reach
  N, is not meaningful), `attack_type_distribution` (count of distinct
  edges each canonical attack label appears on).

Connected components use **weak** connectivity (edges treated as
undirected for reachability) -- the natural notion of "same communication
cluster" for a directed src->dst graph; strong connectivity (mutual
reachability) would rarely be non-trivial here since most flow pairs are
one-directional.

## 9. Temporal handling

Every edge carries `first_seen` / `last_seen` (min/max timestamp across
its aggregated flows). `build_graph_from_directory(..., time_window=(start,
end))` restricts aggregation to flows whose timestamp falls in that range
-- the user-configured time-window mode. A `hourly_windows(start, end)`
generator yields consecutive 1-hour windows a caller can feed to
`build_graph_from_directory` one at a time to get an hourly view; this
module deliberately does not maintain multiple graphs itself, per the
instruction not to overbuild temporal support in this phase.

## 10. Visualization strategy (`attack_graph.visualization.visualize_graph`)

Never renders the full graph (113,769 edges). Three selection strategies
produce a small subgraph first:

- `top_attack_edges` (default, N=30): highest `attack_flow_count` edges.
- `min_attack_threshold`: every edge at/above a given `attack_flow_count`.
- `neighborhood`: every edge touching one chosen IP, capped by flow volume.

Rendering (`draw_graph`) uses a fixed 2-category color scheme -- red for
any node/edge that carried at least one attack flow, blue for benign-only
-- with a legend, directed arrows, edge width scaled to `log(flow_count)`,
and IP labels. This is a categorical attack/benign distinction, **not** a
severity gradient or risk score. `python -m attack_graph.run_pipeline`
generates one sample (`top_attack_edges`, N=30) to
`attack_graph/output/visualizations/top_attack_edges.png`; on the real
dataset this correctly isolated the known CICIDS2017 attacker
(`172.16.0.1`) -> DDoS-victim (`192.168.10.50`) edge and the Bot C2 server
(`205.174.165.73`) fanning out to several internal hosts, without any
manual curation.

## 11. Scalability considerations

- **Column pruning**: only 10 of 85 raw columns are read (`usecols`),
  cutting per-row memory well before any cleaning happens.
- **Chunked reading**: `pandas.read_csv(..., chunksize=100_000)` bounds
  peak memory regardless of file size (largest file: 272MB / 692,703
  rows).
- **Aggregate-before-graph**: plain-dict accumulators, not NetworkX
  objects, during the scan; the final `nx.DiGraph` is built once, from
  113,769 already-aggregated edges -- not 2.8M raw flow objects.
- **Encoding detection**: one whole-file byte-decode check per file
  (`loader._detect_encoding`) rather than per-chunk try/except, since the
  chunked CSV reader needs one fixed encoding decided upfront.

### Measured performance (full real dataset, single run, WSL2 Ubuntu)

| Metric | Value |
|---|---|
| Files processed | 8 |
| Total raw rows | 3,119,345 |
| Blank rows dropped | 288,602 |
| Real flows processed into the graph | 2,830,743 |
| Nodes | 19,129 |
| Edges | 113,769 |
| Runtime | ~57s |
| Peak memory (`resource.ru_maxrss`, in-process) | ~950-960 MB |
| Peak memory (`/usr/bin/time -v`, whole process incl. imports) | ~1.23 GB |

## 12. Limitations

- CICIDS2017 is flow data captured in a lab testbed, not a ground-truth
  multi-stage attack campaign graph. This module and its docs describe an
  **"attack-related communication graph"** -- observed source/destination
  structure annotated with attack statistics. A connected path here is
  not asserted to be a real attack chain.
- `attack_flow_count` on an edge is a total across attack types, not
  per-label -- `attack_labels` records which categories were seen, not how
  many flows of each. Splitting per-label would add a `dict[str, int]` per
  edge; skipped here as unnecessary for this phase's scope.
- `unique_source_ports` / `unique_destination_ports` store counts, not the
  raw port sets, to stay compact -- if per-port detail is ever needed, it
  would have to be recomputed from a re-run with the sets preserved.
- Self-loop double-counting caveat on node stats (see section 5) --
  unverified against future data, only against the current dataset (0
  self-loops observed).
- GraphML output stringifies list/None attributes (GraphML has no native
  list type); the richer structured form is preserved in
  `edge_stats.csv` / `node_stats.csv` / `graph_summary.json`.

## 13. Relationship to the autoencoder and risk engine

The attack graph is generated independently from the feature-vector
autoencoder. The graph represents observed network communication
topology; the autoencoder operates on standardized flow feature vectors.
Their outputs will be combined later by the risk-scoring layer.

## 14. Module structure

```
attack_graph/
├── __init__.py
├── config.py              paths (TOPOLOGY_RAW_DIR, GRAPH_OUTPUT_DIR), chunk size
├── schemas.py              REQUIRED_RAW_COLUMNS, PROTOCOL_NAMES, traffic_class,
│                           CleaningStats, EdgeAccumulator, NodeAccumulator
├── run_pipeline.py         orchestrates build -> analyze -> write artifacts
├── generation/
│   ├── loader.py           chunked, column-limited CSV reading + encoding detection
│   ├── cleaner.py           blank-row/IP/port/timestamp validation, label normalization
│   └── build_graph.py       aggregation + nx.DiGraph construction, time windows
├── analysis/
│   └── graph_metrics.py     graph/node/edge statistics (no risk scores)
└── visualization/
    └── visualize_graph.py   subgraph selection + matplotlib rendering
```

## 15. Generated artifacts (gitignored: `attack_graph/output/`)

Regenerate with `python -m attack_graph.run_pipeline`:

- `graph_summary.json` -- build report + graph metrics + top-N lists + attack-type distribution
- `node_stats.csv` -- one row per node, all node attributes
- `edge_stats.csv` -- one row per edge, all edge attributes (list fields semicolon-joined)
- `graph.graphml` -- full aggregated graph (113,769 edges -- small relative to the 2.8M raw flows, since edges are pre-aggregated)
- `visualizations/top_attack_edges.png` -- sample visualization (top 30 attack-related edges)

## 16. Tests

`tests/test_attack_graph_loader.py`, `test_attack_graph_cleaner.py`,
`test_attack_graph_build.py` (integration: synthetic CSV -> cleaning ->
aggregation -> graph), `test_attack_graph_metrics.py`,
`test_attack_graph_visualization.py` -- all against small synthetic
fixtures, never the full dataset. 65/65 project-wide tests pass.
