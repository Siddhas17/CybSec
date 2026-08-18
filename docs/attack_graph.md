# Attack Graph Module

## Status: topology data verified, awaiting approval to implement (2026-08-18)

The data blocker below is resolved: `GeneratedLabelledFlows.zip` has been
acquired and extracted to `ml/datasets/raw_labelled_flows/`, and a
read-only inspection (`ml/preprocessing/inspect_topology_dataset.py`,
full report in
[dataset_inspection_labelled_flows.md](dataset_inspection_labelled_flows.md))
confirmed all 8 files carry the required topology fields. No
`attack_graph/` code has been written yet — implementation is still
pending explicit approval, per the stop condition for this phase.

## Purpose

Build a directed graph of observed network communication (source ->
destination) from CICIDS2017 flow records, annotate it with benign/attack
traffic statistics per edge and node, and compute graph-level metrics. This
runs as an independent branch from the autoencoder (see
[architecture.md](architecture.md) section 2) and both outputs are combined
later by the risk engine — the attack graph is not passed through or
combined with the autoencoder at this stage.

## Original blocker (resolved) and verified topology data

The raw CICIDS2017 files in `ml/datasets/raw/` (`MachineLearningCSV.zip`
distribution) contain 79 columns — 77 numeric CICFlowMeter features,
`Destination Port`, and `Label` — with no Source IP, Destination IP,
Source Port, Protocol, Timestamp, or Flow ID. This was already anticipated
in [cleaning_decision_report.md](cleaning_decision_report.md) (Phase 1).

Resolved by acquiring `GeneratedLabelledFlows.zip` (a.k.a.
`TrafficLabelling`), the sibling CICIDS2017 distribution from the same
official source (https://www.unb.ca/cic/datasets/ids-2017.html), extracted
to `ml/datasets/raw_labelled_flows/` (gitignored, same as `ml/datasets/raw/`).
This is the same underlying captures as the already-acquired
`MachineLearningCSV.zip`, not a different dataset — no change to the
Phase 1 pipeline or its 67-feature contract is implied.

**Verified schema (2026-08-18, `ml/preprocessing/inspect_topology_dataset.py`,
full detail in [dataset_inspection_labelled_flows.md](dataset_inspection_labelled_flows.md)):**

- All 8 files share an identical 85-column schema: the same 79 columns as
  `ml/datasets/raw/` plus `Flow ID, Source IP, Source Port, Destination IP,
  Destination Port, Protocol, Timestamp` — all confirmed present by name in
  every file.
- `Source IP` / `Destination IP`: valid dotted-quad addresses everywhere
  except one file's known artifact (see below).
- `Source Port` / `Destination Port`: valid integers in [0, 65535].
- `Protocol`: exactly 3 distinct values across the entire dataset — `6`
  (TCP), `17` (UDP), `0` (flows CICFlowMeter couldn't attribute to
  TCP/UDP). No anomalies.
- `Timestamp`: format is `D/M/YYYY H:MM[:SS]` — **day-first**, confirmed
  by cross-referencing known capture dates (e.g. Monday file dates show
  `03/07/2017` = 3 July 2017 = Monday). Formatting is inconsistent between
  files (zero-padding and seconds present in some, not others); any
  parser must use `dayfirst=True` and tolerate mixed formats.
- **Known artifact:** `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv`
  has 288,602 fully-blank trailing rows (63% of the file) — verified as a
  distribution-specific artifact (Phase 1's `MachineLearningCSV` version
  of the same file has exactly the same 170,366 real rows with no
  padding). These rows must be dropped before graph construction.
- Label mojibake in the three "Web Attack" categories reproduces exactly
  as in Phase 1 (same U+FFFD byte); `ml/preprocessing/labels.py`'s
  existing normalization applies unchanged.
- The `Fwd Header Length` / `Fwd Header Length.1` duplicate-column quirk
  from Phase 1 reproduces here too (same CICFlowMeter header artifact).

Graph-generation code is still not written — awaiting explicit approval to
begin implementation now that data availability is confirmed.

## Planned graph schema (subject to confirmation once real columns are inspected)

```
Node:
{
    "ip": "...",
    "role": "source" | "destination" | "both"
}

Edge (aggregated across repeated flows between the same src/dst/port/protocol):
{
    "src_ip": "...",
    "dst_ip": "...",
    "protocol": ...,
    "dst_port": ...,
    "flow_count": ...,
    "attack_flow_count": ...,
    "benign_flow_count": ...,
    "attack_ratio": ...,
    "canonical_labels_seen": [...],
    "source_file": ...
}
```

`canonical_label` (from Phase 1, e.g. `DDoS`, `PortScan`, `DoS Hulk`) is
preserved per flow/edge; a derived binary `traffic_class` (`BENIGN` /
`ATTACK`) is computed from it for graph-level aggregate statistics, without
discarding the specific attack category.

## Limitations to document once implemented

- CICIDS2017 is flow data captured in a lab testbed, not a ground-truth
  multi-stage attack campaign graph. Graph structures found in it will be
  described as "attack-related communication graphs," not asserted to be
  real attack paths.
- Millions of flows require aggregation before graph construction; no
  per-flow NetworkX nodes/edges.

## Relationship to the autoencoder and risk engine

The attack graph is generated independently from the feature-vector
autoencoder. The two outputs are combined later by the risk engine.
