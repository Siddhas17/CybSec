# Attack Graph Module

## Status: blocked on data acquisition (2026-08-18)

Phase 2 (attack-graph generation) cannot start implementation yet. This
document currently records only the blocker and the plan; it will be
filled in with the actual schema, aggregation strategy, and results once
the required data is available.

## Purpose

Build a directed graph of observed network communication (source ->
destination) from CICIDS2017 flow records, annotate it with benign/attack
traffic statistics per edge and node, and compute graph-level metrics. This
runs as an independent branch from the autoencoder (see
[architecture.md](architecture.md) section 2) and both outputs are combined
later by the risk engine — the attack graph is not passed through or
combined with the autoencoder at this stage.

## Blocker: no topology fields in the acquired raw data

The raw CICIDS2017 files currently in `ml/datasets/raw/` (`MachineLearningCSV.zip`
distribution, 8 files, verified 2026-08-18 by inspecting every file's header
directly) contain 79 columns: 77 numeric CICFlowMeter flow-statistics
features, `Destination Port`, and `Label`. They do **not** contain:

- Source IP
- Destination IP
- Source Port
- Protocol
- Timestamp
- Flow ID

This was already anticipated in
[cleaning_decision_report.md](cleaning_decision_report.md) (Phase 1). A
source -> destination graph cannot be built from this data without
fabricating host identifiers, which this project will not do.

**Resolution in progress:** acquiring `GeneratedLabelledFlows.zip` (a.k.a.
`TrafficLabelling`), the sibling CICIDS2017 distribution from the same
official source (https://www.unb.ca/cic/datasets/ids-2017.html) that
retains `Flow ID, Source IP, Source Port, Destination IP, Destination Port,
Protocol, Timestamp` alongside the same 78 CICFlowMeter features and Label.
This is the same underlying captures as the already-acquired
`MachineLearningCSV.zip`, not a different dataset — no change to the
Phase 1 pipeline or its 67-feature contract is implied.

Until these files are acquired and their schema is verified with the
existing generic inspector (`ml/preprocessing/inspect_dataset.py`), no
graph-generation code will be written, per the explicit stop condition for
this phase.

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
