# Architecture

## 1. Current scope (Phase 1 report — core deliverable)

This document describes the **core academic track**: a single-machine,
offline detection-and-analysis pipeline, matching the submitted Phase 1
report. It does not include live telemetry, a backend API, a database, or
prevention — those are documented as a future roadmap in §3, not built now.

## 2. Design decision: the autoencoder does not consume the attack graph

The Phase 1 report's data-flow description reads as if attack graphs are
"passed through" the autoencoder. Taken literally that isn't coherent:

- An autoencoder is trained on **fixed-length feature vectors** (numeric
  flow features — packet counts, byte counts, durations, flags, etc.). It
  reconstructs a vector and scores anomaly by reconstruction error.
- A graph (nodes = hosts/services, edges = connections) is a different data
  structure. A model that natively consumes graph structure would be a
  **graph neural network (GNN)**, which the report's own literature survey
  treats as a separate technique — not what's being built here.

**Decision:** run these as two independent branches over the same source
flow records, and merge only at the risk-scoring stage:

```
Network flow records (raw dataset)
        |
        +-----------------------------+
        |                              |
        v                              v
  Preprocessing                 Attack graph generation
  (clean, encode,                (NetworkX: nodes = hosts/
   scale numeric                  services, edges = observed
   features)                      connections/flows)
        |                              |
        v                              |
  Autoencoder                          |
  (trained on feature                  |
   vectors; reconstruction             |
   error = anomaly score)              |
        |                              |
        +--------------+---------------+
                       |
                       v
              Risk scoring (1-10)
     anomaly score + graph context (node
     degree, path to critical asset, repeat
     offenders, etc.) -> explainable score
                       |
                       v
        Visualization dashboard + alerts/reports
```

Practically: the autoencoder's per-flow anomaly score becomes an attribute
attached to the corresponding node/edge in the graph. The graph itself is
built from connection topology (source, destination, service/port,
protocol, frequency), independent of whether the autoencoder has run yet.
Risk scoring is the join point where both signals combine.

This keeps each component testable in isolation (autoencoder metrics don't
depend on graph correctness, and graph construction doesn't depend on a
trained model existing yet) and mirrors how the eventual live system would
have to work anyway (§3) — a graph builder watching topology, and a
detector scoring flows, running as separate concerns.

## 3. Future integration roadmap (not implemented in Phase 0)

The core pipeline above is deliberately structured so each stage can later
be wrapped by a live-system component **without redesigning the stage
itself**. None of the components below exist yet; this section exists so
Phase 0's structure doesn't have to be redone to accommodate them later.

```
Live telemetry (sensor on lab hosts)
        |
        v
Feature extraction  <-- reuses ml/preprocessing/ logic
        |
        v
Autoencoder          <-- reuses ml/models/ + ml/evaluation/ logic
        |
        v
Detection / classification
        |
        v
Risk engine           <-- reuses the same scoring logic as the batch pipeline
        |
        v
Attack graph           <-- reuses attack_graph/generation/ logic, fed
        |                  incrementally instead of from a static CSV
        v
FastAPI (backend/)      <-- new: ingestion + REST + orchestration
        |
        v
MySQL (database/)       <-- new: persistence for events/detections/graph
        |
        v
WebSocket                <-- new: push live detections to clients
        |
        v
React dashboard (frontend/) <-- new: replaces the Matplotlib/Jupyter
        |                          dashboard for live use
        v
Controlled prevention (prevention/) <-- new: policy -> adapter -> action,
                                          lab-only, dry-run by default
```

Mapping of *why* the current structure supports this without rework:

| Core-track module | Reused as-is by | New wrapper needed |
|---|---|---|
| `ml/preprocessing/` | live feature extraction | sensor collector feeding it structured events instead of a CSV |
| `ml/models/`, `ml/training/`, `ml/evaluation/` | live inference | a thin inference service loading the saved model (no retraining per request) |
| `attack_graph/generation/` | live graph updates | incremental update calls instead of one-shot batch build |
| risk scoring logic | live risk engine | same formula, called per-event instead of per-batch |

Top-level folders reserved for the future layer (`backend/`, `frontend/`,
`sensor/`, `database/`) are intentionally **not** created in Phase 0 — they
don't exist until that work actually starts, per the instruction not to
implement components ahead of their phase.

## 4. Out of scope, always

Per the project's safety rule: no attack/exploitation scripts are ever
part of this repository. Everything here is detection, analysis, graph
generation, anomaly scoring, and (later, lab-only) defensive response.
