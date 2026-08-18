"""Explainable, deterministic risk-scoring layer that combines the
independently-generated autoencoder anomaly score (ml/models/) with
attack-communication-graph context (attack_graph/) into a project-specific
1-10 prioritization score.

Not a classifier and not a universal cybersecurity severity standard --
see docs/risk_engine.md. The autoencoder and the attack graph remain
architecturally independent; this package is the only place their outputs
are combined, and it never feeds graph objects into the autoencoder or
vice versa.
"""
