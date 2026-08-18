"""CICIDS2017 attack-communication graph module.

Builds a directed source-IP -> destination-IP communication graph from the
topology-bearing CICIDS2017 distribution (GeneratedLabelledFlows), entirely
independent of the ml/ feature-vector autoencoder pipeline. See
docs/attack_graph.md for the full design, schema, and limitations.
"""
