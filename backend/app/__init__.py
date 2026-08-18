"""FastAPI application layer around the validated Phase 1-4 analytical
core (ml/, attack_graph/, risk_engine/). Never duplicates ML/risk logic --
every analytical result is computed by calling those existing modules
(see backend/app/services/analytical_pipeline.py)."""
