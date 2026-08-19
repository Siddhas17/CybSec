"""Phase 6: real-time telemetry integration.

Replaces only the OFFLINE event source with authorized lab telemetry. The
analytical core (ml/, attack_graph/, risk_engine/) is never modified or
retrained by this package -- see docs/live_telemetry.md.

    Authorized Lab Telemetry -> RawPacketEvent -> FlowAccumulator
        -> RawFlow -> FeatureAdapter -> TelemetryEvent
        -> (existing) AnalyticalPipeline.score() -> DetectionResult
"""
