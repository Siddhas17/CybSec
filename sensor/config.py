"""Environment-driven sensor configuration (section 15). No machine-specific
IP addresses are hard-coded here -- everything comes from the project-root
.env, the same file backend/app/core/config.py reads.
"""

from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[1]


class SensorConfig(BaseSettings):
    model_config = SettingsConfigDict(env_file=PROJECT_ROOT / ".env", extra="ignore")

    # Master switch -- the sensor never starts capturing on its own; an
    # admin action (POST /api/v1/admin/sensor/start) is always required in
    # addition to this being true (defense in depth, section 15/22).
    telemetry_enabled: bool = False

    # Which authorized interface to capture on inside the isolated network
    # namespace the collector creates (section 3). "lo" is the only
    # interface that namespace has -- see docs/live_telemetry.md section 1
    # for why loopback-in-a-fresh-netns was chosen over the host's shared
    # eth0/Wi-Fi adapter.
    telemetry_interface: str = "lo"

    # Flow reconstruction (sensor/normalization/flow_reconstruction.py)
    flow_idle_timeout_seconds: float = 30.0  # no packet on this 5-tuple for this long -> flow ends
    flow_max_duration_seconds: float = 300.0  # hard cap so one long-lived connection can't grow unbounded
    flow_max_packets: int = 200_000  # hard cap on packets buffered per in-progress flow
    activity_idle_threshold_seconds: float = 5.0  # CICFlowMeter's own Active/Idle burst-boundary default

    # Live graph (sensor/live_graph.py) -- bounded, so an unattended sensor
    # cannot grow memory without limit (section 9).
    live_graph_window_seconds: float = 3600.0  # edges idle longer than this are evicted
    live_graph_max_edges: int = 5000
    live_graph_cleanup_interval_seconds: float = 60.0

    # Backpressure: raw packet events queued between the capture worker
    # subprocess and the parent process before the oldest is dropped
    # (section 9's "maximum retained events").
    max_queued_packet_events: int = 20000

    @property
    def project_root(self) -> Path:
        return PROJECT_ROOT


sensor_config = SensorConfig()
