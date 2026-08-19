"""The first live collector (section 4): real packet capture, but scoped to
an isolated, unprivileged network namespace this process creates for
itself rather than the host's shared eth0/Wi-Fi adapter.

Why this instead of arbitrary packet capture on a shared interface:
  - This machine has no Npcap/Wireshark on Windows and no tcpdump/tshark in
    WSL2, and this agent has no sudo password to install/authorize them
    (see docs/live_telemetry.md section 2 for the full environment audit).
  - `unshare --map-root-user --net` creates a *new* user + network
    namespace where the calling user is mapped to root *inside that
    namespace only* -- this grants CAP_NET_RAW there (verified: raw
    AF_PACKET sockets work) without touching the host's real root/sudo at
    all, and without any special privilege grant from the user.
  - The new namespace starts with nothing but its own private loopback
    interface -- traffic on it is exactly and only what the sensor's own
    test client/server (or another authorized process explicitly launched
    inside the same namespace) generates. This is a stronger isolation
    guarantee than capturing on eth0 would have been, and matches "own
    isolated/authorized laboratory" precisely: the namespace boundary
    makes it structurally impossible to capture anyone else's traffic.

Trade-off, stated plainly: this sees only loopback traffic inside a
namespace this process controls, not the shared LAN/eth0. Section 4
explicitly asked for the simplest reliable authorized source before
attempting broader capture -- this is that first step; a later step could
launch the same worker against a real interface once the user grants the
necessary capability (see docs/live_telemetry.md section 10 for exactly
what that would require).
"""

from __future__ import annotations

import json
import logging
import queue
import shutil
import subprocess
import sys
import threading
from datetime import UTC, datetime

from sensor.collectors.base import (
    BaseTelemetryCollector,
    CollectorHealth,
    CollectorStatus,
    RawPacketEvent,
    TcpFlags,
)
from sensor.config import PROJECT_ROOT, sensor_config

logger = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


class NetnsLoopbackCollector(BaseTelemetryCollector):
    def __init__(self, interface: str | None = None) -> None:
        self._interface = interface or sensor_config.telemetry_interface
        self._process: subprocess.Popen | None = None
        self._queue: queue.Queue[RawPacketEvent] = queue.Queue(maxsize=sensor_config.max_queued_packet_events)
        self._reader_thread: threading.Thread | None = None
        self._stderr_thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._health = CollectorHealth(status=CollectorStatus.STOPPED, interface=self._interface)

    def start(self) -> None:
        with self._lock:
            if self._process is not None and self._process.poll() is None:
                return  # already running -- start() is idempotent
            if shutil.which("unshare") is None:
                self._health.status = CollectorStatus.ERROR
                self._health.last_error = "'unshare' (util-linux) not found on PATH inside WSL2"
                raise RuntimeError(self._health.last_error)

            self._health = CollectorHealth(status=CollectorStatus.STARTING, interface=self._interface)
            worker_module = "sensor.collectors._capture_worker"
            cmd = [
                "unshare",
                "--map-root-user",
                "--net",
                "--",
                sys.executable,
                "-m",
                worker_module,
                "--interface",
                self._interface,
            ]
            try:
                self._process = subprocess.Popen(
                    cmd,
                    cwd=str(PROJECT_ROOT),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                )
            except OSError as exc:
                self._health.status = CollectorStatus.ERROR
                self._health.last_error = str(exc)
                raise RuntimeError(f"Failed to launch capture worker: {exc}") from exc

            self._reader_thread = threading.Thread(target=self._read_stdout, daemon=True)
            self._stderr_thread = threading.Thread(target=self._read_stderr, daemon=True)
            self._reader_thread.start()
            self._stderr_thread.start()

    def stop(self) -> None:
        with self._lock:
            process = self._process
        if process is None:
            return
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        if self._reader_thread is not None:
            self._reader_thread.join(timeout=5)
        if self._stderr_thread is not None:
            self._stderr_thread.join(timeout=5)
        with self._lock:
            self._health.status = CollectorStatus.STOPPED

    def health(self) -> CollectorHealth:
        with self._lock:
            # shallow copy so callers can't mutate internal state
            return CollectorHealth(**{**self._health.__dict__, "extra": dict(self._health.extra)})

    def events(self):
        while True:
            with self._lock:
                stopped = self._health.status in (CollectorStatus.STOPPED, CollectorStatus.ERROR)
            try:
                event = self._queue.get(timeout=0.5)
            except queue.Empty:
                if stopped and self._queue.empty():
                    return
                continue
            yield event

    # -- internals ------------------------------------------------------

    def _read_stdout(self) -> None:
        assert self._process is not None and self._process.stdout is not None
        try:
            for line in self._process.stdout:
                self._handle_line(line)
        except Exception as exc:  # the reader thread must never crash silently (section 13)
            with self._lock:
                self._health.status = CollectorStatus.ERROR
                self._health.last_error = f"stdout reader crashed: {exc}"
        finally:
            with self._lock:
                if self._health.status != CollectorStatus.ERROR:
                    self._health.status = CollectorStatus.STOPPED

    def _read_stderr(self) -> None:
        assert self._process is not None and self._process.stderr is not None
        for line in self._process.stderr:
            line = line.strip()
            if line:
                logger.warning("capture worker stderr: %s", line)
                with self._lock:
                    self._health.last_error = line

    def _handle_line(self, line: str) -> None:
        line = line.strip()
        if not line:
            return
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            with self._lock:
                self._health.parse_errors += 1
                self._health.last_error = f"malformed worker output: {exc}"
            return

        record_type = record.get("type")
        if record_type == "ready":
            with self._lock:
                self._health.status = CollectorStatus.RUNNING
                self._health.started_at = _now_iso()
            return
        if record_type == "stopped":
            with self._lock:
                self._health.status = CollectorStatus.STOPPED
            return
        if record_type == "parse_error":
            with self._lock:
                self._health.parse_errors += 1
                self._health.last_error = record.get("error")
            return
        if record_type != "packet":
            return

        try:
            event = self._to_event(record)
        except (KeyError, TypeError, ValueError) as exc:
            with self._lock:
                self._health.parse_errors += 1
                self._health.last_error = f"malformed packet record: {exc}"
            return

        with self._lock:
            self._health.packets_received += 1
            self._health.last_event_at = _now_iso()
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            with self._lock:
                self._health.packets_dropped += 1

    @staticmethod
    def _to_event(record: dict) -> RawPacketEvent:
        flags = record.get("tcp_flags")
        return RawPacketEvent(
            timestamp=float(record["timestamp"]),
            src_ip=str(record["src_ip"]),
            dst_ip=str(record["dst_ip"]),
            src_port=record.get("src_port"),
            dst_port=record.get("dst_port"),
            protocol=int(record["protocol"]),
            total_length=int(record["total_length"]),
            ip_header_length=int(record["ip_header_length"]),
            transport_header_length=int(record["transport_header_length"]),
            payload_length=int(record["payload_length"]),
            tcp_flags=TcpFlags(**flags) if flags else None,
            tcp_window=record.get("tcp_window"),
        )
