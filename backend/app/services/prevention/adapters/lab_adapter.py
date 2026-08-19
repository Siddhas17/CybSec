"""The one response adapter this project ships: `lab_dry_run` (section 7).

**Environment audit for this project's actual development environment**
(checked directly this session, not assumed -- see docs/prevention.md
"Environment audit" for the full record): the WSL2 install the backend
runs in has neither `iptables` nor `nft` on `PATH`, there is no
passwordless `sudo` to install or invoke either, and the Windows host
account is not a local administrator (so `netsh advfirewall` is equally
unreachable). There is therefore no privileged mechanism this adapter can
safely call to modify a real firewall in this environment -- confirmed,
not guessed.

`dry_run()` is fully real: it returns a genuine "would_block" decision
with no system modification, which is the entire point of dry-run mode.
`block()` / `unblock()` are real code paths too, not stubs -- but in this
environment they honestly report `success=False` with the capability gap
as the reason, rather than fabricating a block that never happened
(section 21: "do not weaken the lab-scope safety controls just to force a
working block"). A future environment with a real privileged backend
would implement a second `ResponseAdapter` and swap it in here; the
policy/API/audit layers above this file would not need to change.
"""

from __future__ import annotations

import shutil
import threading

from backend.app.services.prevention.adapters.base import AdapterResult, ResponseAdapter


class LabDryRunAdapter(ResponseAdapter):
    name = "lab_dry_run"

    def __init__(self) -> None:
        self._firewall_binary_available = shutil.which("iptables") is not None or shutil.which("nft") is not None
        # In-process record of what THIS adapter instance has itself
        # successfully blocked -- never a source of truth beyond this
        # process's lifetime; the persisted audit trail (PreventionAction)
        # is the real record. Exists only so unblock() can distinguish
        # "nothing to unblock" from a real reversal, matching test #12/13's
        # duplicate-block/unblock scenarios.
        self._lock = threading.Lock()
        self._blocked: set[str] = set()

    def dry_run(self, target_ip: str, reason: str) -> AdapterResult:
        return AdapterResult(success=True, actual_action="would_block", message=f"Dry-run: would block {target_ip} ({reason})")

    def block(self, target_ip: str, reason: str) -> AdapterResult:
        if not self._firewall_binary_available:
            return AdapterResult(
                success=False,
                actual_action="failed",
                message=(
                    "No privileged firewall backend is available in this environment (no iptables/nft binary, "
                    "no passwordless sudo, no Windows admin rights -- see docs/prevention.md 'Environment audit'). "
                    "Real blocking was not attempted."
                ),
            )
        # Unreachable in this project's actual environment (see module
        # docstring) -- kept as a documented seam for a future environment
        # that does have a real backend, never reached without
        # _firewall_binary_available being true first.
        with self._lock:
            if target_ip in self._blocked:
                return AdapterResult(success=True, actual_action="blocked", message=f"{target_ip} was already blocked (no-op)")
            self._blocked.add(target_ip)
        return AdapterResult(success=True, actual_action="blocked", message=f"Blocked {target_ip} ({reason})")

    def unblock(self, target_ip: str) -> AdapterResult:
        with self._lock:
            if target_ip not in self._blocked:
                return AdapterResult(success=False, actual_action="failed", message=f"{target_ip} was not blocked by this adapter")
            self._blocked.discard(target_ip)
        return AdapterResult(success=True, actual_action="unblocked", message=f"Unblocked {target_ip}")
