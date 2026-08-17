"""Environment verification for the ML/attack-graph pipeline.

Run inside the WSL2 Ubuntu Python environment (not native Windows Python):

    python scripts/verify_environment.py

Prints a PASS/FAIL line per dependency plus basic hardware info. Exits with
a non-zero status code if any required check fails, so it can be used in
CI or a pre-flight check.
"""

from __future__ import annotations

import importlib
import os
import platform
import sys
from dataclasses import dataclass


@dataclass
class CheckResult:
    name: str
    ok: bool
    detail: str


REQUIRED_MODULES = [
    ("numpy", "numpy"),
    ("pandas", "pandas"),
    ("scikit-learn", "sklearn"),
    ("networkx", "networkx"),
    ("matplotlib", "matplotlib"),
    ("scipy", "scipy"),
    ("python-dotenv", "dotenv"),
]

# Optional: not required for Phase 0, checked if present.
OPTIONAL_MODULES = [
    ("torch", "torch"),
]


def check_python_version(minimum: tuple[int, int] = (3, 10)) -> CheckResult:
    actual = sys.version_info[:2]
    ok = actual >= minimum
    detail = f"{platform.python_version()} (need >= {minimum[0]}.{minimum[1]})"
    return CheckResult("Python version", ok, detail)


def check_module(display_name: str, import_name: str) -> CheckResult:
    try:
        module = importlib.import_module(import_name)
        version = getattr(module, "__version__", "unknown version")
        return CheckResult(display_name, True, version)
    except ImportError as exc:
        return CheckResult(display_name, False, f"not importable: {exc}")


def check_optional_module(display_name: str, import_name: str) -> CheckResult:
    try:
        module = importlib.import_module(import_name)
        version = getattr(module, "__version__", "unknown version")
        return CheckResult(display_name, True, f"{version} (optional, found)")
    except ImportError:
        return CheckResult(display_name, True, "not installed (optional, skipped)")


def check_cpu_count() -> CheckResult:
    count = os.cpu_count()
    ok = count is not None and count > 0
    return CheckResult("CPU count", ok, str(count))


def check_cuda() -> CheckResult:
    try:
        import torch  # noqa: local import, optional dependency
    except ImportError:
        return CheckResult("CUDA availability", True, "torch not installed, skipped")

    available = torch.cuda.is_available()
    if available:
        detail = f"available ({torch.cuda.get_device_name(0)})"
    else:
        detail = "not available (CPU-only training)"
    return CheckResult("CUDA availability", True, detail)


def run() -> int:
    results: list[CheckResult] = [check_python_version()]
    results += [check_module(name, mod) for name, mod in REQUIRED_MODULES]
    results += [check_optional_module(name, mod) for name, mod in OPTIONAL_MODULES]
    results.append(check_cpu_count())
    results.append(check_cuda())

    width = max(len(r.name) for r in results)
    print(f"Platform: {platform.platform()}")
    print("-" * (width + 40))
    for r in results:
        status = "PASS" if r.ok else "FAIL"
        print(f"[{status}] {r.name.ljust(width)}  {r.detail}")
    print("-" * (width + 40))

    failed = [r for r in results if not r.ok]
    if failed:
        print(f"RESULT: FAIL ({len(failed)} check(s) failed)")
        return 1

    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(run())
