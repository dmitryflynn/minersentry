"""Per-process GPU-compute telemetry.

A GPU miner is invisible to CPU accounting, but it has to saturate the GPU's
*compute* engine. Windows exposes per-process, per-engine GPU utilization through
the PDH "GPU Engine" counter set, whose instance names embed both `pid_<N>` and
`engtype_<Type>`; summing the `engtype_Compute` instances per PID gives each
process's compute load across every adapter. That is the authoritative,
vendor-neutral source (works for the NVIDIA + Intel GPUs on this box).

`nvidia-smi --query-compute-apps` is used only as enrichment — it reveals which
PIDs hold a CUDA compute context (per-process utilization reads N/A under WDDM),
which raises confidence but is never relied on alone.

Everything here is best-effort: any failure returns empty so a scan never breaks.
The parsers are pure and unit-tested; the subprocess/WinAPI wrappers are thin.
"""

from __future__ import annotations

import csv
import ctypes
import io
import re
import subprocess
import sys
from ctypes import wintypes

IS_WINDOWS = sys.platform == "win32"
_PID_RE = re.compile(r"pid_(\d+)_")
_CREATE_NO_WINDOW = 0x08000000


# -- pure parsers -----------------------------------------------------------
def parse_gpu_engine_counters(csv_text: str) -> dict[int, float]:
    """Parse `typeperf "\\GPU Engine(*)\\Utilization Percentage"` PDH-CSV output
    into {pid: summed compute-engine utilization %}. Non-Compute engines
    (3D/VideoDecode/Copy/…) are ignored."""
    rows = list(csv.reader(io.StringIO(csv_text)))
    header = data = None
    for r in rows:
        if not r:
            continue
        if r[0].startswith("(PDH-CSV"):
            header = r
        elif header is not None and len(r) == len(header):
            data = r  # keep the last data row
    if not header or not data:
        return {}
    out: dict[int, float] = {}
    for name, val in zip(header[1:], data[1:]):
        if "engtype_Compute" not in name:
            continue
        m = _PID_RE.search(name)
        if not m:
            continue
        pid = int(m.group(1))
        if pid <= 0:
            continue
        try:
            f = float(val) if val not in ("", " ") else 0.0
        except ValueError:
            continue
        out[pid] = out.get(pid, 0.0) + f
    return out


def parse_nvidia_compute_apps(text: str) -> set[int]:
    """Parse `nvidia-smi --query-compute-apps=pid,... --format=csv,noheader`
    into the set of PIDs holding a CUDA compute context."""
    pids: set[int] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.lower().startswith("pid"):
            continue
        first = line.split(",")[0].strip()
        if first.isdigit():
            pids.add(int(first))
    return pids


# -- thin collectors --------------------------------------------------------
def _run(args: list[str], timeout: float) -> str:
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                           creationflags=_CREATE_NO_WINDOW if IS_WINDOWS else 0)
        return p.stdout or ""
    except Exception:  # noqa: BLE001 - telemetry must never break a scan
        return ""


def _sample_pdh_compute() -> dict[int, float]:
    out = _run(["typeperf", r"\GPU Engine(*)\Utilization Percentage", "-sc", "1"],
               timeout=8.0)
    return parse_gpu_engine_counters(out)


def _sample_nvidia_ctx() -> set[int]:
    out = _run(["nvidia-smi", "--query-compute-apps=pid,used_gpu_memory",
                "--format=csv,noheader"], timeout=6.0)
    return parse_nvidia_compute_apps(out)


def window_owner_pids() -> set[int]:
    """PIDs owning at least one visible top-level window (miners are headless)."""
    if not IS_WINDOWS:
        return set()
    pids: set[int] = set()
    user32 = ctypes.windll.user32
    WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

    def _cb(hwnd, _lparam):
        try:
            if user32.IsWindowVisible(hwnd):
                pid = wintypes.DWORD()
                user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                if pid.value:
                    pids.add(pid.value)
        except Exception:  # noqa: BLE001
            pass
        return True

    try:
        user32.EnumWindows(WNDENUMPROC(_cb), 0)
    except Exception:  # noqa: BLE001
        return set()
    return pids


def sample() -> tuple[dict[int, float], set[int], set[int]]:
    """Return (compute_util {pid: pct}, window_pids, compute_ctx_pids).

    Safe to call on a background thread; returns empties on any failure."""
    if not IS_WINDOWS:
        return {}, set(), set()
    return _sample_pdh_compute(), window_owner_pids(), _sample_nvidia_ctx()
