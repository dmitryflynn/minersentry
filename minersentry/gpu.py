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

Linux NVIDIA sampling uses nvidia-smi pmon SM activity for compute-only rows.
Unsupported metrics stay unavailable rather than inheriting whole-GPU load.

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
import warnings
from ctypes import wintypes

IS_WINDOWS = sys.platform == "win32"
_PID_RE = re.compile(r"pid_(\d+)_")
_CREATE_NO_WINDOW = 0x08000000


# -- pure parsers -----------------------------------------------------------
def parse_gpu_engine_counters(csv_text: str,
                              engine_types: tuple[str, ...] = ("Compute",)
                              ) -> dict[int, float]:
    """Parse `typeperf "\\GPU Engine(*)\\Utilization Percentage"` PDH-CSV output
    into {pid: summed utilization %} for the named engine types.

    `engine_types` is not fixed to Compute because on this hardware there IS no
    Compute instance: an NVIDIA WDDM driver reports OpenCL/CUDA work under the
    **3D** engine, so filtering on Compute alone meant the GPU signal could
    never read anything (confirmed with real OpenCL load: 567 instances, engine
    types 3D / Copy / VideoDecode / …, not one Compute). The caller decides
    which types to trust and pairs the 3D fallback with compute-context
    membership, so a game is not mistaken for a miner.
    """
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
    wanted = tuple(f"engtype_{t}" for t in engine_types)
    for name, val in zip(header[1:], data[1:]):
        if not any(w in name for w in wanted):
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
def compute_pids() -> set[int]:
    """Strict NVIDIA compute-context query for GPU-only scan scope.

    A successful empty list is valid. Driver/command/format failures must not
    become an empty scope and a misleading successful clean scan.
    """
    try:
        result = subprocess.run(
            ["nvidia-smi", "--query-compute-apps=pid", "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=6.0,
            creationflags=_CREATE_NO_WINDOW if IS_WINDOWS else 0)
    except (OSError, subprocess.SubprocessError) as error:
        raise RuntimeError(f"GPU process query failed: {error}") from error
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "no diagnostic output").strip()[:300]
        raise RuntimeError(f"GPU process query failed (exit {result.returncode}): {detail}")
    pids: set[int] = set()
    for line in result.stdout.splitlines():
        value = line.strip()
        if not value:
            continue
        if not value.isdecimal() or int(value) <= 0:
            raise RuntimeError(f"GPU process query returned unsupported data: {value[:100]}")
        pids.add(int(value))
    return pids


def _run(args: list[str], timeout: float) -> str:
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                           creationflags=_CREATE_NO_WINDOW if IS_WINDOWS else 0)
        return (p.stdout or "") if p.returncode == 0 else ""
    except Exception:  # noqa: BLE001 - telemetry must never break a scan
        return ""


def _sample_pdh(compute_ctx: set[int]) -> dict[int, float]:
    """Per-process GPU utilization from the PDH GPU Engine counters.

    Two samples, not one: a utilization counter is a RATE, and PDH's first
    sample is always 0.000000 — with `-sc 1` every value read zero, which on
    its own was enough to keep the GPU signal silent everywhere.

    Compute-engine instances are authoritative. Where the driver publishes none
    (NVIDIA under WDDM), 3D-engine load is used instead, but only for processes
    that hold a GPU compute context — a game drives the same engine and must
    not be scored as compute.
    """
    out = _run(["typeperf", r"\GPU Engine(*)\Utilization Percentage", "-sc", "2"],
               timeout=20.0)
    util = parse_gpu_engine_counters(out, ("Compute",))
    if compute_ctx:
        graphics = parse_gpu_engine_counters(out, ("3D",))
        for pid in compute_ctx:
            if pid not in util and graphics.get(pid):
                util[pid] = graphics[pid]
    return util


def _sample_nvidia_ctx() -> set[int]:
    out = _run(["nvidia-smi", "--query-compute-apps=pid,used_gpu_memory",
                "--format=csv,noheader"], timeout=6.0)
    return parse_nvidia_compute_apps(out)



def pmon_is_usable(text: str) -> bool:
    """True if `nvidia-smi pmon` actually ran and produced its table.

    An idle GPU gives a valid header and no compute rows, which is an ANSWER
    ("nothing is computing"), not a failure. Treating it as a failure sent
    every sample on to `typeperf`, costing seconds for a counter set that
    reports nothing for NVIDIA anyway.
    """
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            fields = line.split()
            if all(key in fields for key in ("gpu", "pid", "type", "sm")):
                return True
    return False


def parse_nvidia_pmon(text: str) -> dict[int, float]:
    """Read per-process SM utilization, keeping the busiest GPU for each PID.

    Only compute-only rows qualify: graphics or mixed rows cannot establish
    compute saturation. Missing/unsupported utilization is not a numeric zero.
    """
    columns: list[str] = []
    per_gpu: dict[tuple[int, int], float] = {}
    for line in text.splitlines():
        fields = line.split()
        if not fields:
            continue
        if fields[0] == "#":
            if all(key in fields for key in ("gpu", "pid", "type", "sm")):
                columns = fields[1:]
            continue
        if not columns:
            continue
        try:
            device, pid, kind, sm = (fields[columns.index(key)]
                                     for key in ("gpu", "pid", "type", "sm"))
            if kind != "C" or not all(v.isdecimal() for v in (device, pid, sm)):
                continue
            device_id, process_id, pct = int(device), int(pid), int(sm)
            if process_id <= 0 or not 0 <= pct <= 100:
                continue
            key = (device_id, process_id)
            per_gpu[key] = max(per_gpu.get(key, 0.0), float(pct))
        except (ValueError, IndexError):
            continue
    result: dict[int, float] = {}
    for (_, pid), pct in per_gpu.items():
        result[pid] = max(result.get(pid, 0.0), pct)
    return result


def _sample_linux_nvidia() -> tuple[dict[int, float], set[int], set[int]]:
    text = _run(["nvidia-smi", "pmon", "-s", "u", "-c", "1"], timeout=8.0)
    headers = [line.split()[1:] for line in text.splitlines()
               if line.lstrip().startswith("#")]
    if not any(all(key in header for key in ("gpu", "pid", "type", "sm"))
               for header in headers):
        warnings.warn("NVIDIA per-process GPU telemetry unavailable: check "
                      "nvidia-smi pmon support, driver and permissions.", RuntimeWarning)
    util = parse_nvidia_pmon(text)
    unsupported = any(
        len(fields := line.split()) > 3 and fields[2] == "C"
        for line in text.splitlines() if not line.lstrip().startswith("#")
    ) and not util
    if unsupported:
        warnings.warn("NVIDIA compute processes found, but their SM utilization "
                      "is unavailable; GPU scoring has no valid samples.", RuntimeWarning)
    # Linux has no PDH/window-owner equivalent here. SM is a proxy for compute
    # activity on C-only rows; it does not prove the process is a miner.
    return util, set(), _sample_nvidia_ctx()


def _sample_windows(compute_ctx: set[int]) -> dict[int, float]:
    """Per-process GPU utilization on Windows.

    `nvidia-smi pmon` first, PDH second. That is the reverse of what this file
    used to say, and the reason is measurement: with a real OpenCL job holding
    the GPU at 99% (nvidia-smi agreeing), the PDH GPU Engine counters reported
    one non-zero instance on the whole machine — System/Copy at 0.01% — while
    pmon reported the job at `sm 98%`. PDH stays as the vendor-neutral fallback
    for Intel and AMD, where nvidia-smi does not exist.
    """
    util: dict[int, float] = {}
    text = _run(["nvidia-smi", "pmon", "-s", "u", "-c", "1"], timeout=20.0)
    if pmon_is_usable(text):
        # pmon answered, so skip PDH entirely: `typeperf -sc 2` costs a couple
        # of seconds every sample and reports nothing useful for NVIDIA. An
        # empty map here means "nothing is computing", which is an answer.
        return parse_nvidia_pmon(text)
    for pid, value in _sample_pdh(compute_ctx).items():
        util.setdefault(pid, value)
    return util


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
    if sys.platform.startswith("linux"):
        return _sample_linux_nvidia()
    if not IS_WINDOWS:
        return {}, set(), set()
    ctx = _sample_nvidia_ctx()
    return _sample_windows(ctx), window_owner_pids(), ctx
