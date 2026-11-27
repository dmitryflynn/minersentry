"""Per-process GPU-compute telemetry.

A GPU miner is invisible to CPU accounting, but it has to keep a GPU busy.
There is no single source that sees that on every vendor, and what each one
shows was measured with a real OpenCL job on a hybrid laptop (RTX 3050 + Iris
Xe) rather than assumed:

    job on the NVIDIA GPU   nvidia-smi pmon: 99%, type C   PDH: nothing at all
    job on the Intel GPU    nvidia-smi pmon: not listed    PDH: 98.7%, 3D engine

So on Windows the sources are combined. `nvidia-smi pmon` is authoritative for
NVIDIA. The PDH "GPU Engine" counters cover everything else, but neither GPU
here publishes an `engtype_Compute` instance: compute work is reported on the
3D engine, which is also what every game drives. A 3D reading therefore counts
only for a process that is a compute client — one holding an NVIDIA compute
context, or with an OpenCL/CUDA runtime mapped.

Linux uses `nvidia-smi pmon` for the NVIDIA proprietary driver and DRM fdinfo
(see gpu_drm) for AMD and Intel.

Vulkan and DirectML compute are not covered; see COMPUTE_RUNTIME_MODULES for
why adding their runtimes would do more harm than good.

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


def _sample_pdh() -> tuple[dict[int, float], dict[int, float]]:
    """(Compute-engine, 3D-engine) utilization per process from PDH.

    Two samples, not one: a utilization counter is a RATE, and PDH's first
    sample is always 0.000000 — with `-sc 1` every value read zero, which on
    its own was enough to keep the GPU signal silent everywhere.

    What the 3D reading means is the caller's decision; see merge_gpu_util.
    """
    out = _run(["typeperf", r"\GPU Engine(*)\Utilization Percentage", "-sc", "2"],
               timeout=20.0)
    return (parse_gpu_engine_counters(out, ("Compute",)),
            parse_gpu_engine_counters(out, ("3D",)))


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


def _sample_windows(compute_ctx: set[int]
                         ) -> tuple[dict[int, float], set[int]]:
    """(utilisation, compute-client PIDs found through the PDH path).

    pmon is authoritative for NVIDIA. When it answers AND there is no other
    GPU in the machine, PDH is skipped: `typeperf -sc 2` costs a couple of
    seconds a sample and reports nothing for NVIDIA compute.

    It used to be skipped whenever pmon answered at all, which left a hole
    measured on a hybrid laptop (RTX 3050 + Iris Xe): an OpenCL job on the
    Intel GPU ran at 98.7% on the PDH 3D engine, appeared in neither pmon nor
    this sampler, and so was completely invisible. A miner only had to pick
    the integrated GPU.
    """
    text = _run(["nvidia-smi", "pmon", "-s", "u", "-c", "1"], timeout=20.0)
    nvidia = parse_nvidia_pmon(text) if pmon_is_usable(text) else None
    if nvidia is not None and not other_gpu_present():
        return nvidia, set()
    compute, graphics = _sample_pdh()
    clients = {pid for pid, value in graphics.items()
               if value >= PDH_3D_FLOOR
               and (pid in compute_ctx or has_compute_runtime(pid))}
    return merge_gpu_util(nvidia or {}, compute, graphics, clients), clients


# A process below this on the 3D engine is not worth the module lookup; idle
# desktop apps sit at a few percent.
PDH_3D_FLOOR = 15.0

# Runtime libraries that make a process a GPU *compute* client. On Intel (and,
# by the same WDDM design, AMD) there is no "Compute" engine in the vendor-
# neutral counters: OpenCL work is reported on the 3D engine, which is also
# what a game or a browser drives. What tells them apart is cheap to read —
# the compute job has an OpenCL runtime mapped, measured on a real job
# (opencl.dll, igdrcl64.dll) against Brave, Edge and Explorer (none).
#
# Vulkan and DirectML are deliberately absent. vulkan-1.dll is mapped by every
# Chromium GPU process and most games, and DirectML by ordinary creative and
# camera software, so either would turn desktop graphics into "compute". A
# miner using Vulkan compute is therefore still not seen here.
COMPUTE_RUNTIME_MODULES = frozenset({
    "opencl.dll", "igdrcl64.dll", "igdrcl32.dll", "intelocl64.dll",
    "amdocl64.dll", "amdocl.dll", "amdocl12cl64.dll",
    "nvopencl64.dll", "nvopencl32.dll", "nvcuda.dll", "nvcuda64.dll",
    # Linux: compared with the version suffix removed (see _so_name), because
    # /proc/<pid>/maps names the file actually mapped, the symlink TARGET:
    # libOpenCL.so.1.0.0, libcuda.so.535.104.05. The loader dlopens the
    # vendor ICD too (AMD, Intel NEO), which is listed for a process that
    # skips the loader.
    "libopencl.so", "libcuda.so", "libnvidia-opencl.so",
    "libamdocl64.so", "libamdocl32.so", "libigdrcl.so", "libintelocl.so",
})


def _so_name(base: str) -> str:
    """`libopencl.so.1.0.0` -> `libopencl.so`; anything else unchanged. Pure."""
    head, sep, version = base.partition(".so.")
    if sep and version and all(part.isdigit() for part in version.split(".")):
        return head + ".so"
    return base


def has_compute_runtime(pid: int, modules=None) -> bool:
    """True if the process has an OpenCL or CUDA runtime mapped.

    `modules` is injectable for tests. A process we are not allowed to
    inspect returns False: unknown is not evidence.
    """
    if modules is None:
        try:
            import psutil
            modules = [m.path for m in psutil.Process(pid).memory_maps()]
        except Exception:  # noqa: BLE001 - denied, exited, or unsupported
            return False
    for path in modules:
        base = str(path).replace("\\", "/").rsplit("/", 1)[-1].lower()
        if base in COMPUTE_RUNTIME_MODULES or _so_name(base) in COMPUTE_RUNTIME_MODULES:
            return True
    return False


def merge_gpu_util(nvidia: dict[int, float], compute: dict[int, float],
                   graphics: dict[int, float], clients: set[int]
                   ) -> dict[int, float]:
    """Combine the sources into one {pid: percent}. Pure.

    A Compute-engine reading always counts. A 3D-engine reading counts only
    for a compute client, because the same engine carries every game.
    """
    out = dict(nvidia)
    for pid, value in compute.items():
        out[pid] = max(out.get(pid, 0.0), value)
    for pid in clients:
        value = graphics.get(pid)
        if value:
            out[pid] = max(out.get(pid, 0.0), value)
    # The PDH parser sums a process across engine instances, so a job spread
    # over several 3D engines read 163% on the Iris Xe. A percentage that
    # exceeds 100 is not a stronger signal, only a wrong one.
    return {pid: min(100.0, value) for pid, value in out.items()}


_OTHER_GPU: bool | None = None


def adapters_include_non_nvidia(names: list[str]) -> bool:
    """True if any display adapter is a real non-NVIDIA GPU. Pure."""
    for name in names:
        low = name.strip().lower()
        if not low or "nvidia" in low:
            continue
        # software and remote adapters do no compute worth sampling
        if any(k in low for k in ("microsoft basic", "remote display",
                                  "virtual", "parsec", "citrix", "vmware")):
            continue
        return True
    return False


def other_gpu_present() -> bool:
    """Whether a non-NVIDIA GPU exists, asked once and remembered: adapters do
    not change while the program runs, and the answer decides whether every
    sample pays for PDH."""
    global _OTHER_GPU
    if _OTHER_GPU is None:
        text = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                     "(Get-CimInstance Win32_VideoController).Name"], timeout=20.0)
        names = [ln for ln in text.splitlines() if ln.strip()]
        # No answer at all: assume there might be one, so nothing is skipped.
        _OTHER_GPU = adapters_include_non_nvidia(names) if names else True
    return _OTHER_GPU


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
        util, windows, ctx = _sample_linux_nvidia()
        try:
            from . import gpu_drm
            drm_util, drm_clients = gpu_drm.sample()
        except Exception:  # noqa: BLE001 - AMD/Intel telemetry is best-effort
            drm_util, drm_clients = {}, set()
        for pid, value in drm_util.items():
            util[pid] = max(util.get(pid, 0.0), value)
        return util, windows, ctx | drm_clients
    if not IS_WINDOWS:
        return {}, set(), set()
    ctx = _sample_nvidia_ctx()
    util, clients = _sample_windows(ctx)
    # A compute client found through PDH holds a compute context as surely as
    # one nvidia-smi lists, and the engine treats both the same way.
    return util, window_owner_pids(), ctx | clients
