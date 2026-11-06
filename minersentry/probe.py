"""Active evasion probe: the "fake Task Manager" test.

A whole class of miners throttles or pauses the moment a monitoring tool opens
(taskmgr.exe, procexp, perfmon) so the user never sees the CPU spike. We turn
that evasion into evidence: we spawn a harmless decoy process whose image name
is taskmgr.exe, hold it briefly, and watch which processes sharply drop CPU in
that window. Legitimate software has no reason to react to Task Manager
appearing; a process that quiets down is self-incriminating.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time

import psutil

PROBE_WINDOW = 3.0        # seconds the decoy stays alive while we measure
SETTLE = 1.2              # seconds to let miners react before re-sampling
_DECOY_LIFETIME = 30      # decoys outlive the measurement; we kill them after

DEFAULT_DECOYS_WINDOWS = ("taskmgr.exe", "procexp64.exe", "ProcessHacker.exe",
                          "SystemInformer.exe", "perfmon.exe", "resmon.exe")
DEFAULT_DECOYS_POSIX = ("htop", "top", "nvtop", "btop")


def _processes() -> dict[int, psutil.Process]:
    return {p.pid: p for p in psutil.process_iter()}


def _sample_cpu(procs: dict[int, psutil.Process], interval: float) -> dict[int, float]:
    """Raw per-core CPU (100 == one core) of `procs` over `interval` seconds.

    Callers pass only the processes they care about. Walking every process on
    the machine took 3-5 s on a 400-process desktop, so a "1 s" sample really
    spanned most of the decoy's life and a true evader's recovery leaked in."""
    for p in procs.values():
        try:
            p.cpu_percent(None)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    time.sleep(interval)
    out: dict[int, float] = {}
    for pid, p in procs.items():
        try:
            out[pid] = p.cpu_percent(None)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return out


def _spawn_decoys(names: tuple[str, ...]) -> tuple[list[subprocess.Popen], str | None, str | None]:
    """Spawn one harmless waiting process per decoy name, all at once.

    Each is a copy of a stock utility (ping on Windows, sleep on Linux) saved
    under the name of a monitoring tool, so Process.name() reports e.g.
    "taskmgr.exe" or "ProcessHacker.exe" to a miner checking the process list.
    Nothing real is touched, and no Python interpreter is needed. The decoys
    are told to wait far longer than the probe needs; the caller kills them."""
    tmpdir = tempfile.mkdtemp(prefix="msentry_")
    creation = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0
    if sys.platform == "win32":
        sysroot = os.environ.get("SystemRoot", r"C:\Windows")
        sources = [(os.path.join(sysroot, "System32", "PING.EXE"),
                    ["-n", str(_DECOY_LIFETIME), "127.0.0.1"])]
    else:
        sources = [("/bin/sleep", [str(_DECOY_LIFETIME)]),
                   ("/usr/bin/sleep", [str(_DECOY_LIFETIME)])]
    src_args = next(((s, a) for s, a in sources if os.path.exists(s)), None)
    if src_args is None:
        return [], tmpdir, "no suitable decoy binary found"
    src, args = src_args
    procs: list[subprocess.Popen] = []
    last_err = None
    for name in names:
        # one subfolder per decoy so each keeps its exact image name
        path = os.path.join(tmpdir, str(len(procs)), name)
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            shutil.copy2(src, path)
            procs.append(subprocess.Popen(
                [path, *args], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL, creationflags=creation))
        except Exception as e:  # noqa: BLE001 - probe must never crash the app
            last_err = f"{type(e).__name__}: {e}"
    if not procs:
        return [], tmpdir, last_err or "could not start any decoy"
    return procs, tmpdir, None


def _stop_decoys(procs: list[subprocess.Popen]) -> None:
    for d in procs:
        try:
            if d.poll() is None:
                d.terminate()
        except Exception:  # noqa: BLE001
            pass
    for d in procs:
        try:
            d.wait(timeout=3)   # the copied exe stays locked until it exits
        except Exception:  # noqa: BLE001
            try:
                d.kill()
                d.wait(timeout=2)
            except Exception:  # noqa: BLE001
                pass


def run_probe(window: float = PROBE_WINDOW, settle: float = SETTLE,
              min_before: float = 40.0,
              decoys: tuple[str, ...] | None = None) -> tuple[dict[int, float], str]:
    """Return {pid: cpu_drop_points} and a status string.

    CPU is measured raw (100 == one fully pinned core). The probe is three-phase:
    baseline -> decoys alive -> decoys gone. A genuine evader collapses its load
    while the decoys are alive AND recovers once they leave. Requiring the
    recovery rejects processes that merely finished a burst of legitimate work
    (an AV scan, a build step) during the window and never came back.

    Only the baseline walks every process. The decoy-alive and decoy-gone phases
    re-measure just the processes that were busy, and the decoys are kept
    running until the decoy-alive sample has finished."""
    if decoys is None:
        decoys = DEFAULT_DECOYS_WINDOWS if sys.platform == "win32" else DEFAULT_DECOYS_POSIX
    me = os.getpid()
    before = _sample_cpu(_processes(), 1.0)
    busy_before = {pid: c for pid, c in before.items() if c >= min_before and pid != me}
    if not busy_before:
        return {}, "No process was busy enough to probe (nothing using notable CPU)."
    targets: dict[int, psutil.Process] = {}
    for pid in busy_before:
        try:
            targets[pid] = psutil.Process(pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    procs, tmpdir, err = _spawn_decoys(tuple(decoys))
    if err:
        _cleanup(tmpdir)
        return {}, f"Could not launch decoy: {err}"
    try:
        time.sleep(settle)
        during = _sample_cpu(targets, max(0.5, window - settle - 0.8))  # decoys alive
    finally:
        _stop_decoys(procs)
        _cleanup(tmpdir)
    time.sleep(0.6)                                  # let a true evader resume
    after = _sample_cpu(targets, 1.0)                # decoys gone

    drops = classify_drops(busy_before, during, after, min_before=min_before)
    if not drops:
        return {}, (f"Probed {len(busy_before)} busy process(es); none showed the "
                    f"collapse-then-recover pattern of monitor evasion.")
    return drops, (f"{len(drops)} process(es) throttled under the monitor decoys and "
                   f"recovered after: classic monitor-evasion behavior.")


def classify_drops(before: dict[int, float], during: dict[int, float],
                   after: dict[int, float], *, min_before: float = 40.0,
                   collapse_ratio: float = 0.30, recover_ratio: float = 0.50,
                   min_drop: float = 40.0) -> dict[int, float]:
    """Pure evasion classifier (no I/O) — testable in isolation.

    Returns {pid: drop} for processes that were busy (>= min_before), collapsed
    to <= collapse_ratio of their baseline while the decoy was alive (dropping
    at least min_drop points), and recovered to >= recover_ratio of baseline
    once the decoy was gone.
    """
    out: dict[int, float] = {}
    for pid, b in before.items():
        if b < min_before:
            continue
        d = during.get(pid, 0.0)
        a = after.get(pid, 0.0)
        collapsed = d <= collapse_ratio * b and (b - d) >= min_drop
        recovered = a >= recover_ratio * b
        if collapsed and recovered:
            out[pid] = b - d
    return out


def _cleanup(tmpdir: str | None) -> None:
    if not tmpdir:
        return
    import shutil
    try:
        shutil.rmtree(tmpdir, ignore_errors=True)
    except Exception:  # noqa: BLE001
        pass
