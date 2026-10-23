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

PROBE_WINDOW = 3.0        # seconds the decoy stays alive
SETTLE = 1.2              # seconds to let miners react before re-sampling


def _sample_cpu(interval: float) -> dict[int, float]:
    procs = {}
    for p in psutil.process_iter():
        try:
            p.cpu_percent(None)
            procs[p.pid] = p
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    time.sleep(interval)
    out: dict[int, float] = {}
    for pid, p in procs.items():
        try:
            out[pid] = p.cpu_percent(None)  # raw per-core sum (100 == one core)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return out


def _spawn_decoy(window: float) -> tuple[subprocess.Popen | None, str | None, str | None]:
    """Spawn a harmless sleeping process whose image name is taskmgr.exe.

    We copy a stock Windows utility (ping, which simply waits) to a temp file
    named taskmgr.exe and run it, so Process.name() reports "taskmgr.exe" to
    any miner watching for a monitor — without touching the real Task Manager.
    This works identically whether MinerSentry runs as a script or a frozen
    .exe, because it depends on no Python interpreter being present.
    """
    tmpdir = tempfile.mkdtemp(prefix="msentry_")
    creation = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0

    # (source binary, args to stay alive ~`window` seconds). The decoy is named
    # after the monitor a miner watches for: taskmgr.exe on Windows, htop on
    # Linux. ping -n N / sleep N wait without reading stdin.
    if sys.platform == "win32":
        decoy = os.path.join(tmpdir, "taskmgr.exe")
        sysroot = os.environ.get("SystemRoot", r"C:\Windows")
        pings = str(max(2, int(window) + 1))
        candidates = [
            (os.path.join(sysroot, "System32", "PING.EXE"), ["-n", pings, "127.0.0.1"]),
            (os.path.join(sysroot, "System32", "ping.exe"), ["-n", pings, "127.0.0.1"]),
        ]
    else:
        decoy = os.path.join(tmpdir, "htop")
        secs = str(max(2, int(window)))
        candidates = [("/bin/sleep", [secs]), ("/usr/bin/sleep", [secs])]

    last_err = None
    for src, args in candidates:
        if not os.path.exists(src):
            continue
        try:
            shutil.copy2(src, decoy)
            proc = subprocess.Popen(
                [decoy, *args],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL, creationflags=creation,
            )
            return proc, tmpdir, None
        except Exception as e:  # noqa: BLE001 - probe must never crash the app
            last_err = f"{type(e).__name__}: {e}"
    return None, tmpdir, last_err or "no suitable decoy binary found"


def run_probe(window: float = PROBE_WINDOW, settle: float = SETTLE,
              min_before: float = 40.0) -> tuple[dict[int, float], str]:
    """Return {pid: cpu_drop_points} and a status string.

    CPU is measured raw (100 == one fully pinned core). The probe is three-phase:
    baseline -> decoy alive -> decoy gone. A genuine evader collapses its load
    while the taskmgr.exe decoy is alive AND recovers once it leaves. Requiring
    the recovery rejects processes that merely finished a burst of legitimate
    work (an AV scan, a build step) during the window and never came back.
    """
    before = _sample_cpu(1.0)
    busy_before = {pid: c for pid, c in before.items() if c >= min_before}
    if not busy_before:
        return {}, "No process was busy enough to probe (nothing using notable CPU)."

    decoy, tmpdir, err = _spawn_decoy(window)
    if err:
        _cleanup(tmpdir)
        return {}, f"Could not launch decoy: {err}"

    time.sleep(settle)
    during = _sample_cpu(1.0)                 # decoy alive

    if decoy and decoy.poll() is None:
        try:
            decoy.terminate()
        except Exception:  # noqa: BLE001
            pass
    _cleanup(tmpdir)
    time.sleep(0.6)                           # let a true evader resume
    after = _sample_cpu(1.0)                  # decoy gone

    drops = classify_drops(before, during, after, min_before=min_before)
    if not drops:
        return {}, (f"Probed {len(busy_before)} busy process(es); none showed the "
                    f"collapse-then-recover pattern of monitor evasion.")
    return drops, (f"{len(drops)} process(es) throttled under the decoy and "
                   f"recovered after — classic monitor-evasion behavior.")


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
