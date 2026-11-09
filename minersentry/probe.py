"""Active evasion probe: the "fake Task Manager" test.

A whole class of miners throttles or pauses the moment a monitoring tool opens
(taskmgr.exe, procexp, perfmon) so the user never sees the CPU spike. We turn
that evasion into evidence: we spawn a harmless decoy process whose image name
is taskmgr.exe, hold it briefly, and watch which processes sharply drop CPU in
that window. Legitimate software has no reason to react to Task Manager
appearing; a process that quiets down is self-incriminating.
"""

from __future__ import annotations

import ctypes
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time

from ctypes import wintypes

import psutil

PROBE_WINDOW = 3.0        # seconds the decoy stays alive while we measure
SETTLE = 1.2              # seconds to let miners react before re-sampling
_DECOY_LIFETIME = 30      # decoys outlive the measurement; we kill them after

DEFAULT_DECOYS_WINDOWS = ("taskmgr.exe", "procexp64.exe", "ProcessHacker.exe",
                          "SystemInformer.exe", "perfmon.exe", "resmon.exe")
DEFAULT_DECOYS_POSIX = ("htop", "top", "nvtop", "btop")

# Window titles the matching monitor really shows, for title-based checks.
WINDOW_TITLES = {
    "taskmgr.exe": "Task Manager",
    "procexp64.exe": "Process Explorer",
    "processhacker.exe": "Process Hacker",
    "systeminformer.exe": "System Informer",
    "perfmon.exe": "Performance Monitor",
    "resmon.exe": "Resource Monitor",
}


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


def _spawn_decoys(names: tuple[str, ...], detach: bool = True
                  ) -> tuple[list[subprocess.Popen], str | None, str | None]:
    """Spawn one harmless waiting process per decoy name, all at once.

    Each is a copy of a stock utility (ping on Windows, sleep on Linux) saved
    under the name of a monitoring tool, so Process.name() reports e.g.
    "taskmgr.exe" or "ProcessHacker.exe" to a miner checking the process list.
    Nothing real is touched, and no Python interpreter is needed. The decoys
    are told to wait far longer than the probe needs; the caller kills them.

    Two tells are removed here. The folder no longer carries a fixed
    "msentry_" prefix (a miner could simply ignore any process running from a
    path containing it), and on Windows each decoy is started through
    `cmd /c start` so its parent is not MinerSentry's own interpreter — the
    decoys are re-parented as the launcher exits, as a real monitor would be.
    """
    tmpdir = tempfile.mkdtemp(prefix=secrets.token_hex(4) + "-")
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
    paths: list[str] = []
    last_err = None
    for name in names:
        # one subfolder per decoy so each keeps its exact image name
        path = os.path.join(tmpdir, str(len(paths)), name)
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            shutil.copy2(src, path)
            paths.append(path)
            if detach and sys.platform == "win32":
                # `start` hands the decoy to the shell, which exits immediately,
                # so the decoy's parent is not our interpreter.
                subprocess.Popen(
                    ["cmd", "/c", "start", "", "/b", path, *args],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL, creationflags=creation)
            else:
                procs.append(subprocess.Popen(
                    [path, *args], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL, creationflags=creation))
        except Exception as e:  # noqa: BLE001 - probe must never crash the app
            last_err = f"{type(e).__name__}: {e}"
    if not paths:
        return [], tmpdir, last_err or "could not start any decoy"
    if detach and sys.platform == "win32":
        # The shell needs a moment to hand off, and the probe must not start
        # measuring before the decoys are actually in the process list.
        deadline = time.time() + 2.0
        while time.time() < deadline:
            if len(_decoys_under(tmpdir)) >= len(paths):
                break
            time.sleep(0.05)
    return procs, tmpdir, None


def _decoys_under(tmpdir: str) -> list[psutil.Process]:
    """Live processes running from `tmpdir` (our detached decoys)."""
    root = os.path.normcase(os.path.realpath(tmpdir))
    out = []
    for p in psutil.process_iter(["exe"]):
        try:
            exe = p.info.get("exe") or ""
            if exe and os.path.normcase(exe).startswith(root):
                out.append(p)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return out


def _stop_decoys(procs: list[subprocess.Popen], tmpdir: str | None = None) -> None:
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
    if tmpdir:                  # detached decoys have no Popen handle
        live = _decoys_under(tmpdir)
        for p in live:
            try:
                p.terminate()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        psutil.wait_procs(live, timeout=3)
        for p in _decoys_under(tmpdir):
            try:
                p.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        psutil.wait_procs(_decoys_under(tmpdir), timeout=2)


class _WindowDecoy:
    """A real top-level window titled like a monitor, placed off-screen.

    The process decoys only change the process LIST. Plenty of evasive miners
    look for the window instead (FindWindow / EnumWindows on the title), and a
    windowless decoy is invisible to those. This creates genuine visible
    windows — positioned far off-screen so nothing flashes at the user — for
    the length of the probe. Windows only; a no-op elsewhere.
    """

    def __init__(self, titles: tuple[str, ...]) -> None:
        self.titles = titles
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def __enter__(self):
        if sys.platform == "win32" and self.titles:
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()
            time.sleep(0.25)        # let the windows exist before we sample
        return self

    def __exit__(self, *exc):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
        return False

    def _run(self) -> None:
        try:
            user32 = ctypes.windll.user32
            user32.CreateWindowExW.restype = wintypes.HWND
            user32.CreateWindowExW.argtypes = [
                wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
                ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                wintypes.HWND, wintypes.HMENU, wintypes.HINSTANCE, wintypes.LPVOID]
            user32.DestroyWindow.argtypes = [wintypes.HWND]
            hwnds = []
            for title in self.titles:
                # A plain STATIC control is a real top-level window, so no window
                # class has to be registered.
                hwnd = user32.CreateWindowExW(
                    0x00000080,                      # WS_EX_TOOLWINDOW
                    "STATIC", title,
                    0x90000000,                      # WS_POPUP | WS_VISIBLE
                    -32000, -32000, 200, 100,        # far off-screen
                    None, None, None, None)
                if hwnd:
                    hwnds.append(hwnd)
            # The messages MUST be pumped. GetWindowText on a window whose
            # thread does not pump blocks the CALLER until it gives up, so a
            # decoy without this loop freezes anything enumerating window titles
            # — the miner we are probing, and any real monitor too.
            msg = wintypes.MSG()
            while not self._stop.is_set():
                while user32.PeekMessageW(ctypes.byref(msg), None, 0, 0, 1):
                    user32.TranslateMessage(ctypes.byref(msg))
                    user32.DispatchMessageW(ctypes.byref(msg))
                time.sleep(0.02)
            for hwnd in hwnds:
                user32.DestroyWindow(hwnd)
        except Exception:  # noqa: BLE001 - never break the probe
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
    titles = tuple(dict.fromkeys(WINDOW_TITLES.get(os.path.basename(d).lower(), "")
                                 for d in decoys))
    try:
        with _WindowDecoy(tuple(t for t in titles if t)):
            time.sleep(settle)
            during = _sample_cpu(targets, max(0.5, window - settle - 0.8))
    finally:
        _stop_decoys(procs, tmpdir)
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
