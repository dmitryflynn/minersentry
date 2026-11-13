r"""Processes that live for less than one scan interval (issue #15).

The engine polls every 2.5s, so a process that starts and exits between two
passes is never sampled. This subscribes to process-creation events instead and
records what started, whether or not it is still alive at the next pass.

**Which event source, and what it is really worth.** Measured on this machine,
not elevated. `Win32_ProcessStartTrace` — the source the issue proposed —
cannot be subscribed to at all without Administrator (access denied), and the
Security log's 4688 events cannot be read without it either. That leaves
`__InstanceCreationEvent WITHIN 1` on `Win32_Process`, which needs no
privileges. Twelve `cmd.exe` processes per row:

    lifetime   spawned        caught   with a command line
    ~10 ms     one at a time    1/12            0
    ~10 ms     all at once      0/12            0
    1 s        one at a time   11/12            9
    1 s        all at once     12/12           12
    3 s        either          12/12           12

So this is **not** the dropper case. A process that launches and exits in
milliseconds is still invisible: the subscription is WMI polling
`Win32_Process` on an interval, and a process that never exists at a poll
instant is never in a snapshot. What it does close, reliably and with the
command line intact, is the band between about one second and the engine's
2.5s pass — a miner running in short bursts to stay under a sampling monitor,
which is a real evasion and currently caught only by luck.

Catching the millisecond case needs the elevated trace, and that trace carries
no command line (see below), so even with Administrator it would yield a name
and a PID rather than something scoreable.

An early version of this file claimed 8 of 12 for the short case. That was
measurement error: the harness used `Start-Process`, which returns
immediately, so those processes lived far longer than intended. The table
above comes from a harness with real, verified lifetimes — `ping -n N`, after
discovering that `ping -w` does not delay anything against localhost.

The choice between them is not the obvious one. `Win32_ProcessStartTrace`
carries `ProcessID`, `ProcessName`, `ParentProcessID` and **no command line**
(verified against the class schema, not from memory). `__InstanceCreationEvent`
on `Win32_Process` carries `CommandLine` and `ExecutablePath`. A process that
has already exited has no CPU history and nothing left to memory-scan, so the
command line is very nearly the entire basis for judging it: a dropper running
`xmrig --donate-level 0 -o pool:3333` is convictable on that alone, and the
same process known only as "xmrig.exe" is not. The unprivileged source is
therefore the more useful one, and that is what this uses.

Linux has no equivalent an unprivileged process can use: the netlink proc
connector needs root, and reading `/proc` faster cannot beat a process that
exits in milliseconds. The watcher reports itself unavailable there rather
than pretending to cover it.
"""

from __future__ import annotations

import atexit
import json
import os
import queue
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field

from . import persistence as persist_mod
from .config import Config

IS_WINDOWS = sys.platform == "win32"

# WMI polls Win32_Process on this interval. Shorter catches more and costs
# more; 1s is the shortest WITHIN that WMI accepts without complaint.
POLL_WITHIN = 1

# One JSON object per line on stdout, so the parsing stays pure and the
# helper can be replaced without touching the reader.
# The helper watches its parent and exits when the parent is gone.
#
# Without that it outlives any abnormal end of MinerSentry — a force-quit, a
# crash, a TerminateProcess — because none of those run `finally`, `atexit` or
# a window handler. Each orphan keeps a WMI event subscription, WMI has a
# per-user quota on those, and enough orphans take the machine to "Quota
# violation", after which nothing can subscribe at all. That is exactly what
# happened here while this was being written.
_HELPER = r"""
$ErrorActionPreference = 'Stop'
$parent = {parent}
$query = "SELECT * FROM __InstanceCreationEvent WITHIN {within} " +
         "WHERE TargetInstance ISA 'Win32_Process'"
try {
    Register-CimIndicationEvent -Query $query -SourceIdentifier msProcEvents
} catch {
    [Console]::Out.WriteLine((@{ error = $_.Exception.Message } | ConvertTo-Json -Compress))
    [Console]::Out.Flush()
    exit 1
}
[Console]::Out.WriteLine((@{ ready = $true } | ConvertTo-Json -Compress))
[Console]::Out.Flush()
while ($true) {
    # Short timeout so the parent check runs often and cleanup is prompt.
    $e = Wait-Event -SourceIdentifier msProcEvents -Timeout 5
    if ($null -eq $e) {
        if (-not (Get-Process -Id $parent -ErrorAction SilentlyContinue)) { exit 0 }
        continue
    }
    $t = $e.SourceEventArgs.NewEvent.TargetInstance
    $row = @{
        pid  = [int]$t.ProcessId
        ppid = [int]$t.ParentProcessId
        name = [string]$t.Name
        exe  = [string]$t.ExecutablePath
        cmd  = [string]$t.CommandLine
    }
    [Console]::Out.WriteLine(($row | ConvertTo-Json -Compress))
    [Console]::Out.Flush()
    Remove-Event -EventIdentifier $e.EventIdentifier
}
"""


@dataclass
class ProcEvent:
    pid: int
    name: str
    exe: str = ""
    cmdline: str = ""
    ppid: int = 0
    ts: float = 0.0
    score: int = 0
    labels: list[str] = field(default_factory=list)

    @property
    def summary(self) -> str:
        return f"{self.name} (pid {self.pid}) {self.cmdline[:70]}"


def parse_event_line(line: str) -> ProcEvent | dict | None:
    """One helper line into an event, a control dict, or None. Pure.

    Returns the raw dict for the helper's own `ready` / `error` messages so
    the caller can tell "the subscription failed" from "nothing has started
    yet", which are very different answers.
    """
    line = (line or "").strip()
    if not line:
        return None
    try:
        row = json.loads(line)
    except ValueError:
        return None
    if not isinstance(row, dict):
        return None
    if "error" in row or "ready" in row:
        return row
    try:
        pid = int(row.get("pid") or 0)
    except (TypeError, ValueError):
        return None
    name = str(row.get("name") or "")
    if not pid or not name:
        return None
    return ProcEvent(pid=pid, name=name,
                     exe=str(row.get("exe") or ""),
                     cmdline=str(row.get("cmd") or ""),
                     ppid=int(row.get("ppid") or 0),
                     ts=time.time())


def score_event(event: ProcEvent, cfg: Config) -> ProcEvent:
    """Score a process that may already be gone.

    This reuses `persistence.score_entry`, which is not a pun: scoring an
    autostart entry and scoring a transient process are the same problem —
    a command line, a binary path and a name, with no behaviour to measure.
    Sharing it means the pool URLs, wallet flags, miner names, drop locations
    and hidden-launcher patterns stay defined in one place. The kind is not in
    `RARE_KINDS`, so no location weight is added.
    """
    entry = persist_mod.PersistEntry(
        kind="transient-process",
        location=f"pid {event.pid} (parent {event.ppid})",
        name=event.name, command=event.cmdline or event.name,
        exe=event.exe or persist_mod.command_exe(event.cmdline or ""))
    scored = persist_mod.score_entry(entry, cfg)
    event.score, event.labels = scored.score, scored.labels
    return event


class Watcher:
    """Background subscription to process starts. Non-blocking to read."""

    def __init__(self, cfg: Config | None = None) -> None:
        self.cfg = cfg or Config.load()
        self.mode = "off"
        self.error = ""
        self._proc: subprocess.Popen | None = None
        self._q: "queue.Queue[ProcEvent]" = queue.Queue(maxsize=4096)
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._dropped = 0

    @property
    def available(self) -> bool:
        return self.mode == "wmi-poll"

    def start(self) -> bool:
        if not IS_WINDOWS:
            self.mode = "unavailable"
            self.error = ("no unprivileged process-event source on this "
                          "platform: the netlink proc connector needs root")
            return False
        script = (_HELPER.replace("{within}", str(POLL_WITHIN))
                         .replace("{parent}", str(os.getpid())))
        try:
            self._proc = subprocess.Popen(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL, text=True, bufsize=1,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except (OSError, ValueError) as e:
            self.mode = "unavailable"
            self.error = f"could not start the event helper: {e}"
            return False
        self._thread = threading.Thread(target=self._read, daemon=True,
                                        name="minersentry-procevents")
        self._thread.start()
        # Belt and braces: the helper exits on its own when this process goes
        # away, and this stops it promptly on a normal interpreter exit.
        atexit.register(self.stop)
        # Wait briefly for the helper to say whether it subscribed. Without
        # this the caller cannot tell a working watcher from one that was
        # refused, and would report coverage it does not have.
        deadline = time.time() + 15.0
        while time.time() < deadline:
            if self.mode != "off":
                break
            time.sleep(0.1)
        if self.mode == "off":
            self.mode = "unavailable"
            self.error = "the event helper did not report ready"
        return self.available

    def _read(self) -> None:
        proc = self._proc
        if proc is None or proc.stdout is None:
            return
        for line in proc.stdout:
            if self._stop.is_set():
                return
            parsed = parse_event_line(line)
            if parsed is None:
                continue
            if isinstance(parsed, dict):
                if parsed.get("ready"):
                    self.mode = "wmi-poll"
                else:
                    self.mode = "unavailable"
                    self.error = str(parsed.get("error") or "")[:200]
                continue
            try:
                self._q.put_nowait(parsed)
            except queue.Full:
                # A burst must not grow without bound. Count what was lost
                # rather than silently dropping it.
                self._dropped += 1

    def drain(self, limit: int = 2048) -> list[ProcEvent]:
        """Events since the last call, scored, newest last."""
        out: list[ProcEvent] = []
        own = {os.getpid()}
        while len(out) < limit:
            try:
                event = self._q.get_nowait()
            except queue.Empty:
                break
            if event.pid in own:
                continue
            out.append(score_event(event, self.cfg))
        return out

    @property
    def dropped(self) -> int:
        return self._dropped

    def stop(self) -> None:
        """Stop the helper, and make sure it is actually gone.

        This matters more than it looks. Each helper holds a WMI event
        subscription, and WMI has a per-user quota on those: eleven leaked
        helpers from test runs took the machine to "Quota violation", after
        which no new subscription could be created at all. A terminate that
        is not confirmed is not good enough — if the process is still there
        after the wait, it gets killed.
        """
        self._stop.set()
        proc, self._proc = self._proc, None
        if proc is None:
            return
        try:
            proc.terminate()
        except Exception:  # noqa: BLE001
            pass
        try:
            proc.wait(timeout=5)
        except Exception:  # noqa: BLE001
            pass
        if proc.poll() is None:
            try:
                proc.kill()
                proc.wait(timeout=5)
            except Exception:  # noqa: BLE001
                pass


def summarize(events: list[ProcEvent], min_score: int) -> list[dict]:
    """The transient processes worth reporting, worst first."""
    keep = [e for e in events if e.score >= min_score]
    keep.sort(key=lambda e: (-e.score, e.name))
    return [{"pid": e.pid, "ppid": e.ppid, "name": e.name, "exe": e.exe,
             "cmdline": e.cmdline[:300], "score": e.score,
             "labels": e.labels[:4]} for e in keep]
