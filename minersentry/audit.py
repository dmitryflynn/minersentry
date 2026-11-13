"""Detection logging and in-app events.

Records verdict transitions (Clean -> Suspicious/Likely Miner) to a JSONL file
under %LOCALAPPDATA%\\MinerSentry and forwards short human-readable lines to an
optional in-app callback so the GUI can show a scrolling event history.
"""

from __future__ import annotations

import json
import os
import time
from typing import Callable


MAX_LOG_BYTES = 5 * 1024 * 1024   # rotate the detection log past this size


def default_log_path() -> str:
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    return os.path.join(base, "MinerSentry", "detections.log")


class AuditLog:
    def __init__(self, path: str | None = None,
                 on_event: Callable[[str], None] | None = None,
                 max_bytes: int = MAX_LOG_BYTES) -> None:
        self.path = path or default_log_path()
        self.on_event = on_event
        self.max_bytes = max_bytes

    def _rotate(self) -> None:
        """Keep one previous file (detections.log.1) once the log passes
        max_bytes, so a long-running monitor can't fill the disk."""
        try:
            if os.path.getsize(self.path) >= self.max_bytes:
                os.replace(self.path, self.path + ".1")
        except OSError:
            pass

    def event(self, line: str) -> None:
        """Emit a transient event line to the in-app log (not persisted)."""
        if self.on_event:
            try:
                self.on_event(line)
            except Exception:  # noqa: BLE001
                pass

    def record_detection(self, *, pid: int, name: str, exe: str, score: int,
                         verdict: str, signals: list[tuple[str, int, str]],
                         container: str = "") -> None:
        """Persist a detection (verdict transition) as one JSONL record.

        `container` is written only when the process is in one. A host PID is
        gone the moment a container restarts, so for a containerised workload
        it is the only durable thing in this record — without it a log read
        tomorrow cannot say which workload was mining.
        """
        rec = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "pid": pid, "name": name, "exe": exe,
            "score": score, "verdict": verdict,
            "signals": [{"name": n, "score": s, "detail": d} for n, s, d in signals],
            **({"container": container} if container else {}),
        }
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            self._rotate()
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec) + "\n")
        except OSError:
            pass
        self.event(f"{verdict}: {name} (pid {pid}) score {score}")
