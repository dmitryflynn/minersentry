"""Per-process GPU use on Linux from DRM fdinfo (issue #18, the Linux half).

`nvidia-smi pmon` only exists for the NVIDIA proprietary driver. For AMD and
Intel the kernel publishes per-client engine time in
`/proc/<pid>/fdinfo/<fd>` for every open DRM file, in a format the kernel
documents as stable (Documentation/gpu/drm-usage-stats.rst):

    drm-driver: amdgpu
    drm-client-id: 42
    drm-engine-gfx: 1234567 ns
    drm-engine-compute: 9876543210 ns

Engine time is cumulative, so utilisation is the difference between two
readings over the wall time between them.

Which engines mean compute follows the same rule as the Windows 3D engine: an
engine literally named `compute` always counts (amdgpu, newer Intel), while
`render` / `gfx` / `rcs` carry desktop graphics too and count only for a
process with an OpenCL runtime mapped.

**Not run against hardware.** The parser and the arithmetic are tested against
the documented format; there was no Linux machine with an AMD or Intel GPU to
run a real compute job on. It reads only, returns nothing on any failure, and
cannot see other users' processes without root.
"""

from __future__ import annotations

import os
import time

from . import gpu

ALWAYS_COMPUTE = ("compute",)
COMPUTE_IF_CLIENT = ("render", "gfx", "rcs")


def parse_drm_fdinfo(text: str) -> tuple[str, str, dict[str, int]] | None:
    """(driver, client id, {engine: cumulative ns}) or None if not DRM. Pure."""
    driver = client = ""
    engines: dict[str, int] = {}
    for raw in text.splitlines():
        key, sep, value = raw.partition(":")
        if not sep:
            continue
        key, value = key.strip(), value.strip()
        if key == "drm-driver":
            driver = value
        elif key == "drm-client-id":
            client = value
        elif key.startswith("drm-engine-") and not key.startswith(
                "drm-engine-capacity-"):
            number = value.split()[0] if value else ""
            if number.isdecimal():
                engines[key[len("drm-engine-"):]] = int(number)
    if not driver or not client:
        return None
    return driver, client, engines


def utilisation(previous: dict, current: dict, elapsed_ns: float
                ) -> dict[int, dict[str, float]]:
    """Percent per engine per PID between two readings. Pure.

    Both maps are {(pid, client): {engine: ns}}. A client present only in the
    newer reading has no baseline and contributes nothing yet — its lifetime
    total says nothing about the last few seconds.
    """
    out: dict[int, dict[str, float]] = {}
    if elapsed_ns <= 0:
        return out
    for (pid, client), engines in current.items():
        before = previous.get((pid, client))
        if before is None:
            continue
        for engine, total in engines.items():
            delta = total - before.get(engine, total)
            if delta <= 0:
                continue
            pct = min(100.0, 100.0 * delta / elapsed_ns)
            per_pid = out.setdefault(pid, {})
            per_pid[engine] = min(100.0, per_pid.get(engine, 0.0) + pct)
    return out


def compute_percent(engines: dict[str, float], is_client: bool) -> float:
    """The compute load in one process's engine readings. Pure."""
    value = max((engines.get(name, 0.0) for name in ALWAYS_COMPUTE), default=0.0)
    if is_client:
        value = max(value, max((engines.get(name, 0.0)
                                for name in COMPUTE_IF_CLIENT), default=0.0))
    return value


def read_clients(root: str = "/proc", readlink=os.readlink) -> dict:
    """{(pid, client): {engine: ns}} for every DRM file we are allowed to see."""
    out: dict = {}
    try:
        pids = [name for name in os.listdir(root) if name.isdecimal()]
    except OSError:
        return out
    for name in pids:
        fd_dir = os.path.join(root, name, "fd")
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            continue            # exited, or another user's process
        for fd in fds:
            try:
                if not readlink(os.path.join(fd_dir, fd)).startswith("/dev/dri/"):
                    continue
                with open(os.path.join(root, name, "fdinfo", fd), "r",
                          encoding="utf-8", errors="replace") as f:
                    parsed = parse_drm_fdinfo(f.read(8192))
            except OSError:
                continue
            if parsed is None:
                continue
            _driver, client, engines = parsed
            # several fds can share one client; the totals are the client's
            out[(int(name), client)] = engines
    return out


_previous: dict = {}
_previous_at = 0.0


def sample() -> tuple[dict[int, float], set[int]]:
    """({pid: compute percent}, compute-client PIDs) since the last call.

    The first call only records a baseline and returns nothing.
    """
    global _previous, _previous_at
    now = time.monotonic()
    current = read_clients()
    elapsed_ns = (now - _previous_at) * 1e9 if _previous_at else 0.0
    per_pid = utilisation(_previous, current, elapsed_ns)
    _previous, _previous_at = current, now
    util: dict[int, float] = {}
    clients: set[int] = set()
    for pid, engines in per_pid.items():
        needs_client = (max(engines.get(n, 0.0) for n in COMPUTE_IF_CLIENT)
                        >= gpu.PDH_3D_FLOOR)
        is_client = needs_client and gpu.has_compute_runtime(pid)
        value = compute_percent(engines, is_client)
        if value > 0.0:
            util[pid] = value
            if is_client or engines.get("compute", 0.0) > 0.0:
                clients.add(pid)
    return util, clients
