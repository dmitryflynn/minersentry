"""Per-process hardware performance counters (Linux, user-mode).

The strongest tell of a RandomX miner is the *work itself*: it is memory-hard,
reading randomly across a ~2 GiB dataset, so it generates an extreme rate of
last-level-cache misses per instruction — a fingerprint of the algorithm that
shows up even when the miner is throttled far below the CPU floor.

On Linux this is readable in **user mode with no driver** via `perf_event_open`
(subject to /proc/sys/kernel/perf_event_paranoid). We attach CACHE_MISSES and
INSTRUCTIONS counters to a candidate PID for a short interval and compute the
miss-per-instruction ratio. Everything is best-effort: if perf is unavailable or
not permitted, this degrades to `None` and the signal simply doesn't contribute.

On Windows the equivalent needs a kernel driver / ETW PMU session, so it is not
implemented here (documented as the deferred Windows path).
"""

from __future__ import annotations

import ctypes
import os
import platform
import struct
import sys
import time

IS_LINUX = sys.platform.startswith("linux")

# perf_event_open constants (from <linux/perf_event.h>)
_PERF_TYPE_HARDWARE = 0
_PERF_COUNT_HW_INSTRUCTIONS = 1
_PERF_COUNT_HW_CACHE_MISSES = 3
_PERF_FORMAT_GROUP = 1 << 3

# The perf_event_open syscall number is architecture-specific. Pick by machine;
# unknown architectures get None and the signal simply degrades to a no-op.
_SYSCALL_NR = {
    "x86_64": 298, "amd64": 298,
    "i386": 336, "i686": 336, "i586": 336, "x86": 336,
    "aarch64": 241, "arm64": 241,
    "armv7l": 364, "armv6l": 364, "armv8l": 364,
    "ppc64le": 319, "ppc64": 319,
    "s390x": 331,
    "riscv64": 241,
}
__NR_perf_event_open = _SYSCALL_NR.get(platform.machine().lower()) if IS_LINUX else None


def paranoid_level() -> int | None:
    """Value of /proc/sys/kernel/perf_event_paranoid (gates access), or None."""
    try:
        with open("/proc/sys/kernel/perf_event_paranoid", "r") as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return None


def available() -> bool:
    """True if per-process counters can plausibly be opened here."""
    if not IS_LINUX or __NR_perf_event_open is None:
        return False
    lvl = paranoid_level()
    # <=2 allows per-process (own) counters; root/CAP_PERFMON (<=0) allows others.
    return lvl is not None and lvl <= 2


if IS_LINUX:
    class _perf_event_attr(ctypes.Structure):
        _fields_ = [
            ("type", ctypes.c_uint32), ("size", ctypes.c_uint32),
            ("config", ctypes.c_uint64), ("sample_period", ctypes.c_uint64),
            ("sample_type", ctypes.c_uint64), ("read_format", ctypes.c_uint64),
            ("flags", ctypes.c_uint64),
            ("wakeup", ctypes.c_uint32), ("bp_type", ctypes.c_uint32),
            ("bp_addr", ctypes.c_uint64), ("bp_len", ctypes.c_uint64),
        ]

    _libc = ctypes.CDLL(None, use_errno=True)
    _libc.syscall.restype = ctypes.c_long  # else the 64-bit return is truncated

    # flag bits in the attr bitfield: disabled | exclude_kernel | exclude_hv
    _ATTR_FLAGS = (1 << 0) | (1 << 5) | (1 << 6)

    def _open(config: int, pid: int, group_fd: int, read_group: bool) -> int:
        attr = _perf_event_attr()
        attr.type = _PERF_TYPE_HARDWARE
        attr.size = ctypes.sizeof(_perf_event_attr)
        attr.config = config
        attr.read_format = _PERF_FORMAT_GROUP if read_group else 0
        attr.flags = _ATTR_FLAGS
        # perf_event_open(attr, pid, cpu=-1, group_fd, flags=0)
        fd = _libc.syscall(__NR_perf_event_open, ctypes.byref(attr),
                           ctypes.c_int(pid), ctypes.c_int(-1),
                           ctypes.c_int(group_fd), ctypes.c_ulong(0))
        return fd


def sample_miss_ratio(pid: int, interval: float = 0.3) -> float | None:
    """Return cache-misses-per-1000-instructions for `pid` over `interval`
    seconds, or None if counters couldn't be read. Memory-hard miners show an
    order of magnitude more misses/instr than ordinary compute."""
    if not IS_LINUX or __NR_perf_event_open is None:
        return None
    PERF_EVENT_IOC_RESET = 0x2403
    PERF_EVENT_IOC_ENABLE = 0x2400
    PERF_EVENT_IOC_DISABLE = 0x2401
    lead = _open(_PERF_COUNT_HW_INSTRUCTIONS, pid, -1, True)
    if lead < 0:
        return None
    miss = _open(_PERF_COUNT_HW_CACHE_MISSES, pid, lead, True)
    if miss < 0:
        os.close(lead)
        return None
    try:
        import fcntl
        fcntl.ioctl(lead, PERF_EVENT_IOC_RESET, 1)   # 1 = PERF_IOC_FLAG_GROUP
        fcntl.ioctl(lead, PERF_EVENT_IOC_ENABLE, 1)
        time.sleep(interval)
        fcntl.ioctl(lead, PERF_EVENT_IOC_DISABLE, 1)
        # read_format=GROUP: nr(u64), then value(u64) per member in open order
        raw = os.read(lead, 8 * 3)
        if len(raw) < 24:
            return None
        nr, instrs, misses = struct.unpack("<QQQ", raw[:24])
        if nr < 2 or instrs == 0:
            return None
        return misses * 1000.0 / instrs
    except Exception:  # noqa: BLE001 - telemetry must never crash a scan
        return None
    finally:
        os.close(miss)
        os.close(lead)
