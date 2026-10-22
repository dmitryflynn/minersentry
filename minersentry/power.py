"""Hidden-compute / power-gap detection (system-level).

CPU accounting can be fooled two ways a per-process scan won't catch:
  1. a rootkit hides its PID, so its CPU time appears in the system total but not
     in the sum of visible processes — an "unaccounted CPU" gap; and
  2. a miner runs inside a VM/WSL guest, whose load rolls up under a host process
     (vmmem/vmmemwsl/vmwp) the host can't see into.

This module turns both into a system-level report surfaced as a banner, not a
per-normal-process score. The decision is a pure function (`compute_report`) so
it is unit-testable; the sampling wrapper is thin. True package power (RAPL) is
not exposed in Windows user mode without a driver, so it stays an experimental,
best-effort extra, absent on most hardware.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .config import Config


@dataclass
class HiddenComputeReport:
    flagged: bool = False
    unaccounted_cores: float = 0.0
    vm_loads: dict[str, float] = field(default_factory=dict)  # name -> cores
    note: str = ""


def compute_report(system_busy_raw: float, attributed_raw: float,
                   vm_loads_raw: dict[str, float], persisted_gap: bool,
                   cfg: Config) -> HiddenComputeReport:
    """Pure decision. All CPU figures are raw per-core sums (100 == one core).

    `persisted_gap` is True only when the unaccounted gap has held for
    `cfg.hidden_persist_samples` consecutive samples (rejecting sampling skew);
    the caller tracks that streak.
    """
    unaccounted = max(0.0, system_busy_raw - attributed_raw)
    unaccounted_cores = unaccounted / 100.0
    vm_cores = {name: load / 100.0 for name, load in vm_loads_raw.items()
                if load / 100.0 >= cfg.vm_cores_threshold}

    notes = []
    flagged = False
    if persisted_gap and unaccounted_cores >= cfg.unaccounted_cores_threshold:
        flagged = True
        notes.append(f"{unaccounted_cores:.1f} cores of CPU not attributable to any "
                     f"visible process (possible hidden/rootkit compute)")
    if vm_cores:
        flagged = True
        for name, cores in sorted(vm_cores.items(), key=lambda x: -x[1]):
            notes.append(f"{cores:.1f} cores busy inside a VM/WSL ({name})")
    return HiddenComputeReport(flagged=flagged, unaccounted_cores=unaccounted_cores,
                              vm_loads=vm_cores, note="; ".join(notes))


def sample_vm_loads(procs_cpu: dict[int, tuple[str, float]], cfg: Config) -> dict[str, float]:
    """Sum raw CPU by VM-host process name from a {pid: (name, raw_cpu)} map."""
    from .scoring import name_stem
    out: dict[str, float] = {}
    for _pid, (name, raw) in procs_cpu.items():
        stem = name_stem(name)
        if stem in cfg.vm_host_names:
            out[stem] = out.get(stem, 0.0) + raw
    return out
