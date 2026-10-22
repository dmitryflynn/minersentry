"""Central tuning for MinerSentry.

Everything that decides a verdict — signal weights, CPU cutoffs, verdict bands,
pool ports, miner names, corroboration and conviction rules, probe timing, and
memory-scan budgets — lives here instead of being scattered as literals across
the engine. That makes tuning a data change (and lets tests inject a Config),
not a code edit. Defaults reproduce the behavior the engine shipped with.

An optional %LOCALAPPDATA%\\MinerSentry\\config.json can override any scalar or
collection field; unknown keys are ignored so a stale file never breaks a run.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, fields, replace


@dataclass
class Config:
    # -- CPU signal (raw per-core: 100 == one fully pinned logical core) -----
    cpu_history_len: int = 30
    sustained_seconds: float = 20.0
    cpu_tail: int = 8              # judge the most recent N samples (steady state)
    cpu_min_samples: int = 4      # fewer than this -> "gathering samples"
    cpu_floor_full: float = 85.0  # floor >= this -> strong (score 92)
    cpu_floor_heavy: float = 55.0
    cpu_mean_heavy: float = 70.0  # with floor_heavy -> score 78
    cpu_mean_flat: float = 45.0
    cpu_flat_spread: float = 25.0 # mean-floor < this (flat) -> score 60
    cpu_mean_moderate: float = 28.0  # -> score 35
    cpu_score_full: int = 92
    cpu_score_heavy: int = 78
    cpu_score_flat: int = 60
    cpu_score_moderate: int = 35

    # -- network signal ------------------------------------------------------
    pool_ports: frozenset[int] = field(default_factory=lambda: frozenset({
        3333, 4444, 5555, 7777, 8888, 9999, 14433, 14444, 3334, 5544,
        45560, 45700, 20580, 1111, 2222, 3032, 8008, 8080,
    }))
    common_legit_ports: frozenset[int] = field(default_factory=lambda: frozenset({
        8080, 8008, 1111, 2222,
    }))
    net_score_strong: int = 70
    net_score_weak: int = 30

    # -- name/path signal ----------------------------------------------------
    # Exact stem matches (the whole process name, .exe stripped). Generic tokens
    # like "miner" live here ONLY — matched exactly, never as a substring, so
    # legit apps such as examiner.exe / DataMiner.exe are not flagged.
    known_miner_names: frozenset[str] = field(default_factory=lambda: frozenset({
        "xmrig", "xmr-stak", "nbminer", "phoenixminer", "t-rex", "trex",
        "lolminer", "ethminer", "cgminer", "bfgminer", "ccminer", "cpuminer",
        "minerd", "nanominer", "gminer", "teamredminer", "srbminer",
        "xmrig-cuda", "wildrig", "miner", "winring0",
    }))
    # Distinctive identifiers matched as a SUBSTRING too, to catch renamed
    # variants (e.g. "xmrig-notls.exe"). Only tokens unlikely to appear inside an
    # unrelated program name belong here — never bare "miner".
    known_miner_substrings: frozenset[str] = field(default_factory=lambda: frozenset({
        "xmrig", "xmr-stak", "nbminer", "phoenixminer", "lolminer", "cgminer",
        "bfgminer", "ccminer", "cpuminer", "nanominer", "teamredminer",
        "srbminer", "wildrig",
    }))
    suspicious_dir_hints: tuple[str, ...] = (
        "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
        "\\programdata\\", "\\windows\\fonts\\", "\\recycle",
        "\\appdata\\roaming\\",
    )
    trusted_dirs: tuple[str, ...] = (
        "c:\\program files", "c:\\program files (x86)",
        "c:\\windows\\system32", "c:\\windows\\syswow64",
    )
    name_score_known: int = 85
    name_score_susp_dir: int = 22
    name_score_short: int = 20

    # -- probe signal --------------------------------------------------------
    probe_score_strong: int = 95   # drop >= probe_drop_strong
    probe_score_weak: int = 60     # drop >= probe_drop_weak
    probe_drop_strong: float = 40.0
    probe_drop_weak: float = 20.0

    # -- GPU-compute signal (per-process compute-engine utilization) ---------
    gpu_enabled: bool = True
    gpu_sample_interval: float = 5.0   # seconds between GPU samples (bg thread)
    gpu_history_len: int = 12
    gpu_min_samples: int = 2
    gpu_floor_strong: float = 55.0     # sustained compute floor -> strong
    gpu_mean_moderate: float = 25.0    # average compute -> moderate
    gpu_score_strong: int = 70
    gpu_score_moderate: int = 40
    gpu_window_dampen: float = 0.35    # process owns a visible window (games/UI)
    gpu_ctx_bonus: int = 10            # holds a CUDA/compute context (nvidia-smi)
    gpu_allowlist: frozenset[str] = field(default_factory=lambda: frozenset({
        "blender", "obs64", "obs", "davinci", "resolve", "handbrake",
        "handbrakecli", "ffmpeg", "premiere", "afterfx", "topaz", "boinc",
        "folding", "foldingathome", "dwm",
    }))

    # -- hidden-compute / power-gap (system-level banner, not a per-proc score)
    power_enabled: bool = True
    power_meter_enabled: bool = False  # true package power (rare hardware)
    unaccounted_cores_threshold: float = 1.5   # cores of unexplained CPU
    hidden_persist_samples: int = 3            # must hold this many samples
    vm_host_names: frozenset[str] = field(default_factory=lambda: frozenset({
        "vmmem", "vmmemwsl", "vmwp", "vmcompute",
    }))
    vm_cores_threshold: float = 1.0            # cores inside a VM/WSL to flag

    # -- network-connection persistence --------------------------------------
    net_persist_seconds: float = 30.0  # ESTABLISHED to a pool port for this long
    net_score_persist: int = 15        # bump added to a persisted connection

    # -- blending / verdict --------------------------------------------------
    weights: dict[str, float] = field(default_factory=lambda: {
        "cpu": 0.26, "gpu": 0.16, "memory": 0.26,
        "network": 0.14, "name": 0.10, "probe": 0.08,
    })
    verdict_thresholds: tuple[tuple[int, str], ...] = (
        (75, "Likely Miner"), (45, "Suspicious"), (0, "Clean"),
    )

    # -- corroboration (anti-false-positive core) ----------------------------
    corrob_nonzero_score: int = 25   # a signal counts as "present" at/above this
    corrob_min_signals: int = 2      # need this many present, else cap applies
    hard_memory: int = 40            # memory >= this is standalone hard evidence
    hard_name: int = 70
    hard_probe: int = 60
    suspicious_cap: int = 44         # cap when not corroborated and no hard evidence

    # -- conviction pairs: (sigA, minA, sigB, minB, floor_score) -------------
    # Each requires a behavioral signal AND a corroborating artifact/behavior,
    # so an idle process merely carrying strings can't trip one.
    conviction_rules: tuple[tuple[str, int, str, int, int], ...] = (
        ("cpu", 60, "memory", 60, 82),
        ("cpu", 55, "network", 60, 85),
        ("cpu", 50, "name", 70, 85),
        ("cpu", 40, "probe", 60, 88),
        ("memory", 60, "network", 60, 80),
        # GPU-miner pairs: compute saturation + a corroborating artifact/behavior
        ("gpu", 60, "memory", 60, 82),
        ("gpu", 60, "name", 70, 85),
        ("gpu", 55, "network", 60, 85),
        ("gpu", 60, "cpu", 45, 80),
        # RandomX ~2 GiB dataset + resident miner strings is diagnostic even at
        # low CPU — this is what catches a heavily-throttled stealth miner.
        ("dataset", 60, "memory", 60, 82),
    )

    # -- trust dampening -----------------------------------------------------
    # Multiplier applied to memory/name scores for trusted-signed processes, so
    # a signed Defender/AV binary that legitimately carries miner strings can't
    # alarm. Behavioral signals (cpu/probe) are left at full weight.
    trusted_dampen: float = 0.2

    # -- memory-scan budgets -------------------------------------------------
    mem_max_region_read: int = 4 * 1024 * 1024
    # Miner strings live early in the heap/data; the ~2 GiB RandomX dataset is
    # detected from region *size* (VirtualQueryEx) without reading it. So a
    # modest per-process read budget keeps deep scans fast without missing hits.
    mem_max_bytes_per_proc: int = 48 * 1024 * 1024
    mem_large_dataset_bytes: int = 2 * 1024 * 1024 * 1024 - (64 * 1024 * 1024)

    # -- scan cadence / deep scan -------------------------------------------
    scan_interval: float = 2.5
    deep_limit: int = 6
    # Only deep-scan processes using at least this much CPU (raw per-core: 30 ==
    # ~0.3 of a core). A CPU miner is by definition busy, so this keeps the deep
    # scan fast and skips idle processes whose resident strings are irrelevant.
    deep_cpu_floor: float = 30.0
    # A process holding a private allocation this large is a RandomX-dataset-sized
    # working set (~2 GiB). It is memory-scanned regardless of CPU, so a heavily
    # throttled stealth miner can't hide under the CPU floor.
    dataset_private_bytes: int = 1900 * 1024 * 1024
    dataset_score: int = 70

    @classmethod
    def load(cls, path: str | None = None) -> "Config":
        """Return defaults, overridden by a config.json if one exists."""
        cfg = cls()
        if path is None:
            base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
            path = os.path.join(base, "MinerSentry", "config.json")
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return cfg
        known = {f.name for f in fields(cls)}
        overrides = {}
        for k, v in (data.items() if isinstance(data, dict) else []):
            if k not in known:
                continue
            cur = getattr(cfg, k)
            # Coerce / type-check against the default's type so a malformed entry
            # (e.g. weights given as a list) is skipped rather than crashing later.
            try:
                if isinstance(cur, frozenset):
                    v = frozenset(v)
                elif isinstance(cur, tuple):
                    v = tuple(tuple(x) if isinstance(x, list) else x for x in v)
                elif isinstance(cur, dict):
                    if not isinstance(v, dict):
                        continue
                elif isinstance(cur, bool):   # bool before int (bool subclasses int)
                    if not isinstance(v, bool):
                        continue
                elif isinstance(cur, (int, float)):
                    if isinstance(v, bool) or not isinstance(v, (int, float)):
                        continue
                elif isinstance(cur, str) and not isinstance(v, str):
                    continue
            except (TypeError, ValueError):
                continue
            overrides[k] = v
        return replace(cfg, **overrides) if overrides else cfg
