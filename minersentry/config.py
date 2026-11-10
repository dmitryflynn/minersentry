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
import math
import os
import sys
from dataclasses import dataclass, field, fields, replace

_IS_WINDOWS = sys.platform == "win32"

# Platform-aware directory defaults (trusted system locations vs. the dirs
# miners commonly run from). Overridable via config.json like any other field.
_TRUSTED_DIRS_WIN = ("c:\\program files", "c:\\program files (x86)",
                     "c:\\windows\\system32", "c:\\windows\\syswow64")
_TRUSTED_DIRS_POSIX = ("/usr/bin", "/usr/sbin", "/bin", "/sbin",
                       "/usr/lib", "/usr/libexec", "/opt")
_SUSPICIOUS_DIRS_WIN = ("\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
                        "\\programdata\\", "\\windows\\fonts\\", "\\recycle",
                        "\\appdata\\roaming\\")
_SIG_UNTRUSTED_WIN = ("\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
                      "\\appdata\\roaming\\", "\\$recycle.bin\\", "\\windows\\fonts\\")
_SIG_UNTRUSTED_POSIX = ("/tmp/", "/var/tmp/", "/dev/shm/")
_SUSPICIOUS_DIRS_POSIX =("/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/",
                          "/var/www/", "/.cache/")


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
    net_score_weak: int = 30
    # A long-lived connection to a stratum-typical port (not a common business
    # port). Kept below 60 on purpose: too weak to convict alongside CPU or GPU
    # load (legit services use these ports too), but enough to convict alongside
    # resident miner protocol strings, which are miner-specific on their own.
    net_score_stratum_persisted: int = 50
    net_score_known_pool: int = 90    # connected to a resolved known-pool IP
    pool_intel_enabled: bool = True
    pool_refresh_seconds: float = 900.0

    # -- name/path signal ----------------------------------------------------
    # Known brand basenames, with delimiter/numeric suffix variants. Generic
    # "miner" is not an identity: normal desktop indexers use that word too.
    known_miner_names: frozenset[str] = field(default_factory=lambda: frozenset({
        "xmrig", "xmr-stak", "nbminer", "phoenixminer", "t-rex", "trex",
        "lolminer", "ethminer", "cgminer", "bfgminer", "ccminer", "cpuminer",
        "minerd", "nanominer", "gminer", "teamredminer", "srbminer",
        "xmrig-cuda", "wildrig",
    }))
    # Legacy config key retained for compatibility. Entries are now brand
    # aliases with the same basename/suffix boundaries, not arbitrary substrings.
    known_miner_substrings: frozenset[str] = field(default_factory=lambda: frozenset({
        "xmrig", "xmr-stak", "nbminer", "phoenixminer", "lolminer", "cgminer",
        "bfgminer", "ccminer", "cpuminer", "nanominer", "teamredminer",
        "srbminer", "wildrig",
    }))
    suspicious_dir_hints: tuple[str, ...] = field(
        default_factory=lambda: _SUSPICIOUS_DIRS_WIN if _IS_WINDOWS else _SUSPICIOUS_DIRS_POSIX)
    # Where a valid signature earns NO trust: user-writable drop spots no
    # legitimate signed product runs from. Narrower than suspicious_dir_hints on
    # purpose — Defender itself runs signed from ProgramData.
    signature_untrusted_dirs: tuple[str, ...] = field(
        default_factory=lambda: _SIG_UNTRUSTED_WIN if _IS_WINDOWS else _SIG_UNTRUSTED_POSIX)
    trusted_dirs: tuple[str, ...] = field(
        default_factory=lambda: _TRUSTED_DIRS_WIN if _IS_WINDOWS else _TRUSTED_DIRS_POSIX)
    name_score_known: int = 85
    name_score_susp_dir: int = 22
    name_score_short: int = 20

    # -- probe signal --------------------------------------------------------
    probe_score_strong: int = 95   # drop >= probe_drop_strong
    probe_score_weak: int = 60     # drop >= probe_drop_weak
    probe_drop_strong: float = 40.0
    probe_drop_weak: float = 20.0
    # Decoys spawned together during the probe. Evasive miners watch for more
    # than Task Manager, so the probe impersonates the common monitors at once.
    probe_decoys_windows: tuple[str, ...] = (
        "taskmgr.exe", "procexp64.exe", "ProcessHacker.exe", "SystemInformer.exe",
        "perfmon.exe", "resmon.exe",
    )
    probe_decoys_posix: tuple[str, ...] = ("htop", "top", "nvtop", "btop")

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
    # Consecutive samples a PID may be missing from GPU telemetry before its
    # history is dropped. pmon/typeperf skip rows now and then; resetting on the
    # first gap meant a flapping process never collected enough samples.
    gpu_miss_tolerance: int = 2
    gpu_allowlist: frozenset[str] = field(default_factory=lambda: frozenset({
        "blender", "obs64", "obs", "davinci", "resolve", "handbrake",
        "handbrakecli", "ffmpeg", "premiere", "afterfx", "topaz", "boinc",
        "folding", "foldingathome", "dwm",
    }))

    # -- hidden-compute / power-gap (system-level banner, not a per-proc score)
    power_enabled: bool = True
    power_meter_enabled: bool = False  # true package power (rare hardware)
    # Cores of unexplained CPU ABOVE this machine's learned baseline. Every busy
    # system has some (interrupts, short-lived processes, kernel work) and it
    # scales with load, so the gap is judged against a learned ratio of busy CPU.
    unaccounted_cores_threshold: float = 1.5
    hidden_persist_samples: int = 3            # must hold this many samples
    hidden_calibration_samples: int = 12       # passes used to learn the baseline
    hidden_baseline_alpha: float = 0.05        # slow EMA update while not flagged
    vm_host_names: frozenset[str] = field(default_factory=lambda: frozenset({
        "vmmem", "vmmemwsl", "vmwp", "vmcompute",
    }))
    vm_cores_threshold: float = 1.0            # cores inside a VM/WSL to flag

    # -- network-connection persistence --------------------------------------
    net_persist_seconds: float = 30.0  # ESTABLISHED to a pool port for this long
    # Reconnecting faster than net_persist_seconds used to reset the clock, so a
    # miner that cycles its connection never looked long-lived. Repeatedly
    # returning to the SAME endpoint counts instead: it is miner-like in itself.
    net_reconnects_persist: int = 3
    # Ask Windows how old each connection actually is (Get-NetTCPConnection),
    # so a 20-second scan can still tell an hours-old pool connection from a
    # fresh one. Best effort, on a background thread; Linux exposes no age.
    net_use_connection_age: bool = True
    net_age_refresh_seconds: float = 120.0

    # -- background monitoring / alerts --------------------------------------
    # A command run on each new detection (it receives title and body as two
    # arguments). Empty means use the platform's own notification.
    notify_command: str = ""
    notify_min_verdict: str = "Likely Miner"   # or "Suspicious"

    # -- deployment profile --------------------------------------------------
    # "desktop" (default): a known miner binary name on its own is Suspicious,
    # because on a personal machine an idle or paused xmrig is still worth a look.
    # "cloud": a name alone stays Clean (shared GPU/ML hosts run lots of oddly
    # named jobs and alerts are expensive); it still convicts with CPU/GPU load.
    profile: str = "desktop"
    desktop_name_floor: int = 50   # score given to a lone known name on desktop

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
    # Arguments at/above this are miner-specific enough to count as an artifact
    # (generic flags are capped below it by cmdline.score_of).
    hard_cmdline: int = 40
    suspicious_cap: int = 44         # cap when not corroborated and no hard evidence

    # -- conviction pairs: (sigA, minA, sigB, minB, floor_score) -------------
    # Each requires a behavioral signal AND a corroborating artifact/behavior,
    # so an idle process merely carrying strings can't trip one.
    conviction_rules: tuple[tuple[str, int, str, int, int], ...] = (
        ("cpu", 60, "memory", 60, 82),
        # Resident miner PROTOCOL strings are miner-specific on their own, so
        # they convict next to merely moderate load. A miner throttled to a
        # third of a core used to sit at Clean with xmrig/stratum in memory.
        ("cpu", 35, "memory", 60, 82),
        ("cpu", 55, "network", 60, 85),
        ("cpu", 50, "name", 70, 85),
        ("cpu", 40, "probe", 60, 88),
        # Miner protocol strings in memory + a long-lived stratum-port connection:
        # catches a throttled miner whose pool isn't on the known-pool list.
        ("memory", 60, "network", 50, 80),
        # GPU-miner pairs: compute saturation + a corroborating artifact/behavior
        ("gpu", 60, "memory", 60, 82),
        ("gpu", 40, "memory", 60, 82),
        ("gpu", 60, "name", 70, 85),
        ("gpu", 55, "network", 60, 85),
        # CPU + GPU saturation also occurs in normal CUDA/ML workloads.
        # RandomX ~2 GiB dataset + resident miner strings is diagnostic even at
        # low CPU — this is what catches a heavily-throttled stealth miner.
        ("dataset", 60, "memory", 60, 82),
        # Memory-hard cache-miss fingerprint (Linux PMU) + a corroborating
        # artifact — catches a RandomX miner by its work even when throttled.
        # perf+dataset needs a STRONG miss rate (a busy DB with a 2 GiB cache
        # also misses), but even a MODERATE miss rate convicts alongside resident
        # miner strings or a miner binary name (both miner-specific).
        ("perf", 70, "dataset", 60, 85),
        ("perf", 40, "memory", 60, 82),
        ("perf", 40, "name", 70, 85),
        # Mining arguments (pool URL / wallet / miner-only flags) + the work.
        # Thresholds are low on the behavioral side on purpose: the arguments
        # already say what the process is for, so a miner throttled under the
        # CPU floor no longer needs resident strings to be caught.
        ("cmdline", 40, "cpu", 35, 85),
        ("cmdline", 40, "gpu", 40, 85),
        ("cmdline", 40, "memory", 40, 88),
        ("cmdline", 40, "network", 30, 85),
        ("cmdline", 40, "dataset", 60, 88),
        ("cmdline", 40, "perf", 40, 88),
        ("cmdline", 40, "probe", 60, 90),
        # A swarm of one binary + anything miner-specific about it.
        ("swarm", 40, "memory", 60, 85),
        ("swarm", 40, "cmdline", 40, 85),
        ("swarm", 40, "name", 70, 85),
        ("swarm", 40, "network", 50, 85),
        ("swarm", 40, "dataset", 60, 85),
        ("swarm", 40, "probe", 60, 88),
        # A connection to a RESOLVED known-pool IP (network >= 88) is near
        # conclusive — legit software has no reason to talk to supportxmr — so a
        # minimal behavioral corroborator convicts.
        ("network", 88, "cpu", 28, 82),
        ("network", 88, "gpu", 40, 82),
        ("network", 88, "memory", 40, 85),
        ("network", 88, "dataset", 60, 85),
    )

    # -- trust dampening -----------------------------------------------------
    # Multiplier applied to memory/name scores for trusted-signed processes, so
    # a signed Defender/AV binary that legitimately carries miner strings can't
    # alarm. Behavioral signals (cpu/probe) are left at full weight.
    trusted_dampen: float = 0.2
    # Processes miners inject into. They are signed / live in System32, but none
    # of them has a reason to hold miner strings, so they are never dampened:
    # otherwise an injected miner scores Clean.
    injection_hosts: frozenset[str] = field(default_factory=lambda: frozenset({
        "svchost", "explorer", "dllhost", "rundll32", "regsvr32", "conhost",
        "notepad", "werfault", "wmiprvse", "msbuild", "regasm", "regsvcs",
        "installutil", "aspnet_compiler", "vbc", "csc", "cmd", "powershell",
        "pwsh", "wscript", "cscript", "mshta", "searchprotocolhost", "sihost",
        "taskhostw", "runtimebroker", "winlogon", "services", "spoolsv",
        "wuauclt", "nslookup", "attrib", "colorcpl", "calc", "mspaint",
        "applaunch", "addinprocess", "addinprocess32", "msiexec",
    }))

    # Interpreters and script hosts. A miner written in JS/Python/Java runs
    # under a validly signed interpreter, so trust dampening used to reduce its
    # resident miner strings to nothing (a full-core miner scored Clean 29).
    # The interpreter binary is trusted; the SCRIPT it runs is not, so these are
    # never dampened. Browsers/Electron apps are deliberately absent: they are
    # a large, legitimate population and the generic memory cap already covers
    # the strings they can pick up from a web page.
    interpreter_hosts: frozenset[str] = field(default_factory=lambda: frozenset({
        "python", "python3", "pythonw", "py", "node", "nodejs", "deno", "bun",
        "java", "javaw", "dotnet", "mono", "ruby", "perl", "php", "lua",
        "pwsh", "powershell", "wscript", "cscript", "mshta", "tclsh", "Rscript",
    }))

    # -- process-swarm signal (many small workers of one binary) -------------
    # The split-the-work evasion: 20 processes of the same unsigned binary at a
    # quarter core each stay under every per-process floor while mining several
    # cores. Judged per executable, not per PID.
    swarm_enabled: bool = True
    swarm_min_procs: int = 4         # at least this many processes of one exe
    swarm_min_cores: float = 1.0     # together using at least this many cores
    swarm_min_each: float = 5.0      # ignore idle siblings (raw per-core)
    swarm_score: int = 45

    # -- memory-scan budgets -------------------------------------------------
    mem_max_region_read: int = 4 * 1024 * 1024
    # Chunks per region, spread across it. Reading only the first slice of each
    # region let a miner bury its strings deeper into one big allocation.
    mem_region_samples: int = 4
    # A process at or below this size is scanned COMPLETELY rather than sampled
    # (a miner's own footprint is small; its 2 GiB dataset is judged by size).
    mem_full_scan_max_bytes: int = 128 * 1024 * 1024
    # Miner strings live early in the heap/data; the ~2 GiB RandomX dataset is
    # detected from region *size* (VirtualQueryEx) without reading it. So a
    # modest per-process read budget keeps deep scans fast without missing hits.
    mem_max_bytes_per_proc: int = 48 * 1024 * 1024
    mem_large_dataset_bytes: int = 2 * 1024 * 1024 * 1024 - (64 * 1024 * 1024)

    # -- scan cadence / deep scan -------------------------------------------
    scan_interval: float = 2.5
    deep_limit: int = 6
    # The GUI memory-scans its candidates on its own this often (seconds), so the
    # memory/dataset/perf signals work without anyone clicking a button. 0 = off.
    deep_auto_interval: float = 45.0
    # Only deep-scan processes using at least this much CPU (raw per-core: 30 ==
    # ~0.3 of a core). A CPU miner is by definition busy, so this keeps the deep
    # scan fast and skips idle processes whose resident strings are irrelevant.
    deep_cpu_floor: float = 30.0
    # Floor for a binary that is NOT in a system directory. A CPU-capped miner
    # deliberately sits under the normal floor, and an unsigned process using a
    # tenth of a core is cheap to memory-scan and the likelier suspect.
    deep_cpu_floor_untrusted: float = 8.0
    # A process holding a private allocation this large is a RandomX-dataset-sized
    # working set (~2 GiB). It is memory-scanned regardless of CPU, so a heavily
    # throttled stealth miner can't hide under the CPU floor.
    dataset_private_bytes: int = 1900 * 1024 * 1024
    dataset_score: int = 70

    # -- command-line signal -------------------------------------------------
    cmdline_enabled: bool = True
    # Ceiling when only generic flags matched. Deliberately below
    # corrob_nonzero_score (25): ordinary flags shouldn't even count as a
    # corroborating signal, let alone convict.
    cmdline_generic_cap: int = 24

    # -- hardware perf-counter signal (Linux, user-mode perf_event_open) ------
    perf_enabled: bool = True
    perf_interval: float = 0.3          # seconds to count per candidate PID
    perf_strong: float = 150.0          # cache misses / 1k instr -> strong
    perf_moderate: float = 60.0
    perf_score_strong: int = 75
    perf_score_moderate: int = 40

    # Not settable from any file (bookkeeping, filled in by load()).
    load_warnings: list[str] = field(default_factory=list, repr=False, compare=False)

    @classmethod
    def load(cls, path: str | None = None) -> "Config":
        r"""Build the effective configuration.

        With an explicit `path` (tests, `--config`), that file is trusted fully.
        Otherwise two files are read:

        - the system file (`system_config_path()`), which only an administrator
          can write: every setting may be tuned there;
        - the per-user file under %LOCALAPPDATA% / ~, which anything running as
          the user can write, malware included. It may only touch settings that
          cannot blind detection (bounded scan timing) or ADD miner names and
          pool ports. Everything else in it is ignored with a warning, because
          one line there (raise the verdict thresholds, trust C:\) used to turn
          a convicted miner Clean.

        Every value is validated (type, range, shape). A bad value is skipped and
        reported in `load_warnings` rather than crashing a later scan.
        """
        cfg = cls()
        warnings: list[str] = []
        if path is not None:
            cfg = _apply(cfg, _read(path, warnings), warnings, restricted=False, src=path)
        else:
            sys_path = system_config_path()
            if _system_file_is_protected(sys_path, warnings):
                cfg = _apply(cfg, _read(sys_path, warnings), warnings, restricted=False,
                             src=sys_path)
            user_path = user_config_path()
            cfg = _apply(cfg, _read(user_path, warnings), warnings, restricted=True,
                         src=user_path)
        cfg.load_warnings = warnings
        return cfg


def user_config_path() -> str:
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    return os.path.join(base, "MinerSentry", "config.json")


def system_config_path() -> str:
    if _IS_WINDOWS:
        base = os.environ.get("ProgramFiles") or r"C:\Program Files"
        return os.path.join(base, "MinerSentry", "config.json")
    return "/etc/minersentry/config.json"


def _system_file_is_protected(path: str, warnings: list[str]) -> bool:
    """Only honor the system file if a normal user can't have written it."""
    if not os.path.exists(path):
        return False
    real = os.path.realpath(path)
    if _IS_WINDOWS:
        # Creating anything under Program Files needs admin. Refuse a path that
        # resolves elsewhere (a junction planted to point at a user folder).
        base = os.path.realpath(os.environ.get("ProgramFiles") or r"C:\Program Files")
        if not real.lower().startswith(base.lower().rstrip("\\") + "\\"):
            warnings.append(f"ignored {path}: resolves outside Program Files")
            return False
        return True
    try:
        st = os.stat(real)
        parent = os.stat(os.path.dirname(real))
    except OSError:
        return False
    for what, s_ in (("file", st), ("folder", parent)):
        if s_.st_uid != 0 or s_.st_mode & 0o022:
            warnings.append(f"ignored {path}: {what} must be root-owned and not "
                            f"group/world-writable")
            return False
    return True


def _read(path: str, warnings: list[str]) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as e:
        warnings.append(f"ignored {path}: {type(e).__name__}: {e}")
        return {}
    if not isinstance(data, dict):
        warnings.append(f"ignored {path}: top level must be a JSON object")
        return {}
    return data


# Settings the per-user file may change: timing within safe bounds.
_USER_BOUNDED = {
    "scan_interval": (1.0, 10.0),
    "gpu_sample_interval": (2.0, 60.0),
    "deep_auto_interval": (15.0, 120.0),
}
# Collections the per-user file may only ADD to (union with the defaults).
_USER_ADDITIVE = {"known_miner_names", "known_miner_substrings", "pool_ports"}
_VERDICTS = {"Likely Miner", "Suspicious", "Clean"}
_NOT_SETTABLE = {"load_warnings"}
_SCORE_NAMES = {"suspicious_cap", "hard_memory", "hard_name", "hard_probe",
                "corrob_nonzero_score", "desktop_name_floor"}
_UNIT_NAMES = {"trusted_dampen", "gpu_window_dampen", "hidden_baseline_alpha"}


def _is_num(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


def _range_for(name: str) -> tuple[float, float]:
    if "score" in name or name in _SCORE_NAMES:
        return (0, 100)
    if name in _UNIT_NAMES:
        return (0, 1)
    if name == "scan_interval":
        return (0.5, 3600)
    return (0, float("inf"))


def _validate(name: str, cur, v):
    """Return (ok, coerced value) or (False, reason)."""
    if isinstance(cur, bool):
        return (True, v) if isinstance(v, bool) else (False, "expected true/false")
    if isinstance(cur, (int, float)):
        if not _is_num(v):
            return False, "expected a number"
        if isinstance(cur, int):
            if not float(v).is_integer():
                return False, "expected a whole number"
            v = int(v)
        else:
            v = float(v)
        lo, hi = _range_for(name)
        if not lo <= v <= hi:
            return False, f"out of range [{lo}, {hi}]"
        if name == "deep_auto_interval" and 0 < v < 10:
            return False, "must be 0 (off) or at least 10 seconds"
        return True, v
    if isinstance(cur, str):
        if not isinstance(v, str):
            return False, "expected text"
        if name == "profile" and v not in ("desktop", "cloud"):
            return False, "must be 'desktop' or 'cloud'"
        return True, v
    if isinstance(cur, dict):            # weights
        if not isinstance(v, dict) or not v:
            return False, "expected a non-empty object"
        if not all(isinstance(k, str) and _is_num(x) and x >= 0 for k, x in v.items()):
            return False, "weights must be non-negative numbers"
        return True, dict(v)
    if isinstance(cur, frozenset):
        if not isinstance(v, list):
            return False, "expected a list"
        if cur and isinstance(next(iter(cur)), int):
            if not all(isinstance(x, int) and not isinstance(x, bool) and 0 < x < 65536
                       for x in v):
                return False, "list items must be port numbers"
            return True, frozenset(v)
        if not all(isinstance(x, str) and x for x in v):
            return False, "list items must be text"
        return True, frozenset(x.lower() for x in v)
    if isinstance(cur, tuple):
        if not isinstance(v, list):
            return False, "expected a list"
        if name == "conviction_rules":
            ok = all(isinstance(r, list) and len(r) == 5 and isinstance(r[0], str)
                     and isinstance(r[2], str)
                     and all(_is_num(r[i]) and 0 <= r[i] <= 100 for i in (1, 3, 4))
                     for r in v)
            if not ok:
                return False, "each rule must be [signal, min, signal, min, floor], numbers 0-100"
            return True, tuple(tuple(r) for r in v)
        if name == "verdict_thresholds":
            ok = (all(isinstance(r, list) and len(r) == 2 and _is_num(r[0])
                      and 0 <= r[0] <= 100 and r[1] in _VERDICTS for r in v)
                  and any(r[0] == 0 for r in v))
            if not ok:
                return False, "each entry must be [0-100, verdict] and one must start at 0"
            return True, tuple(sorted((tuple(r) for r in v), key=lambda r: -r[0]))
        if not all(isinstance(x, str) and x for x in v):
            return False, "list items must be text"
        if name.startswith("probe_decoys"):
            # decoy names become file names: no folders, no traversal
            if not all(os.path.basename(x) == x and "/" not in x and "\\" not in x
                       and x not in (".", "..") for x in v):
                return False, "decoy names must be plain file names"
            return True, tuple(v)
        return True, tuple(x.lower() for x in v)
    return False, "unsupported setting"


def _apply(cfg: "Config", data: dict, warnings: list[str], *, restricted: bool,
           src: str) -> "Config":
    known = {f.name for f in fields(Config)} - _NOT_SETTABLE
    overrides = {}
    for k, v in data.items():
        if k not in known:
            continue  # unknown keys are ignored so an old file never breaks a run
        if restricted and k not in _USER_BOUNDED and k not in _USER_ADDITIVE:
            warnings.append(f"ignored '{k}' in {src}: only the admin config "
                            f"({system_config_path()}) may change it")
            continue
        ok, val = _validate(k, getattr(cfg, k), v)
        if not ok:
            warnings.append(f"ignored '{k}' in {src}: {val}")
            continue
        if restricted and k in _USER_BOUNDED:
            lo, hi = _USER_BOUNDED[k]
            if not lo <= val <= hi:
                warnings.append(f"ignored '{k}' in {src}: per-user value must be in [{lo}, {hi}]")
                continue
        if restricted and k in _USER_ADDITIVE:
            val = getattr(cfg, k) | val
        overrides[k] = val
    out = replace(cfg, **overrides) if overrides else cfg
    out.load_warnings = list(cfg.load_warnings)
    return out
