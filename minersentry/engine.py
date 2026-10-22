"""Behavioral detection engine — the collector.

This gathers inputs from psutil (CPU history, connections, name/path, memory
scan results, probe drops) and hands them to the pure functions in `scoring`
to produce per-signal scores and a verdict. All tunables come from `config`.
The combination is deliberate: a miner trips several signals at once, while an
ordinary heavy app trips at most one or two, so requiring corroboration is what
holds false positives down.
"""

from __future__ import annotations

import os
import threading
import time
from collections import defaultdict, deque

import psutil

from . import memscan, power, trust
from .audit import AuditLog
from .config import Config
from .scoring import (
    Signal, combine, is_miner_name, name_stem, score_cpu, score_gpu,
    score_memory, score_name, score_network, score_probe,
)


class ProcInfo:
    __slots__ = ("pid", "name", "exe", "username", "cpu", "cpu_mean", "cpu_min",
                 "mem_mb", "threads", "signals", "verdict", "score", "mem_result",
                 "trusted", "gpu")

    def __init__(self, pid: int, cpu: float = 0.0) -> None:
        self.pid = pid
        self.name = "?"
        self.exe = ""
        self.username = ""
        self.cpu = cpu            # normalized 0-100 of whole machine (display)
        self.cpu_mean = 0.0
        self.cpu_min = 0.0
        self.gpu = 0.0            # latest GPU compute % (display)
        self.mem_mb = 0.0
        self.threads = 0
        self.signals: list[Signal] = []
        self.verdict = "Clean"
        self.score = 0
        self.mem_result: memscan.MemScanResult | None = None
        self.trusted = False

    @property
    def signal_summary(self) -> str:
        return ", ".join(f"{s.name}={s.score}" for s in self.signals if s.score > 0)


class Engine:
    def __init__(self, cfg: Config | None = None, audit: AuditLog | None = None) -> None:
        self.cfg = cfg or Config.load()
        self._ncpu = psutil.cpu_count(logical=True) or 1
        self._cpu_hist: dict[int, deque[tuple[float, float]]] = defaultdict(
            lambda: deque(maxlen=self.cfg.cpu_history_len))
        self._probe_drops: dict[int, float] = {}
        self._warm: set[int] = set()
        self._self_pid = os.getpid()
        self._mem_cache: dict[int, memscan.MemScanResult] = {}  # from deep scans
        # Static per-PID metadata cache (name/exe/username/trusted don't change
        # for a PID's lifetime; recomputing exe()/username()/Authenticode every
        # pass for ~300 processes made each pass multi-second).
        self._meta: dict[int, tuple[str, str, str, bool]] = {}
        self._last_verdict: dict[int, str] = {}
        # GPU snapshot (set by a background sampler, read each pass).
        self._gpu_hist: dict[int, deque[float]] = defaultdict(
            lambda: deque(maxlen=self.cfg.gpu_history_len))
        self._gpu_windows: set[int] = set()
        self._gpu_ctx: set[int] = set()
        # _gpu_hist/_gpu_windows/_gpu_ctx are written by a background GPU sampler
        # thread and read by the scan thread, so every access is lock-guarded.
        self._gpu_lock = threading.Lock()
        self.system_cpu_pct = 0.0  # single-owner system CPU reading (0-100)
        # Network-connection persistence: (pid, ip, port) -> first-seen ts.
        self._conn_seen: dict[tuple[int, str, int], float] = {}
        # Hidden-compute tracking.
        self._gap_streak = 0
        self.hidden_report = power.HiddenComputeReport()
        # Deep-scan target list, recomputed on the scan thread each pass and read
        # as a stable snapshot by the GUI's background deep thread (so that thread
        # never walks the live _cpu_hist/_meta/_conn_seen dicts concurrently).
        self._deep_targets: list[int] = []
        self.audit = audit or AuditLog()
        self.last_scan_errors = 0  # memory OpenProcess failures last deep pass
        for p in psutil.process_iter():  # prime per-process cpu_percent baselines
            try:
                p.cpu_percent(None)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        psutil.cpu_percent(None)  # prime the system-wide baseline too, so the
        # first pass's system_cpu_pct / hidden-compute gap isn't a bogus 0

    # -- input gathering ----------------------------------------------------
    def _pool_hits(self, pid: int, raddrs: list[tuple[str, int]],
                   now: float) -> list[tuple[str, int, bool, bool]]:
        hits = []
        for ip, port in raddrs:
            if port not in self.cfg.pool_ports:
                continue
            key = (pid, ip, port)
            first = self._conn_seen.setdefault(key, now)
            persisted = (now - first) >= self.cfg.net_persist_seconds
            hits.append((ip, port, port in self.cfg.common_legit_ports, persisted))
        return hits

    def _mem_labels(self, r: memscan.MemScanResult | None) -> tuple[bool, int, list[str], str | None, int]:
        if r is None:
            return (False, 0, [], "not scanned", 0)
        labels: list[str] = []
        if r.large_page_dataset:
            labels.append("~2 GiB dataset (RandomX-sized)")
        labels += [h.label for h in r.hits]
        return (r.scanned, r.score, labels, r.error, r.bytes_scanned)

    def _cpu_stats(self, pid: int) -> list[float]:
        now = time.time()
        return [c for t, c in self._cpu_hist[pid]
                if now - t <= self.cfg.sustained_seconds]

    def _build_signals(self, info: ProcInfo, raddrs: list[tuple[str, int]],
                       now: float) -> list[Signal]:
        cfg = self.cfg
        recent = self._cpu_stats(info.pid)
        cpu_sig = score_cpu(recent, self._ncpu, cfg)
        if recent:
            tail = recent[-cfg.cpu_tail:]
            info.cpu_mean = sum(tail) / len(tail) / self._ncpu
            info.cpu_min = min(tail) / self._ncpu

        # GPU-compute signal. Snapshot the shared GPU state under the lock.
        with self._gpu_lock:
            gpu_recent = list(self._gpu_hist.get(info.pid, ()))
            has_window = info.pid in self._gpu_windows
            has_ctx = info.pid in self._gpu_ctx
        if gpu_recent:
            info.gpu = gpu_recent[-1]
        gpu_sig = score_gpu(gpu_recent, has_window,
                            name_stem(info.name) in cfg.gpu_allowlist, has_ctx, cfg)

        scanned, mscore, labels, err, nbytes = self._mem_labels(info.mem_result)
        mem_sig = score_memory(scanned, mscore, labels, err, nbytes)
        name_sig = score_name(info.name, info.exe, cfg)

        # Trust dampening: a validly-signed OS/AV binary legitimately carrying
        # miner strings must not alarm, so cut its memory/name scores. Leave the
        # behavioral signals (cpu/probe) untouched.
        if info.trusted and cfg.trusted_dampen < 1.0:
            if mem_sig.score:
                mem_sig = Signal("memory", int(mem_sig.score * cfg.trusted_dampen),
                                 mem_sig.detail + " (trusted-signed: dampened)")
            if name_sig.score:
                name_sig = Signal("name", int(name_sig.score * cfg.trusted_dampen),
                                  name_sig.detail + " (trusted-signed: dampened)")

        return [
            cpu_sig, gpu_sig, mem_sig,
            score_network(self._pool_hits(info.pid, raddrs, now), cfg),
            name_sig,
            score_probe(self._probe_drops.get(info.pid, 0.0), cfg),
        ]

    # -- deep (memory) scanning: driven async by the GUI, or sync by CLI -----
    def top_cpu_pids(self, limit: int | None = None) -> list[int]:
        limit = limit or self.cfg.deep_limit
        now = time.time()
        ranked = []
        for pid, hist in self._cpu_hist.items():
            recent = [c for t, c in hist if now - t <= self.cfg.sustained_seconds]
            if recent and pid > 4 and pid != self._self_pid:
                peak = max(recent)
                if peak >= self.cfg.deep_cpu_floor:  # only busy processes
                    ranked.append((pid, peak))
        ranked.sort(key=lambda x: x[1], reverse=True)
        return [pid for pid, _ in ranked[:limit]]

    def deep_scan_targets(self, limit: int | None = None,
                          force: set[int] | None = None) -> list[int]:
        """PIDs worth memory-scanning: the busy ones, PLUS any process holding a
        pool-port connection or carrying a miner-like name regardless of CPU,
        PLUS any explicitly forced PIDs (e.g. a --pid target).

        A heavily CPU-capped stealth miner sits below the busy floor, but it
        still has to talk to a pool — so scanning every pool-connected process
        closes that evasion (a resident-strings hit then corroborates the
        connection into a verdict).

        Shared dicts are snapshotted with list(...) so a concurrent caller never
        iterates them live; the result is capped so it can't grow without bound."""
        limit = limit or self.cfg.deep_limit
        targets = self.top_cpu_pids(limit)
        seen = set(targets)

        def _add(pid: int) -> None:
            if pid > 4 and pid != self._self_pid and pid not in seen:
                seen.add(pid)
                targets.append(pid)

        for pid in (force or ()):                      # explicit --pid targets
            _add(pid)
        protected = len(targets)  # busy + forced targets are never truncated
        for pid, _ip, _port in list(self._conn_seen):  # pool-connected, any CPU
            _add(pid)
        for pid, meta in list(self._meta.items()):     # miner-like name, any CPU
            if is_miner_name(meta[0], self.cfg):
                _add(pid)
        # Cap only the auto-discovered additions so the list can't grow without
        # bound, while always keeping the busy and explicitly-forced targets.
        return targets[:max(protected, max(1, limit) * 3)]

    def scan_memory(self, pid: int) -> memscan.MemScanResult:
        """Memory-scan one PID and cache the result (used by the deep worker)."""
        r = memscan.scan_process(
            pid, budget_bytes=self.cfg.mem_max_bytes_per_proc,
            max_region_read=self.cfg.mem_max_region_read,
            large_dataset_bytes=self.cfg.mem_large_dataset_bytes)
        self._mem_cache[pid] = r
        return r

    # -- one pass -----------------------------------------------------------
    def scan_once(self, deep: bool = False) -> list[ProcInfo]:
        """One light pass over all processes. Cached memory results are applied
        to every process. If `deep`, synchronously memory-scan the top CPU users
        first (for headless CLI/bench use; the GUI instead calls scan_memory on
        a background thread so the live loop never blocks)."""
        now = time.time()
        procs: list[tuple[psutil.Process, float]] = []
        # Batch name + cpu_percent through process_iter so each process costs a
        # single proc_info syscall this pass (reading them separately doubled it).
        for p in psutil.process_iter(["pid", "name", "cpu_percent"]):
            if p.pid == 0:
                continue
            raw = p.info.get("cpu_percent")
            if raw is None:
                continue
            procs.append((p, raw))
            if p.pid not in self._warm:  # drop the unreliable first reading
                self._warm.add(p.pid)
                continue
            self._cpu_hist[p.pid].append((now, raw))

        if deep:
            self.last_scan_errors = 0
            for pid in self.deep_scan_targets():
                r = self.scan_memory(pid)
                if r.error and "OpenProcess" in (r.error or ""):
                    self.last_scan_errors += 1

        # Build the TCP connection map ONCE for the whole pass (one syscall),
        # instead of calling net_connections per process (~1500x faster).
        conn_map: dict[int, list[tuple[str, int]]] = defaultdict(list)
        try:
            for c in psutil.net_connections(kind="tcp"):
                if c.pid and c.status == psutil.CONN_ESTABLISHED and c.raddr:
                    conn_map[c.pid].append((c.raddr.ip, c.raddr.port))
        except (psutil.AccessDenied, OSError):
            pass
        live_conns = {(pid, ip, port) for pid, lst in conn_map.items()
                      for ip, port in lst}

        # Single-owner system CPU reading. cpu_percent(None) keeps module-global
        # last-call state, so only the scan thread may call it (the GUI reads
        # self.system_cpu_pct instead) — otherwise two callers steal each other's
        # sampling window and both readings go erratic.
        self.system_cpu_pct = psutil.cpu_percent(None)

        # Hidden-compute accounting: attributed CPU + VM-host loads this pass.
        attributed_raw = sum(raw for _p, raw in procs)
        vm_loads = power.sample_vm_loads(
            {p.pid: (p.info.get("name") or "", raw) for p, raw in procs}, self.cfg)

        results: list[ProcInfo] = []
        live_pids = set()
        for p, raw in procs:
            live_pids.add(p.pid)
            if p.pid == self._self_pid:
                continue
            info = ProcInfo(p.pid, cpu=raw / self._ncpu)
            meta = self._meta.get(p.pid)
            if meta is None:
                # Resolve static fields once per PID (the slow calls: exe(),
                # username() SID lookup, Authenticode trust).
                try:
                    name = p.info.get("name") or p.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                try:
                    exe = p.exe()
                except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                    exe = ""
                try:
                    username = p.username() or ""
                except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                    username = ""
                trusted = trust.is_trusted(exe, self.cfg.trusted_dirs)
                meta = (name, exe, username, trusted)
                self._meta[p.pid] = meta
            info.name, info.exe, info.username, info.trusted = meta
            if os.path.basename(info.exe).lower() == "minersentry.exe":
                continue  # never flag ourselves

            info.mem_result = self._mem_cache.get(p.pid)
            info.signals = self._build_signals(info, conn_map.get(p.pid, []), now)
            info.score, info.verdict = combine(info.signals, self.cfg)

            # Display-only fields (mem/threads) each cost a proc_info syscall, so
            # fetch them lazily only for non-idle rows the GUI actually shows.
            if info.score > 0 or info.cpu >= 2.0 or info.gpu >= 2.0:
                try:
                    with p.oneshot():
                        info.mem_mb = p.memory_info().rss / (1024 * 1024)
                        info.threads = p.num_threads()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            self._note_transition(info)
            results.append(info)

        # Hidden-compute report (system-level). Require the unaccounted gap to
        # hold for several samples before flagging, to reject sampling skew.
        if self.cfg.power_enabled:
            busy = self.system_cpu_pct * self._ncpu  # raw per-core sum
            unaccounted_cores = max(0.0, busy - attributed_raw) / 100.0
            if unaccounted_cores >= self.cfg.unaccounted_cores_threshold:
                self._gap_streak += 1
            else:
                self._gap_streak = 0
            persisted_gap = self._gap_streak >= self.cfg.hidden_persist_samples
            self.hidden_report = power.compute_report(
                busy, attributed_raw, vm_loads, persisted_gap, self.cfg)
            if self.hidden_report.flagged:
                self.audit.event("hidden-compute: " + self.hidden_report.note)

        for dead in set(self._cpu_hist) - live_pids:
            self._cpu_hist.pop(dead, None)
            self._probe_drops.pop(dead, None)
            self._mem_cache.pop(dead, None)
            self._last_verdict.pop(dead, None)
        for dead in set(self._meta) - live_pids:
            self._meta.pop(dead, None)
        self._warm &= live_pids
        # Prune GPU history in place under the lock (reassigning the dict would
        # race the sampler thread's defaultdict insert -> "changed size" errors).
        with self._gpu_lock:
            for dead in set(self._gpu_hist) - live_pids:
                self._gpu_hist.pop(dead, None)
        # Drop first-seen timestamps for connections that have CLOSED, so a
        # process that later re-opens the same ip:port starts its persistence
        # clock fresh instead of inheriting a stale (already-"persisted") entry.
        self._conn_seen = {k: v for k, v in self._conn_seen.items()
                           if k in live_conns}
        # Recompute the deep-target snapshot here (on the scan thread, which owns
        # these dicts) so the GUI deep thread reads a stable list, never the live
        # dicts.
        self._deep_targets = self.deep_scan_targets()

        results.sort(key=lambda i: (i.score, i.cpu), reverse=True)
        return results

    def _note_transition(self, info: ProcInfo) -> None:
        prev = self._last_verdict.get(info.pid, "Clean")
        self._last_verdict[info.pid] = info.verdict
        rank = {"Clean": 0, "Suspicious": 1, "Likely Miner": 2}
        if rank.get(info.verdict, 0) > rank.get(prev, 0) and info.verdict != "Clean":
            self.audit.record_detection(
                pid=info.pid, name=info.name, exe=info.exe,
                score=info.score, verdict=info.verdict,
                signals=[(s.name, s.score, s.detail) for s in info.signals])

    def set_probe_drops(self, drops: dict[int, float]) -> None:
        self._probe_drops = dict(drops)

    def set_gpu_util(self, util: dict[int, float], window_pids: set[int] | None = None,
                     ctx_pids: set[int] | None = None) -> None:
        """Push a GPU-compute snapshot (from a background sampler). Appends each
        PID's compute % to its short history; records window/compute-context sets."""
        with self._gpu_lock:
            for pid, pct in util.items():
                self._gpu_hist[pid].append(pct)
            if window_pids is not None:
                self._gpu_windows = set(window_pids)
            if ctx_pids is not None:
                self._gpu_ctx = set(ctx_pids)

    @property
    def ncpu(self) -> int:
        return self._ncpu
