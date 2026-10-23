"""Pure scoring logic — no psutil, no I/O, no global state.

These functions take plain inputs and return scores, so the heart of the
product (per-signal scoring, the corroboration cap, the conviction pairs, the
verdict bands) is unit-testable in isolation. The Engine is the thin collector
that gathers inputs from psutil and calls into here.
"""

from __future__ import annotations

from dataclasses import dataclass

from .config import Config


@dataclass
class Signal:
    name: str
    score: int                # 0-100
    detail: str


def name_stem(name: str) -> str:
    """Lowercased process name without a trailing .exe (the comparison key used
    for miner-name and GPU-allowlist matching)."""
    n = (name or "").lower()
    return n[:-4] if n.endswith(".exe") else n


def is_miner_name(name: str, cfg: Config) -> bool:
    """True if the process name matches a known miner.

    Exact stem match against the full name list, plus a substring match against
    only the *distinctive* identifiers — so a renamed `xmrig-notls.exe` is caught
    while an unrelated `examiner.exe` / `DataMiner.exe` is not.
    """
    stem = name_stem(name)
    if stem in cfg.known_miner_names:
        return True
    return any(k in stem for k in cfg.known_miner_substrings)


def score_cpu(recent: list[float], ncpu: int, cfg: Config) -> Signal:
    """Score sustained, steady core saturation from raw per-core CPU samples.

    `recent` is the samples within the sustained window (raw: 100 == one full
    core). We judge the most recent tail so a process's startup ramp ages out
    quickly rather than dragging the floor down; a genuinely bursty app still
    shows a low floor in that tail.
    """
    if not recent:
        return Signal("cpu", 0, "no history yet")
    tail = recent[-cfg.cpu_tail:]
    mean = sum(tail) / len(tail)
    floor = min(tail)
    detail = f"{mean/100:.1f} cores sustained (floor {floor/100:.1f})"
    if len(tail) < cfg.cpu_min_samples:
        return Signal("cpu", 0, detail + " (gathering samples)")
    if floor >= cfg.cpu_floor_full:
        return Signal("cpu", cfg.cpu_score_full, detail + " — steady at a full core or more")
    if floor >= cfg.cpu_floor_heavy and mean >= cfg.cpu_mean_heavy:
        return Signal("cpu", cfg.cpu_score_heavy, detail + " — steady heavy core load")
    if mean >= cfg.cpu_mean_flat and (mean - floor) < cfg.cpu_flat_spread:
        return Signal("cpu", cfg.cpu_score_flat, detail + " — flat sustained load")
    if mean >= cfg.cpu_mean_moderate:
        return Signal("cpu", cfg.cpu_score_moderate, detail + " — moderate sustained load")
    return Signal("cpu", 0, detail)


def score_memory(mem_scanned: bool, mem_score: int, labels: list[str],
                 error: str | None, bytes_scanned: int) -> Signal:
    """Score the memory-fingerprint result. `labels` are human descriptions of
    the hits (incl. a large-dataset note); `mem_score` is the scanner's total."""
    if not mem_scanned:
        return Signal("memory", 0, f"memory not scanned ({error or 'not scanned'})")
    if not labels:
        return Signal("memory", 0, f"clean ({bytes_scanned // (1024*1024)} MiB scanned)")
    return Signal("memory", mem_score, "; ".join(labels[:5]))


def score_network(hits: list[tuple[str, int, bool, bool]], cfg: Config) -> Signal:
    """hits: list of (remote_ip, remote_port, is_common_legit_port, persisted).

    A connection that has stayed ESTABLISHED to a pool-range port across many
    scans (persisted) is far more miner-like than a transient one, so it earns a
    bump and a persisted ambiguous port is promoted above transient noise.
    """
    if not hits:
        return Signal("network", 0, "no pool-like connections")
    strong = [h for h in hits if not h[2]]
    if strong:
        ip, port, _, persisted = strong[0]
        score = cfg.net_score_strong + (cfg.net_score_persist if persisted else 0)
        note = " (long-lived)" if persisted else ""
        return Signal("network", min(100, score),
                      f"established to {ip}:{port} (stratum-typical port){note}")
    ip, port, _, persisted = hits[0]
    if persisted:
        return Signal("network", cfg.net_score_strong,
                      f"long-lived connection to {ip}:{port} (ambiguous port, persisted)")
    return Signal("network", cfg.net_score_weak,
                  f"connection to {ip}:{port} (ambiguous port)")


def score_gpu(recent_util: list[float], has_window: bool, allowlisted: bool,
              has_compute_ctx: bool, cfg: Config) -> Signal:
    """Score sustained GPU *compute*-engine utilization (per-process).

    Miners run headless and pin the compute engine; games/creative apps use the
    3D/video engines and own a window. So a high, steady compute floor on a
    headless, non-allowlisted process is miner-like — but headless ML/CUDA is a
    benign false-positive class, so this is never standalone hard evidence
    (corroboration promotes it, exactly like a lone CPU spike)."""
    if allowlisted:
        return Signal("gpu", 0, "allowlisted GPU application")
    if not recent_util:
        return Signal("gpu", 0, "no GPU history yet")
    tail = recent_util[-cfg.gpu_history_len:]
    mean = sum(tail) / len(tail)
    floor = min(tail)
    detail = f"{mean:.0f}% compute (floor {floor:.0f}%)"
    if len(tail) < cfg.gpu_min_samples:
        return Signal("gpu", 0, detail + " (gathering samples)")
    if floor >= cfg.gpu_floor_strong:
        score = cfg.gpu_score_strong
    elif mean >= cfg.gpu_mean_moderate:
        score = cfg.gpu_score_moderate
    else:
        return Signal("gpu", 0, detail)
    if has_compute_ctx:
        score += cfg.gpu_ctx_bonus
        detail += " + compute context"
    if has_window:
        score = int(score * cfg.gpu_window_dampen)
        detail += " (has window: dampened)"
    else:
        detail += " — headless"
    return Signal("gpu", max(0, min(100, score)), detail)


def score_name(name: str, exe: str, cfg: Config) -> Signal:
    stem = name_stem(name)
    exe_l = (exe or "").lower()
    score = 0
    bits: list[str] = []
    if is_miner_name(name, cfg):
        score = max(score, cfg.name_score_known)
        bits.append("known miner name")
    if exe_l:
        for hint in cfg.suspicious_dir_hints:
            if hint in exe_l:
                score = max(score, score + 18 if score else cfg.name_score_susp_dir)
                bits.append(f"runs from {hint.strip(chr(92))}")
                break
        if not exe_l.startswith(cfg.trusted_dirs) and len(stem) <= 3:
            score = max(score, cfg.name_score_short)
            bits.append("very short name outside standard dirs")
    return Signal("name", min(100, score), ", ".join(bits) or "unremarkable name/path")


def score_probe(drop: float, cfg: Config) -> Signal:
    if drop >= cfg.probe_drop_strong:
        return Signal("probe", cfg.probe_score_strong,
                      f"CPU fell {drop:.0f}pts when a Task Manager decoy appeared")
    if drop >= cfg.probe_drop_weak:
        return Signal("probe", cfg.probe_score_weak,
                      f"CPU fell {drop:.0f}pts under monitoring decoy")
    return Signal("probe", 0, "no evasion reaction observed")


def score_dataset(large_dataset: bool, cfg: Config) -> Signal:
    """A confirmed RandomX-dataset-sized committed region (~2 GiB). Not part of
    the weighted blend on its own (a database or VM can hold 2 GiB too); it
    convicts only in combination with resident miner strings (see the
    dataset+memory conviction rule), which together are diagnostic even when the
    miner is throttled below the CPU floor."""
    if large_dataset:
        return Signal("dataset", cfg.dataset_score, "~2 GiB RandomX-sized dataset resident")
    return Signal("dataset", 0, "no large dataset region")


def score_perf(miss_ratio: float | None, cfg: Config) -> Signal:
    """Score a process's cache-misses-per-1000-instructions (Linux PMU).

    RandomX is memory-hard — random reads across a ~2 GiB dataset — so it shows
    an order of magnitude more LLC misses per instruction than ordinary compute.
    Like cpu/gpu this is kept out of the weighted blend (memory-bound databases
    also miss a lot); it convicts only in combination (see conviction rules)."""
    if miss_ratio is None:
        return Signal("perf", 0, "no perf-counter data")
    detail = f"{miss_ratio:.0f} cache misses / 1k instr"
    if miss_ratio >= cfg.perf_strong:
        return Signal("perf", cfg.perf_score_strong, detail + " — memory-hard (RandomX-like)")
    if miss_ratio >= cfg.perf_moderate:
        return Signal("perf", cfg.perf_score_moderate, detail + " — elevated")
    return Signal("perf", 0, detail)


def combine(signals: list[Signal], cfg: Config) -> tuple[int, str]:
    """Blend signal scores into a final (score, verdict).

    Trust dampening (for signed AV/OS binaries) is applied upstream by reducing
    the relevant Signal.score before this runs, so this stays pure and the GUI
    shows the same numbers the verdict was computed from.
    """
    by = {s.name: s.score for s in signals}

    blended = sum(w * by.get(key, 0) for key, w in cfg.weights.items())

    # Corroboration: a lone signal isn't enough unless it is standalone hard
    # evidence (strong memory / known miner name / confirmed evasion).
    present = sum(1 for s in signals if s.score >= cfg.corrob_nonzero_score)
    corroborated = present >= cfg.corrob_min_signals
    hard_evidence = (by.get("memory", 0) >= cfg.hard_memory
                     or by.get("name", 0) >= cfg.hard_name
                     or by.get("probe", 0) >= cfg.hard_probe)

    score = int(round(blended))
    if not corroborated and not hard_evidence:
        score = min(score, cfg.suspicious_cap)

    # Conviction pairs: a behavioral signal + a corroborating one is diagnostic.
    for a, ma, b, mb, floor in cfg.conviction_rules:
        if by.get(a, 0) >= ma and by.get(b, 0) >= mb:
            score = max(score, floor)

    score = max(0, min(100, score))
    verdict = "Clean"
    for thresh, label in cfg.verdict_thresholds:
        if score >= thresh:
            verdict = label
            break
    return score, verdict
