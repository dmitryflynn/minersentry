"""Headless MinerSentry runner.

Runs the behavioral engine for a fixed duration with no GUI and prints a
verdict summary (human table or JSON). Reused by the benchmark harness. It
mirrors the GUI's real detection path: a fast light-sampling loop builds CPU
history, a single memory sweep of the busy processes runs once the history has
warmed, and the final verdicts are read from the last light pass.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Callable

from .config import Config
from .engine import Engine, ProcInfo
from . import gpu as gpu_mod


def run_session(duration: float, cfg: Config | None = None,
                interval: float | None = None, deep: bool = True,
                gpu_sample: bool = False, force_pids: set[int] | None = None,
                progress: Callable[[float, list[ProcInfo]], None] | None = None
                ) -> tuple[Engine, list[ProcInfo], dict[int, float]]:
    """Run the engine for `duration` seconds.

    Returns (engine, last results, first_detection) where first_detection maps a
    PID to the elapsed seconds at which it first scored non-Clean (time-to-detect).
    With `gpu_sample`, each pass also samples per-process GPU compute (slower, via
    typeperf) so the headless scan can score the GPU signal like the GUI does.
    `force_pids` are always memory-scanned even if idle (so --pid genuinely targets
    those processes, not just filters the report).
    """
    e = Engine(cfg=cfg or Config.load())
    interval = interval if interval is not None else e.cfg.scan_interval
    start = time.time()
    first_hit: dict[int, float] = {}
    deep_done = False
    results: list[ProcInfo] = []
    deep_at = min(12.0, duration * 0.5)  # memory-sweep once history has warmed
    while time.time() - start < duration:
        elapsed = time.time() - start
        if deep and not deep_done and elapsed >= deep_at:
            for pid in e.deep_scan_targets(force=force_pids):
                e.deep_probe(pid)
            deep_done = True
        if gpu_sample:
            util, windows, ctx = gpu_mod.sample()
            e.set_gpu_util(util, windows, ctx)
        results = e.scan_once(deep=False)
        for r in results:
            if r.verdict != "Clean" and r.pid not in first_hit:
                first_hit[r.pid] = round(elapsed, 1)
        if progress:
            progress(elapsed, results)
        time.sleep(interval)
    return e, results, first_hit


def summarize(e: Engine, results: list[ProcInfo], first_hit: dict[int, float],
              watch: str | None = None, pids: set[int] | None = None) -> dict:
    procs = []
    for r in results:
        if pids is not None:
            if r.pid not in pids:
                continue
        elif r.verdict == "Clean" and r.cpu < 2.0 and r.gpu < 2.0:
            continue
        if watch and watch.lower() not in r.name.lower():
            continue
        procs.append({
            "pid": r.pid, "name": r.name, "verdict": r.verdict, "score": r.score,
            "cpu": round(r.cpu, 1), "gpu": round(r.gpu, 1),
            "ttd_s": first_hit.get(r.pid),
            "signals": {s.name: s.score for s in r.signals if s.score > 0},
        })
    procs.sort(key=lambda p: p["score"], reverse=True)
    rep = e.hidden_report
    return {
        "ncpu": e.ncpu,
        "likely_miners": sum(1 for p in procs if p["verdict"] == "Likely Miner"),
        "suspicious": sum(1 for p in procs if p["verdict"] == "Suspicious"),
        "hidden_compute": {"flagged": rep.flagged, "note": rep.note},
        "processes": procs,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Headless MinerSentry scan.")
    ap.add_argument("--duration", type=float, default=25.0, help="seconds to run")
    ap.add_argument("--interval", type=float, default=None, help="seconds between passes")
    ap.add_argument("--watch", type=str, default=None, help="only report processes whose name contains this")
    ap.add_argument("--pid", type=int, action="append", default=None,
                    help="target these PIDs (repeatable): force a memory scan of each "
                         "even if idle, and report only them")
    ap.add_argument("--no-deep", action="store_true", help="skip the memory sweep")
    ap.add_argument("--gpu", action="store_true",
                    help="also sample per-process GPU compute each pass (slower)")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    args = ap.parse_args(argv)

    if not args.json:
        print(f"MinerSentry headless scan - {args.duration:.0f}s ...", file=sys.stderr)
    pid_set = set(args.pid) if args.pid else None
    e, results, first_hit = run_session(args.duration, interval=args.interval,
                                        deep=not args.no_deep, gpu_sample=args.gpu,
                                        force_pids=pid_set)
    summary = summarize(e, results, first_hit, watch=args.watch, pids=pid_set)

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        gpu_note = "" if args.gpu else "  (GPU not sampled; pass --gpu)"
        print(f"\n{'PID':>7}  {'CPU%':>5} {'GPU%':>5} {'SCORE':>5}  {'VERDICT':<13} NAME")
        for p in summary["processes"]:
            ttd = f"  (detected +{p['ttd_s']}s)" if p["ttd_s"] is not None else ""
            print(f"{p['pid']:>7}  {p['cpu']:>5.0f} {p['gpu']:>5.0f} {p['score']:>5}  "
                  f"{p['verdict']:<13} {p['name']}{ttd}")
        if summary["hidden_compute"]["flagged"]:
            print("\n[!] hidden compute: " + summary["hidden_compute"]["note"])
        print(f"\n{summary['likely_miners']} likely miner(s), "
              f"{summary['suspicious']} suspicious{gpu_note}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
