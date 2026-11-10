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
import threading
import time
from dataclasses import replace
from typing import Callable

from .config import Config
from .engine import Engine, ProcInfo
from . import gpu as gpu_mod
from . import persistence as persist_mod


def run_session(duration: float, cfg: Config | None = None,
                interval: float | None = None, deep: bool = True,
                gpu_sample: bool = False, force_pids: set[int] | None = None,
                progress: Callable[[float, list[ProcInfo]], None] | None = None,
                gpu_only: bool = False
                ) -> tuple[Engine, list[ProcInfo], dict[int, float]]:
    """Run the engine for `duration` seconds.

    Returns (engine, last results, first_detection) where first_detection maps a
    PID to the elapsed seconds at which it first scored non-Clean (time-to-detect).
    With `gpu_sample`, each pass also samples per-process GPU compute (slower, via
    typeperf on Windows, nvidia-smi pmon on Linux) so the headless scan can score the GPU signal like the GUI does.
    `force_pids` are always memory-scanned even if idle (so --pid genuinely targets
    those processes, not just filters the report).
    """
    e = Engine(cfg=cfg or Config.load(), gpu_only=gpu_only)
    e.start_pool_intel()
    e.start_connection_ages()
    interval = interval if interval is not None else e.cfg.scan_interval
    start = time.time()
    first_hit: dict[int, float] = {}
    deep_thread: threading.Thread | None = None
    scope_ok = False
    results: list[ProcInfo] = []
    deep_at = min(12.0, duration * 0.5)  # memory-sweep once history has warmed
    deep_every = max(10.0, duration / 4)  # and again, in case the first missed
    last_deep = 0.0

    def _record(elapsed: float) -> None:
        for r in results:
            if r.verdict != "Clean" and r.pid not in first_hit:
                first_hit[r.pid] = round(elapsed, 1)
        if progress:
            progress(elapsed, results)

    # Keep passing until the time is up AND the memory sweep has finished, so
    # the final verdict has both fresh CPU history and the sweep's results.
    while (time.time() - start < duration
           or (deep_thread is not None and deep_thread.is_alive())):
        t0 = time.time()
        elapsed = t0 - start
        if gpu_only:
            # The first query must succeed (an empty scope from a broken driver
            # would read as a clean scan). After that, a transient failure keeps
            # the last good scope instead of throwing away the whole session.
            try:
                e.set_gpu_scope(gpu_mod.compute_pids())
                scope_ok = True
            except RuntimeError as error:
                if not scope_ok:
                    raise
                print(f"warning: {error}; keeping the previous GPU scope",
                      file=sys.stderr)
        if gpu_sample or gpu_only:
            util, windows, ctx = gpu_mod.sample()
            e.set_gpu_util(util, windows, ctx)
        if deep and elapsed >= deep_at and (deep_thread is None
                                            or not deep_thread.is_alive()):
            # Memory sweep on its own thread (like the GUI) so CPU sampling keeps
            # its cadence; a synchronous sweep starved the CPU window of samples.
            #
            # Repeated, not once: the targets are chosen from the state at that
            # moment, and a process that is not yet ranked into the list (a busy
            # machine, a target that started late) would otherwise never be
            # memory-scanned for the rest of the session. Already-scanned PIDs
            # come from the cache, so a repeat sweep is cheap.
            if time.time() - last_deep >= deep_every:
                last_deep = time.time()
                targets = e.deep_scan_targets(force=force_pids)
                deep_thread = threading.Thread(
                    target=lambda: [e.deep_probe(pid) for pid in targets], daemon=True)
                deep_thread.start()
        results = e.scan_once(deep=False)
        _record(elapsed)
        # Keep a steady cadence: sleep only what is left of the interval. Sleeping
        # a full interval after a multi-second pass halved the sample rate.
        time.sleep(max(0.0, interval - (time.time() - t0)))
    if deep_thread is not None:
        results = e.scan_once(deep=False)   # fold in the finished memory sweep
        _record(time.time() - start)
    return e, results, first_hit


def _coverage(r: ProcInfo) -> dict | None:
    """How much of the process's memory was actually read. A partial scan that
    found nothing is not the same as a full clean one, so say which it was."""
    m = r.mem_result
    if m is None:
        return None
    return {"status": m.coverage_status, "bytes_scanned": m.bytes_scanned,
            "regions_scanned": m.regions_scanned, "regions_failed": m.regions_failed,
            "error": m.error}


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
            "memory_coverage": _coverage(r),
        })
    procs.sort(key=lambda p: p["score"], reverse=True)
    rep = e.hidden_report
    return {
        "ncpu": e.ncpu,
        "likely_miners": sum(1 for p in procs if p["verdict"] == "Likely Miner"),
        "suspicious": sum(1 for p in procs if p["verdict"] == "Suspicious"),
        "hidden_compute": {"flagged": rep.flagged, "note": rep.note},
        "config_warnings": list(getattr(getattr(e, "cfg", None), "load_warnings", []) or []),
        "processes": procs,
    }


def _print_autostart(found: list[dict]) -> None:
    """Autostart findings as a short table; silence means nothing was found."""
    if not found:
        print("\nAutostart: no miner-like entries.")
        return
    print(f"\nAutostart: {len(found)} miner-like entr"
          f"{'y' if len(found) == 1 else 'ies'}")
    for f in found:
        print(f"  {f['score']:>3}  {f['kind']:<16} {f['name'][:34]:<34} {f['exe'][-44:]}")
        for label in f["labels"][:3]:
            print(f"       - {label}")
        print(f"       in {f['location']}")


def _report_autostart(cfg: Config, as_json: bool) -> int:
    found = persist_mod.summarize(persist_mod.scan(cfg))
    if as_json:
        print(json.dumps({"autostart": found,
                          "config_warnings": list(cfg.load_warnings)}, indent=2))
    else:
        _print_autostart(found)
    return 0


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
    ap.add_argument("--gpu-only", action="store_true",
                    help="scan only NVIDIA compute-context PIDs; implies --gpu; "
                         "fails if the NVIDIA process query is unavailable")
    ap.add_argument("--profile", choices=("desktop", "cloud"), default=None,
                    help="desktop (default): a known miner name alone is Suspicious; "
                         "cloud: a name alone stays Clean until load corroborates it")
    ap.add_argument("--config", type=str, default=None,
                    help="load tuning from this JSON file (trusted fully); default is "
                         "the admin config plus the restricted per-user config")
    ap.add_argument("--autostart", action="store_true",
                    help="also scan autostart locations (Run keys, tasks, services, "
                         "cron, systemd) for miner-like entries")
    ap.add_argument("--autostart-only", action="store_true",
                    help="scan ONLY autostart locations and exit (no process scan)")
    ap.add_argument("--autostart-remove", metavar="NAME",
                    help="disable or remove the autostart entry with this name "
                         "(reversible; recorded in the actions journal)")
    ap.add_argument("--autostart-undo", action="store_true",
                    help="undo the last autostart removal")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    args = ap.parse_args(argv)

    if args.autostart_undo:
        records = persist_mod.removals()
        if not records:
            print("Nothing to undo.", file=sys.stderr)
            return 1
        r = persist_mod.undo_removal(records[-1])
        print(r.message, file=sys.stdout if r.ok else sys.stderr)
        return 0 if r.ok else 1

    if args.autostart_remove:
        cfg = Config.load(args.config)
        wanted = args.autostart_remove.lower()
        found = [e for e in persist_mod.scan(cfg)
                 if wanted in e.name.lower()]
        if not found:
            print(f"No reported autostart entry matches {args.autostart_remove!r}. "
                  f"Run --autostart-only to see what was found.", file=sys.stderr)
            return 1
        if len(found) > 1:
            print("That matches more than one entry; be more specific:", file=sys.stderr)
            for e in found:
                print(f"  {e.name}  ({e.kind}, {e.location})", file=sys.stderr)
            return 1
        r = persist_mod.remove_entry(found[0])
        print(r.message, file=sys.stdout if r.ok else sys.stderr)
        if r.ok:
            print("Undo it with: minersentry-scan --autostart-undo")
        return 0 if r.ok else 1

    if args.autostart_only:
        cfg = Config.load(args.config)
        for w in cfg.load_warnings:
            print(f"config: {w}", file=sys.stderr)
        return _report_autostart(cfg, as_json=args.json)

    if not args.json:
        print(f"MinerSentry headless scan - {args.duration:.0f}s ...", file=sys.stderr)
    pid_set = set(args.pid) if args.pid else None
    try:
        cfg = Config.load(args.config)
        for w in cfg.load_warnings:
            print(f"config: {w}", file=sys.stderr)
        if args.duration < cfg.net_persist_seconds:
            print(f"note: --duration {args.duration:.0f}s is shorter than "
                  f"{cfg.net_persist_seconds:.0f}s, so a pool connection can't be "
                  f"judged long-lived in this scan; it scores as weak evidence.",
                  file=sys.stderr)
        if args.profile:
            cfg = replace(cfg, profile=args.profile)
        e, results, first_hit = run_session(args.duration, cfg=cfg, interval=args.interval,
                                          deep=not args.no_deep, gpu_sample=args.gpu,
                                          force_pids=pid_set, gpu_only=args.gpu_only)
    except RuntimeError as error:
        print(f"Scan failed: {error}", file=sys.stderr)
        return 1
    report_pids = pid_set
    if args.gpu_only:
        report_pids = e.gpu_scope if pid_set is None else pid_set & e.gpu_scope
    summary = summarize(e, results, first_hit, watch=args.watch, pids=report_pids)
    if args.autostart:
        summary["autostart"] = persist_mod.summarize(persist_mod.scan(cfg))

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        gpu_note = "" if args.gpu or args.gpu_only else "  (GPU not sampled; pass --gpu)"
        print(f"\n{'PID':>7}  {'CPU%':>5} {'GPU%':>5} {'SCORE':>5}  {'VERDICT':<13} NAME")
        for p in summary["processes"]:
            ttd = f"  (detected +{p['ttd_s']}s)" if p["ttd_s"] is not None else ""
            print(f"{p['pid']:>7}  {p['cpu']:>5.0f} {p['gpu']:>5.0f} {p['score']:>5}  "
                  f"{p['verdict']:<13} {p['name']}{ttd}")
        if summary["hidden_compute"]["flagged"]:
            print("\n[!] hidden compute: " + summary["hidden_compute"]["note"])
        print(f"\n{summary['likely_miners']} likely miner(s), "
              f"{summary['suspicious']} suspicious{gpu_note}")
        if args.autostart:
            _print_autostart(summary["autostart"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
