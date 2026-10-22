"""MinerSentry evasion benchmark.

Runs each behavioral miner profile (all BENIGN stand-ins from samples/fake_miner.py
— no real mining) past MinerSentry's headless engine and records the verdict and
time-to-detect, then emits bench/results.md + results.csv.

Honesty note (printed into the report): these samples reproduce miner *behavior*
without being malware, so a signature scanner (Defender / Malwarebytes) correctly
will not flag them — that is not a MinerSentry win, it is why behavioral detection
exists. The report states this plainly; a true head-to-head needs live malware in
an isolated VM, which the operator supplies (this harness never runs real miners).
"""

from __future__ import annotations

import csv
import os
import subprocess
import sys
import time

# Make the package importable when run as `python bench/run_bench.py`.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from minersentry.cli import run_session, summarize  # noqa: E402
from minersentry.config import Config  # noqa: E402

FAKE_MINER = os.path.join(ROOT, "samples", "fake_miner.py")

# (label, fake_miner args, what it mimics)
PROFILES = [
    ("stock full-core", ["--threads", "1"], "an un-throttled CPU miner"),
    ("cpu-capped 60%", ["--threads", "1", "--cap", "60"], "a miner throttled to stay busy but moderate"),
    ("cpu-capped 20% (bare)", ["--threads", "1", "--cap", "20"], "a throttled miner with no dataset/pool/name (the sensitivity floor)"),
    ("cpu-capped 20% + RandomX dataset", ["--threads", "1", "--cap", "20", "--dataset", "2048"], "a throttled RandomX miner — its ~2 GiB dataset gives it away"),
    ("cpu-capped 25% + pool", ["--threads", "1", "--cap", "25", "--net"], "a stealth miner that still talks to a pool"),
    ("pool connection", ["--threads", "1", "--net"], "a miner holding a stratum pool connection"),
    ("evasion (headless)", ["--threads", "1", "--evade"], "a miner that pauses when a monitor opens"),
]


NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)  # 0 off-Windows
_UNSIGNED_DIR = None


def _unsigned_python() -> str:
    """Path to a cached, signature-invalidated copy of the interpreter, so the
    benign targets run UNTRUSTED (like a real miner). Signed python.exe would be
    trusted and dampened, making every profile read Clean."""
    global _UNSIGNED_DIR
    import shutil
    import tempfile
    if _UNSIGNED_DIR and os.path.exists(os.path.join(_UNSIGNED_DIR, "msentry_target.exe")):
        return os.path.join(_UNSIGNED_DIR, "msentry_target.exe")
    _UNSIGNED_DIR = tempfile.mkdtemp(prefix="msentry_bench_")
    exe = os.path.join(_UNSIGNED_DIR, "msentry_target.exe")
    shutil.copy2(sys.executable, exe)
    with open(exe, "ab") as f:
        f.write(b"\x00")  # invalidate embedded Authenticode; copy still runs
    return exe


def _cleanup_unsigned() -> None:
    global _UNSIGNED_DIR
    if _UNSIGNED_DIR:
        import shutil
        shutil.rmtree(_UNSIGNED_DIR, ignore_errors=True)
        _UNSIGNED_DIR = None


def _launch(args: list[str]) -> subprocess.Popen:
    return subprocess.Popen([_unsigned_python(), FAKE_MINER, *args],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            creationflags=NO_WINDOW)


def _detector_presence() -> dict[str, str]:
    """Best-effort: is Defender / Malwarebytes present? (We do not run their
    scanners on benign samples; see the honesty note.)"""
    detectors = {}
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command",
                            "(Get-MpComputerStatus).RealTimeProtectionEnabled"],
                           capture_output=True, text=True, timeout=20,
                           creationflags=NO_WINDOW)
        out = (r.stdout or "").strip().lower()
        detectors["defender"] = "present (real-time ON)" if out == "true" else (
            "present (real-time OFF)" if out == "false" else "not detected")
    except Exception:  # noqa: BLE001
        detectors["defender"] = "query failed"
    mbam = any(os.path.exists(p) for p in (
        r"C:\Program Files\Malwarebytes\Anti-Malware\mbam.exe",
        r"C:\Program Files\Malwarebytes\Anti-Malware\MBAMService.exe"))
    detectors["malwarebytes"] = "present" if mbam else "not installed"
    return detectors


def run_profile(label: str, args: list[str], duration: float) -> dict:
    proc = _launch(args)
    verdict, score, ttd, signals = "Clean", 0, None, {}
    error = None
    try:
        time.sleep(2.0)  # let it start and ramp
        target = proc.pid
        e, results, first_hit = run_session(duration, cfg=Config.load())
        summary = summarize(e, results, first_hit)
        # The fake_miner runs under this subprocess PID (python.exe).
        row = next((p for p in summary["processes"] if p["pid"] == target), None)
        if row:
            verdict, score, ttd, signals = (row["verdict"], row["score"],
                                            row["ttd_s"], row["signals"])
    except Exception as e:  # noqa: BLE001 - one profile failing must not abort the run
        error = f"{type(e).__name__}: {e}"
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:  # noqa: BLE001
            try:
                proc.kill()
            except Exception:  # noqa: BLE001
                pass
    return {"label": label, "verdict": verdict, "score": score,
            "ttd_s": ttd, "signals": signals, "error": error}


def main() -> int:
    duration = float(os.environ.get("BENCH_DURATION", "22"))
    print(f"MinerSentry benchmark — {len(PROFILES)} profiles x {duration:.0f}s each "
          f"(~{len(PROFILES) * (duration + 3):.0f}s total)…")
    env = _detector_presence()
    rows = []
    for label, args, mimics in PROFILES:
        print(f"  running: {label} …")
        r = run_profile(label, args, duration)
        r["mimics"] = mimics
        rows.append(r)
        print(f"    -> {r['verdict']} (score {r['score']}"
              f"{', +' + str(r['ttd_s']) + 's' if r['ttd_s'] is not None else ''})")

    _cleanup_unsigned()
    out_dir = os.path.dirname(os.path.abspath(__file__))
    _write_csv(os.path.join(out_dir, "results.csv"), rows)
    _write_md(os.path.join(out_dir, "results.md"), rows, env, duration)
    print(f"\nWrote {os.path.join(out_dir, 'results.md')} and results.csv")
    return 0


def _write_csv(path: str, rows: list[dict]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["profile", "mimics", "minersentry_verdict", "score",
                    "time_to_detect_s", "signals"])
        for r in rows:
            sigs = "; ".join(f"{k}={v}" for k, v in r["signals"].items())
            w.writerow([r["label"], r["mimics"], r["verdict"], r["score"],
                        r["ttd_s"] if r["ttd_s"] is not None else "", sigs])


def _write_md(path: str, rows: list[dict], env: dict, duration: float) -> None:
    lines = [
        "# MinerSentry evasion benchmark",
        "",
        f"Each profile ran for {duration:.0f}s through MinerSentry's headless engine.",
        "",
        "**All samples are benign behavioral stand-ins** (`samples/fake_miner.py`) —",
        "they reproduce the *behaviors* of a miner (steady/throttled core load,",
        "resident stratum/XMRig strings, a pool-port connection, monitor-evasion)",
        "without mining anything. A signature scanner correctly will **not** flag",
        "them, which is exactly why behavioral detection exists — so this table",
        "measures MinerSentry's behavioral coverage, not a signature head-to-head.",
        "A real head-to-head needs live malware in an isolated VM (operator-supplied;",
        "this harness never runs real miners).",
        "",
        f"Detector environment on this host: Defender — {env.get('defender')}; "
        f"Malwarebytes — {env.get('malwarebytes')}.",
        "",
        "| Profile | Mimics | MinerSentry verdict | Score | Time-to-detect | Signals |",
        "|---|---|---|---|---|---|",
    ]
    for r in rows:
        if r.get("error"):
            lines.append(f"| {r['label']} | {r['mimics']} | _error_ | — | — | "
                         f"{r['error']} |")
            continue
        sigs = ", ".join(f"{k} {v}" for k, v in r["signals"].items()) or "—"
        ttd = f"+{r['ttd_s']}s" if r["ttd_s"] is not None else "—"
        lines.append(f"| {r['label']} | {r['mimics']} | **{r['verdict']}** | "
                     f"{r['score']} | {ttd} | {sigs} |")
    lines += [
        "",
        "Notes:",
        "- The evasion profile pauses only when a `taskmgr.exe` decoy appears; the",
        "  headless engine runs no decoy, so here it is caught behaviorally like the",
        "  stock profile. The decoy-based catch is the interactive **evasion probe**.",
        "- A heavily CPU-capped miner can sit below the sustained-load floor; it is",
        "  then caught only with a corroborating signal (pool connection, miner name,",
        "  resident strings + a memory sweep). That sensitivity floor is shown above.",
        "- \"Time-to-detect\" is measured from the start of the monitoring session",
        "  (after a ~2s process-ramp that is not counted) and is floored by the CPU",
        "  history warm-up (~4 samples), so sub-~10s values are not expected by design.",
    ]
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
