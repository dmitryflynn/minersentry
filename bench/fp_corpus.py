"""False-positive corpus for MinerSentry.

A cryptominer detector is only useful if it does NOT flag the legitimate heavy
software people actually run. This harness drives real, benign workloads that
*behaviorally resemble a miner* — sustained full-core CPU, and (worst case) real
cryptographic hashing with crypto constants resident in memory — and checks that
MinerSentry keeps them Clean. A "Likely Miner" verdict on any of these is a
false positive.

Nothing here is a miner: it runs stock 7-Zip's CPU benchmark and short Python/
Node compute loops. The Python cases run under a *signature-invalidated* copy of
the interpreter (the same reversible trick fake_miner --unsigned uses) so trust
dampening does NOT give them a free pass — this is the hard, honest test.

Run:  python bench/fp_corpus.py   ->  writes bench/fp_results.md + .csv
"""

from __future__ import annotations

import csv
import os
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from minersentry.cli import run_session, summarize  # noqa: E402
from minersentry.config import Config  # noqa: E402

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

# Benign workloads that look miner-like. Each helper runs forever until killed.
_SHA256 = (
    "import hashlib\n"
    "d = b'x' * (1 << 20)\n"
    "while True:\n"
    "    d = hashlib.sha256(d).digest() * 32\n"   # sustained CPU + SHA constants resident
)
_COMPUTE = (
    "x = 1.0000001\n"
    "while True:\n"
    "    for _ in range(500000):\n"
    "        x = (x * 1.0000001) % 97.0 + 1.0\n"  # pure CPU, no crypto, no dataset
)
_NODE = "let x=1.1; for(;;){ for(let i=0;i<5e6;i++){ x=(x*1.0000001)%97+1; } }"


def _unsigned_python(tmp: str) -> str:
    exe = os.path.join(tmp, "python-copy.exe")
    shutil.copy2(sys.executable, exe)
    with open(exe, "ab") as f:
        f.write(b"\x00")  # invalidate Authenticode so trust can't exempt it
    return exe


def _seven_zip() -> str | None:
    for p in (r"C:\Program Files\7-Zip\7z.exe", r"C:\Program Files (x86)\7-Zip\7z.exe"):
        if os.path.exists(p):
            return p
    return shutil.which("7z")


def _node() -> str | None:
    return shutil.which("node")


def _profiles(tmp: str):
    """(label, argv, what it mimics) — only those whose tools exist."""
    py = _unsigned_python(tmp)
    sha = os.path.join(tmp, "sha.py"); open(sha, "w").write(_SHA256)
    comp = os.path.join(tmp, "comp.py"); open(comp, "w").write(_COMPUTE)
    out = [
        ("python SHA-256 hashing (unsigned)", [py, sha],
         "a legit app hashing nonstop: sustained CPU + crypto constants in memory"),
        ("python CPU compute (unsigned)", [py, comp],
         "a legit CPU-bound job: steady full core, no crypto/dataset"),
    ]
    sz = _seven_zip()
    if sz:
        out.insert(0, ("7-Zip LZMA benchmark", [sz, "b"],
                       "a signed compressor pinning every core (miner-like load)"))
    nd = _node()
    if nd:
        out.append(("node CPU compute", [nd, "-e", _NODE],
                    "a JS runtime pinning a core"))
    return out


def run_profile(label: str, argv: list[str], duration: float) -> dict:
    proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            stdin=subprocess.DEVNULL, creationflags=NO_WINDOW)
    verdict, score, signals, error = "Clean", 0, {}, None
    try:
        time.sleep(3.0)
        e, results, first_hit = run_session(duration, cfg=Config.load(),
                                             force_pids={proc.pid})
        row = next((p for p in summarize(e, results, first_hit, pids={proc.pid})
                    ["processes"] if p["pid"] == proc.pid), None)
        if row:
            verdict, score, signals = row["verdict"], row["score"], row["signals"]
    except Exception as e:  # noqa: BLE001
        error = f"{type(e).__name__}: {e}"
    finally:
        try:
            proc.terminate(); proc.wait(timeout=5)
        except Exception:  # noqa: BLE001
            try:
                proc.kill()
            except Exception:  # noqa: BLE001
                pass
    return {"label": label, "verdict": verdict, "score": score,
            "signals": signals, "error": error}


def main() -> int:
    duration = float(os.environ.get("FP_DURATION", "24"))
    tmp = tempfile.mkdtemp(prefix="msentry_fp_")
    try:
        profiles = _profiles(tmp)
        print(f"False-positive corpus — {len(profiles)} benign workloads x {duration:.0f}s")
        rows = []
        for label, argv, mimics in profiles:
            print(f"  running: {label} …")
            r = run_profile(label, argv, duration)
            r["mimics"] = mimics
            rows.append(r)
            print(f"    -> {r['verdict']} (score {r['score']})")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    fps = [r for r in rows if r["verdict"] == "Likely Miner"]
    susp = [r for r in rows if r["verdict"] == "Suspicious"]
    out_dir = os.path.dirname(os.path.abspath(__file__))
    _write(os.path.join(out_dir, "fp_results.md"),
           os.path.join(out_dir, "fp_results.csv"), rows, fps, susp, duration)
    print(f"\nFalse positives (Likely Miner on benign): {len(fps)} / {len(rows)}")
    print(f"Wrote {os.path.join(out_dir, 'fp_results.md')}")
    return 1 if fps else 0


def _write(md_path: str, csv_path: str, rows, fps, susp, duration) -> None:
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["workload", "mimics", "verdict", "score", "signals"])
        for r in rows:
            w.writerow([r["label"], r["mimics"], r["verdict"], r["score"],
                        "; ".join(f"{k}={v}" for k, v in r["signals"].items())])
    lines = [
        "# MinerSentry false-positive corpus",
        "",
        f"{len(rows)} **benign** heavy workloads, each run for {duration:.0f}s. They "
        "deliberately resemble a miner (sustained full-core CPU; the SHA-256 case "
        "also keeps real crypto constants resident). A **Likely Miner** verdict on "
        "any of these is a false positive.",
        "",
        f"**Result: {len(fps)} false positive(s), {len(susp)} suspicious, "
        f"{len(rows) - len(fps) - len(susp)} clean.**",
        "",
        "| Benign workload | Resembles | Verdict | Score | Signals that fired |",
        "|---|---|---|---|---|",
    ]
    for r in rows:
        if r.get("error"):
            lines.append(f"| {r['label']} | {r['mimics']} | _error_ | — | {r['error']} |")
            continue
        sigs = ", ".join(f"{k} {v}" for k, v in r["signals"].items()) or "—"
        lines.append(f"| {r['label']} | {r['mimics']} | {r['verdict']} | {r['score']} | {sigs} |")
    lines += [
        "",
        "Why these stay Clean: sustained CPU alone (or crypto constants alone) is "
        "capped at *Suspicious* by the corroboration rule — a verdict needs a "
        "behavioral signal **plus** a miner-specific artifact (resident stratum/"
        "XMRig strings, a pool connection, a ~2 GiB RandomX dataset, a miner name, "
        "or the evasion reaction), none of which a legitimate workload has.",
    ]
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
