# MinerSentry

[![CI](https://github.com/dmitryflynn/minersentry/actions/workflows/ci.yml/badge.svg)](https://github.com/dmitryflynn/minersentry/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)

A behavioral cryptominer detector for **Windows 10/11 and Linux**. It catches
CPU/GPU mining malware by **the work it has to do**, not by file hashes — so
recompiled, packed, renamed, or process-injected miners still show up where a
signature scanner misses them. On Linux it adds a hardware-performance-counter
signal that detects a RandomX miner by its memory-hardness even when throttled.

> Defensive security tool. The included `samples/fake_miner.py` is a **benign**
> test target — it reproduces miner *behaviors* but mines nothing and connects
> nowhere. MinerSentry only reads process state and never modifies the system
> except an optional local detection log and a user-confirmed process terminate.

Catching a RandomX miner **throttled to 1% CPU** (no CPU spike to see, no pool
connection) — flagged by its 2 GB dataset + resident strings:

```text
$ minersentry-scan --duration 28 --watch target
    PID   CPU%  GPU% SCORE  VERDICT       NAME
  11288      1     0    82  Likely Miner  target.exe  (detected +14.0s)

1 likely miner(s), 0 suspicious
```

## Why behavioral

Defender and Malwarebytes lean heavily on signatures and known-bad lists. Miners
beat that routinely: a fresh build has a new hash, the binary gets renamed, the
code is injected into `svchost`, pool traffic is encrypted. But a miner cannot
hide the one thing it exists to do — run a hashing algorithm, nonstop, on the
CPU. MinerSentry scores that behavior directly.

| Evasion technique | Signature / hash scanner | MinerSentry (behavioral) |
|---|---|---|
| Fresh or recompiled build (new hash) | ✗ nothing to match | ✓ work is unchanged |
| Renamed / packed binary | ✗ | ✓ |
| Injected into a signed process (`svchost`) | ✗ (process is signed) | ✓ memory scan of any PID |
| CPU-capped to 1–20% | ✗ | ✓ dataset + (Linux) cache-miss fingerprint |
| Pauses when a monitor opens | ✗ | ✓ the evasion probe |
| Encrypted pool traffic | ✗ (can't inspect payload) | ✓ port + connection persistence |

The honest caveat: this contrasts *approaches*. A measured head-to-head against
Defender/Malwarebytes needs live malware in an isolated VM (see the benchmark),
which this project never runs on your host.

## The signals

Each process gets a set of independent sub-scores (0–100), combined into one
verdict. A process only reaches **Likely Miner** when several signals agree —
that corroboration requirement is what keeps false positives down.

| Signal | What it measures |
|---|---|
| **cpu** | Sustained, steady **core saturation** (a high *floor*, not a bursty peak). Measured per-core, so a one-thread miner on a 20-core box is still caught. |
| **gpu** | Sustained **GPU compute-engine** utilization by a headless process — catches GPU-only miners that CPU accounting can't see. Per-process compute load comes from the Windows PDH "GPU Engine" counters (vendor-neutral); a CUDA compute context (nvidia-smi) raises confidence. Windowed apps (games/creative) and an allowlist (Blender, OBS, DaVinci, ffmpeg…) are dampened. |
| **memory** | Read-only scan of each process's committed memory for miner fingerprints: `stratum+tcp`, `xmrig`, `RandomX`, stratum login/submit JSON, pool names, and a ~2 GiB RandomX dataset. Finds miners injected into signed processes. |
| **network** | Established TCP connections to stratum-typical pool ports. A connection that stays open across many scans (persisted) scores higher than a transient one. |
| **name** | Known miner binary names and execution from suspicious directories (Temp, ProgramData, roaming on Windows; /tmp, /dev/shm, /var/tmp on Linux). |
| **probe** | The **evasion probe** (see below). |
| **perf** *(Linux)* | Per-process **cache-misses-per-instruction** via user-mode `perf_event_open`. RandomX's random reads across its ~2 GB dataset produce an order-of-magnitude higher miss rate than ordinary compute — a fingerprint of the algorithm visible even when the miner is CPU-capped. Degrades to a no-op where `perf_event_paranoid` forbids it. |

Alongside the per-process signals, a **hidden-compute** banner flags work the
process list can't explain: a persistent gap between system-wide CPU and the sum
of visible processes (a rootkit-hidden PID), or sustained load inside a VM/WSL
host (`vmmem`/`vmwp`) you can't see into.

The deep memory scan targets not just the busiest processes but **any process
holding a pool connection, a miner-like name, or a RandomX-dataset-sized (~2 GiB)
private allocation — regardless of CPU**. So a heavily throttled stealth miner
can't hide under the CPU floor: a RandomX miner's 2 GiB dataset (or its pool
connection) pulls it in for a memory scan, and the resident strings then
corroborate it into a verdict even when it's using almost no CPU.

### Conviction rules

Certain signal *pairs* are diagnostic on their own and push a process straight
to **Likely Miner** — but each pair requires a behavioral signal (the actual
work) plus a corroborating artifact, so an idle process merely carrying strings
can't trip it:

- core saturation **+** miner strings resident in memory
- core saturation **+** a live stratum connection
- core saturation **+** a known miner binary name
- a process that **throttles under the evasion probe** while using the CPU
- **GPU compute** saturation **+** miner strings / a known miner name / a pool connection

GPU compute alone (like a lone CPU spike) caps at *Suspicious*, since headless
ML/CUDA is a legitimate false-positive class — corroboration promotes it.

## The evasion probe (the novel part)

A whole class of miners pauses the moment a monitoring tool opens, so you never
see the spike. MinerSentry turns that evasion into evidence: it spawns a harmless
decoy process whose image name is `taskmgr.exe` (a copy of the stock `ping`
utility, which just waits), and watches which busy processes **collapse their CPU
to near zero** while the decoy is alive. Legitimate software has no reason to
react to Task Manager appearing; a process that goes quiet is self-incriminating.

## Run it

Install (gives you the `minersentry` GUI and `minersentry-scan` CLI commands):

```bash
pipx install git+https://github.com/dmitryflynn/minersentry
# or:  pip install git+https://github.com/dmitryflynn/minersentry
minersentry          # GUI
minersentry-scan     # headless scan
```

Or from a checkout:

```bash
pip install -e .
python main.py       # GUI  (same as `minersentry`)
```

Build a standalone `.exe` (no Python needed to run it afterward):

```bash
powershell -ExecutionPolicy Bypass -File build.ps1
# -> dist\MinerSentry.exe
```

Run **as Administrator** for full memory-scan coverage of protected processes and
to be able to terminate them.

## See it work tonight (safely)

`samples/fake_miner.py` is a **benign** test target — it does no mining and
connects to nothing. It only reproduces the *behaviors* a miner shows: steady
core load, miner-signature strings held in its own memory, and (with `--evade`)
throttling when `taskmgr.exe` appears.

```bash
python samples/fake_miner.py --unsigned            # -> MinerSentry flags it "Likely Miner"
python samples/fake_miner.py --unsigned --evade    # -> also caught by the evasion probe
python samples/fake_miner.py --unsigned --net      # -> exercises the network signal (localhost only)
python samples/fake_miner.py --unsigned --dataset 2048   # -> real memory-hard hashing over a 2 GB
                                                         #    RAM working set: trips the RandomX-
                                                         #    dataset memory signal. RAM only,
                                                         #    freed on exit.
```

**Why `--unsigned`:** MinerSentry trusts and dampens validly-signed binaries
(your AV/OS) to avoid false positives. `python.exe` is signed, so a target run
directly under it is correctly dampened to *Clean*. `--unsigned` re-runs the
benign target under a signature-stripped copy of the interpreter in a temp dir
(deleted on exit) so it reads as untrusted — exactly like a real miner, which
is its own unsigned binary. Omit `--unsigned` to see the dampening instead.

With MinerSentry open, start the target, wait ~20 seconds for the CPU window to
fill, then click **Deep scan (memory)** and **Run evasion probe**. (The target
appears as `msentry_target.exe` when run with `--unsigned`.)

## Controls

- **Pause/Resume monitoring** — the live scan loop (every ~2.5 s).
- **Deep scan (memory)** — memory-fingerprint the top CPU users on the next pass.
- **Run evasion probe** — the fake-Task-Manager test.
- **Terminate selected** — ends the selected process (guarded by a confirmation).

## Headless scan & benchmark

Run the engine with no GUI (for scripting, CI, or a quick check):

```bash
python -m minersentry.cli --duration 25            # table of non-idle processes + verdicts
python -m minersentry.cli --duration 25 --json     # machine-readable summary
```

Reproduce the evasion benchmark — each **benign** behavioral profile from
`samples/fake_miner.py` run past the engine, with verdict and time-to-detect:

```bash
python bench/run_bench.py          # writes bench/results.md and results.csv
```

The report is explicit that these are benign behavioral stand-ins: a signature
scanner correctly won't flag them, so the table measures MinerSentry's
*behavioral* coverage (including its sensitivity floor on heavily CPU-capped
miners), not a signature head-to-head — a real comparison needs live malware in
an isolated VM, which the harness never runs itself.

## Limitations (honest ones)

- GPU-compute scoring reads per-process utilization from the PDH "GPU Engine"
  counters, which Windows only materializes while a process is *actively* using
  the compute engine — so an idle GPU shows nothing, and the signal appears once
  a real GPU workload runs.
- The hidden-compute gap catches rootkit-hidden *CPU* and VM/WSL load, but true
  per-process package power (RAPL) isn't exposed in Windows user mode without a
  driver, so that remains experimental/off by default.
- Network detection is port + connection-persistence based; packet-level share/
  job cadence timing and JA4 TLS fingerprinting (which need a capture driver) are
  the next network step, not yet built.
- The CPU signal needs ~20 seconds of history to judge a steady floor; a process
  shows "gathering samples" until then.
- Memory string matches alone aren't conclusive: security tools legitimately
  carry miner signatures in memory, so MinerSentry requires behavioral
  corroboration and dampens validly-signed binaries rather than alarming.
- Full memory coverage of protected/other-user processes requires Administrator.
- A miner running *under* a validly-signed interpreter (e.g. a Python/Node
  script) is dampened along with the interpreter; this is the deliberate
  low-false-positive trade (behavioral cpu/gpu/probe signals are never dampened).
- The hardware-counter (`perf`) signal is **Linux-only** for now — it uses
  user-mode `perf_event_open`, which has no driver-free equivalent on Windows
  (the Windows PMU path needs a kernel driver / ETW PMU session and is deferred).
  On Linux it also requires `/proc/sys/kernel/perf_event_paranoid` ≤ 2 (own
  processes) or `CAP_PERFMON`/root (other users); otherwise it degrades to off.
- Remaining sensitivity floor: a miner throttled below the CPU floor with no
  pool, name, strings, or large dataset **and** on a host where `perf` is
  unavailable can still slip — the narrow residual case.

## Testing

```bash
pip install -r requirements.txt
python -m pytest tests/          # unit + logic tests
```

## License

MIT — see [LICENSE](LICENSE).
