# MinerSentry

A behavioral cryptominer detector for Windows 10/11. It catches CPU/GPU mining
malware by **the work it has to do**, not by file hashes — so recompiled,
packed, renamed, or process-injected miners still show up where a signature
scanner misses them.

> Defensive security tool. The included `samples/fake_miner.py` is a **benign**
> test target — it reproduces miner *behaviors* but mines nothing and connects
> nowhere. MinerSentry only reads process state and never modifies the system
> except an optional local detection log and a user-confirmed process terminate.

## Why behavioral

Defender and Malwarebytes lean heavily on signatures and known-bad lists. Miners
beat that routinely: a fresh build has a new hash, the binary gets renamed, the
code is injected into `svchost`, pool traffic is encrypted. But a miner cannot
hide the one thing it exists to do — run a hashing algorithm, nonstop, on the
CPU. MinerSentry scores that behavior directly.

## The five signals

Each process gets five independent sub-scores (0–100), combined into one verdict.
A process only reaches **Likely Miner** when several signals agree — that
corroboration requirement is what keeps false positives down.

| Signal | What it measures |
|---|---|
| **cpu** | Sustained, steady **core saturation** (a high *floor*, not a bursty peak). Measured per-core, so a one-thread miner on a 20-core box is still caught. |
| **gpu** | Sustained **GPU compute-engine** utilization by a headless process — catches GPU-only miners that CPU accounting can't see. Per-process compute load comes from the Windows PDH "GPU Engine" counters (vendor-neutral); a CUDA compute context (nvidia-smi) raises confidence. Windowed apps (games/creative) and an allowlist (Blender, OBS, DaVinci, ffmpeg…) are dampened. |
| **memory** | Read-only scan of each process's committed memory for miner fingerprints: `stratum+tcp`, `xmrig`, `RandomX`, stratum login/submit JSON, pool names, and a ~2 GiB RandomX dataset. Finds miners injected into signed processes. |
| **network** | Established TCP connections to stratum-typical pool ports. A connection that stays open across many scans (persisted) scores higher than a transient one. |
| **name** | Known miner binary names and execution from suspicious directories (Temp, ProgramData, roaming). |
| **probe** | The **evasion probe** (see below). |

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

From source:

```bash
pip install -r requirements.txt
python main.py
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
- Remaining sensitivity floor: a miner that is throttled below the CPU floor
  **and** has no pool connection, no miner-like name, no resident miner strings,
  and no large dataset (e.g. a tiny cache-mode variant) can still slip. Catching
  that needs per-process hardware performance counters (cache-miss / AES-rate
  fingerprinting via ETW/PMU) — the planned next detection signal.

## Testing

```bash
pip install -r requirements.txt
python -m pytest tests/          # unit + logic tests
```

## License

MIT — see [LICENSE](LICENSE).
