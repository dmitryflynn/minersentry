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
| Injected into a signed process (`svchost`) | ✗ (process is signed) | ✓ memory scan; injection hosts are never trust-dampened |
| CPU-capped to 1–20% | ✗ | ✓ dataset + (Linux) cache-miss fingerprint |
| Pauses when a monitor opens | ✗ | ✓ the evasion probe |
| Encrypted pool traffic | ✗ (can't inspect payload) | ✓ port + connection persistence |

The honest caveat: this contrasts *approaches*. A measured head-to-head against
Defender/Malwarebytes needs live malware in an isolated VM (see the benchmark),
which this project never runs on your host.

## The signals

Each process gets a set of independent sub-scores (0–100), combined into one
verdict. Nothing gets to **Likely Miner** on one signal. It takes the work
(CPU, GPU, cache misses) plus something miner-specific, or two artifacts that
only miners carry. A known miner name on its own shows up as *Suspicious* on a
desktop and stays quiet on a cloud host; see [Profiles](#profiles-desktop-and-cloud).

| Signal | What it measures |
|---|---|
| **cpu** | Sustained, steady **core saturation** (a high *floor*, not a bursty peak). Measured per-core, so a one-thread miner on a 20-core box is still caught. |
| **gpu** | Sustained **GPU compute-engine** utilization by a headless process — catches GPU-only miners that CPU accounting can't see. Per-process compute load comes from `nvidia-smi pmon` where NVIDIA is present, falling back to the Windows PDH "GPU Engine" counters for other vendors. That order is from measurement, not preference: with a real OpenCL job holding this laptop's RTX 3050 at 99%, PDH reported one non-zero instance on the whole machine (System/Copy, 0.01%) while pmon reported the job at 98%. A CUDA/OpenCL compute context raises confidence. Windowed apps (games/creative) and an allowlist (Blender, OBS, DaVinci, ffmpeg…) are dampened. |
| **memory** | Read-only scan of each process's committed memory for miner fingerprints: `stratum+tcp`, `xmrig`, `RandomX`, stratum login/submit JSON, pool names, and a ~2 GiB RandomX dataset. Strings are matched as both 8-bit text and UTF-16 (how .NET miners hold them). Finds miners injected into `svchost`, `explorer`, `dllhost` and the other usual hosts, which are never trust-dampened. |
| **network** | Established TCP connections to stratum-typical pool ports, and — via bundled threat intel — connections to a **resolved known mining-pool IP on *any* port** (e.g. a pool on 443). Only pool stratum endpoints are listed, never pool websites, and any address in a shared CDN range (Cloudflare, Fastly) is dropped, since unrelated sites share it. A persisted connection scores higher than a transient one. |
| **name** | Known miner binary names and execution from suspicious directories (Temp, ProgramData, roaming on Windows; /tmp, /dev/shm, /var/tmp on Linux). |
| **probe** | The **evasion probe** (see below). |
| **cmdline** | Mining indicators in a process's **arguments**: a `stratum://` URL, a known pool host, a wallet address, an algorithm (`rx/0`, `kawpow`), and miner-only flags (`--donate-level`, `--randomx-1gb-pages`). A miner can rename its binary and strip its strings, but it still has to be told where to send the money. Generic flags every CLI uses (`-o`, `-u`, `-t`, `--tls`) are capped below the hard-evidence line, so they corroborate but can never convict. Only the matched **labels** are kept, never the command line: wallets, passwords and worker names are read and discarded. |
| **stealth** | Signs a process is hiding what it is: miner strings sitting in **unbacked executable memory** (code with no file behind it), an image that is gone from the path it started from, a `memfd`-backed binary, a kernel-thread name masquerade, or an unexpected parent for a process that has only one legitimate parent. Hiding is not mining, so this convicts only beside the work or a miner-specific artifact. |
| **swarm** | Load summed **per executable**, not per process. Twenty copies of one unsigned binary at a quarter core each duck every per-process floor while mining five cores; judged together they don't. Only untrusted executables are grouped, so a browser's renderers are not a swarm, and like cpu/gpu it needs miner-specific corroboration to convict. |
| **autostart** | Run keys, startup folders, services, scheduled tasks (Windows); cron, systemd units, shell profiles (Linux). Every other signal judges a process that is already running — this is the one that finds a miner *installed but not started*, which is how practically every real cryptojacker survives a reboot. Entries are scored with the same evidence as processes: command-line indicators, a known miner name, a drop location, an unsigned binary. |
| **perf** *(Linux)* | Per-process **cache-misses-per-instruction** via user-mode `perf_event_open`. RandomX's random reads across its ~2 GB dataset produce an order-of-magnitude higher miss rate than ordinary compute — a fingerprint of the algorithm visible even when the miner is CPU-capped. Degrades to a no-op where `perf_event_paranoid` forbids it. |

Alongside the per-process signals, a **hidden-compute** banner flags work the
process list can't explain: a persistent gap between system-wide CPU and the sum
of visible processes (a rootkit-hidden PID), or sustained load inside a VM/WSL
host (`vmmem`/`vmwp`) you can't see into. Every busy machine has some CPU that
no process is charged for (interrupts, short-lived processes, kernel work), and
it grows with load. So the first dozen passes learn what is normal for this
machine, and only a lasting excess on top of that raises the banner.

On Linux, a process in a container is attributed to it. Cloud cryptojacking
lives in containers, and a host PID is the one number nobody can act on — it is
gone the moment the container restarts, and it does not say which deployment to
roll back. `/proc/<pid>/cgroup` gives the runtime, the container ID, and the
Kubernetes pod UID where there is one, which is enough to find the workload with
one `docker inspect` or `kubectl get pod`. Docker, containerd, CRI-O, Podman and
LXC are each recognised by their own cgroup shape; a process on the host is left
alone, because claiming a container for it would send someone to roll back a
workload that was never involved. The CLI groups the findings by container,
worst first, and a detection in the audit log records which container it was in.
It does not name the container: a human-readable name lives in the runtime's API,
not in cgroup, and reaching for it would mean talking to a daemon and failing
differently on every platform.

A process that starts and exits between two 2.5s passes never appears in the
table, because by the time there is a row to put it on it is gone. MinerSentry
subscribes to process-creation events as well, and reports those separately —
judged on their command line, path and name, since there is no CPU history to
measure and nothing left to memory-scan. A command line is often enough on its
own: `-o stratum+tcp://pool…:3333 --donate-level 0` scores 100.

What that covers, measured here with twelve processes per case:

| process lifetime | caught | with a command line |
| --- | --- | --- |
| ~10 ms | 0–1 of 12 | 0 |
| 1 s | 11–12 of 12 | 9–12 |
| 3 s | 12 of 12 | 12 |

So this is **not** the dropper case. A process that launches and exits in
milliseconds is still invisible: the subscription is WMI polling
`Win32_Process`, and a process that never exists at a poll instant is never in
a snapshot. What it closes reliably is the band between about a second and the
engine's pass — a miner running in short bursts to stay under a sampling
monitor, which until now was caught only by luck. `Win32_ProcessStartTrace`
would catch the millisecond case, but it cannot be subscribed to without
Administrator and it carries no command line, so even elevated it would yield a
name and a PID rather than something scoreable. On Linux there is no
unprivileged equivalent at all — the netlink proc connector needs root — and
the watcher reports itself unavailable there instead of pretending otherwise.

While this is running you will see **one `powershell.exe` child process** — it
holds the WMI event subscription and streams one JSON line per process start.
It is stopped when MinerSentry exits, and it also watches its parent and exits
on its own if MinerSentry is force-quit or crashes, because none of those run a
cleanup handler and an orphan would keep a WMI subscription. WMI has a per-user
quota on those, so a leak is not harmless: eleven orphans from test runs took
this machine to "Quota violation", after which nothing could subscribe at all.

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
- core saturation **+** a connection to a known mining pool
- miner strings in memory **+** a long-lived connection on a stratum port
- core saturation **+** a known miner binary name
- a **swarm** of one binary **+** miner strings, mining arguments, a miner name,
  a pool connection or the evasion reaction
- **mining arguments** (pool URL / wallet / miner-only flags) **+** any sustained
  load, GPU compute, pool connection, resident strings or dataset. The arguments
  already say what the process is for, so the bar on the behavioral side is low:
  a miner throttled to a third of a core is still caught.
- a process that **throttles under the evasion probe** while using the CPU
- **GPU compute** saturation **+** miner strings / a known miner name / a pool connection

GPU compute alone (like a lone CPU spike) caps at *Suspicious*, since headless
ML/CUDA is a legitimate false-positive class — corroboration promotes it.

## The evasion probe (the novel part)

A whole class of miners pauses the moment a monitoring tool opens, so you never
see the spike. MinerSentry turns that evasion into evidence: it spawns harmless
decoys named after the tools miners watch for (`taskmgr.exe`, `procexp64.exe`,
`ProcessHacker.exe`, `SystemInformer.exe`, `perfmon.exe`, `resmon.exe`; `htop`,
`top`, `nvtop`, `btop` on Linux). Each is a copy of the stock `ping` or `sleep`
utility that just waits. It then watches which busy processes **collapse their
CPU to near zero** while the decoys are alive and come back once they're gone.
Legitimate software has no reason to react to a process monitor appearing; a
process that goes quiet is self-incriminating.

Two things that gave the decoys away are gone: the folder no longer carries a
fixed `msentry_` prefix, and each decoy is accompanied by a real off-screen
window with the matching title (`Task Manager`, `Process Explorer`, …), because
plenty of evasive miners look for the window rather than the process. Those
windows pump their messages — a window whose thread doesn't will hang any
process that enumerates window titles, including the miner and real monitors.

On systems where `sleep` is a multi-call binary (busybox, or coreutils built as
one program) a renamed copy refuses to run — it reports `unknown program
'htop'` — so there the decoy carries the monitor name in its command line while
its process name stays the real tool's. Partial, and better than a probe whose
decoys never started.

MinerSentry is still the decoys' parent process, which a determined miner could
check. Launching them through the shell hides that, but then they can only be
found again by resolving their executable path, which some systems refuse —
leaving decoys that cannot be confirmed or stopped. Being certain the decoys
ran is worth more than hiding their parentage, so they are launched directly.

Only the baseline looks at every process. The decoy phases re-measure just the
processes that were busy, because walking all ~400 processes on a desktop took
longer than the decoy lived and let an evader's recovery leak into the reading.
Against the benign evader in `samples/` it caught 4 runs out of 4 with nothing
else flagged. It has not been tested against real evasive malware.

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
- **Deep scan (memory)** — memory-fingerprint the candidates now. This also
  runs by itself every 45 s (`deep_auto_interval`) while monitoring is on.
- **Run evasion probe** — the monitor-decoy test.
- **Scan autostart** — read Run keys, tasks, services, cron and systemd and
  report anything miner-like, with where it lives so you can go and look.
- **Suspend selected** — freeze a process instead of killing it: it stops
  earning and stays intact to inspect. Offers to resume immediately.
- **Terminate selected** — ends the selected process after a confirmation, and
  refuses if the PID now belongs to a different process than the row showed.
- **Quarantine binary** — move the executable somewhere it cannot launch,
  recording where it came from so it can be put back.

## Headless scan & benchmark

Run the engine with no GUI (for scripting, CI, or a quick check):

```bash
python -m minersentry.cli --duration 25            # table of non-idle processes + verdicts
python -m minersentry.cli --duration 25 --json     # machine-readable summary
```

Scan autostart locations, with or without a process scan:

```bash
minersentry-scan --autostart-only          # just the autostart check
minersentry-scan --autostart-only --json
minersentry-scan --duration 30 --autostart # processes and autostart together
```

On the desktop this was built on that reads 1,138 entries in about 4.5 seconds
and reports none of them: the threshold is set so a list nobody reads is not the
default outcome. A Run key pointing at a miner with a pool URL and a wallet
scores 100.

What it reads:

| Windows | Linux |
| --- | --- |
| Run / RunOnce keys (HKCU, HKLM, Wow6432Node) | `/etc/crontab`, `/etc/cron.d`, per-user crontabs |
| Startup folders, including `.lnk` targets | systemd `.service` **and `.timer`** units |
| Services and kernel drivers, including `Parameters\ServiceDll` | `~/.config/autostart`, `/etc/xdg/autostart` |
| Scheduled tasks from `schtasks` **and from task XML on disk** (hidden tasks) | `/etc/ld.so.preload` |
| IFEO debuggers, AppInit_DLLs, Winlogon Shell/Userinit | `authorized_keys` forced commands |
| WMI event subscriptions, BITS jobs | shell profiles, `/etc/profile.d`, `/etc/init.d`, `rc.local` |
| netsh helper DLLs, AppCertDlls, LSA packages | PAM modules loaded from off-path |
| Active Setup `StubPath`, print monitors | udev rules with `RUN+=` / `PROGRAM=` |
| Group Policy startup/logon scripts, Office add-ins | |
| Accessibility binaries replaced by a shell (`sethc.exe`) | |

A service's `ImagePath` is read in all four spellings the service control
manager accepts — relative, `\SystemRoot\`, `%SystemRoot%` and the `\??\`
device prefix — because a path that resolves to no file gives the signature,
unsigned and drop-location checks nothing to look at. Handling only one of
them left 490 of 793 service entries on the development desktop unchecked. A
kernel driver registered from outside `System32\drivers` and the DriverStore
carries its own weight: of 461 driver services here, 460 are in those two
places, and the one exception is signed.

There is no allowlist of known-good DLLs anywhere in this. Every machine has a
dozen legitimate netsh helpers and print monitors, and keeping a list of their
names current is a losing game. Instead a signed file under System32 earns only
the rare-location weight (35), which sits below the reporting threshold (45),
so it stays quiet — while an unsigned DLL, or one in a drop directory, clears
it. The accessibility check is the one exception, and it is not a signature
check either: Windows system binaries are catalog-signed, so verifying the file
alone fails for the genuine article too. It compares digests instead, so the
answer has no middle: either the file in System32 *is* `cmd.exe` or it is not.

Not every finding can be removed for you, and the ones that refuse say why. An
LSA package is one element of a `REG_MULTI_SZ` list and deleting the value stops
Windows booting; a print monitor is a subkey the spooler rewrites if you delete
it in the wrong order; a Group Policy script comes back from the domain on the
next refresh; a PAM file that breaks locks out every account including root.
Those are reported with instructions rather than acted on.

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

## Linux and NVIDIA GPUs

On Linux the GPU signal comes from `nvidia-smi pmon` (SM activity per process).
You need the NVIDIA driver and `nvidia-smi` on PATH, nothing else: no CUDA
toolkit, no PyTorch.

```bash
minersentry-scan --duration 60 --gpu --json
```

A few things worth knowing about what it reads:

- Only compute-only (`C`) rows count. Graphics and mixed rows are ignored, and a
  process on two GPUs gets the busier one, not the sum.
- SM activity isn't the same number as the Windows compute-engine counter, so
  the thresholds may need tuning on your hardware.
- There's no window ownership on a headless Linux box, so the "has a window"
  dampening that protects games on Windows doesn't apply.
- A `-` from pmon is "unknown", never zero. If a process drops out of the
  telemetry for more than `gpu_miss_tolerance` samples (default 2) its GPU
  history is thrown away rather than left stale.
- A GPU-busy process gets memory-scanned even if its CPU is idle.

CPU and GPU both pinned is what a normal training job looks like, so that pair
never convicts. It needs a miner name, miner strings or a pool connection on top.

So far this has been validated on Linux with full-GPU passthrough. MIG, AMD
and mixed graphics/compute haven't been tested yet. Reports welcome.

### GPU-only scan

```bash
minersentry-scan --duration 45 --gpu-only --json
```

`--gpu-only` looks only at processes that hold an NVIDIA compute context,
including idle ones, and skips everything else (CPU-only work, pure graphics).
`--pid` can't widen it. The hidden-compute check is off in this mode because
the process list is deliberately incomplete.

It needs a working `nvidia-smi` on Windows or Linux. If the very first query
fails the scan exits nonzero, since an empty list from a broken driver would
otherwise look like a clean machine. A later hiccup (one timeout halfway
through) keeps the last good list and prints a warning. CPU miners, and miners
that give up their compute context, are outside what this mode can see.

## Profiles: desktop and cloud

The one place the two audiences disagree is a process that is *named* like a
miner but isn't doing anything.

| | `desktop` (default) | `cloud` |
|---|---|---|
| idle `xmrig.exe` | Suspicious | Clean |
| `xmrig` + sustained CPU or GPU | Likely Miner | Likely Miner |
| strings, dataset or pool evidence | unchanged | unchanged |

On your own PC an idle xmrig is still worth a look: it may be paused, or waiting
for you to close Task Manager. On a shared GPU host people run oddly named jobs
all day and every alert costs someone's time. Pick one with `--profile cloud`
or `"profile": "cloud"` in `config.json`.

Name matching is the same in both. It knows the brands and their usual variants
(`xmrig-notls`, `gminer64`, `nbminer_v42`) and checks the executable's basename
too, so renaming the visible process name doesn't help. It won't match the bare
word "miner": `tracker-miner-fs-3`, `miner-cuda12`, `notxmrig` and
`xmrighelper` are all left alone. If your `config.json` overrides
`known_miner_names`, take any generic `miner` entry out of it. A valid signature
doesn't cancel a known brand name either. Plenty of miners ship signed.

Weak memory cues (a 2 GiB mapping, algorithm names like `randomx`, crypto
constants) are capped below the hard-evidence line no matter how many show up.
ML stacks have all of them. Protocol strings like `stratum+tcp` and
`"method":"submit"` are what carry weight.

Thanks to [@cocoLC](https://github.com/cocoLC) for the Linux GPU collector, the
GPU-only mode and the cloud tuning.

## False positives

A cryptominer detector is only useful if it doesn't flag the legitimate heavy
software people actually run. `bench/fp_corpus.py` drives real, benign workloads
that deliberately **resemble a miner** — sustained full-core CPU, and (worst
case) real cryptographic hashing with crypto constants resident in memory — and
checks that none is flagged:

```bash
python bench/fp_corpus.py        # -> bench/fp_results.md
```

| Benign workload (resembles a miner) | Verdict | Signals that fired |
|---|---|---|
| 7-Zip LZMA benchmark (pins every core) | **Clean** | cpu 92 |
| Python SHA-256 hashing (unsigned; CPU + crypto constants) | **Clean** | cpu 92, memory (weak) |
| Python CPU compute (steady full core) | **Clean** | cpu 92 |
| node CPU compute | **Clean** | cpu 92 |

**0 false positives.** Sustained CPU — even alongside crypto constants — is
capped at *Suspicious* by the corroboration rule: a verdict needs a behavioral
signal **plus** a miner-specific artifact (resident stratum/XMRig strings, a
known-pool connection, a ~2 GiB RandomX dataset, a miner name, or the evasion
reaction), none of which legitimate software has.

## Background monitoring

Until you install it, MinerSentry only watches while its window is open, and
only sees what you can see: on one desktop 170 of 352 processes refused to hand
over their memory *or* their arguments to an unelevated scan, so those are
judged on CPU shape alone.

```bash
minersentry-service --run          # watch in this terminal
minersentry-service --install      # start at boot as SYSTEM/root (needs admin)
minersentry-service --status
minersentry-service --uninstall
```

Installing registers a scheduled task on Windows (`schtasks`, running as
SYSTEM) or writes a systemd unit on Linux (running as root). That buys two
things: coverage of processes you cannot otherwise read, and the only honest
form of self-protection available — a miner running as you cannot kill a SYSTEM
service, whereas a user-level watchdog it can kill is theatre.

While it runs there is a tray icon (Windows, built on `Shell_NotifyIcon`, no
dependency) with the few things worth doing from there: open the detection log,
scan autostart now, stop watching. Run it with `--no-tray` if you would rather
it stayed invisible.

New detections raise a desktop notification — a balloon on the tray icon, else a
Windows toast, else `msg`; `notify-send` or `wall` on Linux — and always land in
the detection log. The watcher also re-scans autostart locations periodically,
and notices if its OWN autostart entry is deleted while it is running, which is
something worth being told about.
`notify_min_verdict` chooses the bar (`Likely Miner` by default, or
`Suspicious`), and `notify_command` runs your own command with the title and
body instead.

## Responding to a detection

Killing a miner destroys what you would want to look at and invites it straight
back from whatever autostart entry started it. The alternatives are all
reversible, all confirmed, and all recorded in `actions.jsonl` so an undo never
depends on remembering what was done:

| Action | What it does | Undo |
|---|---|---|
| Suspend | freezes the process; it stops earning, stays inspectable | Resume |
| Remove autostart | deletes the registry value, task, or startup file that revives it | Undo a removal |
| Quarantine | moves the binary where it cannot launch, remembering its home | Restore |
| Block address | one firewall rule by IP; the miner keeps failing to submit | Unblock |
| Terminate | ends it, as before | none |

Autostart removals are verified by execution, not only by unit test. A test
that monkeypatches `subprocess.run` or `winreg` proves the right command was
*built*; it cannot catch a well-formed command pointed at the wrong thing,
which is what both destructive bugs found in review turned out to be. So
`bench/live_removal.py` plants a real entry per kind, runs the real removal,
checks the entry is gone from the authoritative source, runs the real undo and
checks it came back unchanged — then cleans up. `bench/live_removal.md` records
what that covers and, just as importantly, what it does not: a service needs
Administrator, and the system-wide DLL load points (AppCertDlls, LSA packages,
netsh helpers, print monitors) are deliberately never planted on a working
machine.

Suspending your own processes needs no privileges. Firewall rules and moving a
file out of a system directory need Administrator, and the actions say so rather
than failing obscurely.

## Weakened defences

Before a miner settles in it clears the way, so the autostart scan — the
`Scan autostart` button in the GUI as well as `--autostart` and
`--autostart-only` — also reports what has been done to the machine's defences:
an antivirus **exclusion** covering a folder (far more strongly when MinerSentry
has already flagged something inside it), real-time protection switched off by
policy, and `hosts` entries that point antivirus or update domains at nowhere.
Where the exclusion list needs Administrator to read, it says so instead of
reporting that nothing is excluded.

The two scans share one pass so the correlation can actually happen: the
autostart findings' paths are handed to the defence check, and an exclusion
that covers one of them is reported against it. A serious finding raises a
banner at the top of the window rather than only appearing in the event log.

## Configuration

Two files, deliberately not equal in authority:

| File | Who can write it | What it may change |
|---|---|---|
| `%ProgramFiles%\MinerSentry\config.json` (`/etc/minersentry/config.json`) | Administrator / root only | everything |
| `%LOCALAPPDATA%\MinerSentry\config.json` (`~/MinerSentry/config.json`) | the logged-in user, and so anything running as them | scan timing within bounds; **adding** miner names and pool ports |

Anything running as the user can write the per-user file, malware included. One
line there used to be enough to switch detection off — raise the verdict
thresholds, or add `"trusted_dirs": ["C:\\"]` to trust the whole disk. So that
file may now only make MinerSentry *more* suspicious, never less. Everything it
tries to relax is ignored and reported in the event log (`config_warnings` in
`--json`). Real tuning belongs in the admin file, which is honored only when it
is genuinely protected: inside Program Files on Windows, root-owned and not
group- or world-writable on Linux. `--config FILE` loads one file and trusts it
fully, for testing.

Every value is validated for type, range and shape. A malformed entry is skipped
with a warning instead of raising mid-scan, which used to leave the CLI dead and
the GUI stuck showing "Scan error".

## Limitations (honest ones)

- GPU-compute scoring prefers `nvidia-smi pmon` and falls back to the PDH "GPU
  Engine" counters. On the NVIDIA laptop this was developed on, the PDH path
  reports nothing for CUDA/OpenCL work even at 99% GPU load, so without
  `nvidia-smi` on PATH the GPU signal is effectively blind there. Verified with
  real OpenCL load (`samples/gpu_load.py`): 98% read, signal 80, and still
  correctly **Clean** — headless compute alone is not mining.
- Autostart scanning reads what the current user can read. Another user's
  `HKCU` Run keys and some scheduled tasks need elevation, and shortcut targets
  are resolved through the shell, which may be unavailable in a locked-down
  session.
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
  corroboration and dampens trusted binaries rather than alarming. Trusted
  means inside a system folder (matched by whole folder name, so
  `C:\Program Files2` doesn't count) or validly signed. A signature earns
  nothing for a binary running from Temp, Roaming, the Recycle Bin or Fonts,
  and the usual injection hosts are never dampened at all.
- The hidden-compute baseline is learned at startup, so CPU hidden from the
  very start of a session is learned as normal. The VM/WSL check and every
  per-process signal still apply.
- Full memory coverage of protected/other-user processes requires Administrator.
  Run `minersentry-service --install` for that coverage continuously.
  The same applies to reading their **arguments**: on this desktop 166 of 357
  processes would not hand them over unelevated, so a miner running as another
  user (or as SYSTEM) is judged on behavior alone until you elevate.
- MinerSentry recognizes itself by PID, and by its own file path when running as
  the packaged `.exe`. It used to skip anything *named* `MinerSentry.exe`, which
  meant a miner could disappear from the scan by taking that name.
- Content scanning runs at roughly 20 MiB/s (dozens of substring searches per
  chunk; a single compiled regex over the same literals measured ~7x slower, so
  it stays as it is). A process at or below 128 MiB is therefore scanned
  **completely**, which is what a miner's own footprint looks like, while larger
  processes get a bounded budget spread across their regions. A miner that pads
  itself past that limit and buries its strings in the gaps can still evade the
  content scan — its dataset size, arguments, pool traffic and CPU shape don't
  care. The ~2 GiB RandomX dataset is detected by region size and never read.
- Connection age comes from the OS on Windows (`Get-NetTCPConnection`), so a
  short scan can still tell an hours-old pool connection from a fresh one.
  Linux exposes no connection age, so there "long-lived" means MinerSentry
  watched it for `net_persist_seconds`; repeatedly reconnecting to the same
  endpoint counts on both platforms.
- The memory scan reads a bounded slice of large processes, and
  some regions fail to read. `--json` output includes a `memory_coverage` block
  per process (`bounded` or `partial`, bytes read, regions that failed) so a
  partial scan that found nothing isn't mistaken for a clean one.
- A miner running *under* a validly-signed interpreter (e.g. a Python/Node
  script) is dampened along with the interpreter; this is the deliberate
  low-false-positive trade (behavioral cpu/gpu/probe signals are never dampened).
- The hardware-counter (`perf`) signal is **Linux-only** for now — it uses
  user-mode `perf_event_open`, which has no driver-free equivalent on Windows
  (the Windows PMU path needs a kernel driver / ETW PMU session and is deferred).
  On Linux it also requires `/proc/sys/kernel/perf_event_paranoid` ≤ 2 (own
  processes) or `CAP_PERFMON`/root (other users); otherwise it degrades to off.
  Counters are opened on every thread of the process and summed (a counter on
  the PID alone only sees the main thread). The cache-miss thresholds have not
  yet been validated against a real RandomX miner.
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
