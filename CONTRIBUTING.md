# Contributing

Pull requests are welcome, including ones that show the detector is wrong.
A reproducible false positive or a working evasion is worth more here than a
new feature.

## Getting set up

```bash
git clone https://github.com/dmitryflynn/minersentry
cd minersentry
pip install -e ".[dev]"
python -m pytest            # ~380 tests, about a minute
python main.py              # the GUI
```

Python 3.10 or newer, and `psutil` is the only runtime dependency. Please keep
it that way: the GPU, tray, memory, trust and perf-counter code all talk to the
OS through `ctypes` or a stock command-line tool precisely so that installing
this stays a one-liner. If something genuinely needs a dependency, make it
optional and degrade without it.

## How the code is arranged

- `scoring.py` is **pure**: numbers in, verdict out. No `psutil`, no I/O, no
  global state. This is where the decisions live, and it is the easiest place
  to test a change.
- `engine.py` is the collector that feeds it. `memscan`, `gpu`, `probe`,
  `trust`, `poolintel`, `perfcounters`, `cmdline` and `persistence` each gather
  one kind of evidence, with their parsers pure and their OS calls thin.
- `config.py` holds every tunable. A change that needs a new threshold adds a
  field there rather than a literal in the engine.
- Platform differences are handled by dispatch inside a module, not by
  branching at the call site.

A new signal is usually: a pure `score_*` in `scoring.py`, its thresholds in
`config.py`, a conviction pair if it convicts, a line in
`Engine._build_signals`, and tests for the pure parts.

## What a change needs

1. **Tests.** Pure logic gets unit tests. Something that touches the OS gets
   its parser tested against real captured output — there are several examples
   in `tests/` that do exactly that.
2. **A false-positive check** if you touch scoring: `python bench/fp_corpus.py`
   must stay at 0, and it prints how close the nearest benign workload came.
   Narrowing that margin is a reason to reconsider the change.
3. **`python bench/run_bench.py`** if you touch detection, to show nothing
   regressed.
4. **`python -m pyflakes minersentry tests bench samples`** clean.
5. CI runs the suite on Ubuntu and Windows across Python 3.10–3.12. Both
   platforms have to pass, and they catch different things: half the bugs in
   this repo's history were one platform behaving unlike the other.

## Things worth knowing before you change scoring

- CPU is **raw per-core** (100 = one core), never a percentage of the machine.
- A signal that is merely *work* (cpu, gpu, swarm, perf) must not convict on its
  own. Conviction needs something miner-specific alongside it. The corroboration
  cap exists for this and should not be loosened without a corpus run.
- Generic evidence — crypto constants, ordinary CLI flags — is capped below the
  corroboration bar on purpose. Every TLS stack contains Keccak constants.
- Don't replace the memory scan's substring searches with a regex. It was tried
  and measured at roughly seven times slower, and the comment in `memscan.py`
  records it.

## Reporting instead of patching

That is fine too, and often more useful:

- **A false positive:** what the process was, what it was doing, and the
  `--json` output. The signal breakdown is what makes it fixable.
- **An evasion:** how a miner stays under the thresholds. Describe the behaviour
  rather than attaching malware — see below.
- **A crash:** the command, the traceback, your OS and Python version.

## Malware

Do not attach miner samples to issues or commit them, and do not ask for help
running one. `samples/fake_miner.py` reproduces miner *behaviour* and mines
nothing, which is how every test and benchmark here works; `samples/gpu_load.py`
does the same for the GPU. If an evasion can only be shown with real malware,
describe it and I will reason about it from the description.

## Security reports

Use the private channel in [SECURITY.md](SECURITY.md) rather than a public
issue.
