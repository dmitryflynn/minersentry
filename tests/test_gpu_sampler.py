"""GPU sampling must never sit inline in the scan loop.

Regression from #18: on a machine with a second GPU a sample also reads the
vendor-neutral counters and costs 5-10 s. The command-line scan sampled on
every pass, so a 45-second scan got four passes, the GPU history never
matured, and the benchmark's GPU miner went from Likely Miner 82 to Clean 2.
"""

import threading
import time

from minersentry import gpu
from minersentry.config import Config
from minersentry.engine import Engine


def _engine():
    return Engine(cfg=Config(pool_intel_enabled=False, gpu_enabled=True,
                             gpu_sample_interval=2.0))


def test_a_slow_gpu_sample_does_not_slow_the_scan_loop(monkeypatch):
    from minersentry import cli

    def slow_sample():
        time.sleep(3.0)          # what a hybrid-GPU sample costs, roughly
        return {}, set(), set()
    monkeypatch.setattr(gpu, "sample", slow_sample)
    engine = _engine()
    # Stub the pass itself so the only thing that can slow the loop is GPU
    # sampling: a real pass over every process takes ~2 s on its own.
    monkeypatch.setattr(engine, "scan_once", lambda deep=False: [])
    monkeypatch.setattr(cli, "Engine", lambda **kw: engine)
    stamps = []
    e, _results, _ = cli.run_session(
        6, cfg=Config(pool_intel_enabled=False, gpu_enabled=True),
        interval=1.0, gpu_sample=True, deep=False,
        progress=lambda elapsed, res: stamps.append(elapsed))
    e.close()
    assert len(stamps) >= 4, (
        f"only {len(stamps)} passes in 6 s: the GPU sample is blocking the loop")


def test_the_sampler_feeds_the_engine_and_stops_on_close(monkeypatch):
    monkeypatch.setattr(gpu, "sample", lambda: ({4242: 90.0}, set(), {4242}))
    e = _engine()
    before = threading.active_count()
    e.start_gpu_sampler()
    e.start_gpu_sampler()                     # idempotent
    deadline = time.monotonic() + 5
    while not e._gpu_hist.get(4242) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert list(e._gpu_hist.get(4242, [])) == [90.0]
    assert threading.active_count() == before + 1, "a second call started a second thread"
    e.close()
    deadline = time.monotonic() + 5
    while threading.active_count() > before and time.monotonic() < deadline:
        time.sleep(0.05)
    assert threading.active_count() <= before, "the sampler outlived close()"


def test_a_failing_sample_is_reported_and_does_not_end_the_sampler(monkeypatch):
    calls = []

    def flaky():
        calls.append(1)
        if len(calls) == 1:
            raise OSError("typeperf missing")
        return {}, set(), set()
    monkeypatch.setattr(gpu, "sample", flaky)
    errors = []
    e = Engine(cfg=Config(pool_intel_enabled=False, gpu_enabled=True,
                          gpu_sample_interval=2.0))
    e.cfg.gpu_sample_interval = 0.0           # clamp floor is 2 s; shorten the wait
    e.start_gpu_sampler(on_error=errors.append)
    deadline = time.monotonic() + 6
    while len(calls) < 2 and time.monotonic() < deadline:
        time.sleep(0.05)
    e.close()
    assert errors and "typeperf missing" in errors[0]
    assert len(calls) >= 2, "one failure ended the sampler"


def test_a_percentage_never_exceeds_100():
    """Summing a process across several 3D engine instances read 163%."""
    out = gpu.merge_gpu_util({}, {}, {7: 162.9}, {7})
    assert out == {7: 100.0}
    assert gpu.merge_gpu_util({8: 250.0}, {}, {}, set()) == {8: 100.0}
