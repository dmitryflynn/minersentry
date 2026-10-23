"""Tests for the hardware perf-counter signal (scoring is pure; the module
itself degrades safely when perf is unavailable)."""

import os
import sys

from minersentry import perfcounters
from minersentry.config import Config
from minersentry.scoring import Signal, combine, score_perf

CFG = Config()


def test_score_perf_none_is_zero():
    assert score_perf(None, CFG).score == 0


def test_score_perf_memory_hard_is_strong():
    assert score_perf(200.0, CFG).score == CFG.perf_score_strong


def test_score_perf_low_is_zero():
    assert score_perf(5.0, CFG).score == 0


def test_perf_plus_dataset_convicts():
    # memory-hard cache-miss fingerprint + a 2 GiB dataset = RandomX, diagnostic
    score, verdict = combine(
        [Signal("perf", 75, ""), Signal("dataset", 70, "")], CFG)
    assert verdict == "Likely Miner"


def test_lone_perf_not_convicting():
    # a memory-bound database also misses a lot; perf alone must not alarm
    _score, verdict = combine([Signal("perf", 75, "")], CFG)
    assert verdict != "Likely Miner"


def test_perf_safe_when_unavailable():
    # off Linux (or without permission) everything degrades to a no-op, never raises
    if not sys.platform.startswith("linux"):
        assert perfcounters.available() is False
        assert perfcounters.paranoid_level() is None
        assert perfcounters.sample_miss_ratio(os.getpid()) is None
