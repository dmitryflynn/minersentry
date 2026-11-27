"""Share-submission cadence (#14): the pure analyser, its scoring, and how it
sits in the verdict.

Series are synthetic: (timestamp, cumulative bytes out, cumulative bytes in)
sampled every 5 s, the engine's default cadence sample interval.
"""

import random

import pytest

from minersentry import cadence
from minersentry.config import Config
from minersentry.scoring import Signal, combine, score_cadence

CFG = Config()
STEP = 5.0
T0 = 1_000_000.0


def series(duration, beats, out_bytes=260, in_bytes=90, step=STEP,
           background_in=0, t0=T0):
    """Cumulative counters sampled every `step` seconds for `duration`.
    `beats` are offsets (s) at which `out_bytes` go up and `in_bytes` come back."""
    beats = sorted(beats)
    out, inn, samples, bi = 0, 0, [], 0
    t = 0.0
    while t <= duration + 1e-9:
        while bi < len(beats) and beats[bi] <= t:
            out += out_bytes
            inn += in_bytes
            bi += 1
        samples.append((t0 + t, out, inn))
        inn += int(background_in * step)
        t += step
    return samples


def every(period, duration, start=2.0):
    n = int((duration - start) // period) + 1
    return [start + i * period for i in range(n)]


# -- what a miner looks like --------------------------------------------------

def test_regular_beat_is_detected():
    r = cadence.analyse(series(900, every(60, 900)), CFG)
    assert r.beat, r.reason
    assert 55 <= r.median_interval <= 65
    assert r.mean_burst_bytes == 260
    assert "every" in r.describe()


def test_random_share_timing_is_still_a_beat():
    # Shares are found at random, so real gaps are roughly exponential (cv ~1).
    # A strict periodicity test would only ever catch timers.
    rng = random.Random(14)
    t, beats = 3.0, []
    while t < 900:
        beats.append(t)
        t += max(6.0, rng.expovariate(1 / 45))
    r = cadence.analyse(series(900, beats), CFG)
    assert r.beat, r.reason
    assert 0.4 < r.cv <= CFG.cadence_max_cv


def test_submission_straddling_a_sample_boundary_is_one_burst():
    s = series(900, every(60, 900), out_bytes=130)
    # add a second half-write one sample after each beat
    bumped, extra = [], 0
    beat_set = {round(b // STEP * STEP + STEP + STEP, 3) for b in every(60, 900)}
    for t, o, i in s:
        if round(t - T0, 3) in beat_set:
            extra += 130
        bumped.append((t, o + extra, i))
    r = cadence.analyse(bumped, CFG)
    assert r.beat, r.reason
    assert r.mean_burst_bytes == 260


# -- heartbeats: the honest limitation -----------------------------------------

def test_tiny_keepalive_pings_are_not_a_beat():
    # WebSocket/MQTT pings are a handful of bytes.
    r = cadence.analyse(series(900, every(30, 900), out_bytes=6, in_bytes=6), CFG)
    assert not r.beat
    assert r.reason == "no upload bursts"


def test_payload_heartbeat_looks_like_a_miner():
    # A telemetry beacon writing a few hundred bytes every 30 s IS this shape.
    # That is why the signal is corroborating only (see the scoring tests).
    r = cadence.analyse(series(900, every(30, 900), out_bytes=300, in_bytes=40), CFG)
    assert r.beat


# -- things that are not a beat ------------------------------------------------

def test_idle_connection():
    r = cadence.analyse(series(900, []), CFG)
    assert not r.beat and r.reason == "no upload bursts"


def test_single_large_transfer():
    r = cadence.analyse(series(900, [100], out_bytes=5_000_000, in_bytes=200), CFG)
    assert not r.beat and "too few" in r.reason


def test_streaming_upload_is_not_a_beat():
    r = cadence.analyse(series(900, every(5, 900, start=0.0), out_bytes=400), CFG)
    assert not r.beat and "streaming" in r.reason


def test_bursty_chat_traffic_is_not_a_beat():
    # Clusters of quick messages, then minutes of silence.
    beats = []
    for start in (10, 400, 800):
        beats += [start + 7 * k for k in range(6)]
    r = cadence.analyse(series(900, beats, out_bytes=180), CFG)
    assert not r.beat, r


def test_large_periodic_uploads_are_not_small():
    r = cadence.analyse(series(900, every(60, 900), out_bytes=50_000), CFG)
    assert not r.beat and "not small" in r.reason


def test_heavy_inbound_is_not_a_beat():
    r = cadence.analyse(series(900, every(60, 900), background_in=20_000), CFG)
    assert not r.beat and "inbound" in r.reason


def test_too_fast_beat_is_outside_the_band():
    r = cadence.analyse(series(900, every(12, 900)), CFG)
    assert not r.beat and "outside" in r.reason


def test_too_slow_beat_is_outside_the_band():
    r = cadence.analyse(series(900, every(170, 900)), Config(cadence_max_gap=400))
    assert not r.beat and "outside" in r.reason


def test_beat_that_stopped_is_not_current():
    beats = every(45, 420)
    r = cadence.analyse(series(900, beats), CFG)
    assert not r.beat and "stopped" in r.reason


# -- sample hygiene ------------------------------------------------------------

def test_too_few_samples():
    r = cadence.analyse(series(30, every(10, 30)), CFG)
    assert not r.beat and r.reason.startswith("gathering samples")


def test_short_window_with_many_samples():
    s = series(120, every(30, 120), step=1.0)
    assert len(s) >= CFG.cadence_min_samples
    r = cadence.analyse(s, CFG)
    assert not r.beat and r.reason.startswith("gathering samples")


def test_empty_series():
    assert not cadence.analyse([], CFG).beat


def test_counter_reset_is_skipped_not_scored():
    s = series(900, every(60, 900))
    half = len(s) // 2
    base_o, base_i = s[half][1], s[half][2]
    # the counters restart from (nearly) zero half way, e.g. EStats re-enabled
    reset = s[:half] + [(t, o - base_o + 3, i - base_i) for t, o, i in s[half:]]
    r = cadence.analyse(reset, CFG)
    assert r.resets == 1
    assert r.beat, r.reason
    assert r.mean_burst_bytes <= 260      # no fake huge or negative burst


def test_counters_that_only_reset_are_unusable():
    s = [(T0 + i * STEP, 10_000 - i, 10_000 - i) for i in range(80)]
    r = cadence.analyse(s, CFG)
    assert not r.beat and "resetting" in r.reason


def test_unsorted_and_duplicate_timestamps_are_tolerated():
    s = series(900, every(60, 900))
    shuffled = list(reversed(s)) + s[:5]
    r = cadence.analyse(shuffled, CFG)
    assert r.beat, r.reason


# -- scoring: corroborates, never convicts --------------------------------------

def _beat():
    return cadence.analyse(series(900, every(60, 900)), CFG)


def test_score_is_clamped_to_the_weakest_network_score():
    loud = Config(cadence_score=90)
    sig = score_cadence(_beat(), True, loud)
    assert sig.score == loud.net_score_weak
    assert score_cadence(_beat(), True, CFG).score == CFG.cadence_score
    assert CFG.cadence_score <= CFG.net_score_weak


def test_score_is_zero_when_unavailable_off_or_no_beat():
    assert score_cadence(_beat(), False, CFG).score == 0
    assert score_cadence(_beat(), True, Config(cadence_enabled=False)).score == 0
    assert score_cadence(None, True, CFG).score == 0
    idle = cadence.analyse(series(900, []), CFG)
    assert score_cadence(idle, True, CFG).score == 0


def test_cadence_is_not_in_the_weighted_blend():
    assert "cadence" not in CFG.weights


def test_cadence_alone_is_clean():
    sig = score_cadence(_beat(), True, CFG)
    score, verdict = combine([sig], CFG)
    assert verdict == "Clean" and score == 0


@pytest.mark.parametrize("other", [
    Signal("cpu", 70, ""), Signal("gpu", 70, ""), Signal("swarm", 45, ""),
    Signal("network", 50, ""), Signal("perf", 75, ""), Signal("dataset", 70, ""),
    Signal("name", 22, ""),
])
def test_cadence_with_load_or_weak_evidence_cannot_convict(other):
    sig = score_cadence(_beat(), True, CFG)
    score, verdict = combine([sig, other], CFG)
    assert verdict != "Likely Miner"
    assert score <= CFG.suspicious_cap


def test_cadence_with_cpu_and_stratum_port_still_capped():
    sigs = [Signal("cpu", 70, ""), Signal("network", 50, ""),
            score_cadence(_beat(), True, CFG)]
    assert combine(sigs, CFG)[0] <= CFG.suspicious_cap


@pytest.mark.parametrize("partner, value, floor", [
    ("memory", 60, 80), ("cmdline", 40, 85), ("stealth", 50, 85),
])
def test_cadence_convicts_beside_miner_specific_evidence(partner, value, floor):
    sigs = [score_cadence(_beat(), True, CFG), Signal(partner, value, "")]
    score, verdict = combine(sigs, CFG)
    assert score >= floor and verdict == "Likely Miner"
    # and without the beat the same evidence does not get there this way
    assert combine([Signal(partner, value, "")], CFG)[0] < floor


def test_cadence_rules_pair_only_with_miner_specific_signals():
    rules = [r for r in CFG.conviction_rules if "cadence" in (r[0], r[2])]
    assert rules
    partners = {r[2] if r[0] == "cadence" else r[0] for r in rules}
    assert partners <= {"memory", "cmdline", "stealth"}


def test_cadence_floors_never_exceed_the_network_equivalent():
    # "Should not be scored above the network signal it sits beside": each
    # cadence pair's floor is at most the floor of the same partner paired
    # with a (weaker or equal) network signal.
    rules = CFG.conviction_rules
    for a, _ma, b, _mb, floor in rules:
        if "cadence" not in (a, b):
            continue
        partner = b if a == "cadence" else a
        net_floors = [f for x, _m1, y, _m2, f in rules
                      if {x, y} == {partner, "network"}]
        assert net_floors, partner
        assert floor <= max(net_floors)


def test_config_validates_cadence_fractions():
    import json
    import os
    import tempfile
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"cadence_small_fraction": 3, "cadence_score": 140,
                       "cadence_enabled": False}, f)
        cfg = Config.load(path)
        assert cfg.cadence_small_fraction == CFG.cadence_small_fraction
        assert cfg.cadence_score == CFG.cadence_score
        assert cfg.cadence_enabled is False
        assert len(cfg.load_warnings) == 2
    finally:
        os.remove(path)
