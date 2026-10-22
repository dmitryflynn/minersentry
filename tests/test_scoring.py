"""Tests for the pure scoring logic — the heart of the product."""

from minersentry.config import Config
from minersentry.scoring import (
    Signal, combine, score_cpu, score_gpu, score_memory, score_name,
    score_network, score_probe,
)

CFG = Config()
NCPU = 16


def sig(name, score):
    return Signal(name, score, "")


# -- CPU signal -------------------------------------------------------------
def test_cpu_steady_full_core_is_strong():
    s = score_cpu([97.0] * 8, NCPU, CFG)
    assert s.score == CFG.cpu_score_full


def test_cpu_bursty_with_low_floor_scores_low():
    # high peaks but regular dips to near-idle -> not miner-like
    s = score_cpu([100, 5, 98, 3, 100, 4, 99, 6], NCPU, CFG)
    assert s.score <= CFG.cpu_score_moderate


def test_cpu_gathering_samples_below_minimum():
    s = score_cpu([97, 97], NCPU, CFG)
    assert s.score == 0
    assert "gathering" in s.detail


def test_cpu_empty_history():
    assert score_cpu([], NCPU, CFG).score == 0


def test_combine_empty_signals():
    # no signals at all must be a clean, zero verdict, not a crash
    assert combine([], CFG) == (0, "Clean")


def test_cpu_startup_zero_does_not_poison_tail():
    # one startup zero then steady full-core: tail judgement ignores the ramp
    s = score_cpu([0.0] + [95.0] * 8, NCPU, CFG)
    assert s.score == CFG.cpu_score_full


# -- memory signal ----------------------------------------------------------
def test_memory_not_scanned_is_zero():
    assert score_memory(False, 0, [], "no handle", 0).score == 0


def test_memory_clean_is_zero():
    assert score_memory(True, 0, [], None, 50 * 1024 * 1024).score == 0


def test_memory_hits_pass_through_score():
    s = score_memory(True, 100, ["xmrig", "stratum login"], None, 10 * 1024 * 1024)
    assert s.score == 100


# -- network signal ---------------------------------------------------------
def test_network_strong_port():
    s = score_network([("1.2.3.4", 3333, False, False)], CFG)
    assert s.score == CFG.net_score_strong


def test_network_ambiguous_port_is_weak():
    s = score_network([("1.2.3.4", 8080, True, False)], CFG)
    assert s.score == CFG.net_score_weak


def test_network_persisted_strong_gets_bump():
    s = score_network([("1.2.3.4", 3333, False, True)], CFG)
    assert s.score == min(100, CFG.net_score_strong + CFG.net_score_persist)


def test_network_persisted_ambiguous_promoted():
    weak = score_network([("1.2.3.4", 8080, True, False)], CFG).score
    persisted = score_network([("1.2.3.4", 8080, True, True)], CFG).score
    assert persisted > weak


# -- gpu signal -------------------------------------------------------------
def test_gpu_headless_sustained_is_strong():
    s = score_gpu([90.0, 92.0, 88.0], has_window=False, allowlisted=False,
                  has_compute_ctx=False, cfg=CFG)
    assert s.score >= CFG.gpu_score_strong


def test_gpu_windowed_is_dampened():
    head = score_gpu([90.0, 92.0, 88.0], False, False, False, CFG).score
    win = score_gpu([90.0, 92.0, 88.0], True, False, False, CFG).score
    assert win < head


def test_gpu_allowlisted_is_zero():
    s = score_gpu([95.0, 95.0], has_window=False, allowlisted=True,
                  has_compute_ctx=False, cfg=CFG)
    assert s.score == 0


def test_gpu_compute_context_bonus():
    base = score_gpu([90.0, 90.0], False, False, False, CFG).score
    ctx = score_gpu([90.0, 90.0], False, False, True, CFG).score
    assert ctx >= base


def test_gpu_idle_is_zero():
    assert score_gpu([2.0, 1.0, 0.0], False, False, False, CFG).score == 0


def test_lone_gpu_spike_is_capped():
    # headless compute alone (e.g. ML training) must not reach Likely Miner
    score, verdict = combine([Signal("gpu", 80, "")], CFG)
    assert verdict != "Likely Miner"
    assert score <= CFG.suspicious_cap


def test_gpu_plus_memory_is_conviction():
    score, verdict = combine([Signal("gpu", 80, ""), Signal("memory", 100, "")], CFG)
    assert verdict == "Likely Miner"


# -- name signal ------------------------------------------------------------
def test_name_known_miner():
    assert score_name("xmrig.exe", "c:\\tools\\xmrig.exe", CFG).score >= CFG.name_score_known


def test_name_unremarkable():
    assert score_name("notepad.exe", "c:\\windows\\system32\\notepad.exe", CFG).score == 0


# -- probe signal -----------------------------------------------------------
def test_probe_strong_drop():
    assert score_probe(95.0, CFG).score == CFG.probe_score_strong


def test_probe_no_drop():
    assert score_probe(0.0, CFG).score == 0


# -- combine: corroboration + conviction + verdict bands --------------------
def test_lone_cpu_spike_is_capped():
    score, verdict = combine([sig("cpu", 92)], CFG)
    assert score <= CFG.suspicious_cap
    assert verdict != "Likely Miner"


def test_cpu_plus_memory_is_conviction():
    score, verdict = combine([sig("cpu", 92), sig("memory", 100)], CFG)
    assert score >= 82
    assert verdict == "Likely Miner"


def test_cpu_plus_network_is_conviction():
    score, verdict = combine([sig("cpu", 92), sig("network", 70)], CFG)
    assert verdict == "Likely Miner"


def test_probe_catch_with_cpu_is_conviction():
    score, verdict = combine([sig("cpu", 60), sig("probe", 95)], CFG)
    assert verdict == "Likely Miner"


def test_memory_plus_network_is_conviction():
    # the stealth-cap case: a throttled miner (cpu signal 0) caught by resident
    # strings + a live pool connection once it's memory-scanned
    score, verdict = combine([sig("cpu", 0), sig("memory", 100), sig("network", 70)], CFG)
    assert score >= 80
    assert verdict == "Likely Miner"


def test_idle_process_with_strings_stays_clean():
    # memory strings resident but no CPU work -> must not alarm (the AV/self case)
    score, verdict = combine([sig("cpu", 0), sig("memory", 100)], CFG)
    assert verdict == "Clean"


def test_binary_constants_only_is_not_hard_evidence():
    # weak binary-constant memory (max ~32) + nothing else -> capped, Clean
    score, verdict = combine([sig("memory", 32)], CFG)
    assert verdict == "Clean"
    assert score <= CFG.suspicious_cap


def test_verdict_bands():
    assert combine([sig("cpu", 35), sig("memory", 35)], CFG)[1] in ("Clean", "Suspicious")
    hi, v = combine([sig("cpu", 92), sig("memory", 100), sig("network", 70)], CFG)
    assert v == "Likely Miner"
