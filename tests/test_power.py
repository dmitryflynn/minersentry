"""Tests for the pure hidden-compute / power-gap decision."""

from minersentry.config import Config
from minersentry.power import compute_report, sample_vm_loads

CFG = Config()  # unaccounted_cores_threshold 1.5, vm_cores_threshold 1.0


def test_small_gap_not_flagged():
    # system busy ~= attributed -> nothing hidden
    r = compute_report(400.0, 395.0, {}, persisted_gap=True, cfg=CFG)
    assert not r.flagged


def test_large_gap_but_not_persisted_is_not_flagged():
    # a one-off sampling skew must not alarm
    r = compute_report(600.0, 100.0, {}, persisted_gap=False, cfg=CFG)
    assert not r.flagged


def test_persistent_large_gap_flagged():
    r = compute_report(600.0, 100.0, {}, persisted_gap=True, cfg=CFG)
    assert r.flagged
    assert r.unaccounted_cores >= CFG.unaccounted_cores_threshold
    assert "hidden" in r.note.lower()


def test_vm_load_flagged():
    r = compute_report(300.0, 300.0, {"vmmem": 350.0}, persisted_gap=False, cfg=CFG)
    assert r.flagged
    assert "vmmem" in r.note
    assert r.vm_loads["vmmem"] >= CFG.vm_cores_threshold


def test_small_vm_load_ignored():
    r = compute_report(300.0, 300.0, {"vmmem": 40.0}, persisted_gap=False, cfg=CFG)
    assert not r.flagged


def test_sample_vm_loads_sums_by_name():
    procs = {1: ("vmmem.exe", 120.0), 2: ("brave.exe", 50.0), 3: ("vmmem", 30.0)}
    out = sample_vm_loads(procs, CFG)
    assert round(out["vmmem"]) == 150
    assert "brave" not in out
