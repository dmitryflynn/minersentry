"""Tests for the pure evasion classifier (no decoy process needed)."""

from minersentry.probe import classify_drops


def test_true_evader_collapses_and_recovers():
    before = {100: 97.0}
    during = {100: 2.0}      # collapsed while decoy alive
    after = {100: 95.0}      # recovered once decoy gone
    assert 100 in classify_drops(before, during, after)


def test_finished_work_does_not_recover_so_rejected():
    # a process that wound down during the window and stayed down (e.g. an AV
    # scan finishing) must NOT be flagged
    before = {200: 90.0}
    during = {200: 10.0}
    after = {200: 8.0}       # never came back
    assert 200 not in classify_drops(before, during, after)


def test_idle_process_not_considered():
    before = {300: 5.0}      # below min_before
    during = {300: 0.0}
    after = {300: 5.0}
    assert 300 not in classify_drops(before, during, after)


def test_partial_dip_not_a_collapse():
    before = {400: 100.0}
    during = {400: 60.0}     # only dropped to 60% -> not a collapse
    after = {400: 100.0}
    assert 400 not in classify_drops(before, during, after)


def test_steady_miner_not_flagged():
    # an honest (non-evading) miner stays pinned throughout -> no drop
    before = {500: 98.0}
    during = {500: 98.0}
    after = {500: 98.0}
    assert 500 not in classify_drops(before, during, after)
