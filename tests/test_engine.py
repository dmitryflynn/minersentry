"""Tests for engine-level targeting logic (deep-scan target selection).

These construct a real Engine (its __init__ primes psutil briefly) and inject
state, then assert the pure selection behavior.
"""

import time

from minersentry.config import Config
from minersentry.engine import Engine, ProcInfo


def _engine():
    return Engine(cfg=Config())


def test_trusted_process_signals_dampened():
    # a trusted-signed process with a miner-like name must have its name/memory
    # signals dampened (the feature that was dead while the WinVerifyTrust GUID
    # was wrong). An identical untrusted process is not dampened.
    e = _engine()
    trusted = ProcInfo(321); trusted.name = "xmrig.exe"; trusted.trusted = True
    untrusted = ProcInfo(322); untrusted.name = "xmrig.exe"; untrusted.trusted = False
    t_name = next(s for s in e._build_signals(trusted, [], time.time()) if s.name == "name")
    u_name = next(s for s in e._build_signals(untrusted, [], time.time()) if s.name == "name")
    assert u_name.score >= 85
    assert t_name.score < u_name.score


def test_deep_targets_include_pool_connected_low_cpu():
    e = _engine()
    # a stealth, low-CPU process holding a pool connection must still be targeted
    e._conn_seen[(4242, "1.2.3.4", 3333)] = time.time()
    assert 4242 in e.deep_scan_targets()


def test_deep_targets_include_miner_named_low_cpu():
    e = _engine()
    e._meta[5555] = ("xmrig.exe", "c:\\x\\xmrig.exe", "", False)
    assert 5555 in e.deep_scan_targets()


def test_deep_targets_exclude_self_and_system():
    e = _engine()
    e._conn_seen[(e._self_pid, "1.2.3.4", 3333)] = time.time()
    e._conn_seen[(4, "1.2.3.4", 3333)] = time.time()
    targets = e.deep_scan_targets()
    assert e._self_pid not in targets
    assert 4 not in targets


def test_deep_targets_no_duplicates():
    e = _engine()
    e._meta[7777] = ("xmrig.exe", "c:\\x\\xmrig.exe", "", False)
    e._conn_seen[(7777, "1.2.3.4", 3333)] = time.time()
    targets = e.deep_scan_targets()
    assert targets.count(7777) == 1


def test_deep_targets_force_includes_idle_pid():
    # --pid should force a memory scan of a PID even with no CPU/conn/name signal
    e = _engine()
    e._meta[8888] = ("notepad.exe", "c:\\windows\\notepad.exe", "", True)
    assert 8888 not in e.deep_scan_targets()
    assert 8888 in e.deep_scan_targets(force={8888})


def test_deep_targets_capped():
    e = _engine()
    for pid in range(1000, 1200):  # many pool-connected pids
        e._conn_seen[(pid, "1.2.3.4", 3333)] = time.time()
    assert len(e.deep_scan_targets(limit=6)) <= 6 * 3


def test_deep_targets_force_survives_cap():
    # explicitly-forced PIDs must never be dropped by the cap, even when many
    # pool-connected processes would otherwise fill it
    e = _engine()
    for pid in range(2000, 2200):
        e._conn_seen[(pid, "1.2.3.4", 3333)] = time.time()
    forced = {91001, 91002, 91003}
    targets = e.deep_scan_targets(limit=6, force=forced)
    assert forced <= set(targets)
