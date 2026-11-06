"""Regression tests for the issues found in the full audit: trust evasion via
injection hosts, the name-only GPU allowlist, the hidden-compute false alarm,
lazy trust, the PID-reuse race in background memory scans, probe decoys and
log rotation."""

import os
import sys
import time

import pytest

from minersentry import engine as engine_module
from minersentry import probe
from minersentry.audit import AuditLog
from minersentry.config import Config
from minersentry.engine import Engine, ProcInfo
from minersentry.memscan import MemHit, MemScanResult
from minersentry.scoring import combine


def _engine(**kw):
    return Engine(cfg=Config(pool_intel_enabled=False, **kw))


def _miner_memory(pid):
    return MemScanResult(pid=pid, scanned=True, hits=[
        MemHit("XMRig miner identifier", 45, "string"),
        MemHit("stratum pool URL scheme", 40, "string"),
        MemHit("stratum share submission", 45, "string")])


def _busy(e, pid, raw=95.0):
    now = time.time()
    for k in range(8):
        e._cpu_hist[pid].append((now - k, raw))
    return now


# -- trust: injected miners --------------------------------------------------
@pytest.mark.parametrize("host", ["svchost.exe", "explorer.exe", "dllhost.exe", "RegAsm.exe"])
def test_miner_injected_into_signed_host_is_not_dampened(host):
    e = _engine()
    info = ProcInfo(7001); info.name = host
    info.exe = "C:\\Windows\\System32\\" + host; info.trusted = True
    info.mem_result = _miner_memory(7001)
    now = _busy(e, 7001)
    signals = e._build_signals(info, [], now)
    assert next(s.score for s in signals if s.name == "memory") == 100
    assert combine(signals, e.cfg)[1] == "Likely Miner"


def test_signed_security_tool_is_still_dampened():
    e = _engine()
    info = ProcInfo(7002); info.name = "MsMpEng.exe"
    info.exe = r"C:\ProgramData\Microsoft\Windows Defender\Platform\MsMpEng.exe"
    info.trusted = True
    info.mem_result = _miner_memory(7002)
    now = _busy(e, 7002)
    signals = e._build_signals(info, [], now)
    assert next(s.score for s in signals if s.name == "memory") < 40
    assert combine(signals, e.cfg)[1] != "Likely Miner"


# -- lazy trust ----------------------------------------------------------------
def test_trust_not_checked_for_processes_with_nothing_to_dampen(monkeypatch):
    calls = []
    monkeypatch.setattr(engine_module.trust, "is_trusted",
                        lambda *a, **k: calls.append(a) or True)
    e = _engine()
    info = ProcInfo(7003); info.name = "idle.exe"; info.exe = r"C:\x\idle.exe"
    info.trusted = None
    e._build_signals(info, [], time.time())
    assert calls == []                       # nothing scored -> no WinVerifyTrust
    info.mem_result = _miner_memory(7003)
    e._build_signals(info, [], time.time())
    assert len(calls) == 1 and info.trusted is True


# -- GPU allowlist ------------------------------------------------------------
def _gpu_busy(e, pid):
    for _ in range(e.cfg.gpu_min_samples + 1):
        e.set_gpu_util({pid: 95.0}, set(), set())


def test_allowlisted_name_on_untrusted_binary_still_scores_gpu():
    e = _engine()
    _gpu_busy(e, 7004)
    info = ProcInfo(7004); info.name = "ffmpeg.exe"
    info.exe = r"C:\Users\x\AppData\Roaming\ffmpeg.exe"; info.trusted = False
    gpu = next(s for s in e._build_signals(info, [], time.time()) if s.name == "gpu")
    assert gpu.score > 0


def test_allowlisted_trusted_binary_is_exempt():
    e = _engine()
    _gpu_busy(e, 7005)
    info = ProcInfo(7005); info.name = "ffmpeg.exe"
    info.exe = r"C:\Program Files\ffmpeg\ffmpeg.exe"; info.trusted = True
    gpu = next(s for s in e._build_signals(info, [], time.time()) if s.name == "gpu")
    assert gpu.score == 0


# -- hidden compute baseline -------------------------------------------------
def _feed(e, busy, gap, n):
    out = []
    for _ in range(n):
        excess = e._gap_excess(busy, gap)
        e._gap_streak = e._gap_streak + 1 if excess >= e.cfg.unaccounted_cores_threshold * 100 else 0
        out.append(excess)
    return out


def test_normal_unattributed_load_is_learned_not_flagged():
    # the audit machine: ~11 cores busy, ~2 cores nobody accounts for
    e = _engine()
    assert all(x == 0 for x in _feed(e, 1100, 200, e.cfg.hidden_calibration_samples))
    assert max(_feed(e, 1100, 210, 20)) < e.cfg.unaccounted_cores_threshold * 100
    # it scales with load instead of tripping a fixed threshold
    assert max(_feed(e, 1600, 290, 10)) < e.cfg.unaccounted_cores_threshold * 100


def test_hidden_miner_appearing_later_is_flagged_and_not_learned():
    e = _engine()
    _feed(e, 1100, 200, e.cfg.hidden_calibration_samples)
    base = e._gap_baseline
    excess = _feed(e, 1400, 200 + 400, 10)        # 4 hidden cores appear
    assert min(excess[1:]) >= e.cfg.unaccounted_cores_threshold * 100
    assert e._gap_baseline == base               # flagged gaps never move the baseline


# -- PID reuse during a background memory scan ------------------------------
def test_memory_result_dropped_if_pid_was_reused_mid_scan(monkeypatch):
    e = _engine()
    times = iter([100.0, 200.0])                 # start time changes during the scan
    monkeypatch.setattr(e, "_live_ctime", lambda pid: next(times))
    monkeypatch.setattr(engine_module.memscan, "scan_process",
                        lambda pid, **k: _miner_memory(pid))
    e.scan_memory(7006)
    assert 7006 not in e._mem_cache


def test_memory_result_kept_for_same_process(monkeypatch):
    e = _engine()
    monkeypatch.setattr(e, "_live_ctime", lambda pid: 100.0)
    monkeypatch.setattr(engine_module.memscan, "scan_process",
                        lambda pid, **k: _miner_memory(pid))
    e.scan_memory(7007)
    assert 7007 in e._mem_cache


# -- probe decoys --------------------------------------------------------------
def test_decoys_carry_monitor_names_and_are_cleaned_up():
    import psutil
    names = ("taskmgr.exe", "ProcessHacker.exe") if sys.platform == "win32" else ("htop", "nvtop")
    procs, tmpdir, err = probe._spawn_decoys(names)
    if err and "no suitable decoy" in err:
        pytest.skip(err)
    try:
        assert err is None and len(procs) == 2
        seen = {psutil.Process(p.pid).name() for p in procs}
        assert seen == set(names)
    finally:
        probe._stop_decoys(procs)
        probe._cleanup(tmpdir)
    assert all(p.poll() is not None for p in procs)
    assert not os.path.exists(tmpdir)


def test_probe_skips_its_own_process(monkeypatch):
    me = os.getpid()
    monkeypatch.setattr(probe, "_sample_cpu", lambda procs, i: {me: 99.0})
    drops, msg = probe.run_probe()
    assert drops == {} and "busy enough" in msg


# -- audit log rotation --------------------------------------------------------
def test_detection_log_rotates(tmp_path):
    path = tmp_path / "detections.log"
    log = AuditLog(path=str(path), max_bytes=200)
    for i in range(10):
        log.record_detection(pid=i, name="x", exe="y", score=90, verdict="Likely Miner",
                             signals=[("cpu", 92, "z" * 40)])
    assert path.stat().st_size < 600
    assert (tmp_path / "detections.log.1").exists()


def test_deep_targets_scan_suspicious_before_merely_busy():
    e = _engine()
    now = time.time()
    for pid in (9101, 9102, 9103):                 # busy browsers
        for k in range(4):
            e._cpu_hist[pid].append((now - k, 95.0))
    e._conn_seen[(9201, "1.2.3.4", 3333)] = now    # pool-connected, idle
    e._meta[9301] = ("xmrig.exe", r"C:\x\xmrig.exe", "", False)
    order = e.deep_scan_targets()
    assert order.index(9201) < order.index(9101)
    assert order.index(9301) < order.index(9101)
