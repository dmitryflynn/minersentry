"""Regression tests for the post-PR-2 hardening pass: PID reuse, the desktop /
cloud profile, the explicit generic-marker flag, memory-coverage reporting,
the known-pool blend gate and GPU-only scope failures."""

import json
import time
from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from minersentry import cli, memscan
from minersentry import engine as engine_module
from minersentry.audit import AuditLog
from minersentry.config import Config
from minersentry.engine import Engine
from minersentry.scoring import Signal, combine, score_memory, score_name


def sig(name, score):
    return Signal(name, score, "")


# -- PID reuse ---------------------------------------------------------------
def _fake_proc(pid, name, exe, ctime):
    mem = SimpleNamespace(rss=0)
    return SimpleNamespace(
        pid=pid,
        info={"pid": pid, "name": name, "cpu_percent": 0,
              "memory_info": mem, "create_time": ctime},
        name=lambda: name, exe=lambda: exe, username=lambda: "",
        oneshot=nullcontext, memory_info=lambda: mem, num_threads=lambda: 1)


def test_reused_pid_does_not_inherit_trust_or_history(monkeypatch, tmp_path):
    e = Engine(cfg=Config(pool_intel_enabled=False),
               audit=AuditLog(path=str(tmp_path / "a.jsonl")))
    pid = 777001
    procs = [_fake_proc(pid, "svchost.exe", r"C:\Windows\System32\svchost.exe", 100.0)]
    monkeypatch.setattr(engine_module.psutil, "process_iter", lambda *a, **k: iter(procs))
    monkeypatch.setattr(engine_module.psutil, "net_connections", lambda **k: [])
    monkeypatch.setattr(engine_module.psutil, "cpu_percent", lambda *a: 0)

    e.scan_once()
    # pretend the old process was trusted and had built up evidence
    e._meta[pid] = ("svchost.exe", r"C:\Windows\System32\svchost.exe", "", True)
    e._cpu_hist[pid].append((time.time(), 95.0))
    e._conn_seen[(pid, "1.2.3.4", 3333)] = time.time() - 999
    e._probe_drops[pid] = 90.0

    # same PID, new process (different start time)
    procs[:] = [_fake_proc(pid, "worker.exe", r"C:\Users\x\AppData\Local\Temp\worker.exe", 200.0)]
    r = e.scan_once()[0]
    assert r.exe.endswith("worker.exe")
    assert r.trusted is not True          # unresolved (None) or False, never inherited
    assert e._meta[pid][3] is not True
    assert (pid, "1.2.3.4", 3333) not in e._conn_seen
    assert pid not in e._probe_drops
    assert not any(c == 95.0 for _t, c in e._cpu_hist.get(pid, ()))


def test_same_process_keeps_its_cache(monkeypatch, tmp_path):
    e = Engine(cfg=Config(pool_intel_enabled=False),
               audit=AuditLog(path=str(tmp_path / "a.jsonl")))
    pid = 777002
    procs = [_fake_proc(pid, "a.exe", r"C:\a.exe", 100.0)]
    monkeypatch.setattr(engine_module.psutil, "process_iter", lambda *a, **k: iter(procs))
    monkeypatch.setattr(engine_module.psutil, "net_connections", lambda **k: [])
    monkeypatch.setattr(engine_module.psutil, "cpu_percent", lambda *a: 0)
    e.scan_once()
    e._probe_drops[pid] = 90.0
    e.scan_once()
    assert e._probe_drops.get(pid) == 90.0


# -- desktop / cloud profile -------------------------------------------------
def test_desktop_profile_surfaces_idle_known_miner_name():
    cfg = Config()
    assert cfg.profile == "desktop"
    score, verdict = combine([score_name("xmrig.exe", r"C:\x\xmrig.exe", cfg)], cfg)
    assert verdict == "Suspicious"


def test_cloud_profile_keeps_idle_known_miner_name_clean():
    cfg = Config(profile="cloud")
    assert combine([score_name("xmrig.exe", r"C:\x\xmrig.exe", cfg)], cfg)[1] == "Clean"


def test_desktop_profile_does_not_promote_generic_or_short_names():
    cfg = Config()
    for name, exe in [("miner.exe", r"C:\x\miner.exe"), ("abc.exe", r"D:\abc.exe"),
                      ("tracker-miner-fs-3", "/usr/libexec/tracker-miner-fs-3")]:
        assert combine([score_name(name, exe, cfg)], cfg)[1] == "Clean"


def test_desktop_name_plus_load_still_convicts():
    cfg = Config()
    name = score_name("xmrig.exe", r"C:\x\xmrig.exe", cfg)
    assert combine([name, sig("cpu", 92)], cfg)[1] == "Likely Miner"


def test_bad_profile_in_config_file_falls_back(tmp_path):
    p = tmp_path / "config.json"
    p.write_text(json.dumps({"profile": "clod"}), encoding="utf-8")
    assert Config.load(str(p)).profile == "desktop"
    p.write_text(json.dumps({"profile": "cloud"}), encoding="utf-8")
    assert Config.load(str(p)).profile == "cloud"


# -- generic memory markers --------------------------------------------------
def test_generic_flag_drives_the_cap_not_label_text(monkeypatch):
    # renaming a label must not change how it scores
    monkeypatch.setitem(memscan.STRING_MARKERS, b"randomx", ("renamed algo label", 10))
    r = memscan.MemScanResult(pid=1, scanned=True, large_page_dataset=True)
    memscan._search_chunk(b"randomx rx/0 cryptonight", r, set())
    assert all(h.generic for h in r.hits)
    assert r.score <= memscan.GENERIC_SCORE_CAP < Config().hard_memory


def test_protocol_string_lifts_the_generic_cap():
    r = memscan.MemScanResult(pid=1, scanned=True, large_page_dataset=True)
    memscan._search_chunk(b"randomx stratum+tcp://x", r, set())
    assert r.score > memscan.GENERIC_SCORE_CAP


# -- coverage reporting ------------------------------------------------------
def test_partial_scan_is_named_in_memory_detail():
    s = score_memory(True, 85, ["XMRig miner identifier"], "memory read failed or short in 3 region(s)",
                     1024)
    assert s.score == 85 and "partial scan" in s.detail


def test_cli_summary_reports_memory_coverage():
    e = Engine(cfg=Config(pool_intel_enabled=False))
    r = engine_module.ProcInfo(4321, cpu=50.0)
    r.name, r.verdict, r.score = "x.exe", "Suspicious", 50
    r.mem_result = memscan.MemScanResult(pid=4321, scanned=True, bytes_scanned=10,
                                         regions_failed=2, coverage_status="partial")
    out = cli.summarize(e, [r], {})
    cov = out["processes"][0]["memory_coverage"]
    assert cov["status"] == "partial" and cov["regions_failed"] == 2


# -- blend gate --------------------------------------------------------------
def test_persisted_stratum_port_does_not_open_the_blend_gate():
    cfg = Config()
    # many signals, none miner-specific; the raw blend (~49) is above the cap,
    # so this only passes if the gate holds it down
    signals = [sig("cpu", 92), sig("gpu", 80),
               sig("network", cfg.net_score_stratum_persisted),
               sig("name", 22), sig("probe", 40)]
    blended = sum(w * {s.name: s.score for s in signals}.get(k, 0)
                  for k, w in cfg.weights.items())
    assert blended > cfg.suspicious_cap
    score, verdict = combine(signals, cfg)
    assert score <= cfg.suspicious_cap and verdict == "Clean"


# -- GPU-only scope failures -------------------------------------------------
def _patch_session(monkeypatch, queries):
    calls = iter(queries)

    def fake_compute_pids():
        item = next(calls)
        if isinstance(item, Exception):
            raise item
        return item

    monkeypatch.setattr(cli.gpu_mod, "compute_pids", fake_compute_pids)
    monkeypatch.setattr(cli.gpu_mod, "sample", lambda: ({}, set(), set()))
    monkeypatch.setattr(Engine, "scan_once", lambda self, deep=False: [])


def test_gpu_only_first_query_failure_still_fails(monkeypatch):
    _patch_session(monkeypatch, [RuntimeError("driver gone")])
    with pytest.raises(RuntimeError):
        cli.run_session(0.5, cfg=Config(pool_intel_enabled=False), interval=0.01,
                        deep=False, gpu_only=True)


def test_gpu_only_later_failure_keeps_last_scope(monkeypatch, capsys):
    _patch_session(monkeypatch, [{4242}] + [RuntimeError("timeout")] * 10000)
    e, _results, _hits = cli.run_session(0.2, cfg=Config(pool_intel_enabled=False),
                                         interval=0.01, deep=False, gpu_only=True)
    assert e.gpu_scope == {4242}
    assert "keeping the previous GPU scope" in capsys.readouterr().err
