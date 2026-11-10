"""Group 1 regressions: the per-user config can't blind detection, bad values
never crash a scan, and a miner can't hide by naming itself MinerSentry.exe."""

import json
from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from minersentry import config as config_module
from minersentry import engine as engine_module
from minersentry.config import Config
from minersentry.scoring import Signal, combine

MINER = [Signal("cpu", 92, ""), Signal("memory", 100, ""), Signal("network", 90, "")]


@pytest.fixture
def user_cfg(tmp_path, monkeypatch):
    """Point the per-user and admin config paths into tmp_path."""
    user = tmp_path / "user" / "config.json"
    admin = tmp_path / "admin" / "config.json"
    user.parent.mkdir()
    admin.parent.mkdir()
    monkeypatch.setattr(config_module, "user_config_path", lambda: str(user))
    monkeypatch.setattr(config_module, "system_config_path", lambda: str(admin))
    return user, admin


def _write(path, data):
    path.write_text(json.dumps(data), encoding="utf-8")


def test_user_config_cannot_raise_thresholds_or_trust_everything(user_cfg):
    user, _ = user_cfg
    _write(user, {"verdict_thresholds": [[1000, "Likely Miner"], [0, "Clean"]],
                  "trusted_dirs": ["c:\\"], "conviction_rules": [],
                  "profile": "cloud", "suspicious_cap": 0})
    cfg = Config.load()
    assert combine(MINER, cfg)[1] == "Likely Miner"
    assert cfg.trusted_dirs == Config().trusted_dirs
    assert cfg.profile == "desktop"
    assert len(cfg.load_warnings) == 5
    assert all("only the admin config" in w for w in cfg.load_warnings)


def test_user_config_may_add_names_and_tune_timing(user_cfg):
    user, _ = user_cfg
    _write(user, {"known_miner_names": ["customminer"], "scan_interval": 4,
                  "pool_ports": [6666]})
    cfg = Config.load()
    assert "customminer" in cfg.known_miner_names and "xmrig" in cfg.known_miner_names
    assert 6666 in cfg.pool_ports and 3333 in cfg.pool_ports      # added, not replaced
    assert cfg.scan_interval == 4.0 and cfg.load_warnings == []


def test_user_timing_is_bounded(user_cfg):
    user, _ = user_cfg
    _write(user, {"deep_auto_interval": 100000, "scan_interval": 0.01})
    cfg = Config.load()
    assert cfg.deep_auto_interval == Config().deep_auto_interval
    assert cfg.scan_interval == Config().scan_interval
    assert len(cfg.load_warnings) == 2


def test_admin_config_is_honored_only_when_protected(user_cfg, monkeypatch):
    _, admin = user_cfg
    _write(admin, {"profile": "cloud"})
    monkeypatch.setattr(config_module, "_system_file_is_protected", lambda p, w: True)
    assert Config.load().profile == "cloud"
    monkeypatch.setattr(config_module, "_system_file_is_protected", lambda p, w: False)
    assert Config.load().profile == "desktop"


@pytest.mark.parametrize("bad", [
    {"weights": {"cpu": "x"}},
    {"weights": {"cpu": float("nan")}},
    {"conviction_rules": [["cpu", 60]]},
    {"conviction_rules": [["cpu", 60, "memory", 60, 500]]},
    {"verdict_thresholds": [[75]]},
    {"verdict_thresholds": [[75, "Likely Miner"]]},          # no entry starting at 0
    {"verdict_thresholds": [[75, "Pwned"], [0, "Clean"]]},
    {"suspicious_cap": -5}, {"trusted_dampen": 7}, {"scan_interval": 0},
    {"deep_auto_interval": 0.001}, {"pool_ports": [70000]},
    {"probe_decoys_windows": ["..\\..\\evil.exe"]},
    {"probe_decoys_posix": ["../../bin/x"]},
])
def test_malformed_values_are_skipped_not_fatal(tmp_path, bad):
    p = tmp_path / "config.json"
    p.write_text(json.dumps(bad, allow_nan=True), encoding="utf-8")
    cfg = Config.load(str(p))
    assert cfg.load_warnings, bad
    assert combine(MINER, cfg)[1] == "Likely Miner"   # still scores, no exception


def test_valid_admin_tuning_still_applies(tmp_path):
    p = tmp_path / "config.json"
    p.write_text(json.dumps({
        "verdict_thresholds": [[0, "Clean"], [80, "Likely Miner"], [50, "Suspicious"]],
        "conviction_rules": [["cpu", 60, "memory", 60, 90]]}), encoding="utf-8")
    cfg = Config.load(str(p))
    assert cfg.load_warnings == []
    assert cfg.verdict_thresholds[0] == (80, "Likely Miner")   # sorted high to low
    assert combine([Signal("cpu", 92, ""), Signal("memory", 100, "")], cfg) == (90, "Likely Miner")


def test_broken_json_is_reported(tmp_path):
    p = tmp_path / "config.json"
    p.write_text("{not json", encoding="utf-8")
    cfg = Config.load(str(p))
    assert cfg.load_warnings and cfg == Config()


# -- self-identification ---------------------------------------------------
def _fake(pid, name, exe):
    mem = SimpleNamespace(rss=0)
    return SimpleNamespace(
        pid=pid, info={"pid": pid, "name": name, "cpu_percent": 98.0,
                       "memory_info": mem, "create_time": 1.0},
        name=lambda: name, exe=lambda: exe, username=lambda: "", oneshot=nullcontext,
        memory_info=lambda: mem, num_threads=lambda: 4, cpu_percent=lambda *_: 98.0)


def test_process_named_minersentry_is_still_scanned(monkeypatch, tmp_path):
    procs = [_fake(5002, "MinerSentry.exe", r"C:\Users\x\AppData\Local\Temp\MinerSentry.exe")]
    monkeypatch.setattr(engine_module.psutil, "process_iter", lambda *a, **k: iter(procs))
    monkeypatch.setattr(engine_module.psutil, "net_connections", lambda **k: [])
    monkeypatch.setattr(engine_module.psutil, "cpu_percent", lambda *a: 10.0)
    from minersentry.audit import AuditLog
    e = engine_module.Engine(cfg=Config(pool_intel_enabled=False),
                             audit=AuditLog(path=str(tmp_path / "a.log")))
    for _ in range(6):
        results = e.scan_once()
    assert any(r.pid == 5002 for r in results)


def test_frozen_instance_of_our_own_binary_is_skipped(monkeypatch, tmp_path):
    exe = r"C:\Program Files\MinerSentry\MinerSentry.exe"
    monkeypatch.setattr(engine_module.sys, "frozen", True, raising=False)
    monkeypatch.setattr(engine_module.sys, "executable", exe)
    monkeypatch.setattr(engine_module.os.path, "realpath", lambda p: p)
    procs = [_fake(5003, "MinerSentry.exe", exe),
             _fake(5004, "MinerSentry.exe", r"C:\Users\x\Downloads\MinerSentry.exe")]
    monkeypatch.setattr(engine_module.psutil, "process_iter", lambda *a, **k: iter(procs))
    monkeypatch.setattr(engine_module.psutil, "net_connections", lambda **k: [])
    monkeypatch.setattr(engine_module.psutil, "cpu_percent", lambda *a: 10.0)
    from minersentry.audit import AuditLog
    e = engine_module.Engine(cfg=Config(pool_intel_enabled=False),
                             audit=AuditLog(path=str(tmp_path / "a.log")))
    pids = {r.pid for r in e.scan_once()}
    assert 5003 not in pids          # the same installed binary: another instance of us
    assert 5004 in pids              # same name, different file: scanned
