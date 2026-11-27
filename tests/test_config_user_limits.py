"""Issue #53: the per-user file may only make detection stricter."""

import json

import pytest

from minersentry import config as C


def _load(monkeypatch, tmp_path, system: dict | None, user: dict):
    sys_path, user_path = tmp_path / "sys.json", tmp_path / "user.json"
    if system is not None:
        sys_path.write_text(json.dumps(system), encoding="utf-8")
    user_path.write_text(json.dumps(user), encoding="utf-8")
    monkeypatch.setattr(C, "system_config_path", lambda: str(sys_path))
    monkeypatch.setattr(C, "user_config_path", lambda: str(user_path))
    monkeypatch.setattr(C, "_system_file_is_protected",
                        lambda p, w: system is not None)
    return C.Config.load()


def test_user_file_cannot_slow_the_admins_timing(monkeypatch, tmp_path):
    cfg = _load(monkeypatch, tmp_path,
                {"scan_interval": 1.0, "deep_auto_interval": 15,
                 "gpu_sample_interval": 3.0},
                {"scan_interval": 10.0, "deep_auto_interval": 120,
                 "gpu_sample_interval": 60.0})
    assert (cfg.scan_interval, cfg.deep_auto_interval, cfg.gpu_sample_interval) == \
        (1.0, 15.0, 3.0)
    assert sum("slower than the admin" in w for w in cfg.load_warnings) == 3


def test_user_file_may_still_scan_faster_than_the_admin(monkeypatch, tmp_path):
    cfg = _load(monkeypatch, tmp_path, {"scan_interval": 5.0}, {"scan_interval": 2.0})
    assert cfg.scan_interval == 2.0
    assert cfg.load_warnings == []


def test_without_an_admin_value_the_documented_bounds_apply(monkeypatch, tmp_path):
    cfg = _load(monkeypatch, tmp_path, None, {"scan_interval": 4.0})
    assert cfg.scan_interval == 4.0


def test_admin_turning_auto_deep_off_leaves_the_user_free_to_turn_it_on(monkeypatch, tmp_path):
    """0 means off: turning it on is stricter, not slower."""
    cfg = _load(monkeypatch, tmp_path, {"deep_auto_interval": 0},
                {"deep_auto_interval": 60})
    assert cfg.deep_auto_interval == 60.0


@pytest.mark.parametrize("value", ["suspicious", "Clean", "bogus", ""])
def test_notify_min_verdict_must_name_an_alerting_verdict(tmp_path, value):
    p = tmp_path / "c.json"
    p.write_text(json.dumps({"notify_min_verdict": value}), encoding="utf-8")
    cfg = C.Config.load(str(p))
    assert cfg.notify_min_verdict == "Likely Miner"
    assert any("notify_min_verdict" in w for w in cfg.load_warnings)


def test_notify_min_verdict_suspicious_is_accepted(tmp_path):
    p = tmp_path / "c.json"
    p.write_text(json.dumps({"notify_min_verdict": "Suspicious"}), encoding="utf-8")
    assert C.Config.load(str(p)).notify_min_verdict == "Suspicious"
