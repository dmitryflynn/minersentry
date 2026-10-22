"""Tests for Config load/override behavior."""

import json

from minersentry.config import Config


def test_defaults_present():
    c = Config()
    assert c.weights["cpu"] == 0.26
    assert c.weights["gpu"] == 0.16
    assert 3333 in c.pool_ports
    assert "xmrig" in c.known_miner_names


def test_load_missing_file_returns_defaults(tmp_path):
    c = Config.load(str(tmp_path / "nope.json"))
    assert c.weights["cpu"] == 0.26


def test_override_scalar(tmp_path):
    p = tmp_path / "config.json"
    p.write_text(json.dumps({"suspicious_cap": 30, "trusted_dampen": 0.0}))
    c = Config.load(str(p))
    assert c.suspicious_cap == 30
    assert c.trusted_dampen == 0.0


def test_override_collection_coerced(tmp_path):
    p = tmp_path / "config.json"
    p.write_text(json.dumps({"pool_ports": [1234, 5678]}))
    c = Config.load(str(p))
    assert c.pool_ports == frozenset({1234, 5678})


def test_unknown_keys_ignored(tmp_path):
    p = tmp_path / "config.json"
    p.write_text(json.dumps({"bogus_key": 1, "suspicious_cap": 10}))
    c = Config.load(str(p))
    assert c.suspicious_cap == 10
    assert not hasattr(c, "bogus_key")


def test_wrong_typed_dict_override_ignored(tmp_path):
    # weights given as a list (malformed) must be ignored, not crash combine later
    p = tmp_path / "config.json"
    p.write_text(json.dumps({"weights": [1, 2, 3]}))
    c = Config.load(str(p))
    assert isinstance(c.weights, dict)
    assert c.weights["cpu"] == 0.26


def test_wrong_typed_scalar_override_ignored(tmp_path):
    p = tmp_path / "config.json"
    p.write_text(json.dumps({"suspicious_cap": "high", "deep_limit": True}))
    c = Config.load(str(p))
    assert c.suspicious_cap == 44   # string ignored
    assert c.deep_limit == 6        # bool ignored for an int field
