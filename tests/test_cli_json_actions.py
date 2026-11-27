"""Issue #57: --json on the autostart actions, and a sweep that survives one
failed probe."""

import json

from minersentry import cli
from minersentry import persistence as persist_mod
from minersentry.quarantine import Result


def _entry(name):
    return persist_mod.PersistEntry(kind="run-key", location="HKCU\\Run",
                                    name=name, command="x.exe", exe="x.exe")


def test_autostart_remove_no_match_is_json(monkeypatch, capsys):
    monkeypatch.setattr(persist_mod, "scan", lambda cfg: [])
    assert cli.main(["--autostart-remove", "nothing", "--json"]) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is False and "nothing" in out["message"]


def test_autostart_remove_ambiguous_is_json(monkeypatch, capsys):
    monkeypatch.setattr(persist_mod, "scan", lambda cfg: [_entry("Evil A"), _entry("Evil B")])
    assert cli.main(["--autostart-remove", "evil", "--json"]) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is False and len(out["matches"]) == 2


def test_autostart_remove_success_is_json(monkeypatch, capsys):
    monkeypatch.setattr(persist_mod, "scan", lambda cfg: [_entry("Evil")])
    monkeypatch.setattr(persist_mod, "remove_entry", lambda e: Result(True, "Removed Evil."))
    assert cli.main(["--autostart-remove", "evil", "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == {"ok": True, "message": "Removed Evil."}


def test_autostart_undo_is_json(monkeypatch, capsys):
    monkeypatch.setattr(persist_mod, "removals", lambda: [])
    assert cli.main(["--autostart-undo", "--json"]) == 1
    assert json.loads(capsys.readouterr().out)["ok"] is False
    monkeypatch.setattr(persist_mod, "removals", lambda: [{"action": "remove_task"}])
    monkeypatch.setattr(persist_mod, "undo_removal", lambda r: Result(True, "Restored."))
    assert cli.main(["--autostart-undo", "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == {"ok": True, "message": "Restored."}


def test_text_output_is_unchanged(monkeypatch, capsys):
    monkeypatch.setattr(persist_mod, "scan", lambda cfg: [])
    assert cli.main(["--autostart-remove", "nothing"]) == 1
    assert "No reported autostart entry" in capsys.readouterr().err


def test_one_failed_probe_does_not_end_the_sweep(monkeypatch):
    """With --gpu-only the scope changes while the sweep runs, and scan_memory
    raises for a PID that left it. The list comprehension stopped there."""
    from minersentry.engine import Engine
    from minersentry.config import Config
    tried = []

    def probe(self, pid):
        tried.append(pid)
        if pid == 101:
            raise ValueError("PID 101 is outside the GPU-only scan scope")
    monkeypatch.setattr(Engine, "deep_probe", probe)
    monkeypatch.setattr(Engine, "deep_scan_targets", lambda self, force=None: [101, 102, 103])
    monkeypatch.setattr(Engine, "scan_once", lambda self, deep=False: [])
    monkeypatch.setattr(Engine, "start_procevents", lambda self: False)
    monkeypatch.setattr(Engine, "start_pool_intel", lambda self: None)
    monkeypatch.setattr(Engine, "start_connection_ages", lambda self: None)
    cfg = Config(pool_intel_enabled=False, gpu_enabled=False, procevents_enabled=False)
    e, _, _ = cli.run_session(0.4, cfg=cfg, interval=0.05)
    e.close()
    assert tried == [101, 102, 103]
