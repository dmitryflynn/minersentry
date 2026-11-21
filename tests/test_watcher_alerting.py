"""Issue #51: the watcher's alerting on Windows."""

import sys

import pytest

from minersentry import service
from minersentry.config import Config


@pytest.mark.parametrize("command, exe", [
    (r"C:\tools\alert.exe --flag", r"C:\tools\alert.exe"),
    (r'"C:\Program Files\Alert\alert.exe" --flag', r"C:\Program Files\Alert\alert.exe"),
])
def test_notify_command_keeps_a_windows_path(monkeypatch, command, exe):
    """shlex.split is POSIX: it read C:\\tools\\alert.exe as C:toolsalert.exe,
    the command failed to start, and the alert quietly became a toast."""
    monkeypatch.setattr(service.sys, "platform", "win32")
    ran = []
    monkeypatch.setattr(service.subprocess, "run", lambda args, **k: ran.append(args))
    assert service.notify("t", "b", Config(notify_command=command)) == "command"
    assert ran[0] == [exe, "--flag", "t", "b"]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX splitting")
def test_notify_command_keeps_posix_quoting(monkeypatch):
    ran = []
    monkeypatch.setattr(service.subprocess, "run", lambda args, **k: ran.append(args))
    service.notify("t", "b", Config(notify_command="notify 'two words'"))
    assert ran[0] == ["notify", "two words", "t", "b"]


def _quiet_engine(monkeypatch):
    from minersentry import engine as engine_module
    monkeypatch.setattr(engine_module.psutil, "process_iter", lambda *a, **k: iter([]))
    monkeypatch.setattr(engine_module.psutil, "net_connections", lambda **k: [])
    monkeypatch.setattr(engine_module.psutil, "cpu_percent", lambda *a: 5.0)
    monkeypatch.setattr(service.persist_mod, "scan", lambda cfg: [])


def test_an_unknown_status_is_not_reported_as_removal(monkeypatch, tmp_path):
    """status() says "unknown: TimeoutExpired" when schtasks is slow. That is
    not evidence the task was deleted, and the watcher used to say it was and
    then stop checking for good."""
    from minersentry.audit import AuditLog
    _quiet_engine(monkeypatch)
    states = iter(["installed (elevated=True)",
                   "unknown: TimeoutExpired: schtasks timed out"])
    monkeypatch.setattr(service, "status", lambda: next(states, "installed"))
    events, sent = [], []
    log = AuditLog(path=str(tmp_path / "d.jsonl"), on_event=events.append)
    monkeypatch.setattr(service, "notify", lambda t, b, c=None: sent.append(t))
    cfg = Config(pool_intel_enabled=False, gpu_enabled=False, deep_auto_interval=0,
                 persistence_interval=0, tamper_check_interval=1.0,
                 procevents_enabled=False)
    service.run(cfg=cfg, once=True, audit=log)
    assert not any("tamper" in e for e in events), events
    assert not sent


def test_removal_is_still_reported(monkeypatch, tmp_path):
    from minersentry.audit import AuditLog
    _quiet_engine(monkeypatch)
    states = iter(["installed (elevated=True)", "not installed (elevated=True)"])
    monkeypatch.setattr(service, "status", lambda: next(states, "not installed"))
    events = []
    log = AuditLog(path=str(tmp_path / "d.jsonl"), on_event=events.append)
    monkeypatch.setattr(service, "notify", lambda t, b, c=None: None)
    cfg = Config(pool_intel_enabled=False, gpu_enabled=False, deep_auto_interval=0,
                 persistence_interval=0, tamper_check_interval=1.0,
                 procevents_enabled=False)
    service.run(cfg=cfg, once=True, audit=log)
    assert any("tamper" in e for e in events), events
