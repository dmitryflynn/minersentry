"""Issue #56: Suspend selected. No window is created; handlers run unbound."""

import os
from types import SimpleNamespace

import psutil

from minersentry import gui
from minersentry.gui import MinerSentryApp
from minersentry.quarantine import Result


def _app(pid, ctime):
    row = SimpleNamespace(name="target.exe", ctime=ctime, verdict="Suspicious", score=50)
    app = SimpleNamespace(rows={pid: row}, _suspended={}, statuses=[], events=[])
    app._selected = lambda: (pid, row)
    app._set_status = app.statuses.append
    app._add_event = app.events.append
    app._same_process = lambda p, r: MinerSentryApp._same_process(app, p, r)
    app._resume = lambda p, n, ask=True: MinerSentryApp._resume(app, p, n, ask)
    return app


def _answers(monkeypatch, *replies):
    it = iter(replies)
    asked = []
    monkeypatch.setattr(gui.messagebox, "askyesno",
                        lambda title, text, **k: asked.append(text) or next(it))
    for name in ("showinfo", "showwarning", "showerror"):
        monkeypatch.setattr(gui.messagebox, name, lambda *a, **k: None)
    return asked


def test_a_reused_pid_is_not_suspended(monkeypatch):
    """Terminate refuses when the PID now belongs to another process. Suspend
    did not, so a dialog left open across a PID reuse froze the newcomer."""
    pid = os.getpid()
    app = _app(pid, psutil.Process(pid).create_time() - 1000)
    _answers(monkeypatch, True, False)
    called = []
    monkeypatch.setattr(gui.quarantine_mod, "suspend",
                        lambda p: called.append(p) or Result(True, "x"))
    MinerSentryApp.suspend_selected(app)
    assert called == []


def test_a_suspended_process_can_be_resumed_later(monkeypatch):
    """The dialog says "Use Resume to undo" but there was no Resume: decline
    the one prompt after suspending and the process stayed frozen."""
    pid = os.getpid()
    app = _app(pid, psutil.Process(pid).create_time())
    calls = []
    monkeypatch.setattr(gui.quarantine_mod, "suspend",
                        lambda p: calls.append(("suspend", p)) or Result(True, "Suspended"))
    monkeypatch.setattr(gui.quarantine_mod, "resume",
                        lambda p: calls.append(("resume", p)) or Result(True, "Resumed"))
    _answers(monkeypatch, True, False)        # suspend: yes; resume now: no
    MinerSentryApp.suspend_selected(app)
    assert pid in app._suspended
    asked = _answers(monkeypatch, True)       # press the button again
    MinerSentryApp.suspend_selected(app)
    assert calls == [("suspend", pid), ("resume", pid)]
    assert "Resume" in asked[0]
    assert pid not in app._suspended


def test_a_suspended_process_stays_in_the_table():
    """A frozen process uses no CPU; if nothing else scores it, the idle-row
    filter used to hide it, and then it could not be selected to resume."""
    r = SimpleNamespace(pid=7, score=0, cpu=0.0, gpu=0.0)
    app = SimpleNamespace(_suspended={7: 1.0})
    assert MinerSentryApp._shown(app, r)
    app._suspended = {}
    assert not MinerSentryApp._shown(app, r)
