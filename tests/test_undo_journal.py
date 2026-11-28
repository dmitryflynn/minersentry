r"""Issue #58: undoing a registry, task or service removal must be journalled.

`removals()` dropped a startup-folder quarantine once `restore_file` recorded
its undo, but restoring a registry value, re-creating a task or re-enabling a
service wrote nothing. "Undo the last removal" therefore undid the newest
removal again on every call, rewriting the old value over whatever was there
now, and never reached the older ones.

Everything here runs against the in-memory winreg and a mocked schtasks, so
nothing on the machine is touched.
"""

import subprocess
import sys
from types import SimpleNamespace

import pytest

from fakereg import FakeWinreg
from minersentry import persistence as P

RUN = r"Software\Microsoft\Windows\CurrentVersion\Run"
SVC = r"SYSTEM\CurrentControlSet\Services"


@pytest.fixture
def reg(monkeypatch, tmp_path):
    fake = FakeWinreg()
    monkeypatch.setitem(sys.modules, "winreg", fake)
    monkeypatch.setattr(P, "IS_WINDOWS", True)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    return fake


def _run_entry(name):
    return P.PersistEntry(kind="run-key", location="HKCU\\" + RUN,
                          name=name, command="x")


def test_undo_last_walks_back_through_registry_removals(reg):
    reg.set("HKCU", RUN, "A", r"C:\a.exe")
    reg.set("HKCU", RUN, "B", r"C:\b.exe")
    assert P.remove_entry(_run_entry("A")).ok
    assert P.remove_entry(_run_entry("B")).ok

    assert P.undo_removal(P.removals()[-1]).ok
    assert reg.get("HKCU", RUN, "B") == (r"C:\b.exe", 1)
    assert [r["name"] for r in P.removals()] == ["A"], \
        "the undone removal of B is still offered"

    assert P.undo_removal(P.removals()[-1]).ok
    assert reg.get("HKCU", RUN, "A") == (r"C:\a.exe", 1)
    assert P.removals() == []


def test_an_undone_removal_is_not_replayed_over_a_later_change(reg):
    reg.set("HKCU", RUN, "B", r"C:\old.exe")
    assert P.remove_entry(_run_entry("B")).ok
    assert P.undo_removal(P.removals()[-1]).ok
    reg.set("HKCU", RUN, "B", r"C:\new.exe")
    assert P.removals() == []


def test_removing_the_same_value_again_after_an_undo_is_offered_again(reg):
    reg.set("HKCU", RUN, "B", r"C:\b.exe")
    assert P.remove_entry(_run_entry("B")).ok
    assert P.undo_removal(P.removals()[-1]).ok
    assert P.remove_entry(_run_entry("B")).ok
    assert [r["name"] for r in P.removals()] == ["B"]


def test_a_failed_registry_undo_is_not_recorded_as_done(reg, monkeypatch):
    reg.set("HKCU", RUN, "B", r"C:\b.exe")
    assert P.remove_entry(_run_entry("B")).ok

    def refuse(*a, **k):
        raise PermissionError("denied")

    monkeypatch.setattr(reg, "SetValueEx", refuse)
    assert not P.undo_removal(P.removals()[-1]).ok
    assert [r["name"] for r in P.removals()] == ["B"], \
        "a failed undo hid the removal, so it can never be undone"


def test_a_service_undo_is_recorded(reg):
    reg.set("HKLM", SVC + r"\evil", "Start", 2, reg.REG_DWORD)
    entry = P.PersistEntry(kind="service", location="HKLM\\" + SVC + r"\evil",
                           name="evil", command="x")
    assert P.remove_entry(entry).ok
    assert reg.get("HKLM", SVC + r"\evil", "Start")[0] == 4
    assert P.undo_removal(P.removals()[-1]).ok
    assert reg.get("HKLM", SVC + r"\evil", "Start")[0] == 2
    assert P.removals() == []


def _fake_schtasks(returncodes):
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        if "/query" in args:
            return SimpleNamespace(returncode=0, stdout="<Task></Task>", stderr="")
        return SimpleNamespace(returncode=returncodes.get(args[1], 0),
                               stdout="", stderr="refused")
    return run, calls


def test_a_task_undo_is_recorded_and_a_failed_one_is_not(reg, monkeypatch):
    codes = {}
    run, calls = _fake_schtasks(codes)
    monkeypatch.setattr(subprocess, "run", run)
    for name in ("Old", "New"):
        entry = P.PersistEntry(kind="scheduled-task", location="\\" + name,
                               name=name, command="x")
        assert P.remove_entry(entry).ok

    codes["/create"] = 1
    assert not P.undo_removal(P.removals()[-1]).ok
    assert [r["task"] for r in P.removals()] == ["\\Old", "\\New"]

    codes["/create"] = 0
    assert P.undo_removal(P.removals()[-1]).ok
    assert [r["task"] for r in P.removals()] == ["\\Old"]
    assert P.undo_removal(P.removals()[-1]).ok
    assert P.removals() == []
    assert not any("/delete" in c for c in calls[-2:])


def test_undoing_an_older_record_leaves_the_newer_one(reg):
    reg.set("HKCU", RUN, "A", r"C:\a.exe")
    reg.set("HKCU", RUN, "B", r"C:\b.exe")
    assert P.remove_entry(_run_entry("A")).ok
    assert P.remove_entry(_run_entry("B")).ok
    older = P.removals()[0]
    assert P.undo_removal(older).ok
    assert [r["name"] for r in P.removals()] == ["B"]
