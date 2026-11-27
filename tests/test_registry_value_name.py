r"""Which registry value a removal deletes (issue #45).

The value name used to be taken from the entry's display name by splitting on
" -> ", a separator the collector adds for IFEO and Active Setup entries. A
Run value is named by whoever wrote it, so a value called `evil -> OneDrive`
was removed by deleting the `OneDrive` value next to it.

These run against an in-memory winreg, so nothing on the machine is touched
and they run on Linux too.
"""

import sys

import pytest

from fakereg import FakeWinreg
from minersentry import persistence as P

RUN = r"Software\Microsoft\Windows\CurrentVersion\Run"


@pytest.fixture
def reg(monkeypatch, tmp_path):
    fake = FakeWinreg()
    monkeypatch.setitem(sys.modules, "winreg", fake)
    monkeypatch.setattr(P, "IS_WINDOWS", True)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    return fake


def test_a_run_value_named_with_an_arrow_removes_itself_not_its_neighbour(reg):
    legit = r'"C:\Program Files\OneDrive\OneDrive.exe" /background'
    reg.set("HKCU", RUN, "OneDrive", legit)
    reg.set("HKCU", RUN, "evil -> OneDrive", r"C:\Users\x\AppData\Local\Temp\x.exe")
    entry = P.PersistEntry(kind="run-key", location="HKCU\\" + RUN,
                           name="evil -> OneDrive", command="x")

    result = P.remove_entry(entry)

    assert result.ok, result.message
    assert reg.get("HKCU", RUN, "OneDrive") == (legit, 1), \
        "the legitimate value beside it was deleted"
    assert reg.get("HKCU", RUN, "evil -> OneDrive") is None
    assert P.removals()[-1]["name"] == "evil -> OneDrive"


def test_an_ifeo_entry_still_removes_its_debugger_value(reg):
    ifeo = (r"Software\Microsoft\Windows NT\CurrentVersion"
            r"\Image File Execution Options\sethc.exe")
    reg.set("HKLM", ifeo, "Debugger", r"C:\Windows\System32\cmd.exe")
    reg.set("HKLM", ifeo, "GlobalFlag", "0")
    entry = P.PersistEntry(kind="ifeo-debugger", location="HKLM\\" + ifeo,
                           name="sethc.exe -> Debugger", command="cmd.exe")

    assert P.remove_entry(entry).ok
    assert reg.get("HKLM", ifeo, "Debugger") is None
    assert reg.get("HKLM", ifeo, "GlobalFlag") is not None


@pytest.mark.parametrize("kind,name,expected", [
    ("run-key", "evil -> OneDrive", "evil -> OneDrive"),
    ("netsh-helper", "a -> b", "a -> b"),
    ("ifeo-debugger", "x -> y.exe -> Debugger", "Debugger"),
    ("active-setup", "{GUID} -> StubPath", "StubPath"),
])
def test_value_name(kind, name, expected):
    entry = P.PersistEntry(kind=kind, location="HKLM\\x", name=name, command="")
    assert P.registry_value_name(entry) == expected
