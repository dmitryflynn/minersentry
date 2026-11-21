r"""Winlogon Userinit and Shell (issue #48).

Both values are lists Winlogon runs in order, and both hold the stock program
alongside anything added to them. Two consequences are pinned here: a payload
placed before the default must still be reported, and removing an entry must
put the default back rather than delete the value, which would leave the
machine with no Userinit at all.

Run against an in-memory winreg, so nothing on the machine is touched.
"""

import sys

import pytest

from fakereg import FakeWinreg
from minersentry import persistence as P

WL = r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
ROOT = r"C:\Windows"
STOCK_USERINIT = r"C:\WINDOWS\system32\userinit.exe,"     # as read on Windows 11


@pytest.fixture
def reg(monkeypatch, tmp_path):
    fake = FakeWinreg()
    monkeypatch.setitem(sys.modules, "winreg", fake)
    monkeypatch.setattr(P, "IS_WINDOWS", True)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setenv("SystemRoot", ROOT)
    fake.set("HKLM", WL, "Userinit", STOCK_USERINIT)
    fake.set("HKLM", WL, "Shell", "explorer.exe")
    return fake


def winlogon(reg):
    return {e.name: e for e in P._collect_hijacks() if e.kind == "winlogon"}


def test_the_stock_values_are_not_reported(reg):
    assert winlogon(reg) == {}


@pytest.mark.parametrize("name,value", [
    ("Userinit", r"C:\Users\Public\x.exe,C:\Windows\system32\userinit.exe,"),
    ("Userinit", r"C:\Windows\system32\userinit.exe,C:\Users\Public\x.exe"),
    ("Userinit", r"C:\Users\Public\userinit.exe,"),
    ("Shell", r"C:\Users\Public\x.exe explorer.exe"),
    ("Shell", r"C:\Users\Public\x.exe,explorer.exe"),
])
def test_a_payload_anywhere_in_the_list_is_reported(reg, name, value):
    reg.set("HKLM", WL, name, value)
    assert name in winlogon(reg), f"{value!r} was taken for the default"


@pytest.mark.parametrize("name,value", [
    ("Userinit", r"C:\Windows\system32\userinit.exe"),
    ("Userinit", r"%SystemRoot%\system32\userinit.exe,"),
    ("Userinit", "userinit.exe"),
    ("Shell", "Explorer.exe"),
    ("Shell", r"C:\Windows\explorer.exe"),
])
def test_spellings_of_the_default_are_not_reported(name, value):
    assert P.is_winlogon_default(name, value, system_root=ROOT)


def test_removal_resets_userinit_to_its_default_and_undo_puts_it_back(reg):
    tampered = r"C:\Windows\system32\userinit.exe,C:\Users\Public\x.exe"
    reg.set("HKLM", WL, "Userinit", tampered)
    entry = winlogon(reg)["Userinit"]

    result = P.remove_entry(entry)

    assert result.ok, result.message
    assert reg.get("HKLM", WL, "Userinit") == (ROOT + r"\System32\userinit.exe,", 1), \
        "Userinit was deleted rather than reset"
    record = P.removals()[-1]
    assert record["value"] == tampered
    assert P.undo_removal(record).ok
    assert reg.get("HKLM", WL, "Userinit") == (tampered, 1)


def test_removal_resets_shell_to_explorer(reg):
    reg.set("HKLM", WL, "Shell", r"C:\Users\Public\x.exe explorer.exe")
    assert P.remove_entry(winlogon(reg)["Shell"]).ok
    assert reg.get("HKLM", WL, "Shell") == ("explorer.exe", 1)
