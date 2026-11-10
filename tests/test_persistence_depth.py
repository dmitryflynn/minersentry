"""Hidden persistence and remediation.

"It won't find the hidden scheduled task reviving the file on reboot, and it
won't fix your registry keys" was a fair criticism. These pin both halves: the
locations a miner uses *because* the obvious lists do not show them, and the
removal of what is found — reversibly.
"""

import sys

import pytest

from minersentry import persistence as P
from minersentry import quarantine
from minersentry.config import Config

CFG = Config()
POOL_ARGS = "-o pool.supportxmr.com:3333 -u 4" + "9" * 94
TASK_XML = (
    '<?xml version="1.0"?>\n'
    '<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">\n'
    ' <Settings><Enabled>true</Enabled></Settings>\n'
    ' <Actions><Exec><Command>C:\\Temp\\sysworker.exe</Command>\n'
    f' <Arguments>{POOL_ARGS}</Arguments></Exec></Actions></Task>')


def scored(entry):
    return P.score_entry(entry, CFG, is_trusted=lambda *a: False, isfile=lambda p: True)


# -- a task hidden from the scheduler listing ------------------------------
def test_task_read_from_disk_is_marked_hidden_when_the_listing_omits_it():
    hidden = P.parse_task_xml(TASK_XML, r"C:\Windows\System32\Tasks\Evil", visible=False)
    listed = P.parse_task_xml(TASK_XML, r"C:\Windows\System32\Tasks\Known", visible=True)
    assert [e.kind for e in hidden] == ["hidden-task"]
    assert [e.kind for e in listed] == ["scheduled-task"]
    assert hidden[0].exe == r"C:\Temp\sysworker.exe"
    # with a pool URL in the arguments both saturate, so both get reported
    assert scored(hidden[0]).score >= CFG.persistence_min_score
    assert scored(listed[0]).score >= CFG.persistence_min_score
    # being hidden is evidence in itself: with an unremarkable command, only
    # the hidden one carries weight
    plain = r"C:\Windows\System32\cmd.exe /c echo hi"
    bare_hidden = scored(P.PersistEntry(kind="hidden-task", location="x",
                                        name="t", command=plain))
    bare_listed = scored(P.PersistEntry(kind="scheduled-task", location="x",
                                        name="t", command=plain))
    assert bare_hidden.score - bare_listed.score == P.W_RARE_LOCATION


def test_disabled_tasks_and_junk_are_ignored():
    assert P.parse_task_xml(TASK_XML.replace("true", "false"), "x", True) == []
    assert P.parse_task_xml("not xml at all", "x", True) == []
    assert P.parse_task_xml("<Task></Task>", "x", True) == []


# -- the payload hidden behind svchost -------------------------------------
def test_service_dll_payload_is_scored_not_the_svchost_host():
    """A svchost-hosted service runs `svchost.exe -k netsvcs`; the code that
    runs is the DLL. 232 services on the development machine were being checked
    by the wrong file."""
    evil = P.PersistEntry(kind="service-dll", location="HKLM...", name="EvilSvc",
                          command=r"C:\Users\x\AppData\Local\Temp\payload.dll",
                          exe=r"C:\Users\x\AppData\Local\Temp\payload.dll")
    assert scored(evil).score >= CFG.persistence_min_score
    good = P.PersistEntry(kind="service-dll", location="HKLM...", name="Dhcp",
                          command=r"C:\Windows\System32\dhcpcsvc.dll",
                          exe=r"C:\Windows\System32\dhcpcsvc.dll")
    assert P.score_entry(good, CFG, is_trusted=lambda *a: True,
                         isfile=lambda p: True).score == 0


# -- fileless and hijack persistence ---------------------------------------
def test_wmi_consumer_parser_and_score():
    entries = P.parse_wmi_consumers(
        f"Updater\tC:\\Temp\\x.exe {POOL_ARGS}\nBlank\t\n")
    assert [e.kind for e in entries] == ["wmi-consumer"]
    assert scored(entries[0]).score >= CFG.persistence_min_score
    assert P.parse_wmi_consumers("no tabs here") == []


@pytest.mark.parametrize("kind", sorted(P.RARE_KINDS))
def test_rare_locations_carry_their_own_weight(kind):
    """IFEO debuggers, AppInit_DLLs, Winlogon, WMI, COM hijacks and hidden
    tasks are rare in normal use, so the location itself is evidence."""
    rare = scored(P.PersistEntry(kind=kind, location="somewhere", name="x",
                                 command=r"C:\Windows\System32\cmd.exe"))
    ordinary = scored(P.PersistEntry(kind="run-key", location="somewhere", name="x",
                                     command=r"C:\Windows\System32\cmd.exe"))
    assert rare.score - ordinary.score == P.W_RARE_LOCATION
    assert any(lab for lab in rare.labels)


def test_winlogon_defaults_are_not_reported(monkeypatch):
    # Userinit/Shell have known-good values; only a deviation is interesting
    import minersentry.persistence as mod
    if sys.platform != "win32":
        pytest.skip("registry hijack scan is Windows-only")
    entries = mod._collect_hijacks()
    assert all("userinit.exe" not in (e.command or "").lower() or e.kind != "winlogon"
               for e in entries)


# -- removal, and putting it back ------------------------------------------
def test_removal_refuses_what_it_should_not_touch():
    for kind in ("cron", "systemd-unit", "shell-profile"):
        r = P.remove_entry(P.PersistEntry(kind=kind, location="/etc/crontab",
                                          name="x", command="x"))
        assert not r.ok and "by hand" in r.message
    r = P.remove_entry(P.PersistEntry(kind="wmi-consumer", location="root/subscription",
                                      name="x", command="x"))
    assert not r.ok and "reported only" in r.message


@pytest.mark.skipif(sys.platform != "win32", reason="registry removal is Windows-only")
def test_registry_removal_round_trip(tmp_path, monkeypatch):
    import winreg
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    key_path = r"Software\MinerSentryTest"
    name = "Probe"
    command = r'"C:\Temp\x.exe" ' + POOL_ARGS
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path) as k:
        winreg.SetValueEx(k, name, 0, winreg.REG_SZ, command)
    entry = P.PersistEntry(kind="run-key", location=f"HKCU\\{key_path}",
                           name=name, command=command, exe=r"C:\Temp\x.exe")
    try:
        r = P.remove_entry(entry)
        assert r.ok, r.message
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as k:
            with pytest.raises(OSError):
                winreg.QueryValueEx(k, name)
        records = P.removals()
        assert records and records[-1]["action"] == "remove_registry_value"
        back = P.undo_removal(records[-1])
        assert back.ok, back.message
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as k:
            assert winreg.QueryValueEx(k, name)[0] == command   # byte-for-byte
    finally:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0,
                                winreg.KEY_SET_VALUE) as k:
                winreg.DeleteValue(k, name)
        except OSError:
            pass
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key_path)


def test_removal_of_a_missing_value_is_reported_not_crashed(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    if sys.platform != "win32":
        pytest.skip("registry removal is Windows-only")
    entry = P.PersistEntry(kind="run-key",
                           location=r"HKCU\Software\MinerSentryNotThere",
                           name="Nope", command="x")
    r = P.remove_entry(entry)
    assert not r.ok


def test_unrecognised_registry_location_is_rejected():
    r = P.remove_entry(P.PersistEntry(kind="run-key", location="nonsense",
                                      name="x", command="x"))
    assert not r.ok and "Unrecognised" in r.message


def test_undo_reports_an_unknown_record():
    assert not P.undo_removal({"action": "something else"}).ok
    assert not P.undo_removal({"action": "remove_task", "task": "x", "xml": ""}).ok


def test_removals_only_lists_removals(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    quarantine.record_action("suspend", pid=1, name="x")
    quarantine.record_action("remove_registry_value", hive="HKCU", path="p",
                             name="n", value="v", value_type=1, kind="run-key")
    actions = [r["action"] for r in P.removals()]
    assert actions == ["remove_registry_value"]
