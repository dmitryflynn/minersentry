r"""Removal paths executed for real, against real entries (issue #25).

Every other removal test in this suite monkeypatches `subprocess.run`,
`winreg` and `quarantine_file`, so it asserts that the right command is
*constructed*. That cannot catch a command that is well-formed and wrong —
which is the class both destructive bugs from the #22 review belonged to: a
startup `.lnk` whose removal quarantined the application it pointed at, and a
disk-found task whose removal passed only its leaf name to `schtasks /delete`
and could have deleted a different task.

So these tests plant a real entry, run the real removal, check the entry is
gone *from the authoritative source* rather than from a mock, run the real
undo, and check it came back unchanged.

They mutate the machine they run on, so they are **off by default** and only
run with MINERSENTRY_LIVE_REMOVAL=1 (bench/live_removal.py sets it). Every
fixture cleans up in a finally, so a failure mid-test does not leave a Run key
or a scheduled task behind.

What is deliberately NOT here, and will not be:

  netsh-helper, appcert-dll, lsa-package, print-monitor

Those are system-wide DLL load points. An AppCertDll is loaded into every
process that starts one, and an LSA package into lsass at boot. Planting one
on a working machine to watch it being removed is not a test, it is a way to
lose the machine. Their removal paths refuse by design and that refusal is
covered by ordinary unit tests.

Service and HKLM cases additionally need Administrator and are skipped without
it rather than half-run.
"""

import json
import os
import subprocess
import sys

import pytest

from minersentry import persistence as P
from minersentry import quarantine

LIVE = os.environ.get("MINERSENTRY_LIVE_REMOVAL") == "1"
pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(not LIVE, reason="set MINERSENTRY_LIVE_REMOVAL=1 to run"),
    pytest.mark.skipif(sys.platform != "win32", reason="Windows removal paths"),
]

MARK = "MinerSentryLiveTest"
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
TASK_NAME = "\\" + MARK
# A .cmd that does nothing. Named so that anyone who finds it knows what it is.
# Bytes, written and compared in binary: writing "\r\n" in TEXT mode makes
# Python translate it to "\r\r\n", which reads back as "\n\n". That is a
# difference in the test, not in the file, and the file is what this is about.
PAYLOAD = b"@echo off\r\nrem MinerSentry live removal test. Safe to delete.\r\n"


def _no_window():
    return {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0)}


def _last_journal(action):
    """The newest journal record for `action`, which is what undo consumes."""
    for rec in reversed(quarantine.history(200)):
        if rec.get("action") == action:
            return rec
    return None


@pytest.fixture
def payload(tmp_path):
    """A harmless file for entries to point at."""
    path = tmp_path / f"{MARK}.cmd"
    path.write_bytes(PAYLOAD)
    return str(path)


# == run-key: the one path that was already exercised ======================
def test_a_run_key_is_really_removed_and_really_restored(payload):
    import winreg as wr
    command = f'"{payload}" --quiet'
    with wr.OpenKey(wr.HKEY_CURRENT_USER, RUN_KEY, 0, wr.KEY_SET_VALUE) as key:
        wr.SetValueEx(key, MARK, 0, wr.REG_SZ, command)
    try:
        entry = P.PersistEntry(kind="run-key", location=f"HKCU\\{RUN_KEY}",
                               name=MARK, command=command, exe=payload)
        result = P.remove_entry(entry)
        assert result.ok, result.message

        # gone from the registry itself, not from a mock
        with wr.OpenKey(wr.HKEY_CURRENT_USER, RUN_KEY) as key:
            with pytest.raises(FileNotFoundError):
                wr.QueryValueEx(key, MARK)

        record = _last_journal("remove_registry_value")
        assert record and record["name"] == MARK
        assert P.undo_removal(record).ok

        with wr.OpenKey(wr.HKEY_CURRENT_USER, RUN_KEY) as key:
            value, value_type = wr.QueryValueEx(key, MARK)
        assert value == command, "restored with different content"
        assert value_type == wr.REG_SZ, "restored with a different value type"
    finally:
        try:
            with wr.OpenKey(wr.HKEY_CURRENT_USER, RUN_KEY, 0,
                            wr.KEY_SET_VALUE) as key:
                wr.DeleteValue(key, MARK)
        except OSError:
            pass


# == startup folder: a plain file ==========================================
def test_a_startup_file_is_really_moved_and_really_restored(tmp_path):
    folder = P._startup_folders()[0]
    item = os.path.join(folder, f"{MARK}.cmd")
    with open(item, "wb") as f:
        f.write(PAYLOAD)
    stored = None
    try:
        entry = P.PersistEntry(kind="startup-folder", location=folder,
                               name=os.path.basename(item), command=item,
                               exe=item, file=item)
        result = P.remove_entry(entry)
        assert result.ok, result.message
        assert not os.path.exists(item), "the file is still in the Startup folder"

        record = _last_journal("quarantine_file")
        assert record and record["original"] == item
        stored = record["stored"]
        assert os.path.isfile(stored), "nothing arrived in the quarantine folder"

        assert quarantine.restore_file(stored).ok
        assert os.path.isfile(item), "the file did not come back"
        with open(item, "rb") as f:
            assert f.read() == PAYLOAD, "came back with different content"
        stored = None
    finally:
        for path in (item, stored):
            if path and os.path.isfile(path):
                try:
                    os.unlink(path)
                except OSError:
                    pass


# == startup folder: a shortcut. This is destructive bug (A). ==============
def test_removing_a_startup_shortcut_leaves_its_target_alone(payload):
    r"""The bug: `_resolve_shortcuts` replaces an entry's `command` with the
    shortcut's TARGET, and removal passed that to quarantine_file — so
    quarantining a malicious `.lnk` moved the legitimate application it
    pointed at and left the shortcut in place. The unit test for the fix
    passes a hand-built entry; this one builds a real shortcut, lets the real
    scan resolve it, and checks the real filesystem afterwards."""
    folder = P._startup_folders()[0]
    link = os.path.join(folder, f"{MARK}.lnk")
    script = (
        "$s = (New-Object -ComObject WScript.Shell).CreateShortcut('%s'); "
        "$s.TargetPath = '%s'; $s.Save()" % (link, payload))
    made = subprocess.run(["powershell", "-NoProfile", "-Command", script],
                          capture_output=True, text=True, timeout=60,
                          **_no_window())
    if made.returncode != 0 or not os.path.isfile(link):
        pytest.skip(f"could not create a shortcut: {made.stderr.strip()[:120]}")

    stored = None
    try:
        entries = [P.PersistEntry(kind="startup-folder", location=folder,
                                  name=os.path.basename(link), command=link,
                                  exe=link, file=link)]
        P._resolve_shortcuts(entries)
        entry = entries[0]
        # the resolution is what made this dangerous; confirm it happened
        assert payload.lower() in entry.command.lower(), (
            "the shortcut did not resolve, so this test is not exercising the bug")
        assert entry.file == link

        result = P.remove_entry(entry)
        assert result.ok, result.message
        assert not os.path.exists(link), "the shortcut is still there"
        assert os.path.isfile(payload), (
            "THE TARGET APPLICATION WAS QUARANTINED — this is the destructive "
            "bug from the #22 review, back again")

        record = _last_journal("quarantine_file")
        assert record["original"] == link, (
            f"quarantined the wrong file: {record['original']}")
        stored = record["stored"]
        assert quarantine.restore_file(stored).ok
        assert os.path.isfile(link)
        stored = None
    finally:
        for path in (link, stored):
            if path and os.path.isfile(path):
                try:
                    os.unlink(path)
                except OSError:
                    pass


# == scheduled task. This is destructive bug (B). ==========================
def test_a_task_is_really_deleted_and_really_re_created(payload):
    r"""The bug: removal passed only the task's LEAF name to `schtasks
    /delete`, so a task at `\Microsoft\Windows\Foo\Bar` either failed or
    matched a different task named `Bar` at the root and deleted that one.

    The nested case cannot be tested without writing into the Microsoft task
    tree, so this covers the round trip at the root and the name derivation is
    unit-tested separately."""
    made = subprocess.run(
        ["schtasks", "/create", "/tn", MARK, "/tr", f'"{payload}"',
         "/sc", "once", "/st", "23:59", "/f"],
        capture_output=True, text=True, timeout=60, **_no_window())
    if made.returncode != 0:
        pytest.skip(f"could not create a task: {(made.stderr or made.stdout).strip()[:160]}")

    created = False
    try:
        listed = subprocess.run(["schtasks", "/query", "/tn", MARK],
                                capture_output=True, text=True, timeout=60,
                                **_no_window())
        assert listed.returncode == 0, "the task was not created, so nothing is tested"
        created = True

        entry = P.PersistEntry(kind="scheduled-task", location=TASK_NAME,
                               name=MARK, command=payload, exe=payload)
        result = P.remove_entry(entry)
        assert result.ok, result.message

        gone = subprocess.run(["schtasks", "/query", "/tn", MARK],
                              capture_output=True, text=True, timeout=60,
                              **_no_window())
        assert gone.returncode != 0, "the scheduler still lists the task"
        created = False

        record = _last_journal("remove_task")
        assert record, "no journal record, so there is nothing to undo from"
        assert record.get("xml", "").strip(), (
            "the task was deleted without its XML being captured first — the "
            "deletion is then irreversible")
        assert P.undo_removal(record).ok

        back = subprocess.run(["schtasks", "/query", "/tn", MARK],
                              capture_output=True, text=True, timeout=60,
                              **_no_window())
        assert back.returncode == 0, "the task did not come back"
        created = True
    finally:
        if created:
            subprocess.run(["schtasks", "/delete", "/tn", MARK, "/f"],
                           capture_output=True, text=True, timeout=60,
                           **_no_window())


# == the journal every undo depends on =====================================
def test_the_journal_is_append_only_and_parses_as_jsonl():
    """Each undo reads this file. A single malformed line that breaks the
    parse would make every earlier removal unrecoverable."""
    path = quarantine.journal_path()
    assert os.path.isfile(path), "no journal was written by the tests above"
    with open(path, encoding="utf-8") as f:
        lines = [ln for ln in f if ln.strip()]
    assert lines
    for i, line in enumerate(lines, 1):
        try:
            record = json.loads(line)
        except ValueError as e:
            pytest.fail(f"journal line {i} does not parse: {e}")
        assert "action" in record, f"journal line {i} has no action"


# == admin-gated: the service path =========================================
@pytest.mark.skipif(not quarantine.is_elevated(),
                    reason="creating a service needs Administrator")
def test_a_service_is_disabled_not_deleted_and_is_re_enabled(payload):
    r"""`_disable_service` sets Start=4 rather than deleting the service,
    because deleting one that something else depends on breaks more than it
    fixes. That distinction has never been executed."""
    import winreg as wr
    made = subprocess.run(["sc", "create", MARK, "binPath=", payload,
                           "start=", "demand"],
                          capture_output=True, text=True, timeout=60,
                          **_no_window())
    if made.returncode != 0:
        pytest.skip(f"could not create a service: {made.stdout.strip()[:160]}")
    key_path = rf"SYSTEM\CurrentControlSet\Services\{MARK}"
    try:
        entry = P.PersistEntry(kind="service", name=MARK,
                               location=r"HKLM\SYSTEM\CurrentControlSet\Services",
                               command=payload, exe=payload)
        result = P.remove_entry(entry)
        assert result.ok, result.message

        with wr.OpenKey(wr.HKEY_LOCAL_MACHINE, key_path) as key:
            start, _ = wr.QueryValueEx(key, "Start")
        assert start == 4, f"Start is {start}, so the service was not disabled"
        # it must still EXIST: disabled, not deleted
        assert subprocess.run(["sc", "query", MARK], capture_output=True,
                              text=True, timeout=60, **_no_window()
                              ).returncode == 0, "the service was deleted"

        record = _last_journal("disable_service")
        assert record and record["service"] == MARK
        assert P.undo_removal(record).ok
        with wr.OpenKey(wr.HKEY_LOCAL_MACHINE, key_path) as key:
            start, _ = wr.QueryValueEx(key, "Start")
        assert start == record["previous_start"], "Start was not restored"
    finally:
        subprocess.run(["sc", "delete", MARK], capture_output=True, text=True,
                       timeout=60, **_no_window())
