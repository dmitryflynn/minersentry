r"""The actions journal is user-writable; an elevated undo must not trust it.

Anything running as the user can append to `actions.jsonl`. Replayed by an
unelevated MinerSentry that is harmless: the record can do nothing its writer
could not. Replayed by an ELEVATED one it was a UAC bypass. A forged
`remove_task` record with a SYSTEM principal in its XML became a SYSTEM task
the moment an administrator ran `--autostart-undo`, which takes the newest
record without showing it. Records an elevated session writes are now signed
with a key only administrators can read, and an elevated session replays
nothing else.

The quarantine folder is user-writable too, so a held binary can be swapped
before an elevated restore puts it back into System32. Its hash is checked.
"""

import json
import os

import pytest

from minersentry import persistence as P
from minersentry import quarantine as Q


@pytest.fixture
def journal(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    return tmp_path


def _elevated(monkeypatch, yes=True):
    monkeypatch.setattr(Q, "is_elevated", lambda: yes)


def _append_raw(record):
    os.makedirs(os.path.dirname(Q.journal_path()), exist_ok=True)
    with open(Q.journal_path(), "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


FORGED_TASK = {"ts": "2099-01-01T00:00:00+0000", "action": "remove_task",
               "task": "\\Updater", "kind": "scheduled-task",
               "xml": "<Task><Principals><Principal><UserId>S-1-5-18</UserId>"
                      "</Principal></Principals></Task>"}


# == signing ================================================================
def test_an_elevated_session_signs_what_it_writes(journal, monkeypatch):
    _elevated(monkeypatch)
    Q.record_action("disable_service", service="X", previous_start=2)
    rec = Q.history()[-1]
    assert "sig" in rec and Q.is_trusted(rec)


def test_an_unelevated_session_signs_nothing(journal, monkeypatch):
    _elevated(monkeypatch, False)
    Q.record_action("disable_service", service="X", previous_start=2)
    assert "sig" not in Q.history()[-1]


def test_a_changed_field_breaks_the_signature(journal, monkeypatch):
    _elevated(monkeypatch)
    Q.record_action("remove_task", task="\\T", xml="<Task/>")
    rec = Q.history()[-1]
    rec["xml"] = "<Task>evil</Task>"
    assert not Q.is_trusted(rec)


def test_a_signature_copied_from_another_record_does_not_verify(journal, monkeypatch):
    _elevated(monkeypatch)
    Q.record_action("disable_service", service="X", previous_start=2)
    good = Q.history()[-1]
    forged = dict(FORGED_TASK, sig=good["sig"])
    assert not Q.is_trusted(forged)


# == replay policy ==========================================================
def test_an_elevated_undo_refuses_a_forged_task_record(journal, monkeypatch):
    _elevated(monkeypatch)
    ran = []
    monkeypatch.setattr(P.subprocess, "run", lambda *a, **k: ran.append(a))
    _append_raw(FORGED_TASK)
    newest = P.removals()[-1]
    r = P.undo_removal(newest)
    assert not r.ok and "Administrator" in r.message
    assert ran == [], "schtasks must never have been called"


def test_an_unelevated_undo_still_replays_an_unsigned_record(journal, monkeypatch):
    """It can do nothing the record's writer could not, so it is allowed;
    otherwise every pre-existing journal would become undoable."""
    _elevated(monkeypatch, False)
    assert Q.replay_refusal(FORGED_TASK) == ""


def test_an_elevated_undo_replays_its_own_signed_record(journal, monkeypatch):
    _elevated(monkeypatch)
    Q.record_action("disable_service", service="X", previous_start=2,
                    kind="service")
    rec = Q.history()[-1]
    assert Q.replay_refusal(rec) == ""


# == quarantine =============================================================
def _quarantine(journal, name="svc.exe", data=b"original bytes"):
    f = journal / "work" / name
    f.parent.mkdir(exist_ok=True)
    f.write_bytes(data)
    assert Q.quarantine_file(str(f)).ok
    return f, Q.quarantined()[-1]["stored"]


def test_a_quarantined_file_swapped_while_held_is_not_restored(journal, monkeypatch):
    original, stored = _quarantine(journal)
    with open(stored, "wb") as f:
        f.write(b"planted payload")
    r = Q.restore_file(stored)
    assert not r.ok and "changed" in r.message
    assert not original.exists()


def test_an_unchanged_file_is_restored(journal):
    original, stored = _quarantine(journal)
    assert Q.restore_file(stored).ok
    assert original.read_bytes() == b"original bytes"


def test_a_file_outside_the_quarantine_folder_is_never_moved(journal, monkeypatch):
    """A forged record naming any file on disk as `stored` used to move it to
    any `original` the record chose."""
    _elevated(monkeypatch, False)
    victim = journal / "elsewhere" / "data.txt"
    victim.parent.mkdir()
    victim.write_text("mine")
    _append_raw({"ts": "t", "action": "quarantine_file", "stored": str(victim),
                 "original": str(journal / "moved.txt")})
    r = Q.restore_file(str(victim))
    assert not r.ok and victim.exists()


def test_an_elevated_restore_refuses_an_unsigned_record(journal, monkeypatch):
    _elevated(monkeypatch, False)
    original, stored = _quarantine(journal)        # written unsigned
    _elevated(monkeypatch)
    r = Q.restore_file(stored)
    assert not r.ok and "Administrator" in r.message
    assert os.path.isfile(stored)


def test_two_files_of_the_same_name_in_one_second_both_survive(journal, monkeypatch):
    monkeypatch.setattr(Q.time, "strftime", lambda fmt, *a: "20990101-000000"
                        if "%Y%m%d" in fmt else "2099-01-01T00:00:00+0000")
    a = journal / "a" / "svc.exe"
    b = journal / "b" / "svc.exe"
    for f, data in ((a, b"first"), (b, b"second")):
        f.parent.mkdir()
        f.write_bytes(data)
        assert Q.quarantine_file(str(f)).ok
    held = Q.quarantined()
    assert len(held) == 2 and held[0]["stored"] != held[1]["stored"]
    assert sorted(open(h["stored"], "rb").read() for h in held) == [b"first", b"second"]


# == the key itself =========================================================
@pytest.fixture
def real_key(tmp_path, monkeypatch):
    """The real _journal_key, with its file in a temporary folder."""
    monkeypatch.undo()
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setattr(Q, "_key_cache", None)
    path = tmp_path / "pf" / "MinerSentry" / "journal.key"
    monkeypatch.setattr(Q, "journal_key_path", lambda: str(path))
    monkeypatch.setattr(Q, "_lock_down", lambda p: True)
    monkeypatch.setattr(Q, "_posix_key_is_private", lambda p: True)
    return path


def test_the_key_is_created_once_and_reused(real_key, monkeypatch):
    _elevated(monkeypatch)
    k1 = Q._journal_key(create=True)
    assert k1 and len(k1) == 32 and real_key.read_bytes() == k1
    monkeypatch.setattr(Q, "_key_cache", None)
    assert Q._journal_key() == k1


def test_an_unelevated_process_never_gets_the_key(real_key, monkeypatch):
    _elevated(monkeypatch)
    Q._journal_key(create=True)
    monkeypatch.setattr(Q, "_key_cache", None)
    _elevated(monkeypatch, False)
    assert Q._journal_key() is None


def test_no_key_is_left_behind_when_it_cannot_be_locked(real_key, monkeypatch):
    _elevated(monkeypatch)
    monkeypatch.setattr(Q, "_lock_down", lambda p: False)
    assert Q._journal_key(create=True) is None
    assert not real_key.exists(), "an unlocked key file would be readable by users"


def test_the_key_lives_under_program_files_from_hklm(monkeypatch):
    if not Q.IS_WINDOWS:
        pytest.skip("Windows location")
    monkeypatch.setenv("ProgramFiles", r"C:\Users\Public\fake")
    assert "Public" not in Q.journal_key_path()
