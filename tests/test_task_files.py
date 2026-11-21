r"""Task definitions read from disk (issues #71 and #55).

The scheduler writes System32\Tasks files as UTF-16 LE with a BOM. They were
read as UTF-8, so every real file failed the "starts with <" check and the
hidden-task scan never reported anything. The fixtures elsewhere are UTF-8,
which is why nothing noticed.

And a task removal deleted the task even when no copy of it could be saved,
then promised an undo that could only fail.
"""

from types import SimpleNamespace

import pytest

from minersentry import persistence as P

TASK_XML = (
    '<?xml version="1.0" encoding="UTF-16"?>\r\n'
    '<Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">\r\n'
    '  <Actions Context="Author"><Exec><Command>C:\\Temp\\x.exe</Command>'
    '<Arguments>-o stratum+tcp://p:3333</Arguments></Exec></Actions>\r\n'
    '</Task>\r\n')


@pytest.mark.parametrize("encoding,bom", [
    ("utf-16-le", b"\xff\xfe"),      # what the scheduler writes
    ("utf-16-be", b"\xfe\xff"),
    ("utf-8", b"\xef\xbb\xbf"),
    ("utf-8", b""),
    ("utf-16-le", b""),
])
def test_task_files_are_decoded_by_their_bom(encoding, bom):
    text = P.decode_task_xml(bom + TASK_XML.encode(encoding))
    assert text.startswith("<?xml")
    assert P.parse_task_xml(text, "x", False, "\\x")


def test_a_hidden_utf16_task_file_is_reported(tmp_path):
    (tmp_path / "Evil").mkdir()
    (tmp_path / "Evil" / "Updater").write_bytes(
        b"\xff\xfe" + TASK_XML.encode("utf-16-le"))

    found = P._collect_task_files(set(), root=str(tmp_path))

    assert [(e.kind, e.location) for e in found] == [("hidden-task", "\\Evil\\Updater")]


# -- removal must not be irreversible -------------------------------------
def scheduler(monkeypatch, query_ok: bool):
    calls = []

    def fake_run(args, **kw):
        calls.append(args)
        if "/query" in args and not query_ok:
            return SimpleNamespace(returncode=1, stdout="",
                                   stderr="ERROR: The system cannot find the file specified.")
        return SimpleNamespace(returncode=0, stdout=TASK_XML if "/query" in args
                               else "SUCCESS", stderr="")
    monkeypatch.setattr(P.subprocess, "run", fake_run)
    return calls


@pytest.fixture
def journal(monkeypatch, tmp_path):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "appdata"))


def test_a_task_that_cannot_be_saved_is_not_deleted(monkeypatch, journal, tmp_path):
    calls = scheduler(monkeypatch, query_ok=False)
    entry = P.PersistEntry(kind="hidden-task", location="\\Evil\\Updater",
                           name="Updater", command="x",
                           file=str(tmp_path / "missing"))

    result = P.remove_entry(entry)

    assert not result.ok
    assert not [c for c in calls if "/delete" in c], "deleted with no copy kept"
    assert P.removals() == []


def test_a_hidden_task_is_saved_from_its_file_before_deletion(monkeypatch, journal, tmp_path):
    calls = scheduler(monkeypatch, query_ok=False)
    task_file = tmp_path / "Updater"
    task_file.write_bytes(b"\xff\xfe" + TASK_XML.encode("utf-16-le"))
    entry = P.PersistEntry(kind="hidden-task", location="\\Evil\\Updater",
                           name="Updater", command="x", file=str(task_file))

    result = P.remove_entry(entry)

    assert result.ok, result.message
    assert [c for c in calls if "/delete" in c]
    record = P.removals()[-1]
    assert "stratum+tcp://p:3333" in record["xml"]
