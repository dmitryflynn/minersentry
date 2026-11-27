r"""Scheduled tasks come from `schtasks /query /xml`, not the CSV (issue #49).

The CSV's "Task To Run" column is cut at about 253 characters and shows a
task with several actions as "Multiple actions", so a padded command line or
a second action added to an existing task was never scored. The fixture
follows the layout of the real dump captured on Windows 11: `<Tasks>`, then
per task a `<!-- \Folder\Name -->` comment and the task's own document.
"""

from types import SimpleNamespace

from minersentry import persistence as P
from minersentry.config import Config

NS = "http://schemas.microsoft.com/windows/2004/02/mit/task"
PAD = "--log-level=info " * 20                      # pushes the pool past 253 chars
POOL = "-o stratum+tcp://pool.example.net:3333 -u 4" + "9" * 94


def task(uri, *actions, enabled=True):
    execs = "".join(f"<Exec><Command>{c}</Command><Arguments>{a}</Arguments></Exec>"
                    for c, a in actions)
    return (f'\r\n\r\n<!-- {uri} -->\r\n<?xml version="1.0" encoding="UTF-16"?>\r\n'
            f'<Task version="1.3" xmlns="{NS}">\r\n'
            f'  <RegistrationInfo><URI>{uri}</URI></RegistrationInfo>\r\n'
            f'  <Settings><Enabled>{"true" if enabled else "false"}</Enabled></Settings>\r\n'
            f'  <Actions Context="Author">{execs}</Actions>\r\n</Task>\r\n')


DUMP = ("\r\n<Tasks>\r\n"
        + task(r"\Updater", (r"C:\Users\x\AppData\Roaming\u\worker.exe", PAD + POOL))
        + task(r"\Microsoft\Windows\Application Experience\MareBackup",
               (r"%windir%\system32\compattelrunner.exe", "-m:aeinv.dll"),
               (r"C:\Users\Public\svc.exe", POOL))
        + task(r"\Off", (r"C:\x.exe", ""), enabled=False)
        + "</Tasks>\r\n")


def test_every_action_is_read_in_full():
    entries = P.parse_schtasks_xml(DUMP)
    by_task = {}
    for e in entries:
        by_task.setdefault(e.location, []).append(e)

    assert set(by_task) == {r"\Updater",
                            r"\Microsoft\Windows\Application Experience\MareBackup"}
    updater = by_task[r"\Updater"][0]
    assert updater.command.endswith(POOL), "the command was truncated"
    assert updater.name == "Updater" and updater.kind == "scheduled-task"
    mare = by_task[r"\Microsoft\Windows\Application Experience\MareBackup"]
    assert [e.exe for e in mare] == [r"%windir%\system32\compattelrunner.exe",
                                     r"C:\Users\Public\svc.exe"]


def test_the_padded_pool_and_the_second_action_are_both_scored():
    cfg = Config()
    scored = [P.score_entry(e, cfg, is_trusted=lambda *a: False,
                            isfile=lambda p: False)
              for e in P.parse_schtasks_xml(DUMP)]
    flagged = {e.exe for e in scored if e.score >= cfg.persistence_min_score}
    assert r"C:\Users\x\AppData\Roaming\u\worker.exe" in flagged
    assert r"C:\Users\Public\svc.exe" in flagged


def test_the_collector_prefers_the_dump_and_falls_back_to_the_csv(monkeypatch):
    calls = []

    def fake_run(args, **kw):
        calls.append(args)
        if "/xml" in args:
            return SimpleNamespace(returncode=1, stdout="", stderr="")
        header = '"HostName","TaskName","Task To Run","Scheduled Task State"\r\n'
        return SimpleNamespace(returncode=0, stdout=header +
                               '"h","\\T","C:\\t.exe","Enabled"\r\n', stderr="")
    monkeypatch.setattr(P.subprocess, "run", fake_run)
    assert [e.location for e in P._collect_tasks()] == ["\\T"]
    assert "/xml" in calls[0]

    monkeypatch.setattr(P.subprocess, "run", lambda args, **kw: SimpleNamespace(
        returncode=0, stdout=DUMP, stderr=""))
    assert len(P._collect_tasks()) == 3


def test_text_that_is_not_a_dump_is_not_taken_for_an_empty_one():
    assert P.parse_schtasks_xml("ERROR: Access is denied.") is None
    assert P.parse_schtasks_xml("") is None
