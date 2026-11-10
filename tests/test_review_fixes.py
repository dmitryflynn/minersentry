"""Regressions from the bug review of the Tier 1 / Phase 4 implementation.

Two of these were destructive: removing a malicious shortcut would have moved
the application it pointed at, and removing a task found on disk could have
deleted a different task with the same leaf name.
"""

import sys
from types import SimpleNamespace

import pytest

from minersentry import gpu as gpu_mod
from minersentry import persistence as P
from minersentry import quarantine, service
from minersentry.config import Config
from minersentry.engine import Engine

CFG = Config()
TASKS_ROOT = r"C:\Windows\System32\Tasks"
TASK_XML = ('<?xml version="1.0"?>\n'
            '<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">\n'
            ' <Settings><Enabled>true</Enabled></Settings>\n'
            ' <Actions><Exec><Command>C:\\Temp\\x.exe</Command></Exec></Actions></Task>')


# == A: a shortcut's removal must touch the shortcut ========================
def test_removing_a_startup_shortcut_moves_the_lnk_not_its_target(monkeypatch):
    """_resolve_shortcuts replaces `command` with the TARGET. Quarantining that
    would move the legitimate application the shortcut points at."""
    moved = []
    monkeypatch.setattr(quarantine, "quarantine_file",
                        lambda path, kill_first=False: moved.append(path) or
                        quarantine.Result(True, "moved"))
    entry = P.PersistEntry(
        kind="startup-folder", location=r"C:\Users\x\...\Startup",
        name="Thing.lnk",
        command=r'"C:\Program Files\Vendor\app.exe" --quiet',   # the TARGET
        exe=r"C:\Program Files\Vendor\app.exe",
        file=r"C:\Users\x\...\Startup\Thing.lnk")               # the shortcut
    P.remove_entry(entry)
    assert moved == [entry.file]
    assert r"Program Files" not in moved[0]


def test_a_plain_startup_file_still_removes_itself(monkeypatch):
    moved = []
    monkeypatch.setattr(quarantine, "quarantine_file",
                        lambda path, kill_first=False: moved.append(path) or
                        quarantine.Result(True, "moved"))
    item = r"C:\Users\x\...\Startup\dropper.exe"
    P.remove_entry(P.PersistEntry(kind="startup-folder", location="f", name="d",
                                  command=item, exe=item, file=item))
    assert moved == [item]


# == B: a task found on disk must carry its scheduler name =================
def test_task_name_comes_from_the_path_not_the_file_name():
    assert P.task_name_from_path(TASKS_ROOT + r"\Evil", TASKS_ROOT) == r"\Evil"
    assert P.task_name_from_path(TASKS_ROOT + r"\Microsoft\Windows\Foo\Bar",
                                 TASKS_ROOT) == r"\Microsoft\Windows\Foo\Bar"
    # a path outside the root falls back to the leaf rather than inventing one
    assert P.task_name_from_path(r"D:\elsewhere\X", TASKS_ROOT) == r"\X"


def test_a_task_parsed_from_disk_is_identified_by_its_scheduler_name():
    name = r"\Microsoft\Windows\Foo\Bar"
    entries = P.parse_task_xml(TASK_XML, TASKS_ROOT + r"\Microsoft\Windows\Foo\Bar",
                               visible=False, task_name=name)
    assert entries[0].location == name            # what schtasks /tn needs
    assert entries[0].file.endswith("Bar")        # the XML on disk


@pytest.mark.skipif(sys.platform != "win32", reason="schtasks is Windows-only")
def test_task_removal_passes_the_full_name_to_the_scheduler(monkeypatch):
    calls = []

    def fake_run(args, **kw):
        calls.append(args)
        return SimpleNamespace(returncode=0, stdout="<Task/>", stderr="")
    monkeypatch.setattr(P.subprocess, "run", fake_run)
    monkeypatch.setattr(quarantine, "record_action", lambda *a, **k: None)
    name = r"\Microsoft\Windows\Foo\Bar"
    entry = P.PersistEntry(kind="hidden-task", location=name, name="Bar",
                           command="x", exe="x", file=TASKS_ROOT + r"\Microsoft\Windows\Foo\Bar")
    assert P.remove_entry(entry).ok
    deleted = [c for c in calls if "/delete" in c][0]
    assert deleted[deleted.index("/tn") + 1] == name    # not the bare "Bar"


def test_tasks_already_listed_are_not_reported_twice(monkeypatch, tmp_path):
    """The file walk exists to find tasks the scheduler did NOT list."""
    root = tmp_path / "Tasks"
    (root / "Microsoft").mkdir(parents=True)
    (root / "Known").write_text(TASK_XML, encoding="utf-8")
    (root / "Microsoft" / "Hidden").write_text(TASK_XML, encoding="utf-8")
    found = P._collect_task_files({"known"}, root=str(root))
    kinds = {e.kind for e in found}
    names = {e.name for e in found}
    assert "Known" not in names, "a listed task was reported a second time"
    assert kinds == {"hidden-task"}


# == C: own-tooling detection must not switch off with the cmdline signal ==
def test_our_own_tooling_is_recognised_even_with_cmdline_disabled():
    engine = Engine(cfg=Config(pool_intel_enabled=False, cmdline_enabled=False))
    ours = SimpleNamespace(
        pid=4321,
        cmdline=lambda: [sys.executable, str(P.os.path.join(
            P.os.path.dirname(P.os.path.dirname(P.os.path.abspath(P.__file__))),
            "bench", "run_bench.py"))])
    assert engine._read_cmdline(ours) == []          # no cmdline indicators
    assert 4321 in engine._own_tooling               # but still recognised as ours


# == D: do not pay for PDH when nvidia-smi answered ========================
def test_pdh_is_skipped_when_pmon_reports(monkeypatch):
    pdh_called = []
    monkeypatch.setattr(gpu_mod, "_run", lambda args, timeout:
                        "# gpu pid type sm mem\n# Idx # C/G % %\n 0 777 C 91 0\n")
    monkeypatch.setattr(gpu_mod, "_sample_pdh",
                        lambda ctx: pdh_called.append(ctx) or {})
    assert gpu_mod._sample_windows({777})[777] == 91.0
    assert pdh_called == [], "typeperf ran even though nvidia-smi answered"


def test_pdh_still_runs_when_pmon_is_silent(monkeypatch):
    monkeypatch.setattr(gpu_mod, "_run", lambda args, timeout: "")
    monkeypatch.setattr(gpu_mod, "_sample_pdh", lambda ctx: {888: 42.0})
    assert gpu_mod._sample_windows(set()) == {888: 42.0}


# == F: an entry that comes back must alert again ==========================
def test_a_recreated_autostart_entry_alerts_again(monkeypatch, tmp_path):
    """A miner that rewrites its Run key after you delete it is exactly what a
    watcher should keep saying."""
    from minersentry import engine as engine_module
    from minersentry.audit import AuditLog

    monkeypatch.setattr(engine_module.psutil, "process_iter", lambda *a, **k: iter([]))
    monkeypatch.setattr(engine_module.psutil, "net_connections", lambda **k: [])
    monkeypatch.setattr(engine_module.psutil, "cpu_percent", lambda *a: 5.0)
    entry = P.PersistEntry(kind="run-key", location="HKCU", name="Evil",
                           command="x", exe="x")
    entry.score, entry.labels = 100, ["pool"]
    states = iter([[entry], [], [entry]])            # present, gone, back again
    monkeypatch.setattr(service.persist_mod, "scan", lambda cfg: next(states, []))
    sent = []
    monkeypatch.setattr(service, "notify", lambda t, b, c=None: sent.append(t))
    cfg = Config(pool_intel_enabled=False, gpu_enabled=False, deep_auto_interval=0,
                 persistence_interval=0.01, tamper_check_interval=0)
    log = AuditLog(path=str(tmp_path / "d.jsonl"))
    for _ in range(3):
        service.run(cfg=cfg, once=True, audit=log, alert=True)
    assert len(sent) == 2, f"expected an alert for each appearance, got {sent}"


# == I: one row per trigger must not mean one finding per trigger ==========
def test_a_task_with_several_triggers_is_reported_once():
    """schtasks /query /v emits a row per TRIGGER. A task that runs at logon
    and on a schedule was reported two, three, five times."""
    header = ('"HostName","TaskName","Next Run Time","Status","Task To Run",'
              '"Scheduled Task State"\n')
    row = (r'"PC","\Microsoft\Windows\WER\QueueReporting","N/A","Ready",'
           r'"%windir%\system32\wermgr.exe -upload","Enabled"' + "\n")
    out = P.parse_schtasks_csv(header + row * 5)
    assert len(out) == 1
    # a genuinely different command under the same name is still its own entry
    other = row.replace("-upload", "-queuereporting")
    assert len(P.parse_schtasks_csv(header + row + other)) == 2


# == J: an idle GPU is an answer, not a failure ============================
def test_an_idle_pmon_table_counts_as_an_answer(monkeypatch):
    """A valid header with no compute rows means "nothing is computing". It
    was being treated as a failure, sending every sample on to typeperf."""
    idle = "# gpu        pid  type    sm   mem\n# Idx          #   C/G     %     %\n"
    assert gpu_mod.pmon_is_usable(idle)
    assert not gpu_mod.pmon_is_usable("")
    assert not gpu_mod.pmon_is_usable("nvidia-smi: command not found")

    pdh_called = []
    monkeypatch.setattr(gpu_mod, "_run", lambda args, timeout: idle)
    monkeypatch.setattr(gpu_mod, "_sample_pdh",
                        lambda ctx: pdh_called.append(ctx) or {})
    assert gpu_mod._sample_windows(set()) == {}
    assert pdh_called == [], "typeperf ran for an idle GPU that had already answered"
