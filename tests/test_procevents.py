r"""Processes shorter than one scan interval (issue #15).

Measured on the development machine, not elevated, twelve cmd.exe per row:

    lifetime   spawned        caught   with a command line
    ~10 ms     one at a time    1/12            0
    ~10 ms     all at once      0/12            0
    1 s        one at a time   11/12            9
    1 s        all at once     12/12           12
    3 s        either          12/12           12

So the millisecond dropper case is NOT covered -- the subscription is WMI
polling Win32_Process, and a process that never exists at a poll instant is
never in a snapshot. What is covered, with the command line intact, is the
band between about a second and the engine's 2.5s pass. The tests below pin
both halves of that, so neither gets quietly forgotten.
"""

import json
import os
import subprocess
import sys
import time

import pytest

from minersentry import procevents as PE
from minersentry.config import Config

CFG = Config()


def _line(**fields):
    return json.dumps(fields)


# == parsing the helper's output ==========================================
def test_an_event_line_becomes_an_event():
    event = PE.parse_event_line(_line(
        pid=4242, ppid=99, name="xmrig.exe",
        exe=r"C:\Users\x\AppData\Local\Temp\xmrig.exe",
        cmd=r'"C:\Users\x\AppData\Local\Temp\xmrig.exe" -o pool:3333'))
    assert isinstance(event, PE.ProcEvent)
    assert event.pid == 4242 and event.ppid == 99
    assert event.name == "xmrig.exe"
    assert "-o pool:3333" in event.cmdline
    assert event.ts > 0


def test_the_helpers_control_messages_come_back_as_dicts():
    """"The subscription failed" and "nothing has started yet" are very
    different answers, and the caller has to be able to tell them apart."""
    assert PE.parse_event_line(_line(ready=True)) == {"ready": True}
    assert PE.parse_event_line(_line(error="Access denied")) == {
        "error": "Access denied"}


@pytest.mark.parametrize("line", [
    "", "   ", "not json", "[]", "null", '"a string"',
    _line(pid=0, name="x"),            # no pid
    _line(pid=5),                      # no name
    _line(pid="not a number", name="x"),
])
def test_junk_lines_are_ignored_rather_than_raising(line):
    assert PE.parse_event_line(line) is None


def test_a_missing_command_line_is_not_fatal():
    """ExecutablePath and CommandLine are both empty for a process that
    exited before WMI filled them in."""
    event = PE.parse_event_line(_line(pid=7, name="x.exe", exe="", cmd=""))
    assert isinstance(event, PE.ProcEvent)
    assert event.cmdline == "" and event.exe == ""


# == scoring a process that is already gone ===============================
def test_a_miner_command_line_convicts_on_its_own():
    """There is no CPU history and nothing to memory-scan for a process that
    has exited, so the command line is nearly the whole basis for judging
    it -- which is why the event source that carries one was chosen."""
    event = PE.score_event(PE.ProcEvent(
        pid=1, name="svc.exe", exe=r"C:\Users\x\AppData\Local\Temp\svc.exe",
        cmdline=r'"C:\Users\x\AppData\Local\Temp\svc.exe" -o '
                r'stratum+tcp://pool.supportxmr.com:3333 --donate-level 0'),
        CFG)
    assert event.score >= CFG.persistence_min_score, event.labels
    assert event.labels


def test_an_ordinary_short_lived_process_scores_nothing():
    """Every build, installer and shell script spawns these constantly. A
    scanner that reports them all is a scanner nobody reads."""
    for name, exe, cmd in [
        ("conhost.exe", r"C:\Windows\System32\conhost.exe",
         r"\??\C:\Windows\system32\conhost.exe 0x4"),
        ("cmd.exe", r"C:\Windows\System32\cmd.exe", "cmd.exe /c exit"),
        ("git.exe", r"C:\Program Files\Git\cmd\git.exe", "git rev-parse HEAD"),
    ]:
        event = PE.score_event(PE.ProcEvent(pid=1, name=name, exe=exe,
                                            cmdline=cmd), CFG)
        assert event.score < CFG.persistence_min_score, (name, event.labels)


def test_the_scorer_is_the_one_used_for_autostart_entries():
    """Shared on purpose: pool URLs, wallet flags, miner names, drop
    locations and hidden launchers stay defined in one place."""
    event = PE.score_event(PE.ProcEvent(pid=1, name="x.exe", cmdline="x.exe"),
                           CFG)
    assert isinstance(event.labels, list)
    # the kind must not be in RARE_KINDS or every transient process would
    # collect a location weight it has not earned
    assert "transient-process" not in PE.persist_mod.RARE_KINDS


def test_summarize_keeps_only_what_clears_the_threshold():
    events = [
        PE.ProcEvent(pid=1, name="a.exe", score=80),
        PE.ProcEvent(pid=2, name="b.exe", score=10),
        PE.ProcEvent(pid=3, name="c.exe", score=55),
    ]
    out = PE.summarize(events, min_score=45)
    assert [row["pid"] for row in out] == [1, 3], "worst first, quiet dropped"
    assert set(out[0]) == {"pid", "ppid", "name", "exe", "cmdline", "score",
                           "labels"}


def test_a_very_long_command_line_is_truncated_for_reporting():
    out = PE.summarize([PE.ProcEvent(pid=1, name="a", score=50,
                                     cmdline="x" * 5000)], min_score=1)
    assert len(out[0]["cmdline"]) == 300


# == the watcher's contract ===============================================
def test_the_watcher_reports_itself_unavailable_off_windows(monkeypatch):
    monkeypatch.setattr(PE, "IS_WINDOWS", False)
    watcher = PE.Watcher(CFG)
    assert watcher.start() is False
    assert watcher.available is False
    assert watcher.mode == "unavailable"
    assert "root" in watcher.error, (
        "it should say why, not just that it cannot")


def test_a_refused_subscription_is_reported_not_silently_empty(monkeypatch):
    """Win32_ProcessStartTrace is access-denied without admin. A watcher that
    reported success and then no events would claim coverage it lacks."""
    monkeypatch.setattr(PE, "IS_WINDOWS", True)
    watcher = PE.Watcher(CFG)

    class FakeProc:
        stdout = iter([_line(error="Access denied") + "\n"])

        def terminate(self):
            pass

        def wait(self, timeout=None):
            pass

        def poll(self):
            return 0        # stop() confirms the exit before killing
    monkeypatch.setattr(PE.subprocess, "Popen", lambda *a, **k: FakeProc())
    assert watcher.start() is False
    assert watcher.mode == "unavailable"
    assert "Access denied" in watcher.error
    watcher.stop()


def test_a_ready_helper_makes_the_watcher_available(monkeypatch):
    monkeypatch.setattr(PE, "IS_WINDOWS", True)
    watcher = PE.Watcher(CFG)

    lines = [_line(ready=True) + "\n",
             _line(pid=4242, ppid=1, name="xmrig.exe", exe="", cmd="xmrig.exe") + "\n"]

    class FakeProc:
        stdout = iter(lines)

        def terminate(self):
            pass

        def wait(self, timeout=None):
            pass

        def poll(self):
            return 0        # stop() confirms the exit before killing
    monkeypatch.setattr(PE.subprocess, "Popen", lambda *a, **k: FakeProc())
    assert watcher.start() is True
    assert watcher.mode == "wmi-poll"

    deadline = time.time() + 5
    events = []
    while not events and time.time() < deadline:
        events = watcher.drain()
    assert [e.pid for e in events] == [4242]
    watcher.stop()


def test_a_helper_that_cannot_be_started_is_handled(monkeypatch):
    monkeypatch.setattr(PE, "IS_WINDOWS", True)

    def no_powershell(*a, **k):
        raise OSError("powershell is not on PATH")
    monkeypatch.setattr(PE.subprocess, "Popen", no_powershell)
    watcher = PE.Watcher(CFG)
    assert watcher.start() is False
    assert "could not start" in watcher.error


def test_our_own_pid_is_never_reported(monkeypatch):
    """Starting the helper starts processes. Reporting those would be the
    tool reacting to itself."""
    monkeypatch.setattr(PE, "IS_WINDOWS", True)
    watcher = PE.Watcher(CFG)
    watcher._q.put_nowait(PE.ProcEvent(pid=os.getpid(), name="python.exe"))
    watcher._q.put_nowait(PE.ProcEvent(pid=999999, name="other.exe"))
    assert [e.pid for e in watcher.drain()] == [999999]


def test_a_burst_is_bounded_and_the_loss_is_counted(monkeypatch):
    """A build or an installer can start thousands of processes. The queue
    must not grow without bound, and what was lost has to be visible rather
    than quietly discarded."""
    monkeypatch.setattr(PE, "IS_WINDOWS", True)
    watcher = PE.Watcher(CFG)
    watcher._q.maxsize = 4
    for pid in range(10):
        try:
            watcher._q.put_nowait(PE.ProcEvent(pid=pid + 1, name="x.exe"))
        except Exception:  # noqa: BLE001
            watcher._dropped += 1
    assert watcher._q.full()
    assert watcher.dropped > 0


def test_drain_is_empty_when_nothing_started(monkeypatch):
    monkeypatch.setattr(PE, "IS_WINDOWS", True)
    assert PE.Watcher(CFG).drain() == []


def test_stop_is_safe_before_start_and_twice():
    watcher = PE.Watcher(CFG)
    watcher.stop()
    watcher.stop()


# == the real thing =======================================================
@pytest.mark.skipif(sys.platform != "win32", reason="WMI events are Windows-only")
@pytest.mark.live
@pytest.mark.skipif(os.environ.get("MINERSENTRY_LIVE_PROCEVENTS") != "1",
                    reason="set MINERSENTRY_LIVE_PROCEVENTS=1 to run")
def test_a_second_long_process_is_caught_with_its_command_line():
    """The capability this feature actually delivers: the band between about
    a second and the engine's 2.5s pass, which the poll catches only by luck.

    Off by default: it starts a PowerShell helper and spawns processes.
    """
    watcher = PE.Watcher(CFG)
    if not watcher.start():
        pytest.skip(f"no event source here: {watcher.error}")
    try:
        time.sleep(2.0)
        watcher.drain()
        procs = [subprocess.Popen(
            ["cmd.exe", "/c", "ping -n 2 127.0.0.1 >nul"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            for _ in range(6)]
        for p in procs:
            p.wait(timeout=20)
        time.sleep(4.0)
        caught = [e for e in watcher.drain() if e.name.lower() == "cmd.exe"]
        assert len(caught) >= 4, (
            f"caught {len(caught)} of 6 one-second processes; measured 12/12")
        assert any(e.cmdline.strip() for e in caught), (
            "no command line came through, which is the whole reason this "
            "source was chosen over the elevated trace")
    finally:
        watcher.stop()


@pytest.mark.skipif(sys.platform != "win32", reason="WMI events are Windows-only")
@pytest.mark.live
@pytest.mark.skipif(os.environ.get("MINERSENTRY_LIVE_PROCEVENTS") != "1",
                    reason="set MINERSENTRY_LIVE_PROCEVENTS=1 to run")
def test_the_millisecond_case_is_still_missed():
    """Documents the limit as a test, so it cannot be quietly forgotten or
    quietly fixed without someone noticing.

    A dropper that launches and exits in milliseconds is not covered: 1 of 12
    and 0 of 12 were measured, with no command line on the one that landed.
    If this test ever starts failing because everything is caught, the
    mechanism has changed and the README claim needs revisiting.
    """
    watcher = PE.Watcher(CFG)
    if not watcher.start():
        pytest.skip(f"no event source here: {watcher.error}")
    try:
        time.sleep(2.0)
        watcher.drain()
        for _ in range(12):
            subprocess.run(["cmd.exe", "/c", "exit"], capture_output=True,
                           creationflags=getattr(subprocess,
                                                 "CREATE_NO_WINDOW", 0))
        time.sleep(4.0)
        caught = [e for e in watcher.drain() if e.name.lower() == "cmd.exe"]
        assert len(caught) <= 6, (
            f"caught {len(caught)} of 12 millisecond processes, far more than "
            f"the 0-1 measured. If this is real, the docstring's table and "
            f"the README are now understating what this does.")
    finally:
        watcher.stop()


# == the wiring: a watcher nobody starts is not a feature =================
def test_the_engine_does_not_start_a_helper_just_by_existing(monkeypatch):
    """An Engine is constructed by every test, the benchmark and each CLI run.
    Spawning a PowerShell helper in __init__ would start a subprocess nobody
    asked for, hundreds of times over a test run."""
    from minersentry.engine import Engine
    started = []
    monkeypatch.setattr(PE.Watcher, "start",
                        lambda self: started.append(1) or False)
    engine = Engine(cfg=Config(pool_intel_enabled=False, gpu_enabled=False))
    assert started == []
    assert engine.procevents_mode == "off"
    assert engine.transient == []


def test_starting_is_explicit_and_idempotent(monkeypatch):
    from minersentry.engine import Engine
    calls = []

    def fake_start(self):
        calls.append(1)
        self.mode = "wmi-poll"
        return True
    monkeypatch.setattr(PE.Watcher, "start", fake_start)
    engine = Engine(cfg=Config(pool_intel_enabled=False, gpu_enabled=False))
    assert engine.start_procevents() is True
    assert engine.start_procevents() is True
    assert calls == [1], "a second call must not start a second helper"
    assert engine.procevents_mode == "wmi-poll"
    engine.close()


def test_the_config_flag_switches_it_off(monkeypatch):
    from minersentry.engine import Engine
    started = []
    monkeypatch.setattr(PE.Watcher, "start", lambda self: started.append(1))
    engine = Engine(cfg=Config(pool_intel_enabled=False, gpu_enabled=False,
                               procevents_enabled=False))
    assert engine.start_procevents() is False
    assert started == []


def test_only_findings_over_the_threshold_are_kept(monkeypatch):
    from minersentry.engine import Engine
    cfg = Config(pool_intel_enabled=False, gpu_enabled=False,
                 procevents_min_score=45)
    engine = Engine(cfg=cfg)

    loud = PE.ProcEvent(pid=1, name="x.exe", score=80)
    quiet = PE.ProcEvent(pid=2, name="conhost.exe", score=5)

    class FakeWatcher:
        available = True
        mode = "wmi-poll"

        def drain(self):
            return [loud, quiet]

        def stop(self):
            pass
    engine._procevents = FakeWatcher()
    engine._collect_transient()
    assert [e.pid for e in engine.transient] == [1]


def test_the_transient_list_is_bounded(monkeypatch):
    """A build or installer can start thousands of processes. This is a report
    of the session, not a log, and must not grow without end."""
    from minersentry.engine import Engine
    engine = Engine(cfg=Config(pool_intel_enabled=False, gpu_enabled=False))

    class FakeWatcher:
        available = True
        mode = "wmi-poll"

        def drain(self):
            return [PE.ProcEvent(pid=i, name="x.exe", score=99)
                    for i in range(400)]

        def stop(self):
            pass
    engine._procevents = FakeWatcher()
    for _ in range(4):
        engine._collect_transient()
    assert len(engine.transient) <= 500


def test_a_transient_detection_reaches_the_audit_log(tmp_path):
    import json
    from minersentry.audit import AuditLog
    from minersentry.engine import Engine
    log = AuditLog(path=str(tmp_path / "d.jsonl"))
    engine = Engine(cfg=Config(pool_intel_enabled=False, gpu_enabled=False),
                    audit=log)

    class FakeWatcher:
        available = True
        mode = "wmi-poll"

        def drain(self):
            return [PE.ProcEvent(pid=7, name="x.exe", exe="C:/x.exe",
                                 cmdline="x.exe -o pool:3333", score=90,
                                 labels=["stratum URL in arguments"])]

        def stop(self):
            pass
    engine._procevents = FakeWatcher()
    engine._collect_transient()
    records = [json.loads(ln) for ln in
               open(tmp_path / "d.jsonl", encoding="utf-8") if ln.strip()]
    hit = [r for r in records if r.get("verdict") == "Transient"]
    assert hit and hit[0]["pid"] == 7
    assert hit[0]["score"] == 90


def test_closing_the_engine_stops_the_helper(monkeypatch):
    from minersentry.engine import Engine
    stopped = []

    def fake_start(self):
        self.mode = "wmi-poll"
        return True
    monkeypatch.setattr(PE.Watcher, "start", fake_start)
    monkeypatch.setattr(PE.Watcher, "stop", lambda self: stopped.append(1))
    engine = Engine(cfg=Config(pool_intel_enabled=False, gpu_enabled=False))
    engine.start_procevents()
    engine.close()
    assert stopped == [1]
    engine.close()          # safe twice
    assert stopped == [1]


def test_the_cli_summary_carries_the_transient_findings():
    from minersentry.cli import summarize
    from minersentry.engine import Engine
    cfg = Config(pool_intel_enabled=False, gpu_enabled=False)
    engine = Engine(cfg=cfg)
    engine.transient = [
        PE.ProcEvent(pid=7, ppid=4, name="x.exe", cmdline="x.exe -o pool:3333",
                     score=90, labels=["stratum URL in arguments"]),
        PE.ProcEvent(pid=8, name="conhost.exe", score=2),
    ]
    out = summarize(engine, [], first_hit={})
    assert [t["pid"] for t in out["transient"]] == [7], "the quiet one is dropped"
    assert out["transient"][0]["labels"]
    assert out["transient_watch"] == "off"


# == the leak that took the machine to "Quota violation" =================
def test_stop_kills_a_helper_that_ignores_terminate():
    """Each helper holds a WMI event subscription, and WMI has a per-user
    quota on those. Eleven leaked helpers from test runs exhausted it, after
    which nothing could subscribe at all. A terminate that is not confirmed
    is not good enough."""
    watcher = PE.Watcher(CFG)
    calls = []

    class StubbornProc:
        def terminate(self):
            calls.append("terminate")

        def wait(self, timeout=None):
            calls.append("wait")

        def poll(self):
            return None if "kill" not in calls else 0

        def kill(self):
            calls.append("kill")
    watcher._proc = StubbornProc()
    watcher.stop()
    assert calls == ["terminate", "wait", "kill", "wait"], calls


def test_stop_does_not_kill_a_helper_that_exited_cleanly():
    watcher = PE.Watcher(CFG)
    calls = []

    class TidyProc:
        def terminate(self):
            calls.append("terminate")

        def wait(self, timeout=None):
            calls.append("wait")

        def poll(self):
            return 0

        def kill(self):
            calls.append("kill")
    watcher._proc = TidyProc()
    watcher.stop()
    assert "kill" not in calls


def test_the_cli_stops_the_helper_on_every_path(monkeypatch):
    """The actual bug: the CLI started the watcher and never stopped it, so
    each run left a PowerShell process alive for the rest of the session."""
    from minersentry import cli as cli_mod
    closed = []

    class FakeEngine:
        cfg = Config(pool_intel_enabled=False, gpu_enabled=False)
        transient: list = []
        procevents_mode = "off"

        def close(self):
            closed.append(1)
    monkeypatch.setattr(cli_mod, "run_session",
                        lambda *a, **k: (FakeEngine(), [], {}))

    def boom(*a, **k):
        raise RuntimeError("reporting blew up")
    monkeypatch.setattr(cli_mod, "_report", boom)
    with pytest.raises(RuntimeError):
        cli_mod.main(["--duration", "1"])
    assert closed == [1], "the helper was left running when reporting failed"


def test_the_watcher_service_stops_the_helper(monkeypatch, tmp_path):
    from minersentry import engine as engine_module
    from minersentry import service
    from minersentry.audit import AuditLog

    monkeypatch.setattr(engine_module.psutil, "process_iter",
                        lambda *a, **k: iter([]))
    monkeypatch.setattr(engine_module.psutil, "net_connections", lambda **k: [])
    monkeypatch.setattr(engine_module.psutil, "cpu_percent", lambda *a: 5.0)
    monkeypatch.setattr(service.persist_mod, "scan", lambda cfg: [])
    closed = []
    monkeypatch.setattr(engine_module.Engine, "close",
                        lambda self: closed.append(1))
    service.run(cfg=Config(pool_intel_enabled=False, gpu_enabled=False,
                           deep_auto_interval=0, persistence_interval=0,
                           tamper_check_interval=0),
                once=True, audit=AuditLog(path=str(tmp_path / "d.jsonl")),
                alert=False)
    assert closed == [1]


@pytest.mark.skipif(sys.platform != "win32", reason="WMI events are Windows-only")
@pytest.mark.live
@pytest.mark.skipif(os.environ.get("MINERSENTRY_LIVE_PROCEVENTS") != "1",
                    reason="set MINERSENTRY_LIVE_PROCEVENTS=1 to run")
def test_starting_and_stopping_leaves_no_helper_behind():
    """The regression test for the leak, against real processes."""
    import psutil

    def helpers():
        found = []
        for p in psutil.process_iter(["name", "cmdline"]):
            try:
                if "powershell" not in (p.info["name"] or "").lower():
                    continue
                if "msProcEvents" in " ".join(p.info["cmdline"] or []):
                    found.append(p.pid)
            except psutil.Error:
                continue
        return set(found)

    before = helpers()
    watcher = PE.Watcher(CFG)
    if not watcher.start():
        pytest.skip(f"no event source here: {watcher.error}")
    assert helpers() - before, "no helper appeared, so nothing is being tested"
    watcher.stop()
    time.sleep(1.0)
    assert not (helpers() - before), "the helper outlived stop()"


@pytest.mark.skipif(sys.platform != "win32", reason="WMI events are Windows-only")
@pytest.mark.live
@pytest.mark.skipif(os.environ.get("MINERSENTRY_LIVE_PROCEVENTS") != "1",
                    reason="set MINERSENTRY_LIVE_PROCEVENTS=1 to run")
def test_the_helper_cleans_itself_up_when_its_parent_is_killed():
    """The leak that stop() alone could not fix.

    A force-quit, a crash or a TerminateProcess runs no `finally`, no
    `atexit` and no window handler, so the helper was orphaned and kept its
    WMI subscription. Enough orphans take the machine to "Quota violation",
    after which nothing can subscribe at all -- which is what happened here.
    The helper therefore watches its parent and exits on its own.
    """
    import psutil

    def helpers():
        found = set()
        for p in psutil.process_iter(["name", "cmdline"]):
            try:
                if "powershell" not in (p.info["name"] or "").lower():
                    continue
                if "msProcEvents" in " ".join(p.info["cmdline"] or []):
                    found.add(p.pid)
            except psutil.Error:
                continue
        return found

    before = helpers()
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    child = subprocess.Popen(
        [sys.executable, "-c",
         "import sys; sys.path.insert(0, r'%s');"
         "from minersentry import procevents as PE;"
         "from minersentry.config import Config;"
         "w = PE.Watcher(Config());"
         "print(w.start(), flush=True);"
         "import time; time.sleep(600)" % root],
        stdout=subprocess.PIPE, text=True,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    try:
        started = (child.stdout.readline() or "").strip()
        spawned = helpers() - before
        if started != "True" or not spawned:
            pytest.skip("no event source in this environment")
        psutil.Process(child.pid).kill()        # no cleanup hooks will run
        child.wait(timeout=10)
        deadline = time.time() + 40
        while time.time() < deadline:
            if not (helpers() & spawned):
                return
            time.sleep(2)
        pytest.fail(f"helper {helpers() & spawned} outlived its killed parent")
    finally:
        if child.poll() is None:
            child.kill()
        for pid in helpers() - before:
            try:
                psutil.Process(pid).kill()
            except psutil.Error:
                pass
