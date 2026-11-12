r"""Issue #28: the GUI never showed tampering, and offered no undo.

The packaged binary is `main.py` -> `minersentry.gui`, built `--windowed`, so
the GUI is the whole product for anyone running the exe. Two tested features
were unreachable there, and a third defect turned up while fixing them:
`removals()` left out the action a startup-folder removal journals, so "undo
the last removal" restored an older, unrelated entry.

No window is created here. The helpers under test touch no widgets, so they
are called unbound — a Tk root would not open on a CI runner anyway.
"""

import os
import sys
from types import SimpleNamespace

import pytest

from minersentry import persistence as P
from minersentry import quarantine
from minersentry.config import Config
from minersentry.gui import MinerSentryApp, _describe_removal
from minersentry.tamper import TamperFinding

CFG = Config()


def _history(*records):
    """Stand in for the journal, oldest first, as history() returns it."""
    return list(records)


# == removals() must see a startup-folder removal ==========================
def test_a_startup_folder_removal_counts_as_a_removal(monkeypatch):
    r"""The bug: `quarantine_file` was not in the accepted actions, so after
    removing a malicious shortcut the newest "removal" was an older registry
    entry — and an undo restored THAT. The user never asked for it back, and
    the shortcut stayed quarantined."""
    monkeypatch.setattr(quarantine, "history", lambda limit=200: _history(
        {"ts": "t1", "action": "remove_registry_value", "hive": "HKCU",
         "path": "Software\\X", "name": "Older"},
        {"ts": "t2", "action": "quarantine_file", "kind": "startup-folder",
         "original": r"C:\Users\x\Startup\Evil.lnk", "stored": r"Q\Evil.lnk"},
    ))
    out = P.removals()
    assert len(out) == 2
    assert out[-1]["action"] == "quarantine_file", (
        "the newest removal is the shortcut; an undo must offer that first")


def test_a_quarantined_process_binary_is_not_an_autostart_removal(monkeypatch):
    """Quarantining a running miner's binary from the dashboard is a different
    action with a different meaning. It carries no `kind`, and undoing an
    autostart removal must not offer it."""
    monkeypatch.setattr(quarantine, "history", lambda limit=200: _history(
        {"ts": "t1", "action": "quarantine_file",
         "original": r"C:\Temp\miner.exe", "stored": r"Q\miner.exe"},
    ))
    assert P.removals() == []


def test_a_removal_already_undone_is_not_offered_again(monkeypatch):
    monkeypatch.setattr(quarantine, "history", lambda limit=200: _history(
        {"ts": "t1", "action": "quarantine_file", "kind": "startup-folder",
         "original": r"C:\Users\x\Startup\Evil.lnk", "stored": r"Q\Evil.lnk"},
        {"ts": "t2", "action": "restore_file",
         "original": r"C:\Users\x\Startup\Evil.lnk", "stored": r"Q\Evil.lnk"},
    ))
    assert P.removals() == [], "restoring it already put it back"


def test_the_other_removal_actions_are_unchanged(monkeypatch):
    monkeypatch.setattr(quarantine, "history", lambda limit=200: _history(
        {"ts": "t1", "action": "remove_registry_value", "name": "A"},
        {"ts": "t2", "action": "remove_task", "task": "\\B"},
        {"ts": "t3", "action": "disable_service", "service": "C"},
        {"ts": "t4", "action": "suspend", "pid": 1},        # not a removal
        {"ts": "t5", "action": "block_ip", "ip": "1.2.3.4"},  # not a removal
    ))
    assert [r["action"] for r in P.removals()] == [
        "remove_registry_value", "remove_task", "disable_service"]


# == undo must know how to reverse it ======================================
def test_undoing_a_startup_folder_removal_restores_the_file(monkeypatch):
    restored = []
    monkeypatch.setattr(quarantine, "restore_file",
                        lambda stored: restored.append(stored) or
                        quarantine.Result(True, "back"))
    record = {"action": "quarantine_file", "kind": "startup-folder",
              "original": r"C:\Users\x\Startup\Evil.lnk", "stored": r"Q\Evil.lnk"}
    assert P.undo_removal(record).ok
    assert restored == [r"Q\Evil.lnk"]


def test_removing_a_startup_entry_tags_the_record_with_its_kind(monkeypatch):
    """Without the tag the record is indistinguishable from a quarantined
    process binary, which is how removals() came to miss it."""
    seen = {}
    monkeypatch.setattr(quarantine, "quarantine_file",
                        lambda path, kill_first=False, kind="":
                        seen.update(path=path, kind=kind) or
                        quarantine.Result(True, "moved"))
    entry = P.PersistEntry(kind="startup-folder", location="f", name="Evil.lnk",
                           command=r"C:\Program Files\App\app.exe",
                           exe=r"C:\Program Files\App\app.exe",
                           file=r"C:\Users\x\Startup\Evil.lnk")
    assert P.remove_entry(entry).ok
    assert seen["kind"] == "startup-folder"
    assert seen["path"] == entry.file, "still must move the .lnk, not its target"


def test_the_journal_records_the_kind_only_when_given(tmp_path, monkeypatch):
    """A plain quarantine keeps the record it always had."""
    written = []
    monkeypatch.setattr(quarantine, "_record",
                        lambda action, **f: written.append((action, f)))
    monkeypatch.setattr(quarantine, "processes_using", lambda p: [])
    monkeypatch.setattr(quarantine, "quarantine_dir", lambda: str(tmp_path / "q"))
    target = tmp_path / "x.exe"
    target.write_bytes(b"x")
    assert quarantine.quarantine_file(str(target)).ok
    assert "kind" not in written[-1][1]

    target.write_bytes(b"x")
    assert quarantine.quarantine_file(str(target), kind="startup-folder").ok
    assert written[-1][1]["kind"] == "startup-folder"


# == the undo list has to read as something a person can choose from ======
@pytest.mark.parametrize("record,expected", [
    ({"ts": "2026-11-11T21:19:02+0000", "action": "remove_registry_value",
      "hive": "HKCU", "path": "Software\\X\\Run", "name": "Evil"}, "Evil"),
    ({"ts": "2026-11-11T21:19:02+0000", "action": "remove_task",
      "task": "\\Evil"}, "scheduled task \\Evil"),
    ({"ts": "2026-11-11T21:19:02+0000", "action": "disable_service",
      "service": "EvilSvc"}, "service EvilSvc"),
    ({"ts": "2026-11-11T21:19:02+0000", "action": "quarantine_file",
      "original": r"C:\Users\x\Startup\Evil.lnk"}, "Evil.lnk"),
])
def test_each_removal_describes_itself(record, expected):
    line = _describe_removal(record)
    assert expected in line
    assert "2026-11-11 21:19:02" in line


def test_an_unknown_action_still_produces_a_line():
    """A journal written by a newer version must not break the undo dialog."""
    line = _describe_removal({"action": "something_new_entirely"})
    assert "something_new_entirely" in line
    assert "no timestamp" in line


def test_a_record_with_nothing_in_it_does_not_raise():
    assert _describe_removal({})


# == the defence findings panel ============================================
def _lines(findings):
    return "\n".join(MinerSentryApp._tamper_lines(None, findings))


def test_defence_findings_are_rendered_with_their_detail():
    text = _lines([
        TamperFinding(kind="defender-exclusion",
                      detail=r"C:\Users\x\AppData\Local\Temp is excluded",
                      where="Get-MpPreference", score=70,
                      labels=["covers a folder already flagged"]),
        TamperFinding(kind="hosts-blackhole",
                      detail="update.microsoft.com -> 127.0.0.1",
                      where=r"C:\Windows\System32\drivers\etc\hosts", score=55),
    ])
    assert "2 defence findings" in text
    assert "defender-exclusion" in text
    assert "covers a folder already flagged" in text
    assert "hosts-blackhole" in text


def test_a_clean_machine_says_so_rather_than_saying_nothing():
    assert "nothing tampered with" in _lines([])


def test_an_unreadable_check_is_reported_not_passed_off_as_clean():
    """A score-0 finding means the check could not run. Printing nothing there
    would imply the defences were verified."""
    text = _lines([TamperFinding(
        kind="defender-unreadable",
        detail="could not read the Defender exclusion list",
        where="Get-MpPreference", score=0)])
    assert "could not read" in text
    assert "nothing tampered with" not in text


def test_one_finding_is_singular():
    text = _lines([TamperFinding(kind="k", detail="d", where="w", score=10)])
    assert "1 defence finding:" in text


# == the correlation the issue asked for ===================================
def test_the_autostart_scan_hands_its_flagged_paths_to_the_tamper_scan(monkeypatch):
    """An exclusion covering a path the autostart scan just flagged is close to
    conclusive. Running the two scans independently made that impossible to
    see, which is why they share a pass now."""
    from minersentry import gui as gui_mod

    flagged = []
    found = [P.PersistEntry(kind="run-key", location="HKCU", name="Evil",
                            command="x", exe=r"C:\Users\x\Temp\miner.exe"),
             P.PersistEntry(kind="run-key", location="HKCU", name="NoExe",
                            command="x", exe="")]
    monkeypatch.setattr(gui_mod.persist_mod, "scan", lambda cfg: found)
    monkeypatch.setattr(gui_mod.tamper_mod, "scan",
                        lambda cfg, flagged_paths=(): flagged.append(flagged_paths) or [])

    posted = []
    app = SimpleNamespace(engine=SimpleNamespace(cfg=CFG),
                          q=SimpleNamespace(put=posted.append))
    MinerSentryApp._autostart_thread(app)

    assert flagged == [(r"C:\Users\x\Temp\miner.exe",)], (
        "the tamper scan was not given the flagged paths")
    assert posted[-1][0] == "autostart"
    assert posted[-1][1] is found


def test_a_failing_tamper_scan_does_not_lose_the_autostart_results(monkeypatch):
    """The autostart findings are the point of the pass; a defence check that
    raises must not take them down with it."""
    from minersentry import gui as gui_mod

    found = [P.PersistEntry(kind="run-key", location="HKCU", name="Evil",
                            command="x", exe="x")]
    monkeypatch.setattr(gui_mod.persist_mod, "scan", lambda cfg: found)

    def boom(cfg, flagged_paths=()):
        raise OSError("Get-MpPreference is not available")
    monkeypatch.setattr(gui_mod.tamper_mod, "scan", boom)

    posted = []
    app = SimpleNamespace(engine=SimpleNamespace(cfg=CFG),
                          q=SimpleNamespace(put=posted.append))
    MinerSentryApp._autostart_thread(app)

    kinds = [p[0] for p in posted]
    assert "autostart" in kinds, "the autostart results were lost"
    assert "event" in kinds, "the failure was not reported anywhere"
    assert posted[-1][2] == [], "no findings, rather than a crash"


# == the widget code itself ================================================
# Everything above tests logic that touches no widgets, which is most of the
# fix but not the part that would crash the window. These build real Tk
# widgets and call the methods against them, without starting the engine.
@pytest.fixture
def tk_root():
    tk = pytest.importorskip("tkinter")
    try:
        root = tk.Tk()
    except Exception as e:  # noqa: BLE001 - no display, or no Tk build
        pytest.skip(f"no usable Tk: {type(e).__name__}: {e}")
    root.withdraw()
    try:
        yield root
    finally:
        try:
            root.destroy()
        except Exception:  # noqa: BLE001
            pass


def _banner_app(root):
    """A stand-in carrying the real widgets `_show_tamper` touches."""
    import tkinter as tk
    banner = tk.Frame(root)
    label = tk.Label(banner, text="")
    label.pack()
    events = []
    app = SimpleNamespace(tamper_banner=banner, tamper_lbl=label,
                          _add_event=events.append, events=events)
    app._hide_tamper_banner = lambda: MinerSentryApp._hide_tamper_banner(app)
    return app, events


def test_the_banner_appears_for_a_finding_and_goes_away_again(tk_root):
    app, events = _banner_app(tk_root)
    finding = TamperFinding(kind="defender-disabled",
                            detail="real-time monitoring is off by policy",
                            where="HKLM\\...\\Real-Time Protection", score=80)
    MinerSentryApp._show_tamper(app, [finding])
    tk_root.update()
    assert app.tamper_banner.winfo_manager(), "the banner was never packed"
    assert "off by policy" in app.tamper_lbl.cget("text")
    assert any("defences 80" in e for e in events)

    MinerSentryApp._show_tamper(app, [])
    tk_root.update()
    assert not app.tamper_banner.winfo_manager(), "the banner stayed up"


def test_the_banner_shows_the_worst_finding_and_counts_the_rest(tk_root):
    app, _ = _banner_app(tk_root)
    MinerSentryApp._show_tamper(app, [
        TamperFinding(kind="a", detail="lesser thing", where="w", score=30),
        TamperFinding(kind="b", detail="the worst thing", where="w", score=90),
        TamperFinding(kind="c", detail="middling", where="w", score=50)])
    tk_root.update()
    text = app.tamper_lbl.cget("text")
    assert "the worst thing" in text
    assert "+2 more" in text


def test_a_score_zero_note_is_logged_without_raising_a_banner(tk_root):
    app, events = _banner_app(tk_root)
    MinerSentryApp._show_tamper(app, [TamperFinding(
        kind="defender-unreadable", detail="could not read the exclusions",
        where="Get-MpPreference", score=0)])
    tk_root.update()
    assert not app.tamper_banner.winfo_manager()
    assert any("could not read" in e for e in events), (
        "an unreadable check must still be said out loud somewhere")


def test_the_undo_dialog_opens_and_lists_the_removals(tk_root, monkeypatch):
    import tkinter as tk
    from minersentry import gui as gui_mod

    records = [
        {"ts": "2026-11-11T20:00:00+0000", "action": "remove_registry_value",
         "hive": "HKCU", "path": "Software\\X", "name": "Older"},
        {"ts": "2026-11-11T21:00:00+0000", "action": "quarantine_file",
         "kind": "startup-folder", "original": r"C:\Users\x\Startup\Evil.lnk",
         "stored": r"Q\Evil.lnk"},
    ]
    monkeypatch.setattr(gui_mod.persist_mod, "removals", lambda: records)

    app = SimpleNamespace(root=tk_root, _add_event=lambda s: None,
                          _set_status=lambda s: None,
                          _btn=lambda parent, text, cmd, color:
                          tk.Button(parent, text=text, command=cmd))
    MinerSentryApp.undo_removal(app)
    tk_root.update()

    tops = [w for w in tk_root.winfo_children() if isinstance(w, tk.Toplevel)]
    assert tops, "no undo window opened"
    boxes = [w for w in tops[0].winfo_children() if isinstance(w, tk.Listbox)]
    assert boxes, "the undo window has no list"
    items = boxes[0].get(0, "end")
    assert len(items) == 2
    assert "Evil.lnk" in items[0], "newest first: the shortcut was removed last"
    assert "Older" in items[1]
    tops[0].destroy()


def test_the_undo_dialog_says_so_when_there_is_nothing_to_undo(tk_root, monkeypatch):
    from minersentry import gui as gui_mod
    told = []
    monkeypatch.setattr(gui_mod.persist_mod, "removals", lambda: [])
    monkeypatch.setattr(gui_mod.messagebox, "showinfo",
                        lambda title, message, **k: told.append(message))
    MinerSentryApp.undo_removal(SimpleNamespace(root=tk_root))
    assert told and "nothing to put back" in told[0]


@pytest.mark.skipif(sys.platform != "win32", reason="the real scan is Windows-only")
def test_the_tamper_scan_accepts_what_the_gui_hands_it():
    """A live call, so a signature change in tamper.scan cannot pass the
    mocked tests above while breaking the real window."""
    from minersentry import tamper
    findings = tamper.scan(CFG, flagged_paths=(os.environ.get("TEMP", "C:\\Temp"),))
    assert isinstance(findings, list)
    for f in findings:
        assert isinstance(f.score, int) and f.detail and f.kind
