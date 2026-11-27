"""The packaged exe's entry point (main.py, built --onefile --windowed)."""

import importlib.util
import os
import sys

from minersentry import service

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_main():
    spec = importlib.util.spec_from_file_location(
        "minersentry_entry", os.path.join(ROOT, "main.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_the_installed_task_starts_the_watcher_not_the_gui(monkeypatch):
    """`--install` from MinerSentry.exe registers `MinerSentry.exe --service`
    (service._run_target). main.py ignored its arguments, so at boot the task
    opened the GUI as SYSTEM and nothing was watching at all."""
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    target = service._run_target()
    entry = _load_main()
    ran = []
    import minersentry.gui as gui
    monkeypatch.setattr(service, "main", lambda argv=None: ran.append(argv) or 0)
    monkeypatch.setattr(gui, "main", lambda: ran.append("gui"))
    assert entry.launch(target[1:]) == 0
    assert ran == [["--run"]]


def test_the_windowed_exe_has_streams_to_print_to(monkeypatch):
    """PyInstaller --windowed leaves sys.stdout and sys.stderr as None, and
    the watcher prints its start-up line to stderr: AttributeError before the
    first pass."""
    entry = _load_main()
    monkeypatch.setattr(sys, "stdout", None)
    monkeypatch.setattr(sys, "stderr", None)

    def fake_main(argv=None):
        print("watching", file=sys.stderr)
        print("hello")
        return 0
    monkeypatch.setattr(service, "main", fake_main)
    assert entry.launch(["--service"]) == 0


def test_no_arguments_still_opens_the_gui(monkeypatch):
    entry = _load_main()
    ran = []
    import minersentry.gui as gui
    monkeypatch.setattr(gui, "main", lambda: ran.append("gui"))
    monkeypatch.setattr(service, "main", lambda argv=None: ran.append("service"))
    assert entry.launch([]) == 0
    assert ran == ["gui"]
