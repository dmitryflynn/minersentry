r"""Issue #50: autostart executables written with %VARS%.

Run keys (REG_EXPAND_SZ), task actions, Active Setup StubPaths and IFEO values
store their executable as `%APPDATA%\...` or `%windir%\...`. Scored as it
stands, such a path names no file and contains none of the drop-location hints,
so the same binary scored 0 written one way and 40 written the other.
"""

import posixpath

from minersentry import persistence as P
from minersentry.config import Config

CFG = Config()
ENV = {"APPDATA": r"C:\Users\x\AppData\Roaming",
       "windir": r"C:\Windows"}
REAL = r"C:\Users\x\AppData\Roaming\svc\worker.exe"


def _score(command, exe, trusted_paths=()):
    seen = []

    def is_trusted(path, trusted_dirs, untrusted_hints=()):
        seen.append(path)
        return path in trusted_paths

    entry = P.PersistEntry(kind="run-key", location=r"HKCU\Run", name="svc",
                           command=command, exe=exe)
    P.score_entry(entry, CFG, is_trusted=is_trusted,
                  isfile=lambda p: p in (REAL, r"C:\Windows\System32\ok.exe"),
                  environ=ENV)
    return entry, seen


def test_a_variable_path_scores_the_same_as_the_expanded_one():
    var, _ = _score(r"%APPDATA%\svc\worker.exe", r"%APPDATA%\svc\worker.exe")
    plain, _ = _score(REAL, REAL)
    assert plain.score > 0
    assert var.score == plain.score
    assert var.labels == plain.labels
    assert "unsigned binary outside the system directories" in var.labels


def test_the_trust_check_is_handed_the_expanded_path():
    entry, seen = _score(r"%windir%\System32\ok.exe",
                         r"%windir%\System32\ok.exe",
                         trusted_paths=(r"C:\Windows\System32\ok.exe",))
    assert seen == [r"C:\Windows\System32\ok.exe"]
    assert "unsigned binary outside the system directories" not in entry.labels


def test_the_entry_keeps_its_command_and_exe_as_written():
    entry, _ = _score(r"%APPDATA%\svc\worker.exe -q", r"%APPDATA%\svc\worker.exe")
    assert entry.command == r"%APPDATA%\svc\worker.exe -q"
    assert entry.exe == r"%APPDATA%\svc\worker.exe"


def test_an_unknown_variable_is_left_in_place_and_scores_nothing_on_its_file():
    entry, seen = _score(r"%NOPE%\svc\worker.exe", r"%NOPE%\svc\worker.exe")
    assert seen == []
    assert entry.score == 0


def test_resolve_system_dll_expands_percent_variables_on_any_platform(monkeypatch):
    # Simulate Linux, where os.path.expandvars only knows $VAR.
    monkeypatch.setattr(P.os.path, "expandvars", posixpath.expandvars)
    monkeypatch.setenv("MS_TEST_ROOT", r"C:\Evil")
    out = P.resolve_system_dll(r"%MS_TEST_ROOT%\x.dll", isfile=lambda p: False)
    assert out == r"C:\Evil\x.dll"
