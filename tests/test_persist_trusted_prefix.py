r"""Issue #70: the short-name label in persistence.score_entry used a raw prefix
test, so `C:\Program Files2\abc.exe` (a folder any user can create) counted as
Program Files and skipped it. Same bug as #65 in scoring.score_name.
"""

import pytest

from minersentry import persistence as P
from minersentry.config import Config

CFG = Config()


def _labels(exe):
    entry = P.PersistEntry(kind="run-key", location=r"HKCU\Run", name="abc",
                           command=exe, exe=exe)
    P.score_entry(entry, CFG, is_trusted=lambda *a, **k: False,
                  isfile=lambda p: False)
    return entry.labels


@pytest.mark.parametrize("exe", [r"C:\Program Files2\abc.exe",
                                 r"C:\Windows2\abc.exe",
                                 r"C:\Program Files (x86)Evil\abc.exe"])
def test_a_lookalike_of_a_trusted_dir_still_gets_the_short_name_label(exe):
    assert "very short name" in _labels(exe)


@pytest.mark.parametrize("exe", [r"C:\Program Files\abc.exe",
                                 r"C:\Windows\System32\abc.exe"])
def test_a_binary_really_inside_a_trusted_dir_does_not(exe):
    assert "very short name" not in _labels(exe)


def test_a_trusted_directory_written_with_a_variable_is_still_trusted():
    r"""With #50 the checks run on the expanded path. The short-name check has
    to as well, or `%ProgramFiles%\abc.exe` is labelled as if it were
    outside the trusted directories while `C:\Program Files\abc.exe` is not."""
    from minersentry import persistence as P
    from minersentry.config import Config
    cfg = Config(trusted_dirs=(r"c:\program files", r"c:\windows\system32"))
    env = {"ProgramFiles": r"C:\Program Files"}

    def labels(exe):
        e = P.PersistEntry(kind="run-key", location="HKCU", name="x",
                           command=exe, exe=exe)
        return P.score_entry(e, cfg, is_trusted=lambda *a, **k: True,
                             isfile=lambda p: True, environ=env).labels

    assert "very short name" not in labels(r"%ProgramFiles%\abc.exe")
    assert "very short name" not in labels(r"C:\Program Files\abc.exe")
