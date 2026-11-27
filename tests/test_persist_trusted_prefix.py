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
