r"""Known-abused kernel drivers (issue #20).

A name list, with the limits that implies stated in the module. What is tested
hardest is the part that keeps it honest: every driver on the list also has an
innocent explanation, so a hit where an installer would have put the file is a
low note, and only the same driver loaded from somewhere no installer uses is
a finding.
"""

import os
import sys

import pytest

from minersentry import drivers as D
from minersentry import tamper

ROOT = r"C:\Windows"
ENV = {"SystemRoot": ROOT}

ROWS = [
    ('ACPI', 'Running', 'C:\\Windows\\system32\\drivers\\ACPI.sys'),
    ('EhStorTcgDrv', 'Running', 'C:\\Windows\\system32\\drivers\\EhStorTcgDrv.sys'),
    ('WinRing0_1_2_0', 'Running', 'C:\\Program Files\\HWMonitor\\WinRing0x64.sys'),
    ('RTCore64', 'Running', '\\??\\C:\\Program Files (x86)\\MSI Afterburner\\RTCore64.sys'),
    ('evil', 'Running', 'C:\\Users\\x\\AppData\\Local\\Temp\\WinRing0x64.sys'),
    ('gdrv', 'Stopped', 'C:\\Windows\\gdrv.sys'),
    ('rel', 'Running', 'System32\\drivers\\dbutil_2_3.sys'),
    ('nopath', 'Running', ''),
]
CSV = "\n".join(['"Name","State","PathName"']
                + ['"%s","%s","%s"' % row for row in ROWS]) + "\n"


def _parsed():
    return D.parse_system_drivers(CSV, system_root=ROOT, environ=ENV)


def test_the_driver_list_is_parsed_with_paths_resolved():
    by_name = {d.name: d for d in _parsed()}
    assert by_name["RTCore64"].path == \
        r"C:\Program Files (x86)\MSI Afterburner\RTCore64.sys", \
        "the NT device prefix must be stripped"
    assert by_name["rel"].path == r"C:\Windows\System32\drivers\dbutil_2_3.sys", \
        "a relative path is relative to the system root"
    assert by_name["ACPI"].running and not by_name["gdrv"].running
    assert "nopath" not in by_name


@pytest.mark.parametrize("text", ["", "garbage", '"Name","State"\n"x","Running"\n'])
def test_unparseable_output_yields_nothing(text):
    assert D.parse_system_drivers(text, system_root=ROOT, environ=ENV) == []


def test_matching_is_on_the_exact_file_name():
    """"gdrv" as a substring matches Windows' own EhStorTcgDrv -- found by
    running the naive version against a real machine."""
    names = {a.driver.name for a in D.abused(_parsed(), system_root=ROOT)}
    assert "EhStorTcgDrv" not in names
    assert "ACPI" not in names


def test_a_stopped_driver_is_not_reported_as_loaded():
    assert "gdrv" not in {a.driver.name
                          for a in D.abused(_parsed(), system_root=ROOT)}


def test_a_dropped_driver_scores_far_above_one_an_installer_placed():
    by_name = {a.driver.name: a for a in D.abused(_parsed(), system_root=ROOT)}
    assert by_name["evil"].dropped and by_name["evil"].score == D.SCORE_DROPPED
    # under System32\drivers: where an installer puts it
    assert not by_name["rel"].dropped
    assert by_name["rel"].score == D.SCORE_IN_PLACE


def test_a_driver_in_program_files_counts_as_out_of_place():
    """Program Files is not a driver directory. is_rogue_driver measured 460
    of 461 real driver services under the system driver directories, and
    this module does not get to be more lenient than that."""
    by_name = {a.driver.name: a for a in D.abused(_parsed(), system_root=ROOT)}
    assert by_name["RTCore64"].dropped


def test_worst_first():
    scores = [a.score for a in D.abused(_parsed(), system_root=ROOT)]
    assert scores == sorted(scores, reverse=True)


def test_every_entry_says_who_ships_it_and_what_it_is_abused_for():
    for name, (shipped, abused_for) in D.KNOWN_ABUSED.items():
        assert name == name.lower() and name.endswith(".sys")
        assert shipped and abused_for


# == as findings ===========================================================
def test_findings_carry_both_explanations():
    out = tamper.driver_findings(_parsed())
    assert out and all(f.kind == "abused-driver" for f in out)
    for f in out:
        text = " ".join(f.labels)
        assert "abused for" in text and "ships legitimately" in text


def test_an_unreadable_driver_list_is_said_out_loud(monkeypatch):
    monkeypatch.setattr(tamper, "IS_WINDOWS", True)
    out = tamper.driver_findings(None)
    assert len(out) == 1 and out[0].score == 0
    assert out[0].kind == "drivers-unreadable"


def test_nothing_is_said_off_windows(monkeypatch):
    monkeypatch.setattr(tamper, "IS_WINDOWS", False)
    assert tamper.driver_findings(None) == []


def test_an_in_place_driver_does_not_raise_the_gui_banner():
    """RTCore64 IS MSI Afterburner. A red banner for someone who installed a
    fan-curve tool teaches them to ignore the banner."""
    from minersentry import gui
    assert D.SCORE_IN_PLACE < gui.BANNER_MIN_SCORE
    assert D.SCORE_MSR_DRIVER < gui.BANNER_MIN_SCORE
    assert D.SCORE_DROPPED >= gui.BANNER_MIN_SCORE


# == the real machine ======================================================
@pytest.mark.skipif(sys.platform != "win32", reason="Windows drivers")
def test_the_machines_own_drivers_resolve_and_none_is_called_dropped():
    drivers = D.loaded()
    if drivers is None:
        pytest.skip("driver list unreadable here")
    running = [d for d in drivers if d.running]
    assert len(running) > 20, "no drivers read; this control means nothing"
    unresolved = [d for d in running if not os.path.isfile(d.path)]
    assert len(unresolved) <= 3, [(d.name, d.path) for d in unresolved[:5]]
    assert not [a for a in D.abused(drivers) if a.dropped]
