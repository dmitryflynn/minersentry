"""Service ImagePath resolution and the rogue-driver weight (issue #24).

The bug: the service collector expanded only the `\\SystemRoot\\` prefix and
never called expandvars, so 490 of the 793 service entries on the development
machine had an `exe` that named no file. With no file there is nothing for the
signature check, the unsigned weight or the drop-location hints to work on, and
a driver registered relatively scored 15 where the same driver written
absolutely scored 50.
"""

import os

import pytest

from minersentry import persistence as P
from minersentry.config import Config

CFG = Config()
THRESHOLD = CFG.persistence_min_score
ROOT = r"C:\Windows"
ENV = {"SystemRoot": ROOT, "ProgramFiles": r"C:\Program Files"}

# Config picks platform-specific directory sets, so a test that needs the
# WINDOWS sets has to say so — these entries come out of the Windows registry
# whatever platform the suite is running on.
WIN_CFG = Config(
    trusted_dirs=(r"c:\program files", r"c:\program files (x86)",
                  r"c:\windows\system32", r"c:\windows\syswow64"),
    suspicious_dir_hints=("\\temp\\", "\\appdata\\local\\temp\\",
                          "\\programdata\\", "\\appdata\\roaming\\"),
    signature_untrusted_dirs=("\\temp\\", "\\appdata\\",))


def _untrusted(exe, trusted_dirs, untrusted_hints=()):
    return False


def _score(stored, trusted=False):
    """Score a service entry the way the collector builds one."""
    image = P.resolve_image_path(stored, system_root=ROOT, environ=ENV)
    entry = P.PersistEntry(
        kind="service", location=r"HKLM\SYSTEM\CurrentControlSet\Services",
        name="WinRing0x64", command=image,
        exe=P.command_exe(image, isfile=lambda p: True))
    return P.score_entry(
        entry, WIN_CFG, isfile=lambda p: True,
        is_trusted=(lambda *a, **k: True) if trusted else _untrusted)


# == the four spellings the SCM accepts =====================================
@pytest.mark.parametrize("stored,expected", [
    # relative: 214 of 793 entries on the development machine
    (r"System32\drivers\x.sys", r"C:\Windows\System32\drivers\x.sys"),
    (r"system32\svchost.exe", r"C:\Windows\system32\svchost.exe"),
    # \SystemRoot\ : 251 entries. This was the only form handled before.
    (r"\SystemRoot\System32\drivers\x.sys", r"C:\Windows\System32\drivers\x.sys"),
    (r"\systemroot\system32\x.sys", r"C:\Windows\system32\x.sys"),
    # %var% : 276 entries, and nothing called expandvars on this path.
    # Expansion is ours rather than os.path's, so these hold on Linux too.
    (r"%SystemRoot%\system32\svchost.exe", r"C:\Windows\system32\svchost.exe"),
    (r"%systemroot%\x.sys", r"C:\Windows\x.sys"),          # case-insensitive
    (r"%NoSuchVar%\x.sys", r"C:\Windows\%NoSuchVar%\x.sys"),   # left standing
    # \??\ : the NT device prefix
    (r"\??\C:\ProgramData\x\x.sys", r"C:\ProgramData\x\x.sys"),
    # already absolute: left exactly as it is
    (r"C:\Program Files\Vendor\x.sys", r"C:\Program Files\Vendor\x.sys"),
    (r"\\server\share\x.sys", r"\\server\share\x.sys"),
])
def test_every_imagepath_spelling_resolves(stored, expected):
    assert P.resolve_image_path(stored, system_root=ROOT, environ=ENV) == expected


def test_a_drive_rooted_path_lands_on_the_system_roots_drive():
    r"""`\Windows\x.sys` is rooted on the CURRENT drive, not absolute."""
    assert P.resolve_image_path(r"\Windows\x.sys",
                                system_root=r"D:\Windows") == r"D:\Windows\x.sys"


def test_arguments_survive_resolution():
    """An ImagePath usually carries them: `svchost.exe -k netsvcs`."""
    out = P.resolve_image_path(r"system32\svchost.exe -k netsvcs -p",
                               system_root=ROOT)
    assert out == r"C:\Windows\system32\svchost.exe -k netsvcs -p"


def test_a_quoted_path_is_resolved_inside_its_quotes():
    out = P.resolve_image_path(r'"System32\drivers\x y.sys" -quiet',
                               system_root=ROOT)
    assert out == r'"C:\Windows\System32\drivers\x y.sys" -quiet'
    assert P.command_exe(out, isfile=lambda p: False) == \
        r"C:\Windows\System32\drivers\x y.sys"


def test_an_empty_imagepath_resolves_to_nothing():
    assert P.resolve_image_path("") == ""
    assert P.resolve_image_path("   ") == ""


def test_resolution_does_not_touch_the_filesystem():
    """It is pure, so it can be tested against paths this machine lacks."""
    out = P.resolve_image_path(r"System32\drivers\nothing-here.sys",
                               system_root=r"Z:\NoSuchRoot")
    assert out == r"Z:\NoSuchRoot\System32\drivers\nothing-here.sys"


# == a driver whose path now resolves can finally be scored ================
def test_a_relative_driver_path_no_longer_hides_35_points():
    """The regression this issue was filed for: the same driver, written two
    ways, must score the same."""
    absolute = _score(r"C:\ProgramData\x\WinRing0x64.sys").score
    relative = _score(r"\??\C:\ProgramData\x\WinRing0x64.sys").score
    assert absolute == relative
    assert absolute >= THRESHOLD


@pytest.mark.parametrize("stored", [
    r"C:\Users\x\AppData\Local\Temp\WinRing0x64.sys",
    r"C:\ProgramData\x\WinRing0x64.sys",
    r"\??\C:\ProgramData\x\WinRing0x64.sys",
    r'"C:\Program Data\x y\WinRing0x64.sys" -quiet',
])
def test_a_driver_registered_outside_the_driver_directories_is_reported(stored):
    entry = _score(stored)
    assert entry.score >= THRESHOLD, (entry.score, entry.labels)
    assert any("kernel driver" in lab for lab in entry.labels), entry.labels


def test_a_driver_inside_the_driver_directories_gets_no_driver_weight():
    """An unsigned .sys in System32\\drivers is not the signal here. Windows
    will not load an unsigned driver on x64 anyway, and the WinRing0 pattern
    uses a legitimately SIGNED vulnerable driver — that is #20's problem, and
    it needs the loaded-module list, not a path check."""
    entry = _score(r"System32\drivers\WinRing0x64.sys")
    assert not any("kernel driver" in lab for lab in entry.labels)
    assert entry.score < THRESHOLD


def test_a_signed_driver_outside_those_directories_earns_nothing():
    """Measured first: of 461 driver services on the development machine, 460
    are under System32\\drivers or the DriverStore. The one exception is a
    VPN's driver under Program Files, which is signed, so gating the weight on
    trust costs that exception nothing."""
    entry = _score(r"C:\Program Files\Proton\VPN\resources\x.sys", trusted=True)
    assert entry.score == 0, entry.labels


# == containment must not be a substring test ==============================
def test_a_folder_merely_named_like_the_driver_directory_does_not_count():
    r"""Anyone can create C:\Users\x\System32\drivers. A substring test would
    accept it, which is the mistake that once let C:\Program Files2 pass as
    C:\Program Files."""
    assert P.is_rogue_driver(r"C:\Users\x\System32\drivers\evil.sys",
                             system_root=ROOT)


def test_a_traversal_out_of_the_driver_directory_does_not_count():
    r"""C:\Windows\System32\drivers\..\..\Users\x\evil.sys begins with the
    driver directory as a string while the file is somewhere else."""
    assert P.is_rogue_driver(
        r"C:\Windows\System32\drivers\..\..\Users\x\evil.sys",
        system_root=ROOT)


def test_a_traversal_into_the_driver_directory_is_accepted():
    assert not P.is_rogue_driver(
        r"C:\Users\x\..\..\Windows\System32\drivers\ok.sys", system_root=ROOT)


def test_a_traversal_does_not_buy_a_trusted_directory():
    r"""The same hole one level down, in trust._under, which every signal
    uses. A Run key or ImagePath is attacker-controlled, so this was
    reachable: the path below begins with a trusted directory while the file
    is in Temp, and it scored 10 instead of 50 — under the threshold."""
    from minersentry import trust
    evil = r"C:\Windows\System32\..\..\Users\x\AppData\Local\Temp\miner.exe"
    assert not trust.in_trusted_dir(evil, WIN_CFG.trusted_dirs)
    assert trust.in_trusted_dir(r"C:\Windows\System32\svchost.exe",
                                WIN_CFG.trusted_dirs)


def test_a_traversal_in_a_run_key_scores_the_same_as_the_real_path():
    import ntpath
    evil = r"C:\Windows\System32\..\..\Users\x\AppData\Local\Temp\miner.exe"
    def scored(exe):
        e = P.PersistEntry(kind="run-key", location="HKCU", name="x",
                           command=exe, exe=exe)
        return P.score_entry(e, WIN_CFG, isfile=lambda p: True).score
    assert scored(evil) == scored(ntpath.normpath(evil))
    assert scored(evil) >= THRESHOLD


def test_posix_paths_are_normalised_as_posix():
    r"""ntpath.normpath("/tmp/x") returns "\\tmp\\x", which would break every
    Linux path. The style detection in _under picks the right one."""
    from minersentry import trust
    assert trust.in_trusted_dir("/usr/bin/../bin/python3", ("/usr/bin",))
    assert not trust.in_trusted_dir("/usr/bin/../../tmp/miner", ("/usr/bin",))


@pytest.mark.parametrize("exe", [
    r"C:\Windows\System32\drivers\ok.sys",
    r"C:\Windows\system32\DRIVERS\ok.sys",          # case
    r"C:/Windows/System32/drivers/ok.sys",          # separators
    r"C:\Windows\System32\DriverStore\FileRepository\x.inf_amd64_1\ok.sys",
    r"C:\Windows\SysWOW64\drivers\ok.sys",
])
def test_the_real_driver_directories_are_recognised(exe):
    assert not P.is_rogue_driver(exe, system_root=ROOT)


def test_a_non_driver_is_never_a_rogue_driver():
    for exe in (r"C:\Users\x\Temp\miner.exe", r"C:\Temp\x.dll", "", "x"):
        assert not P.is_rogue_driver(exe, system_root=ROOT)


# == command_exe now knows about the extensions services point at ==========
def test_a_driver_path_containing_a_space_is_not_truncated():
    """Without .sys in the extension list this fell through to parts[0] and
    came back as "C:\\Program"."""
    out = P.command_exe(r"C:\Program Data\x y\WinRing0x64.sys",
                        isfile=lambda p: False)
    assert out == r"C:\Program Data\x y\WinRing0x64.sys"


def test_a_service_dll_path_containing_a_space_is_not_truncated():
    out = P.command_exe(r"C:\Program Files\Vendor App\svc.dll",
                        isfile=lambda p: False)
    assert out == r"C:\Program Files\Vendor App\svc.dll"


# == the real machine ======================================================
@pytest.mark.skipif(os.name != "nt", reason="services are Windows-only")
def test_the_machines_services_now_resolve_to_real_files():
    """The negative control. Before the fix 490 of 793 entries resolved to
    nothing; a stale service whose file has genuinely been deleted is the only
    legitimate miss, so this allows a small number rather than zero."""
    entries = [e for e in P._collect_windows(CFG)
               if e.kind in ("service", "service-dll")]
    assert len(entries) > 50, "no services read; the survey below means nothing"
    unresolved = [e for e in entries if e.exe and not os.path.isfile(e.exe)]
    assert len(unresolved) <= 5, [(e.name, e.exe) for e in unresolved[:10]]


@pytest.mark.skipif(os.name != "nt", reason="services are Windows-only")
def test_no_service_on_this_machine_is_reported():
    entries = [e for e in P._collect_windows(CFG)
               if e.kind in ("service", "service-dll")]
    noisy = [e for e in (P.score_entry(e, CFG) for e in entries)
             if e.score >= THRESHOLD]
    assert noisy == [], [(e.name, e.exe, e.score, e.labels) for e in noisy]


@pytest.mark.skipif(os.name != "nt", reason="services are Windows-only")
def test_none_of_the_machines_real_drivers_is_called_rogue():
    drivers = [e for e in P._collect_windows(CFG)
               if e.exe.lower().endswith(".sys")]
    assert len(drivers) > 50, "no drivers read; this control means nothing"
    flagged = [e for e in (P.score_entry(e, CFG) for e in drivers)
               if any("kernel driver" in lab for lab in e.labels)]
    assert flagged == [], [(e.name, e.exe) for e in flagged]
