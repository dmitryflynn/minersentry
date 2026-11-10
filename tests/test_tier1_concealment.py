"""Tier 1: concealment detection (issues #8-#12).

The weights here were chosen from a survey of a real machine rather than
assumed, and these tests pin the conclusions of that survey: private executable
memory is everywhere (72 of 166 processes) so it means nothing alone, while a
missing image and miner strings inside unbacked memory are rare and do.
"""

import sys

import pytest

from minersentry import persistence as P
from minersentry import tamper
from minersentry.config import Config
from minersentry.engine import Engine, ProcInfo
from minersentry.memscan import MemHit, MemScanResult
from minersentry.scoring import Signal, combine, score_cpu, score_stealth

CFG = Config()
NCPU = 20


def _engine(**kw):
    return Engine(cfg=Config(pool_intel_enabled=False, **kw))


def _info(pid=5000, name="worker.exe", exe=r"C:\Temp\worker.exe"):
    i = ProcInfo(pid)
    i.name, i.exe, i.trusted = name, exe, False
    return i


# == the stealth signal ====================================================
def test_nothing_concealed_scores_nothing():
    assert score_stealth([], CFG).score == 0
    assert "nothing concealed" in score_stealth([], CFG).detail


def test_reasons_add_up_and_the_strongest_is_reported_first():
    s = score_stealth([("a quiet thing", 25), ("the loud thing", 55)], CFG)
    assert s.score == 80
    assert s.detail.startswith("the loud thing")


def test_the_signal_can_be_switched_off():
    off = Config(stealth_enabled=False)
    assert score_stealth([("x", 55)], off).score == 0


def test_concealment_alone_never_convicts():
    """Hiding is not mining: a packer, a self-updater and an installer all
    conceal something."""
    lone = score_stealth([("miner strings in unbacked executable memory", 55)], CFG)
    score, verdict = combine([lone], CFG)
    assert verdict != "Likely Miner" and score <= CFG.suspicious_cap


def test_concealment_plus_the_work_convicts():
    strong = score_stealth([("miner strings in unbacked executable memory", 55)], CFG)
    cpu = score_cpu([95.0] * 8, NCPU, CFG)
    assert combine([strong, cpu], CFG)[1] == "Likely Miner"
    assert combine([strong, Signal("gpu", 80, "")], CFG)[1] == "Likely Miner"


def test_weak_concealment_does_not_reach_the_artifact_bar():
    """A moved binary is corroboration. A self-updater does that too."""
    weak = score_stealth([("the image it started from is gone from that path", 35)], CFG)
    assert weak.score < CFG.hard_stealth
    assert combine([weak, score_cpu([95.0] * 8, NCPU, CFG)], CFG)[1] != "Likely Miner"


# == what the engine actually notices ======================================
def test_missing_image_is_noticed_but_a_bare_name_is_not(tmp_path):
    e = _engine()
    gone = _info(exe=str(tmp_path / "deleted.exe"))
    assert any("gone from that path" in label
               for label, _w in e._stealth_reasons(gone))
    # Registry and MemCompression report a bare name, not a path: not evidence
    kernelish = _info(name="MemCompression", exe="MemCompression")
    assert e._stealth_reasons(kernelish) == []
    present = _info(exe=sys.executable)
    assert e._stealth_reasons(present) == []


def test_memfd_and_deleted_suffixes_are_recognised():
    e = _engine()
    for exe in ("memfd:payload (deleted)", "/tmp/x (deleted)"):
        info = _info(exe=exe)
        reasons = e._stealth_reasons(info)
        assert reasons, exe
        assert reasons[0][1] in (CFG.stealth_memfd_image, CFG.stealth_deleted_image)


def test_miner_strings_in_unbacked_memory_are_the_strong_reason():
    e = _engine()
    info = _info(exe=sys.executable)
    info.mem_result = MemScanResult(pid=info.pid, scanned=True, injected_hits=2, hits=[
        MemHit("stratum pool URL scheme", 40, "string", injected=True)])
    reasons = e._stealth_reasons(info)
    assert any(w == CFG.stealth_injected_strings for _label, w in reasons)


def test_private_executable_memory_without_miner_strings_is_not_a_reason():
    """72 of 166 processes on a clean desktop have private executable memory:
    every JIT does. Only markers found inside it count."""
    e = _engine()
    info = _info(exe=sys.executable)
    info.mem_result = MemScanResult(pid=info.pid, scanned=True, injected_hits=0, hits=[
        MemHit("Keccak round constant", 12, "binary", generic=True, injected=True)])
    assert e._stealth_reasons(info) == []


def test_parent_anomaly_only_for_processes_with_one_right_parent():
    e = _engine()
    e._parent_names = {7001: "explorer.exe", 7002: "services.exe", 7003: "cmd.exe"}
    bad = _info(pid=7001, name="svchost.exe", exe=r"C:\Windows\System32\svchost.exe")
    good = _info(pid=7002, name="svchost.exe", exe=r"C:\Windows\System32\svchost.exe")
    # conhost has many honest parents and is deliberately not in the rule list
    other = _info(pid=7003, name="conhost.exe", exe=r"C:\Windows\System32\conhost.exe")
    assert "started by explorer.exe" in e._parent_anomaly(bad)
    assert e._parent_anomaly(good) == ""
    assert e._parent_anomaly(other) == ""


def test_an_exited_parent_is_unknown_not_wrong():
    e = _engine()
    e._parent_names = {}
    info = _info(pid=7004, name="svchost.exe", exe=r"C:\Windows\System32\svchost.exe")
    assert e._parent_anomaly(info) == ""


def test_stealth_stays_silent_across_this_machine():
    """The survey found no real process with any stealth reason. If that stops
    being true, the weights need revisiting before anyone trusts them."""
    e = _engine()
    for _ in range(3):
        results = e.scan_once()
    noisy = [r for r in results
             if next((s.score for s in r.signals if s.name == "stealth"), 0) > 0]
    assert noisy == [], [(r.name, r.signal_summary) for r in noisy[:5]]


# == defensive tampering ===================================================
def test_hosts_parsing_and_blackholed_security_domains():
    text = ("# a comment\n"
            "127.0.0.1 localhost\n"
            "0.0.0.0 www.virustotal.com\n"
            "0.0.0.0   update.microsoft.com windowsupdate.microsoft.com\n"
            "192.168.1.5 printer.local\n")
    entries = tamper.parse_hosts(text)
    assert ("127.0.0.1", "localhost") in entries
    blocked = dict(tamper.blackholed_security_domains(entries))
    assert "www.virustotal.com" in blocked.values() or \
        any("virustotal" in h for _ip, h in tamper.blackholed_security_domains(entries))
    hosts = [h for _ip, h in tamper.blackholed_security_domains(entries)]
    assert "printer.local" not in hosts and "localhost" not in hosts


def test_an_exclusion_message_is_not_mistaken_for_a_path():
    """Get-MpPreference answers an unprivileged caller with a sentence in the
    field where paths go; it was reported as an excluded folder."""
    assert tamper.parse_mppreference(
        "N/A: Must be an administrator to view exclusions\n") == []
    assert tamper.looks_like_a_path(r"C:\Temp\miner")
    assert tamper.looks_like_a_path("/opt/miner")
    assert not tamper.looks_like_a_path("N/A: Must be an administrator")
    assert not tamper.looks_like_a_path("")


def test_unreadable_exclusions_are_reported_as_unknown(monkeypatch):
    def denied():
        raise PermissionError("Must be an administrator")
    monkeypatch.setattr(tamper, "_defender_exclusions", denied)
    monkeypatch.setattr(tamper, "_defender_disabled", lambda: [])
    monkeypatch.setattr(tamper, "_read", lambda p: "")
    found = tamper.scan()
    assert [f.kind for f in found] == ["defender-unreadable"]
    assert found[0].score == 0          # not a finding, and not a clean bill either


def test_an_exclusion_over_a_flagged_path_outranks_a_plain_one(monkeypatch):
    monkeypatch.setattr(tamper, "_defender_exclusions",
                        lambda: [r"C:\Users\x\AppData\Local\Temp\miner"])
    monkeypatch.setattr(tamper, "_defender_disabled", lambda: [])
    monkeypatch.setattr(tamper, "_read", lambda p: "")
    plain = tamper.scan()[0].score
    linked = tamper.scan(flagged_paths=(
        r"C:\Users\x\AppData\Local\Temp\miner\sysworker.exe",))[0].score
    assert linked > plain


def test_disabled_protection_is_reported(monkeypatch):
    monkeypatch.setattr(tamper, "_defender_exclusions", lambda: [])
    monkeypatch.setattr(tamper, "_defender_disabled",
                        lambda: [("HKLM\\...\\DisableAntiSpyware", "Defender is off")])
    monkeypatch.setattr(tamper, "_read", lambda p: "")
    found = tamper.scan()
    assert found and found[0].kind == "defender-disabled" and found[0].score >= 70


def test_live_tamper_scan_returns_well_formed_findings():
    """Runs against whatever machine this is, and checks the shape rather than
    the result.

    An earlier version asserted "nothing is tampered with here", which is a
    fact about one desktop and not about the code. CI disproved it the honest
    way: the GitHub Windows runner excludes `C:\\` and `D:\\` from Defender
    entirely, and the scan reported both — correctly.
    """
    kinds = {"defender-exclusion", "defender-disabled", "hosts-blackhole",
             "defender-unreadable"}
    for f in tamper.scan():
        assert f.kind in kinds, f.kind
        assert 0 <= f.score <= 100
        assert f.detail and f.where
        assert isinstance(f.labels, list)


def test_an_exclusion_covering_a_whole_drive_scores_high(monkeypatch):
    """What the CI runner turned out to have: the entire drive excluded."""
    monkeypatch.setattr(tamper, "_defender_exclusions", lambda: ["C:\\"])
    monkeypatch.setattr(tamper, "_defender_disabled", lambda: [])
    monkeypatch.setattr(tamper, "_read", lambda p: "")
    found = tamper.scan()
    assert found[0].kind == "defender-exclusion" and found[0].score >= 70
    assert any("whole drive" in label for label in found[0].labels)


# == the remaining autostart locations =====================================
def test_bits_job_parser():
    jobs = P.parse_bits_jobs("Updater\tC:\\Temp\\x.exe -o pool.supportxmr.com:3333\nNone\t\n")
    assert [j.kind for j in jobs] == ["bits-job"]
    assert jobs[0].exe == r"C:\Temp\x.exe"


def test_xdg_autostart_parser():
    desktop = "[Desktop Entry]\nType=Application\nExec=/tmp/miner -o pool:3333\n"
    got = P.parse_desktop_entry(desktop, "/home/x/.config/autostart/m.desktop")
    assert [e.kind for e in got] == ["xdg-autostart"] and got[0].exe == "/tmp/miner"
    assert P.parse_desktop_entry(desktop + "Hidden=true\n", "x") == []
    assert P.parse_desktop_entry("[Desktop Entry]\nType=Application\n", "x") == []


def test_authorized_keys_forced_command_parser():
    keys = ('command="/tmp/miner -o pool:3333" ssh-rsa AAAA user@host\n'
            "ssh-rsa AAAB plain@host\n"
            "# comment\n")
    got = P.parse_authorized_keys(keys, "/home/x/.ssh/authorized_keys")
    assert len(got) == 1 and got[0].exe == "/tmp/miner"
    assert got[0].kind == "ssh-forced-command"


@pytest.mark.parametrize("kind", ["ld-preload", "ssh-forced-command"])
def test_the_new_rare_locations_carry_weight(kind):
    plain = r"C:\Windows\System32\cmd.exe" if sys.platform == "win32" else "/bin/sh"
    rare = P.score_entry(P.PersistEntry(kind=kind, location="x", name="y",
                                        command=plain, exe=plain),
                         CFG, is_trusted=lambda *a: True, isfile=lambda p: True)
    assert rare.score == P.W_RARE_LOCATION
    assert rare.labels


def test_scan_still_reports_nothing_on_this_machine():
    assert P.scan(CFG) == []
