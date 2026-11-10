"""Phase 4 and the Phase 3 GPU profile: autostart scanning, response actions,
the tray, service tamper detection, and the GPU sampling fix."""

import json
import os
import sys
import time

import psutil
import pytest

from minersentry import gpu as gpu_mod
from minersentry import persistence, quarantine, service, tray
from minersentry.config import Config

CFG = Config()
WALLET = "4" + "9" * 94
MINER_CMD = (r'"C:\Users\x\AppData\Local\Temp\w\sysworker.exe" '
             f"-o pool.supportxmr.com:3333 -u {WALLET} -p x --donate-level=1")


def entry(**kw):
    kw.setdefault("kind", "run-key")
    kw.setdefault("location", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run")
    kw.setdefault("name", "Updater")
    kw.setdefault("command", "")
    e = persistence.PersistEntry(**kw)
    e.exe = e.exe or persistence.command_exe(e.command)
    return e


# == autostart: the executable must be identified correctly ================
def test_command_exe_handles_quotes_wrappers_and_spaces():
    f = persistence.command_exe
    assert f(r'"C:\Tools\x.exe" -o pool:3333') == r"C:\Tools\x.exe"
    assert f(r"C:\Tools\x.exe -o pool:3333") == r"C:\Tools\x.exe"
    assert f(r'cmd /c "C:\Tools\x.exe"') == r"C:\Tools\x.exe"
    assert f("") == "" and f(None) == ""
    # the bug this had: an unquoted path with spaces was cut at the first space,
    # and the truncated prefix happened to exist as a FOLDER
    unquoted = r"C:\ProgramData\Microsoft\Windows Defender\Platform\MpCmdRun.exe -t 4"
    assert f(unquoted, isfile=lambda p: p.endswith("MpCmdRun.exe")) == \
        r"C:\ProgramData\Microsoft\Windows Defender\Platform\MpCmdRun.exe"


def test_miner_autostart_entry_is_reported():
    e = persistence.score_entry(entry(command=MINER_CMD), CFG,
                                is_trusted=lambda *a: False)
    assert e.score >= CFG.persistence_min_score
    assert any("pool" in lab for lab in e.labels)


@pytest.mark.parametrize("command", [
    r'"C:\Program Files\Vendor\updater.exe" --check -t 4',
    r'"C:\Program Files\Steam\steam.exe" -silent',
    r'C:\Windows\System32\rundll32.exe shell32.dll,Something',
])
def test_ordinary_autostart_entries_are_not_reported(command):
    e = persistence.score_entry(entry(command=command), CFG, is_trusted=lambda *a: True)
    assert e.score < CFG.persistence_min_score, e.labels


def test_a_signed_binary_is_not_charged_for_its_directory():
    """Defender runs signed from ProgramData; charging it for that put its own
    scheduled tasks one point under the reporting threshold."""
    cmd = r'"C:\ProgramData\Microsoft\Windows Defender\Platform\MpCmdRun.exe" -t 4'
    exists = lambda p: p.endswith("MpCmdRun.exe")   # noqa: E731 - test stub
    signed = persistence.score_entry(entry(command=cmd), CFG,
                                     is_trusted=lambda *a: True, isfile=exists)
    unsigned = persistence.score_entry(entry(command=cmd), CFG,
                                       is_trusted=lambda *a: False, isfile=exists)
    # signed keeps only the generic "-t" flag; it loses the drop-location and
    # unsigned weights that together took it to within a point of reporting
    assert signed.score < CFG.persistence_min_score
    assert not any("runs from" in lab for lab in signed.labels)
    assert unsigned.score >= signed.score + persistence.W_DROP_DIR


# == autostart: parsers ====================================================
def test_schtasks_parser_skips_disabled_and_com_handlers():
    text = (
        '"Folder: \\"\n'
        '"HostName","TaskName","Next Run Time","Status","Task To Run","Scheduled Task State"\n'
        '"PC","\\MinerTask","N/A","Ready","C:\\Temp\\x.exe -o pool:3333","Enabled"\n'
        '"PC","\\OffTask","N/A","Disabled","C:\\Temp\\y.exe","Disabled"\n'
        '"PC","\\ComTask","N/A","Ready","COM handler","Enabled"\n')
    out = persistence.parse_schtasks_csv(text)
    assert [e.name for e in out] == ["MinerTask"]
    assert out[0].exe == r"C:\Temp\x.exe"


def test_crontab_parser_handles_user_and_system_tables():
    user = persistence.parse_crontab("*/5 * * * * /tmp/x -o pool:3333\n# a note\n",
                                     "crontab")
    assert len(user) == 1 and user[0].exe == "/tmp/x"
    system = persistence.parse_crontab("*/5 * * * * root /tmp/y --donate-level=1\n",
                                       "/etc/cron.d/miner")
    assert len(system) == 1 and system[0].exe == "/tmp/y"
    assert persistence.parse_crontab("@reboot /tmp/z\n", "crontab")[0].exe == "/tmp/z"
    assert persistence.parse_crontab("PATH=/usr/bin\n\n", "crontab") == []


def test_systemd_parser_reads_execstart():
    unit = ("[Unit]\nDescription=x\n\n[Service]\n"
            "ExecStart=-/opt/m/miner --donate-level=1\n"
            "ExecStop=/bin/true\n")
    out = persistence.parse_systemd_unit(unit, "/etc/systemd/system/m.service")
    assert len(out) == 1 and out[0].exe == "/opt/m/miner"


def test_shortcut_target_parser():
    text = "C:\\a\\x.lnk\tC:\\Tools\\real.exe\t--flag\nC:\\a\\y.lnk\tC:\\b.exe\t\n"
    got = persistence.parse_shortcut_targets(text)
    assert got["C:\\a\\x.lnk"] == '"C:\\Tools\\real.exe" --flag'
    assert got["C:\\a\\y.lnk"] == "C:\\b.exe"
    assert persistence.parse_shortcut_targets("junk") == {}


def test_scan_is_quiet_on_this_machine():
    """A scanner that reports a dozen normal entries is a scanner nobody reads."""
    found = persistence.scan(CFG)
    assert found == [] or all(e.score >= CFG.persistence_min_score for e in found)
    assert persistence.summarize(found) == [] or "score" in persistence.summarize(found)[0]


def test_scan_respects_the_off_switch():
    assert persistence.scan(Config(persistence_enabled=False)) == []


# == response actions ======================================================
def test_suspend_and_resume_a_real_process():
    import subprocess
    p = subprocess.Popen([sys.executable, "-I", "-c", "import time; time.sleep(30)"])
    try:
        time.sleep(0.6)
        r = quarantine.suspend(p.pid)
        assert r.ok, r.message
        assert psutil.Process(p.pid).status() == psutil.STATUS_STOPPED
        assert "resume" in r.undo
        back = quarantine.resume(p.pid)
        assert back.ok
        assert psutil.Process(p.pid).status() != psutil.STATUS_STOPPED
    finally:
        p.kill()


def test_suspend_reports_a_missing_process():
    r = quarantine.suspend(999_999)
    assert not r.ok and "gone" in r.message


def test_quarantine_and_restore_round_trip(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    f = tmp_path / "work" / "sysworker.exe"
    f.parent.mkdir()
    f.write_bytes(b"not a real binary")
    r = quarantine.quarantine_file(str(f))
    assert r.ok, r.message
    assert not f.exists()
    held = quarantine.quarantined()
    assert len(held) == 1 and held[0]["original"] == str(f)
    back = quarantine.restore_file(held[0]["stored"])
    assert back.ok and f.exists()
    assert quarantine.quarantined() == []


def test_quarantine_refuses_while_the_binary_is_running(tmp_path, monkeypatch):
    import shutil
    import subprocess
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    copy = tmp_path / "runner.exe"
    shutil.copy2(sys.executable, copy)
    p = subprocess.Popen([str(copy), "-I", "-c", "import time; time.sleep(30)"])
    try:
        time.sleep(1.0)
        r = quarantine.quarantine_file(str(copy))
        assert not r.ok and "still running" in r.message
    finally:
        p.kill()
        p.wait(timeout=10)


def test_quarantine_will_not_overwrite_a_restored_original(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    f = tmp_path / "x.exe"
    f.write_bytes(b"a")
    assert quarantine.quarantine_file(str(f)).ok
    stored = quarantine.quarantined()[0]["stored"]
    f.write_bytes(b"something else is there now")
    back = quarantine.restore_file(stored)
    assert not back.ok and "not overwriting" in back.message


def test_firewall_actions_validate_and_require_privileges(monkeypatch):
    assert not quarantine.block_ip("nope").ok
    assert not quarantine.block_ip("1.2.3.4.5").ok
    monkeypatch.setattr(quarantine, "is_elevated", lambda: False)
    r = quarantine.block_ip("203.0.113.9")
    assert not r.ok and ("Administrator" in r.message or "root" in r.message)
    assert not quarantine.unblock_ip("203.0.113.9").ok


def test_actions_are_journalled(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    f = tmp_path / "y.exe"
    f.write_bytes(b"a")
    quarantine.quarantine_file(str(f))
    recs = quarantine.history()
    assert recs and recs[-1]["action"] == "quarantine_file"
    assert json.dumps(recs[-1])          # serializable, so it can be shown anywhere


# == tray ==================================================================
@pytest.mark.skipif(sys.platform != "win32", reason="the tray is Windows-only")
def test_tray_icon_appears_and_dispatches_its_menu():
    clicked = []
    icon = tray.TrayIcon(tooltip="MinerSentry (test)", items=[
        tray.MenuItem("First", lambda: clicked.append("first")),
        tray.MenuItem("", None),
        tray.MenuItem("Second", lambda: clicked.append("second"))])
    assert icon.start(), icon.error
    try:
        assert icon.notify("MinerSentry", "test balloon")
        icon._invoke(0)
        icon._invoke(2)
        deadline = time.time() + 3
        while len(clicked) < 2 and time.time() < deadline:
            time.sleep(0.05)
        assert clicked == ["first", "second"]
    finally:
        icon.stop()
    assert icon._hwnd == 0


def test_tray_is_a_no_op_off_windows(monkeypatch):
    monkeypatch.setattr(tray, "IS_WINDOWS", False)
    icon = tray.TrayIcon(items=[tray.MenuItem("x", lambda: None)])
    assert not icon.start()
    assert "Windows-only" in icon.error
    assert not icon.notify("a", "b")


# == service: tamper detection and autostart alerts ========================
def test_service_alerts_on_a_new_autostart_entry(monkeypatch, tmp_path):
    from minersentry.audit import AuditLog
    from minersentry import engine as engine_module

    monkeypatch.setattr(engine_module.psutil, "process_iter", lambda *a, **k: iter([]))
    monkeypatch.setattr(engine_module.psutil, "net_connections", lambda **k: [])
    monkeypatch.setattr(engine_module.psutil, "cpu_percent", lambda *a: 5.0)
    found = [persistence.score_entry(entry(command=MINER_CMD), CFG,
                                     is_trusted=lambda *a: False)]
    monkeypatch.setattr(service.persist_mod, "scan", lambda cfg: found)
    sent = []
    monkeypatch.setattr(service, "notify", lambda t, b, c=None: sent.append((t, b)))
    log = AuditLog(path=str(tmp_path / "d.jsonl"))
    cfg = Config(pool_intel_enabled=False, gpu_enabled=False, deep_auto_interval=0,
                 persistence_interval=1.0)
    alerts = service.run(cfg=cfg, once=True, audit=log)
    assert alerts == 1
    assert sent and "autostart" in sent[0][0]
    assert "Autostart" in (tmp_path / "d.jsonl").read_text(encoding="utf-8")


def test_service_notices_its_autostart_entry_being_removed(monkeypatch, tmp_path):
    from minersentry.audit import AuditLog
    from minersentry import engine as engine_module

    monkeypatch.setattr(engine_module.psutil, "process_iter", lambda *a, **k: iter([]))
    monkeypatch.setattr(engine_module.psutil, "net_connections", lambda **k: [])
    monkeypatch.setattr(engine_module.psutil, "cpu_percent", lambda *a: 5.0)
    monkeypatch.setattr(service.persist_mod, "scan", lambda cfg: [])
    states = iter(["installed (elevated=True)", "not installed"])
    monkeypatch.setattr(service, "status", lambda: next(states, "not installed"))
    events = []
    log = AuditLog(path=str(tmp_path / "d.jsonl"), on_event=events.append)
    sent = []
    monkeypatch.setattr(service, "notify", lambda t, b, c=None: sent.append((t, b)))
    cfg = Config(pool_intel_enabled=False, gpu_enabled=False, deep_auto_interval=0,
                 persistence_interval=0, tamper_check_interval=1.0)
    service.run(cfg=cfg, once=True, audit=log)
    assert any("tamper" in e for e in events), events
    assert sent and "removed" in sent[0][0]


# == the GPU sampling fix ==================================================
def test_engine_counter_parser_can_be_asked_for_other_engine_types():
    text = ('"(PDH-CSV 4.0)","\\\\PC\\GPU Engine(pid_42_luid_0_phys_0_eng_0_engtype_3D)'
            '\\Utilization Percentage","\\\\PC\\GPU Engine(pid_43_luid_0_phys_0_eng_1'
            '_engtype_Compute)\\Utilization Percentage"\n'
            '"10/10/2026 00:00:00.000","0.000000","0.000000"\n'
            '"10/10/2026 00:00:01.000","55.500000","22.250000"\n')
    assert gpu_mod.parse_gpu_engine_counters(text) == {43: 22.25}      # Compute only
    assert gpu_mod.parse_gpu_engine_counters(text, ("3D",)) == {42: 55.5}
    both = gpu_mod.parse_gpu_engine_counters(text, ("Compute", "3D"))
    assert both == {42: 55.5, 43: 22.25}
    # the LAST sample is used: PDH's first row of a rate counter is always zero
    assert 0.0 not in both.values()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows sampling path")
def test_windows_sampler_prefers_pmon_over_pdh(monkeypatch):
    monkeypatch.setattr(gpu_mod, "_run", lambda args, timeout: (
        "# gpu        pid  type    sm   mem\n"
        "# Idx          #   C/G     %     %\n"
        "    0        777     C    91     0\n") if "pmon" in args else "")
    monkeypatch.setattr(gpu_mod, "_sample_pdh", lambda ctx: {888: 12.0})
    util = gpu_mod._sample_windows({777})
    assert util[777] == 91.0          # pmon wins where it reports
    assert util[888] == 12.0          # PDH still fills in the rest


def test_gpu_load_sample_is_importable_and_honest_about_missing_opencl(monkeypatch):
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "samples"))
    import gpu_load
    monkeypatch.setattr(gpu_load, "_load",
                        lambda: (_ for _ in ()).throw(gpu_load.OpenCLUnavailable("none")))
    assert gpu_load.main(["--seconds", "0.1"]) == 2     # non-zero, not a fake success
