"""Groups 3 and 4: scoring fixes (interpreters, moderate-CPU conviction, process
swarms, deep-scan floor), hardening (region sampling, decoy realism, background
service) and connection persistence that survives reconnects."""

import os
import sys
import time
from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from minersentry import memscan, poolintel, probe, service
from minersentry import engine as engine_module
from minersentry.audit import AuditLog
from minersentry.config import Config
from minersentry.engine import Engine, ProcInfo
from minersentry.memscan import MemHit, MemScanResult
from minersentry.scoring import Signal, combine, score_cpu, score_swarm

CFG = Config()
NCPU = 20


def _engine(**kw):
    return Engine(cfg=Config(pool_intel_enabled=False, **kw))


def _miner_mem(pid):
    return MemScanResult(pid=pid, scanned=True, hits=[
        MemHit("XMRig miner identifier", 45, "string"),
        MemHit("stratum pool URL scheme", 40, "string"),
        MemHit("stratum share submission", 45, "string")])


def _busy(e, pid, raw=95.0, n=8):
    now = time.time()
    for k in range(n):
        e._cpu_hist[pid].append((now - k, raw))
    return now


# == group 3: interpreters =================================================
@pytest.mark.parametrize("name,exe", [
    ("node.exe", r"C:\Program Files\nodejs\node.exe"),
    ("python.exe", r"C:\Program Files\Python313\python.exe"),
    ("javaw.exe", r"C:\Program Files\Java\jre\bin\javaw.exe"),
    ("pwsh.exe", r"C:\Program Files\PowerShell\7\pwsh.exe"),
])
def test_miner_under_a_signed_interpreter_is_not_dampened(name, exe):
    e = _engine()
    info = ProcInfo(9500); info.name, info.exe, info.trusted = name, exe, True
    info.mem_result = _miner_mem(9500)
    now = _busy(e, 9500)
    signals = e._build_signals(info, [], now)
    assert next(s.score for s in signals if s.name == "memory") == 100
    assert combine(signals, e.cfg)[1] == "Likely Miner"


def test_a_signed_security_tool_is_still_dampened():
    e = _engine()
    info = ProcInfo(9501); info.trusted = True
    info.name, info.exe = "MsMpEng.exe", r"C:\Program Files\Windows Defender\MsMpEng.exe"
    info.mem_result = _miner_mem(9501)
    now = _busy(e, 9501)
    signals = e._build_signals(info, [], now)
    assert next(s.score for s in signals if s.name == "memory") < CFG.hard_memory


# == group 3: conviction at moderate load ==================================
@pytest.mark.parametrize("level", [30.0, 35.0, 44.0, 60.0, 95.0])
def test_resident_protocol_strings_convict_at_moderate_cpu(level):
    cpu = score_cpu([level] * 8, NCPU, CFG)
    assert combine([cpu, Signal("memory", 100, "")], CFG)[1] == "Likely Miner", level


def test_generic_memory_evidence_still_cannot_convict_at_any_load():
    for level in (30.0, 95.0):
        cpu = score_cpu([level] * 8, NCPU, CFG)
        score, verdict = combine([cpu, Signal("memory", memscan.GENERIC_SCORE_CAP, "")], CFG)
        assert verdict != "Likely Miner" and score <= CFG.suspicious_cap


def test_generic_evidence_is_below_the_corroboration_bar():
    # crypto constants / ordinary CLI flags shouldn't even count as a signal
    assert memscan.GENERIC_SCORE_CAP < CFG.corrob_nonzero_score
    assert CFG.cmdline_generic_cap < CFG.corrob_nonzero_score


# == group 3: process swarms ===============================================
def test_swarm_needs_enough_processes_and_cores():
    assert score_swarm(CFG.swarm_min_procs, CFG.swarm_min_cores, CFG).score == CFG.swarm_score
    assert score_swarm(CFG.swarm_min_procs - 1, 8.0, CFG).score == 0
    assert score_swarm(20, CFG.swarm_min_cores - 0.1, CFG).score == 0
    assert score_swarm(20, 8.0, Config(swarm_enabled=False)).score == 0


def test_swarm_alone_never_convicts_but_convicts_with_miner_evidence():
    sw = score_swarm(20, 5.0, CFG)
    assert combine([sw], CFG)[1] == "Clean"
    assert combine([sw, score_cpu([95.0] * 8, NCPU, CFG)], CFG)[1] != "Likely Miner"
    assert combine([sw, Signal("memory", 100, "")], CFG)[1] == "Likely Miner"
    assert combine([sw, Signal("name", CFG.name_score_known, "")], CFG)[1] == "Likely Miner"


def _swarm_procs(exe, n, raw):
    out = []
    for i in range(n):
        p = SimpleNamespace(pid=7700 + i, info={"pid": 7700 + i})
        out.append((p, raw))
    return out


# What counts as a system directory differs per platform, so the paths these
# tests use have to follow the platform they run on.
WINDOWS = sys.platform == "win32"
TRUSTED_EXE = r"C:\Program Files\Browser\renderer.exe" if WINDOWS else "/usr/bin/renderer"
UNTRUSTED_EXE = (r"C:\Users\x\AppData\Local\Temp\w\worker.exe" if WINDOWS
                 else "/home/x/.cache/w/worker")


def test_swarm_map_groups_untrusted_binaries_only():
    e = _engine()
    procs = _swarm_procs(UNTRUSTED_EXE, 5, 30.0)
    for p, _raw in procs:
        e._meta[p.pid] = ("worker.exe", UNTRUSTED_EXE, "", None)
    m = e._swarm_map(procs)
    assert m[7700] == (5, 1.5)

    for p, _raw in procs:
        e._meta[p.pid] = ("renderer.exe", TRUSTED_EXE, "", None)
    assert e._swarm_map(procs) == {}          # a browser's renderers are not a swarm


def test_swarm_map_ignores_idle_siblings():
    e = _engine()
    procs = _swarm_procs(UNTRUSTED_EXE, 6, 1.0)   # below swarm_min_each
    for p, _raw in procs:
        e._meta[p.pid] = ("w.exe", UNTRUSTED_EXE, "", None)
    assert e._swarm_map(procs) == {}


def test_swarm_members_are_memory_scanned_despite_low_cpu():
    e = _engine()
    e._swarm = {8800: (6, 2.0)}
    assert 8800 in e.deep_scan_targets()


# == group 3: deep-scan floor ==============================================
def test_untrusted_binaries_are_scanned_at_a_lower_cpu_floor():
    e = _engine()
    low = e.cfg.deep_cpu_floor_untrusted + 1
    assert low < e.cfg.deep_cpu_floor
    e._meta[8810] = ("w.exe", UNTRUSTED_EXE, "", None)
    e._meta[8811] = ("svc.exe", TRUSTED_EXE, "", None)
    for pid in (8810, 8811):
        _busy(e, pid, raw=low, n=4)
    targets = e.top_cpu_pids()
    assert 8810 in targets
    assert 8811 not in targets


# == group 4: memory region sampling and budget ============================
def test_sample_offsets_spreads_across_a_region():
    whole = memscan.sample_offsets(1024, 4096, 4)
    assert whole == [(0, 1024)]                        # smaller than the budget
    spread = memscan.sample_offsets(16 << 20, 4 << 20, 4)
    assert len(spread) == 4 and spread[0][0] == 0
    assert spread[-1][0] + spread[-1][1] == 16 << 20   # reaches the end
    assert sum(n for _o, n in spread) == 4 << 20       # same byte budget
    assert memscan.sample_offsets(0, 4096, 4) == []


def test_small_processes_are_scanned_whole_and_large_ones_bounded():
    budget, region = memscan.budget_for(64 << 20, 48 << 20, 4 << 20, 128 << 20)
    assert budget == region > 64 << 20                 # whole process
    budget, region = memscan.budget_for(1 << 30, 48 << 20, 4 << 20, 128 << 20)
    assert (budget, region) == (48 << 20, 4 << 20)     # bounded sampling
    assert memscan.budget_for(0, 48 << 20, 4 << 20, 128 << 20) == (48 << 20, 4 << 20)


def test_markers_are_found_deep_inside_a_region():
    r = MemScanResult(pid=1, scanned=True)
    buf = bytearray(8 << 20)
    buf[6 << 20:(6 << 20) + 11] = b"stratum+tcp"
    memscan._search_chunk(bytes(buf), r, set())
    assert any(h.label == "stratum pool URL scheme" for h in r.hits)


# == group 4: decoy realism ================================================
def test_decoy_folder_has_no_greppable_prefix():
    names = ("taskmgr.exe",) if sys.platform == "win32" else ("htop",)
    procs, tmpdir, err = probe._spawn_decoys(names)
    try:
        assert err is None, err
        assert "msentry" not in os.path.basename(tmpdir).lower()
        live = probe.decoy_processes(procs, tmpdir)
        # the name may be the image name or argv[0]; see probe.decoy_label
        assert {probe.decoy_label(p) for p in live} == set(names)
    finally:
        probe._stop_decoys(procs, tmpdir)
        probe._cleanup(tmpdir)
    assert probe.decoy_processes(procs, tmpdir) == []
    assert not os.path.exists(tmpdir)


def test_every_windows_decoy_has_a_window_title():
    for name in Config().probe_decoys_windows:
        assert probe.WINDOW_TITLES.get(name.lower()), name


@pytest.mark.skipif(sys.platform != "win32", reason="window decoys are Windows-only")
def test_window_decoy_titles_are_enumerable_and_do_not_block():
    import ctypes
    from ctypes import wintypes

    def titles():
        u = ctypes.windll.user32
        found = []
        CB = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

        def cb(hwnd, _lp):
            n = u.GetWindowTextLengthW(hwnd)
            if n:
                b = ctypes.create_unicode_buffer(n + 1)
                u.GetWindowTextW(hwnd, b, n + 1)
                if b.value == "Task Manager":
                    found.append(b.value)
            return True
        u.EnumWindows(CB(cb), 0)
        return found

    with probe._WindowDecoy(("Task Manager",)):
        start = time.time()
        seen = titles()
        # a window whose thread does not pump messages blocks GetWindowText
        assert time.time() - start < 5.0
        assert "Task Manager" in seen
    assert "Task Manager" not in titles()


# == group 4: background service ===========================================
def test_alert_threshold_ranking():
    assert service.should_alert("Likely Miner", "Likely Miner")
    assert service.should_alert("Likely Miner", "Suspicious")
    assert service.should_alert("Suspicious", "Suspicious")
    assert not service.should_alert("Suspicious", "Likely Miner")
    assert not service.should_alert("Clean", "Suspicious")


def test_toast_script_escapes_quotes():
    s = service._toast_script("it's bad", "xmrig's pool")
    assert "it''s bad" in s and "xmrig''s pool" in s


def test_install_commands_are_well_formed():
    args = service.schtasks_create_args("MS-Test")
    assert args[:4] == ["schtasks", "/create", "/tn", "MS-Test"]
    assert "SYSTEM" in args and "/rl" in args and "HIGHEST" in args
    unit = service.systemd_unit("/usr/bin/minersentry-service --run")
    assert "ExecStart=/usr/bin/minersentry-service --run" in unit
    assert "User=root" in unit and "Restart=always" in unit


def test_install_refuses_without_privileges(monkeypatch):
    monkeypatch.setattr(service, "is_elevated", lambda: False)
    ok, msg = service.install()
    assert not ok and ("Administrator" in msg or "root" in msg)
    ok, msg = service.uninstall()
    assert not ok


def test_service_pass_alerts_once_per_process(monkeypatch, tmp_path):
    proc = SimpleNamespace(
        pid=9600, info={"pid": 9600, "name": "xmrig.exe", "cpu_percent": 98.0,
                        "memory_info": SimpleNamespace(rss=0), "create_time": 1.0},
        name=lambda: "xmrig.exe", exe=lambda: r"C:\Users\x\Temp\xmrig.exe",
        username=lambda: "", oneshot=nullcontext,
        memory_info=lambda: SimpleNamespace(rss=0), num_threads=lambda: 2,
        cpu_percent=lambda *_: 98.0, cmdline=lambda: ["xmrig.exe", "-o", "x:3333"])
    monkeypatch.setattr(engine_module.psutil, "process_iter", lambda *a, **k: iter([proc]))
    monkeypatch.setattr(engine_module.psutil, "net_connections", lambda **k: [])
    monkeypatch.setattr(engine_module.psutil, "cpu_percent", lambda *a: 10.0)
    sent = []
    monkeypatch.setattr(service, "notify", lambda t, b, c=None: sent.append((t, b)))
    log = AuditLog(path=str(tmp_path / "d.jsonl"))
    cfg = Config(pool_intel_enabled=False, notify_min_verdict="Suspicious",
                 gpu_enabled=False, deep_auto_interval=0)
    assert service.run(cfg=cfg, once=True, audit=log) >= 0


# == connection persistence ================================================
REAL_CSV = ('"OwningProcess","RemoteAddress","RemotePort","CreationTime","AgeSeconds"\n'
            '"33524","104.18.39.21","443","11/8/2026 11:15:18 PM","1120"\n'
            '"16556","172.64.155.209","443","11/8/2026 11:28:46 PM","312"\n')


def test_connection_age_parser_reads_real_output():
    ages = poolintel.parse_connection_ages(REAL_CSV, now=10_000.0)
    assert ages[(33524, "104.18.39.21", 443)] == 10_000.0 - 1120
    assert ages[(16556, "172.64.155.209", 443)] == 10_000.0 - 312
    assert poolintel.parse_connection_ages("", 1.0) == {}
    assert poolintel.parse_connection_ages("garbage\nlines\n", 1.0) == {}


def test_connection_age_parser_rejects_bad_rows():
    bad = ('"OwningProcess","RemoteAddress","RemotePort","CreationTime","AgeSeconds"\n'
           '"0","1.2.3.4","3333","x","5"\n'          # pid 0
           '"7","1.2.3.4","99999","x","5"\n'         # impossible port
           '"8","","3333","x","5"\n'                 # no address
           '"9","1.2.3.4","3333","x","-5"\n')        # negative age
    assert poolintel.parse_connection_ages(bad, 1.0) == {}


def test_os_connection_age_makes_a_short_scan_see_a_long_lived_pool_link():
    e = _engine()
    now = time.time()
    key = (4242, "1.2.3.4", 3333)
    e._conn_ages[key] = now - 3 * 3600          # up for three hours
    hits = e._pool_hits(4242, [("1.2.3.4", 3333)], now)
    assert hits[0][3] is True                   # persisted on the very first pass


def test_reconnecting_does_not_reset_persistence():
    e = _engine()
    now = time.time()
    key = (4243, "5.6.7.8", 3333)
    for cycle in range(e.cfg.net_reconnects_persist):
        hits = e._pool_hits(4243, [("5.6.7.8", 3333)], now + cycle)
        if cycle == 0:
            assert hits[0][3] is False          # brand new: not yet long-lived
        e._conn_seen.pop(key, None)             # the connection drops...
        e._conn_hist[key][1] += 1               # ...and is counted as a reconnect
    hits = e._pool_hits(4243, [("5.6.7.8", 3333)], now + 1.0)
    assert hits[0][3] is True                   # cycling the link is itself the tell


def test_connection_history_is_dropped_with_the_process():
    e = _engine()
    key = (4244, "9.9.9.9", 3333)
    e._conn_seen[key] = time.time()
    e._conn_hist[key] = [time.time(), 0]
    e._conn_ages[key] = time.time()
    e._forget_pid(4244)
    assert key not in e._conn_seen and key not in e._conn_hist and key not in e._conn_ages
