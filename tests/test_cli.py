"""Tests for the headless CLI summary logic."""

from minersentry.cli import summarize
from minersentry.engine import ProcInfo
from minersentry.power import HiddenComputeReport
from minersentry.scoring import Signal


class _StubEngine:
    ncpu = 8

    def __init__(self, report=None):
        self.hidden_report = report or HiddenComputeReport()


def _proc(pid, name, verdict, score, cpu=0.0, gpu=0.0, sigs=None):
    p = ProcInfo(pid, cpu=cpu)
    p.name = name
    p.gpu = gpu
    p.verdict = verdict
    p.score = score
    p.signals = [Signal(n, s, "") for n, s in (sigs or {}).items()]
    return p


def test_summary_excludes_idle_clean():
    res = [_proc(1, "idle.exe", "Clean", 0, cpu=0.1),
           _proc(2, "miner.exe", "Likely Miner", 82, cpu=5, sigs={"cpu": 92, "memory": 100})]
    out = summarize(_StubEngine(), res, {2: 3.5})
    pids = [p["pid"] for p in out["processes"]]
    assert pids == [2]
    assert out["likely_miners"] == 1
    assert out["processes"][0]["ttd_s"] == 3.5
    assert out["processes"][0]["signals"] == {"cpu": 92, "memory": 100}


def test_summary_keeps_busy_clean():
    # a clean but CPU-busy process is still shown (so the operator sees load)
    res = [_proc(5, "ffmpeg.exe", "Clean", 0, cpu=40)]
    out = summarize(_StubEngine(), res, {})
    assert [p["pid"] for p in out["processes"]] == [5]


def test_summary_watch_filter():
    res = [_proc(1, "python.exe", "Likely Miner", 82, cpu=5),
           _proc(2, "svchost.exe", "Suspicious", 50, cpu=5)]
    out = summarize(_StubEngine(), res, {}, watch="python")
    assert [p["name"] for p in out["processes"]] == ["python.exe"]


def test_summary_pid_filter_includes_idle_target():
    # --pid restricts the report to the named PIDs, even an idle/clean one
    res = [_proc(1, "python.exe", "Likely Miner", 82, cpu=5),
           _proc(99, "svchost.exe", "Clean", 0, cpu=0.0)]
    out = summarize(_StubEngine(), res, {}, pids={99})
    assert [p["pid"] for p in out["processes"]] == [99]


def test_summary_hidden_compute_passthrough():
    rep = HiddenComputeReport(flagged=True, note="2.0 cores inside a VM/WSL (vmmem)")
    out = summarize(_StubEngine(rep), [], {})
    assert out["hidden_compute"]["flagged"] is True
    assert "vmmem" in out["hidden_compute"]["note"]
