"""In-browser mining (issue #17), and the scanner bug it exposed.

Measured with a benign page in headless Edge that pins one core and holds the
text a web miner keeps in memory:

    before   Clean 1     CPU "gathering samples", memory 2 (37 MiB read)
    after    Likely Miner 82, first flagged 27 s in

and the control, a page that pins a core and holds nothing:

    after    Clean 30    CPU 92, memory 24 (generic markers only)

Three separate faults stood between those. Passes slowed by the memory sweep
starved the CPU window (its own issue and tests). The read budget was sized
from private bytes but spent on everything readable, so DLL images used it up
before the heap. And a renderer's memory evidence inherited the browser's
signature.
"""

from types import SimpleNamespace

import pytest

from minersentry import memscan
from minersentry.config import Config
from minersentry.engine import Engine
from minersentry.scoring import Signal, is_browser_content_process

MIB = 1024 * 1024


# == which process is a tab ================================================
@pytest.mark.parametrize("argv", [
    ["C:/Program Files/Google/Chrome/Application/chrome.exe", "--type=renderer",
     "--field-trial-handle=1"],
    ["msedge.exe", "--type=renderer", "--renderer-client-id=7"],
    ["/opt/Signal/signal-desktop", "--type=renderer"],        # Electron
    ["C:/Program Files/Mozilla Firefox/firefox.exe", "-contentproc",
     "--channel=1", "-isForBrowser", "-prefsLen", "100", "tab"],
])
def test_a_content_process_is_recognised(argv):
    assert is_browser_content_process(argv)


@pytest.mark.parametrize("argv", [
    [],
    ["chrome.exe"],                                   # the browser itself
    ["chrome.exe", "--type=gpu-process"],
    ["chrome.exe", "--type=utility", "--utility-sub-type=network.mojom"],
    ["msedge.exe", "--type=crashpad-handler"],
    ["firefox.exe", "-contentproc", "--channel=1", "gpu"],
    ["python.exe", "script.py", "--type", "renderer"],  # two args, not the flag
    ["evil.exe", "--note=--type=renderer"],
])
def test_other_processes_are_not(argv):
    assert not is_browser_content_process(argv)


# == the read budget: two pots =============================================
def test_images_cannot_spend_the_heaps_budget():
    """The bug: one budget, sized from private bytes, spent in address order
    on everything readable. A 29 MiB renderer has 66 MiB readable; the 37 MiB
    budget ran out in mapped images and the heap was never read."""
    budget = memscan.ReadBudget(private=37 * MIB, other=64 * MIB)
    budget.spend(False, 64 * MIB)          # images arrive first and use theirs
    assert budget.left(False) == 0
    assert budget.left(True) == 37 * MIB, "the heap's budget was touched"
    assert not budget.exhausted
    budget.spend(True, 37 * MIB)
    assert budget.exhausted


def test_private_memory_cannot_spend_the_image_allowance():
    budget = memscan.ReadBudget(private=10, other=20)
    budget.spend(True, 10)
    assert budget.left(True) == 0 and budget.left(False) == 20


def test_negative_budgets_are_treated_as_empty():
    budget = memscan.ReadBudget(private=-5, other=-1)
    assert budget.exhausted


# == chunked reads =========================================================
def test_a_small_read_is_one_piece():
    assert list(memscan.chunks(100, 50, chunk=1000, overlap=8)) == [(100, 50, 50)]


def test_a_large_read_is_split_with_overlap_and_counts_each_byte_once():
    """One read used to be as large as the per-region cap, which for a small
    process is the whole process: a 1 GiB cap meant a 1 GiB buffer per region
    and 100 seconds for 66 MiB."""
    pieces = list(memscan.chunks(0, 2500, chunk=1000, overlap=8))
    assert pieces == [(0, 1000, 1000), (992, 1008, 1000), (1992, 508, 500)]
    assert sum(fresh for _at, _size, fresh in pieces) == 2500


def test_a_marker_across_a_seam_is_still_found():
    marker = b"stratum+tcp"
    data = b"x" * 995 + marker + b"y" * 1000
    found = False
    for at, size, _fresh in memscan.chunks(0, len(data), chunk=1000,
                                          overlap=memscan.CHUNK_OVERLAP):
        if marker in data[at:at + size]:
            found = True
    assert found


def test_the_overlap_is_longer_than_any_marker():
    longest = max(len(m) for m in memscan.STRING_MARKERS)
    assert memscan.CHUNK_OVERLAP >= 2 * longest, (
        "a UTF-16 marker is twice as long and must fit in the overlap too")


def test_an_empty_read_yields_nothing():
    assert list(memscan.chunks(0, 0)) == []


# == a tab that holds a core is judged on its own memory ===================
def _engine_with_tab(cpu_score, mem_score, renderer=True, trusted=True):
    e = Engine(cfg=Config(pool_intel_enabled=False, gpu_enabled=False))
    if renderer:
        e._renderers.add(4242)
    e._trusted = lambda info: trusted
    return e


def _signals(e, monkeypatch, cpu_score, mem_score):
    from minersentry import engine as engine_mod
    monkeypatch.setattr(engine_mod, "score_cpu",
                        lambda recent, ncpu, cfg: Signal("cpu", cpu_score, "cpu"))
    monkeypatch.setattr(engine_mod, "score_memory",
                        lambda *a, **k: Signal("memory", mem_score, "strings"))
    info = SimpleNamespace(pid=4242, name="msedge.exe",
                           exe=r"C:\Program Files\Edge\msedge.exe",
                           mem_result=None, trusted=True, gpu=0.0)
    out = {s.name: s for s in e._build_signals(info, [], 0.0)}
    return out


def test_a_busy_tabs_memory_is_not_dampened(monkeypatch):
    """A content process runs the page's code. When it is also holding a core,
    what is in its memory is the page's doing and the browser's signature says
    nothing about it."""
    e = _engine_with_tab(92, 100)
    mem = _signals(e, monkeypatch, cpu_score=92, mem_score=100)["memory"]
    assert mem.score == 100
    assert "browser tab" in mem.detail


def test_an_idle_tabs_memory_stays_dampened(monkeypatch):
    """Someone reading an article about miners has the same words in a tab.
    That tab is not holding a core, and must stay as quiet as it always was."""
    e = _engine_with_tab(0, 100)
    mem = _signals(e, monkeypatch, cpu_score=0, mem_score=100)["memory"]
    assert mem.score < 100
    assert "dampened" in mem.detail


def test_the_browser_process_itself_is_still_dampened(monkeypatch):
    e = _engine_with_tab(92, 100, renderer=False)
    mem = _signals(e, monkeypatch, cpu_score=92, mem_score=100)["memory"]
    assert mem.score < 100


def test_a_pid_that_exits_stops_being_a_tab():
    e = Engine(cfg=Config(pool_intel_enabled=False, gpu_enabled=False))
    e._renderers.add(4242)
    e._forget_pid(4242)
    assert 4242 not in e._renderers, (
        "a recycled PID would inherit the tab's treatment")


def test_a_busy_tab_is_read_completely_and_an_idle_one_is_sampled(monkeypatch):
    from minersentry import engine as engine_mod
    e = Engine(cfg=Config(pool_intel_enabled=False, gpu_enabled=False))
    e._renderers.add(4242)
    monkeypatch.setattr(e, "_proc_private", lambda pid: 400 * MIB)
    monkeypatch.setattr(e, "_live_ctime", lambda pid: None)
    seen = {}

    def fake_scan(pid, budget_bytes, **kw):
        seen["budget"] = budget_bytes
        return memscan.MemScanResult(pid=pid)
    monkeypatch.setattr(engine_mod.memscan, "scan_process", fake_scan)

    monkeypatch.setattr(e, "_holds_a_core", lambda pid: False)
    e.scan_memory(4242)
    assert seen["budget"] == e.cfg.mem_max_bytes_per_proc, "an idle tab is sampled"

    monkeypatch.setattr(e, "_holds_a_core", lambda pid: True)
    e.scan_memory(4242)
    assert seen["budget"] >= 400 * MIB, "a tab holding a core is read in full"


def test_the_image_allowance_reaches_the_scanner(monkeypatch):
    from minersentry import engine as engine_mod
    e = Engine(cfg=Config(pool_intel_enabled=False, gpu_enabled=False))
    monkeypatch.setattr(e, "_proc_private", lambda pid: 10 * MIB)
    monkeypatch.setattr(e, "_live_ctime", lambda pid: None)
    seen = {}
    monkeypatch.setattr(engine_mod.memscan, "scan_process",
                        lambda pid, **kw: seen.update(kw) or
                        memscan.MemScanResult(pid=pid))
    e.scan_memory(4242)
    assert seen["other_budget_bytes"] == e.cfg.mem_image_budget_bytes
