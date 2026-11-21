"""A ~2 GiB region is one piece of evidence, scored once (#66).

It is the `dataset` signal. It used to add 30 to the memory score as well,
so the dataset+memory pair convicted on the dataset plus ONE weak string.
"""

import time

from minersentry import memscan
from minersentry.config import Config
from minersentry.engine import Engine, ProcInfo
from minersentry.scoring import Signal, combine, score_dataset, score_memory

CFG = Config()


def _result(dataset, *hits):
    return memscan.MemScanResult(pid=1, scanned=True, large_page_dataset=dataset,
                                 hits=list(hits))


def _memory(r):
    return score_memory(True, r.score, [h.label for h in r.hits], None, 1)


NICEHASH = memscan.MemHit("NiceHash pool reference", 30, "string")


def test_the_dataset_does_not_raise_the_memory_score():
    assert _result(True, NICEHASH).score == _result(False, NICEHASH).score == 30


def test_dataset_and_one_weak_string_do_not_convict_an_idle_process():
    r = _result(True, NICEHASH)
    score, verdict = combine([_memory(r), score_dataset(True, CFG)], CFG)
    assert verdict != "Likely Miner", score


def test_a_weak_string_and_moderate_load_do_not_convict_through_the_dataset():
    r = _result(True, NICEHASH)
    assert combine([_memory(r), Signal("cpu", 35, "")], CFG)[1] != "Likely Miner"


def test_the_engine_does_not_convict_an_idle_big_heap_with_one_weak_string():
    e = Engine(cfg=Config(pool_intel_enabled=False))
    try:
        info = ProcInfo(424242)
        info.name, info.exe, info.trusted = "java.exe", r"C:\apps\java.exe", False
        info.mem_result = _result(True, NICEHASH)
        signals = e._build_signals(info, [], time.time())
        assert combine(signals, e.cfg)[1] != "Likely Miner"
    finally:
        e.close()


def test_dataset_with_real_miner_strings_still_convicts():
    r = _result(True)
    memscan._search_chunk(b"XMRig stratum+tcp://example.invalid:3333", r, set())
    assert combine([_memory(r), score_dataset(True, CFG)], CFG)[1] == "Likely Miner"
