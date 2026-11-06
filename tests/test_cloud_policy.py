"""Cloud VM policy: benign names stay clean; miner names need corroboration."""
import time

import pytest

from minersentry import memscan
from minersentry.config import Config
from minersentry.engine import Engine, ProcInfo
from minersentry.scoring import (
    Signal, combine, is_miner_name, score_cpu, score_gpu, score_memory, score_name,
)

CFG = Config()


@pytest.mark.parametrize('name', sorted(CFG.known_miner_names))
def test_known_miner_name_alone_does_not_alert_when_idle(name):
    signal = score_name(name, '/opt/' + name, CFG)
    score, verdict = combine([signal], CFG)
    assert signal.score == CFG.name_score_known
    assert verdict == 'Clean'
    assert score < 45


@pytest.mark.parametrize('name', [
    'gminer_3_44', 'gminer64', 't-rex-0.26.8.exe', 'SRBMiner-MULTI', 'SRBMiner-MULTI.exe',
    'xmrig-notls.exe', 'lolMiner.exe', 'nbminer_v42',
])
def test_miner_variants_are_not_lost(name):
    assert is_miner_name(name, CFG)
    name_signal = score_name(name, '/opt/' + name, CFG)
    assert combine([name_signal], CFG)[1] == 'Clean'
    assert combine([name_signal, Signal('cpu', 92, '')], CFG)[1] == 'Likely Miner'
    assert combine([name_signal, Signal('gpu', 80, '')], CFG)[1] == 'Likely Miner'


@pytest.mark.parametrize('name', [
    'examiner', 'DataMiner.exe', 'minerals', 'minerva', 'python', 'pt_main_thread',
    'torch_train', 'WinRing0.exe', 'blender', 'jupyter-lab',
    'tracker-miner-fs-3', 'tracker-miner-fs', 'tracker-miner-apps', 'data-miner',
    'miner', 'miner.exe', 'miner-cuda12', 'miner_cuda11', 'miner64', 'cuda-miner',
    'notxmrig', 'xmrighelper', 'xmrigreport', 'xmrig2helper',
    'xmrigminerals', 'backup-xmrig', 'notnbminer',
])
def test_legitimate_names_do_not_match_bare_substring(name):
    assert not is_miner_name(name, CFG)
    assert combine([score_name(name, '/opt/' + name, CFG)], CFG)[1] == 'Clean'


@pytest.mark.parametrize('exe', [
    '/opt/mining/nbminer_v42', r'C:\tools\SRBMiner-MULTI.exe',
])
def test_executable_name_is_checked_when_comm_is_disguised(exe):
    name_signal = score_name('worker', exe, CFG)
    assert name_signal.score == CFG.name_score_known
    assert combine([name_signal], CFG)[1] == 'Clean'
    assert combine([name_signal, Signal('gpu', 80, '')], CFG)[1] == 'Likely Miner'


@pytest.mark.parametrize('name', ['tracker-miner-fs-3', 'tracker-miner-fs', 'data-miner', 'miner-cuda12'])
@pytest.mark.parametrize('cpu,gpu', [(0, 0), (92, 0), (0, 80), (92, 80)])
def test_generic_miner_names_do_not_convict_even_under_load(name, cpu, gpu):
    # Include generic memory/dataset cues: none establish a miner identity.
    signals = [score_name(name, '/usr/libexec/' + name, CFG),
               Signal('cpu', cpu, ''), Signal('gpu', gpu, ''),
               Signal('memory', 30, ''), Signal('dataset', 70, '')]
    assert signals[0].score == 0
    assert combine(signals, CFG)[1] == 'Clean'


@pytest.mark.parametrize('name', sorted(CFG.known_miner_names))
def test_known_brand_requires_sustained_cpu_or_gpu_samples(name):
    name_signal = score_name(name, '/opt/' + name, CFG)
    startup_cpu = score_cpu([100.0], 32, CFG)
    startup_gpu = score_gpu([97.0], False, False, True, CFG)
    assert combine([name_signal, startup_cpu, startup_gpu], CFG)[1] == 'Clean'
    cpu = score_cpu([100.0] * CFG.cpu_min_samples, 32, CFG)
    gpu = score_gpu([97.0] * CFG.gpu_min_samples, False, False, True, CFG)
    assert combine([name_signal, cpu], CFG)[1] == 'Likely Miner'
    assert combine([name_signal, gpu], CFG)[1] == 'Likely Miner'


def test_old_config_aliases_use_boundaries_instead_of_substring_search():
    cfg = Config(known_miner_names=frozenset(), known_miner_substrings=frozenset({'xmrig'}))
    assert is_miner_name('xmrig-notls.exe', cfg)
    assert not is_miner_name('notxmrig', cfg)
    assert not is_miner_name('xmrighelper', cfg)


@pytest.mark.parametrize('memory_score', [0, 12, 24, 30, 32])
def test_load_and_weak_memory_evidence_stay_clean(memory_score):
    signals = [Signal('cpu', 92, ''), Signal('gpu', 80, ''),
               Signal('memory', memory_score, ''), Signal('dataset', 70, '')]
    score, verdict = combine(signals, CFG)
    assert score <= CFG.suspicious_cap
    assert verdict == 'Clean'


def test_large_mapping_crypto_constants_and_algorithm_names_stay_weak():
    result = memscan.MemScanResult(pid=1234, scanned=True, large_page_dataset=True)
    buf = b'RandomX rx/0 CryptoNight ' + b''.join(memscan.BINARY_MARKERS)
    memscan._search_chunk(buf, result, set())
    assert result.hits
    assert result.score < CFG.hard_memory
    memory = score_memory(True, result.score, [h.label for h in result.hits], None, len(buf))
    assert combine([Signal('cpu', 92, ''), Signal('gpu', 80, ''),
                    Signal('dataset', 70, ''), memory], CFG)[1] == 'Clean'


def test_large_dataset_with_miner_strings_still_catches_throttled_miner():
    result = memscan.MemScanResult(pid=1234, scanned=True, large_page_dataset=True)
    memscan._search_chunk(b'XMRig stratum+tcp://example.invalid:3333', result, set())
    assert result.score >= 60
    assert combine([Signal('dataset', 70, ''), Signal('memory', result.score, '')], CFG)[1] == 'Likely Miner'


def test_signed_status_does_not_suppress_explicit_miner_identity():
    engine = Engine(cfg=Config())
    info = ProcInfo(987654)
    info.name, info.exe, info.trusted = 'worker', '/opt/nbminer_v42', True
    signals = engine._build_signals(info, [], time.time())
    assert next(s.score for s in signals if s.name == 'name') == CFG.name_score_known
    assert combine(signals, engine.cfg)[1] == 'Clean'
    assert combine(signals + [Signal('gpu', 80, '')], engine.cfg)[1] == 'Likely Miner'
    engine._meta[info.pid] = (info.name, info.exe, '', True)
    assert info.pid in engine.deep_scan_targets()


def test_common_weak_service_port_plus_compute_does_not_convict():
    assert combine([Signal('cpu', 92, ''), Signal('gpu', 80, ''),
                    Signal('memory', 30, ''), Signal('network', 30, '')], CFG)[1] == 'Clean'


def test_live_name_refresh_does_not_keep_cached_benign_name(monkeypatch, tmp_path):
    from contextlib import nullcontext
    from types import SimpleNamespace
    from minersentry import engine as engine_module
    from minersentry.audit import AuditLog

    engine = Engine(cfg=Config(), audit=AuditLog(path=str(tmp_path / 'events.jsonl')))
    pid = 987654
    mem = SimpleNamespace(rss=0)
    fake = SimpleNamespace(pid=pid, info={
        'pid': pid, 'name': 'worker', 'cpu_percent': 0, 'memory_info': mem,
    }, oneshot=nullcontext, memory_info=lambda: mem, num_threads=lambda: 1)
    engine._meta[pid] = ('worker', '/usr/bin/python', '', False)
    monkeypatch.setattr(engine_module.psutil, 'process_iter', lambda *a, **kw: iter([fake]))
    monkeypatch.setattr(engine_module.psutil, 'net_connections', lambda **kw: [])
    monkeypatch.setattr(engine_module.psutil, 'cpu_percent', lambda *a: 0)
    assert engine.scan_once()[0].verdict == 'Clean'
    fake.info['name'] = 'nbminer_v42'
    result = engine.scan_once()[0]
    assert result.name == 'nbminer_v42'
    assert result.verdict == 'Clean'
    assert next(s.score for s in result.signals if s.name == 'name') == CFG.name_score_known
    assert pid in engine.deep_scan_targets()
