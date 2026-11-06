"""GPU-only scope, error handling and CLI integration; no GPU/network needed."""
from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from minersentry import cli, engine as engine_module, gpu
from minersentry.audit import AuditLog
from minersentry.config import Config
from minersentry.engine import Engine
from minersentry.memscan import MemScanResult


@pytest.mark.parametrize('stdout,expected', [('', set()), ('\n', set()), ('42\n42\n77\n', {42, 77})])
def test_compute_scope_distinguishes_successful_empty_list(monkeypatch, stdout, expected):
    calls = []
    def run(args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(returncode=0, stdout=stdout, stderr='')
    monkeypatch.setattr(gpu.subprocess, 'run', run)
    assert gpu.compute_pids() == expected
    assert calls[0][0] == ['nvidia-smi', '--query-compute-apps=pid', '--format=csv,noheader,nounits']
    assert calls[0][1]['timeout'] == 6.0


@pytest.mark.parametrize('stdout', ['N/A', 'No devices were found', '0', '-1', 'pid', '42\ninvalid'])
def test_compute_scope_rejects_unsupported_data(monkeypatch, stdout):
    monkeypatch.setattr(gpu.subprocess, 'run', lambda *a, **k: SimpleNamespace(
        returncode=0, stdout=stdout, stderr=''))
    with pytest.raises(RuntimeError, match='unsupported data'):
        gpu.compute_pids()


def test_compute_scope_driver_failure_is_not_empty_success(monkeypatch):
    monkeypatch.setattr(gpu.subprocess, 'run', lambda *a, **k: SimpleNamespace(
        returncode=9, stdout='Driver unavailable', stderr=''))
    with pytest.raises(RuntimeError, match='exit 9.*Driver unavailable'):
        gpu.compute_pids()


@pytest.mark.parametrize('error', [FileNotFoundError('nvidia-smi'), gpu.subprocess.TimeoutExpired('nvidia-smi', 6)])
def test_compute_scope_missing_command_or_timeout_fails(monkeypatch, error):
    def run(*args, **kwargs):
        raise error
    monkeypatch.setattr(gpu.subprocess, 'run', run)
    with pytest.raises(RuntimeError, match='GPU process query failed'):
        gpu.compute_pids()


@pytest.fixture
def scoped_engine(monkeypatch, tmp_path):
    def forbidden(*args, **kwargs):
        raise AssertionError('GPU-only mode must not enumerate all processes')
    monkeypatch.setattr(engine_module.psutil, 'process_iter', forbidden)
    monkeypatch.setattr(engine_module.psutil, 'net_connections', lambda **kwargs: [])
    e = Engine(cfg=Config(pool_intel_enabled=False, perf_enabled=False),
               audit=AuditLog(path=str(tmp_path / 'audit.jsonl')), gpu_only=True)
    calls = []
    class Process:
        def __init__(self, pid):
            self.pid = pid
            calls.append(pid)
        def is_running(self): return True
        def as_dict(self, attrs):
            return dict(pid=self.pid, name='python', cpu_percent=100.0,
                        memory_info=SimpleNamespace(rss=4096))
        def exe(self): return '/usr/bin/python'
        def username(self): return 'test'
        def oneshot(self): return nullcontext()
        def memory_info(self): return SimpleNamespace(rss=4096)
        def num_threads(self): return 1
    monkeypatch.setattr(engine_module.psutil, 'Process', Process)
    return e, calls


def test_only_gpu_pids_read_and_cpu_process_objects_reused(scoped_engine):
    e, calls = scoped_engine
    e.set_gpu_scope({42001})
    e.set_gpu_util({42001: 0.0}, set(), {42001})
    assert [p.pid for p in e.scan_once()] == [42001]
    assert [p.pid for p in e.scan_once()] == [42001]
    assert calls == [42001]
    assert not e.hidden_report.flagged
    assert 'disabled' in e.hidden_report.note


def test_deep_scope_includes_idle_gpu_and_excludes_forced_cpu_pid(scoped_engine, monkeypatch):
    e, _ = scoped_engine
    e.set_gpu_scope({42001})
    e._meta[42002] = ('xmrig', '/opt/xmrig', '', False)
    e._cpu_hist[42002].append((engine_module.time.time(), 100.0))
    e._conn_seen[(42002, '192.0.2.1', 3333)] = engine_module.time.time()
    assert e.deep_scan_targets(force={42002}) == [42001]
    scanned = []
    monkeypatch.setattr(e, 'deep_probe', lambda pid: scanned.append(pid) or MemScanResult(pid=pid))
    e.scan_once(deep=True)
    assert scanned == [42001]


def test_direct_memory_scan_cannot_bypass_scope(scoped_engine, monkeypatch):
    e, _ = scoped_engine
    monkeypatch.setattr(engine_module.memscan, 'scan_process', lambda *a, **k: pytest.fail('out of scope memory read'))
    with pytest.raises(ValueError, match='outside the GPU-only'):
        e.deep_probe(42002)


def test_released_gpu_pid_no_longer_reported_or_deep_scanned(scoped_engine):
    e, _ = scoped_engine
    e.set_gpu_scope({42001})
    e.scan_once()
    e.scan_once()
    e._mem_cache[42001] = MemScanResult(pid=42001)
    e.set_gpu_scope(set())
    assert e.scan_once() == []
    assert e.deep_scan_targets(force={42001}) == []
    assert 42001 not in e._gpu_processes
    assert 42001 not in e._cpu_hist
    assert 42001 not in e._meta
    assert 42001 not in e._mem_cache
    assert 42001 not in e._warm


@pytest.mark.parametrize('name,expected', [('python', 'Clean'), ('nbminer_v42', 'Likely Miner')])
def test_scoped_high_gpu_compute_still_needs_miner_evidence(scoped_engine, name, expected):
    e, _ = scoped_engine
    e.set_gpu_scope({42001})
    e.scan_once()
    p = e._gpu_processes[42001]
    original = p.as_dict
    p.as_dict = lambda attrs: {**original(attrs), 'name': name}
    e._meta.pop(42001, None)
    e._mem_cache[42001] = MemScanResult(pid=42001, scanned=True, large_page_dataset=True)
    for _ in range(6):
        e.set_gpu_util({42001: 97}, set(), {42001})
        row = e.scan_once()[0]
        if expected == 'Clean':
            assert row.verdict == 'Clean'
    assert row.verdict == expected
    assert next(s.score for s in row.signals if s.name == 'gpu') == 80


def test_cli_query_failure_returns_nonzero_without_clean_json(monkeypatch, capsys):
    monkeypatch.setattr(cli.Config, 'load', lambda: Config(pool_intel_enabled=False))
    def fail(): raise RuntimeError('driver unavailable')
    monkeypatch.setattr(gpu, 'compute_pids', fail)
    assert cli.main(['--gpu-only', '--json']) == 1
    captured = capsys.readouterr()
    assert captured.out == ''
    assert 'driver unavailable' in captured.err


def test_session_refreshes_scope_before_deep_scan_and_implies_gpu(monkeypatch, scoped_engine):
    e, _ = scoped_engine
    clock = [100.0]
    monkeypatch.setattr(cli, 'Engine', lambda **kwargs: e)
    monkeypatch.setattr(cli.time, 'time', lambda: clock[0])
    monkeypatch.setattr(cli.time, 'sleep', lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    scopes = iter([{42001}, {42001}, {42002}, set()])
    monkeypatch.setattr(gpu, 'compute_pids', lambda: next(scopes))
    sampled = []
    monkeypatch.setattr(gpu, 'sample', lambda: sampled.append(True) or ({}, set(), set()))
    scanned = []
    monkeypatch.setattr(e, 'deep_probe', lambda pid: scanned.append(pid) or MemScanResult(pid=pid))
    _, rows, _ = cli.run_session(4, interval=1, gpu_only=True, force_pids={42001})
    assert scanned == [42002]
    assert len(sampled) == 4
    assert rows == []


def test_default_mode_still_uses_all_processes(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(engine_module.psutil, 'process_iter', lambda *args: calls.append(args) or iter(()))
    e = Engine(cfg=Config(), audit=AuditLog(path=str(tmp_path / 'audit.jsonl')))
    list(e._processes())
    assert calls == [(), (['pid', 'name', 'cpu_percent', 'memory_info'],)]
