"""Linux collector and engine checks; no real GPU, network or miner needed."""
import sys
from unittest.mock import patch

import pytest

from minersentry import gpu
from minersentry.config import Config
from minersentry.engine import Engine, ProcInfo
from minersentry.scoring import combine


PMON = '''# gpu pid type sm mem enc dec jpg ofa command
# Idx # C/G % % % % % % name
0 1605 G - - - - - - Xorg
0 22066 C 97 22 - - - - python
1 22066 C 85 20 - - - - python
0 7777 C - 10 - - - - unsupported
0 8888 C 0 0 - - - - idle
0 9999 C+G 99 10 - - - - mixed
'''


def test_real_a100_output_shape_and_multi_gpu():
    assert gpu.parse_nvidia_pmon(PMON) == {22066: 97.0, 8888: 0.0}


@pytest.mark.parametrize('row', [
    '0 42 C 101', '0 42 C -1', '0 42 C nan', '0 0 C 90',
    '0 nope C 90', '0 42 C', '0 42 C N/A', '0 42 C -',
])
def test_rejects_invalid_or_unavailable_metrics(row):
    assert gpu.parse_nvidia_pmon('# gpu pid type sm\n' + row) == {}


def test_reordered_header_and_empty_output():
    assert gpu.parse_nvidia_pmon('# gpu sm type pid mem\n0 91 C 42 0') == {42: 91.0}
    assert gpu.parse_nvidia_pmon('driver error') == {}
    assert gpu.parse_nvidia_pmon('# gpu pid type sm\n0 - - -') == {}


def test_linux_calls_pmon_and_context_query_not_typeperf():
    calls = []

    def run(args, timeout):
        calls.append(args)
        return PMON if 'pmon' in args else '22066, 512\n7777, 128\n'

    with patch.object(sys, 'platform', 'linux'), patch.object(gpu, 'IS_WINDOWS', False), \
         patch.object(gpu, '_run', side_effect=run):
        assert gpu.sample() == ({22066: 97.0, 8888: 0.0}, set(), {22066, 7777})
    assert calls == [
        ['nvidia-smi', 'pmon', '-s', 'u', '-c', '1'],
        ['nvidia-smi', '--query-compute-apps=pid,used_gpu_memory', '--format=csv,noheader'],
    ]


@pytest.mark.parametrize('text', ['', 'NVIDIA-SMI has failed'])
def test_driver_failure_warns_and_does_not_invent_load(text):
    with patch.object(sys, 'platform', 'linux'), patch.object(gpu, '_run', return_value=text):
        with pytest.warns(RuntimeWarning, match='unavailable'):
            assert gpu.sample() == ({}, set(), set())


def test_unsupported_sm_values_warn():
    text = '# gpu pid type sm mem\n0 42 C - -\n'
    with patch.object(gpu, '_run', return_value=text):
        with pytest.warns(RuntimeWarning, match='SM utilization'):
            util, _, _ = gpu._sample_linux_nvidia()
    assert util == {}


def test_windows_keeps_existing_collectors():
    with patch.object(sys, 'platform', 'win32'), patch.object(gpu, 'IS_WINDOWS', True), \
         patch.object(gpu, '_sample_pdh_compute', return_value={42: 80}), \
         patch.object(gpu, 'window_owner_pids', return_value={43}), \
         patch.object(gpu, '_sample_nvidia_ctx', return_value={42}):
        assert gpu.sample() == ({42: 80}, {43}, {42})


def test_nonzero_command_exit_is_not_valid_telemetry():
    from types import SimpleNamespace
    with patch.object(gpu.subprocess, 'run', return_value=SimpleNamespace(
        returncode=1, stdout=PMON)):
        assert gpu._run(['nvidia-smi'], timeout=1) == ''


def test_gpu_only_work_enters_deep_targets_without_mining_conviction():
    engine = Engine(cfg=Config())
    for _ in range(engine.cfg.gpu_min_samples):
        engine.set_gpu_util({22066: 97}, set(), {22066})
    assert 22066 in engine.deep_scan_targets()
    info = ProcInfo(22066)
    info.name = 'python'
    signals = engine._build_signals(info, [], 0)
    assert info.gpu == 97
    assert next(s for s in signals if s.name == 'gpu').score > 0
    assert combine(signals, engine.cfg)[1] != 'Likely Miner'
    engine.set_gpu_util({}, set(), set())
    assert 22066 not in engine._gpu_hist
    assert 22066 not in engine.deep_scan_targets()


def test_valid_zero_retires_high_load_and_preserves_other_processes():
    engine = Engine(cfg=Config())
    engine.set_gpu_util({22066: 97, 8888: 80})
    engine.set_gpu_util({22066: 0})
    assert list(engine._gpu_hist[22066]) == [97, 0]
    assert 8888 not in engine._gpu_hist
