"""Recognising MinerSentry's own tooling must not be spoofable (#62).

A process running our code holds our marker table in memory, so it is left
out of the scan. That exclusion used to be granted to ANY process with ANY
argument that resolved into our tree - no write access needed - so a miner
could hide by naming one of our files on its command line.
"""

import os
import sys
from types import SimpleNamespace

import pytest

import minersentry.engine as engine_module
from minersentry.config import Config
from minersentry.engine import Engine, _python_script

PKG = os.path.dirname(os.path.abspath(engine_module.__file__))
CHECKOUT = os.path.dirname(PKG)
OURS = os.path.join(PKG, "engine.py")


@pytest.fixture
def engine():
    e = Engine(cfg=Config(pool_intel_enabled=False))
    yield e
    e.close()


def _proc(pid, argv, exe, cwd=""):
    return SimpleNamespace(pid=pid, cmdline=lambda: argv, exe=lambda: exe,
                           cwd=lambda: cwd)


def test_a_native_binary_naming_our_file_is_not_ours(engine):
    miner = r"C:\Users\x\Downloads\xmrig.exe" if os.name == "nt" else "/tmp/xmrig"
    argv = [miner, "-o", "stratum+tcp://pool:3333", OURS]
    engine._read_cmdline(_proc(5001, argv, miner))
    assert 5001 not in engine._own_tooling


def test_argv0_claiming_python_does_not_make_it_ours(engine):
    miner = r"C:\Users\x\Downloads\xmrig.exe" if os.name == "nt" else "/tmp/xmrig"
    engine._read_cmdline(_proc(5002, [sys.executable, OURS], miner))
    assert 5002 not in engine._own_tooling


def test_python_with_our_file_as_a_mere_argument_is_not_ours(engine):
    script = os.path.join(os.sep, "tmp", "miner.py")
    engine._read_cmdline(_proc(5003, [sys.executable, script, OURS], sys.executable))
    assert 5003 not in engine._own_tooling


def test_relative_paths_resolve_against_the_target_not_us(engine, tmp_path, monkeypatch):
    """With MinerSentry started from its checkout, a bare `main.py` argument
    used to resolve to OUR main.py, whatever process it belonged to."""
    monkeypatch.chdir(CHECKOUT)
    argv = [sys.executable, os.path.join("minersentry", "engine.py")]
    engine._read_cmdline(_proc(5004, argv, sys.executable, cwd=str(tmp_path)))
    assert 5004 not in engine._own_tooling
    engine._read_cmdline(_proc(5005, argv, sys.executable, cwd=""))
    assert 5005 not in engine._own_tooling


def test_python_running_our_script_is_still_ours(engine):
    engine._read_cmdline(_proc(5006, [sys.executable, "-u", OURS], sys.executable))
    assert 5006 in engine._own_tooling
    argv = [sys.executable, os.path.join("minersentry", "engine.py")]
    engine._read_cmdline(_proc(5007, argv, sys.executable, cwd=CHECKOUT))
    assert 5007 in engine._own_tooling


@pytest.mark.parametrize("argv,script", [
    (["python", "x.py", "a"], "x.py"),
    (["python", "-u", "-W", "ignore", "x.py"], "x.py"),
    (["python", "-Xutf8", "-OO", "x.py"], "x.py"),
    (["python", "-c", "import x", "x.py"], ""),
    (["python", "-m", "pytest", "tests"], ""),
    (["python", "-Bc", "pass"], ""),
    (["python"], ""),
    (["python", "-"], ""),
])
def test_the_script_position_is_found(argv, script):
    assert _python_script(argv) == script
