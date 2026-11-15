"""GPU compute on something other than NVIDIA (issue #18).

Measured on a hybrid laptop (RTX 3050 + Iris Xe) with a real OpenCL job:

    job on the NVIDIA GPU   pmon: 99% type C      PDH: nothing at all
    job on the Intel GPU    pmon: not listed      PDH: 98.7% on the 3D engine

The sampler read only "Compute" engines from PDH, and skipped PDH altogether
whenever pmon answered, so the second row was invisible. A miner only had to
pick the integrated GPU.
"""

import subprocess
import sys
import time

import pytest

from minersentry import gpu

PMON_IDLE = ("# gpu        pid  type    sm   mem\n"
             "# Idx          #   C/G     %     %\n")
PMON_BUSY = PMON_IDLE + "    0        777     C    91     0\n"


# == what marks a process as a compute client =============================
@pytest.mark.parametrize("modules", [
    ["C:/Windows/System32/OpenCL.dll"],
    ["C:\\Windows\\System32\\DriverStore\\FileRepository\\x\\igdrcl64.dll"],
    ["C:\\Windows\\System32\\amdocl64.dll"],
    ["/usr/lib/x86_64-linux-gnu/libOpenCL.so.1"],
    ["C:\\Windows\\System32\\nvcuda64.dll"],
])
def test_an_opencl_or_cuda_runtime_makes_a_compute_client(modules):
    assert gpu.has_compute_runtime(1, modules=modules)


@pytest.mark.parametrize("modules", [
    [],
    ["C:\\Windows\\System32\\d3d11.dll", "C:\\Windows\\System32\\dxgi.dll"],
    # mapped by every Chromium GPU process and most games
    ["C:\\Program Files\\App\\vulkan-1.dll"],
    # mapped by ordinary creative and camera software
    ["C:\\Windows\\System32\\DirectML.dll"],
    # a name that merely contains one of ours
    ["C:\\x\\notopencl.dll.bak", "C:\\x\\myopencl.dll.txt"],
])
def test_graphics_and_ml_runtimes_do_not(modules):
    """Vulkan and DirectML are excluded on purpose: counting them would turn
    desktop graphics into "compute"."""
    assert not gpu.has_compute_runtime(1, modules=modules)


def test_a_process_we_cannot_inspect_is_not_a_compute_client():
    """Unknown is not evidence."""
    assert gpu.has_compute_runtime(0) is False
    assert gpu.has_compute_runtime(99999999) is False


# == merging the sources ==================================================
def test_3d_engine_load_counts_only_for_compute_clients():
    """The 3D engine carries every game and browser as well."""
    out = gpu.merge_gpu_util(nvidia={}, compute={},
                             graphics={10: 98.7, 20: 95.0}, clients={10})
    assert out == {10: 98.7}


def test_a_compute_engine_reading_always_counts():
    out = gpu.merge_gpu_util(nvidia={}, compute={5: 60.0}, graphics={},
                             clients=set())
    assert out == {5: 60.0}


def test_the_higher_reading_wins_when_sources_overlap():
    out = gpu.merge_gpu_util(nvidia={7: 91.0}, compute={7: 10.0},
                             graphics={7: 95.0}, clients={7})
    assert out == {7: 95.0}


def test_a_zero_3d_reading_adds_nothing():
    assert gpu.merge_gpu_util({}, {}, {9: 0.0}, {9}) == {}


# == deciding whether PDH is worth paying for ============================
@pytest.mark.parametrize("names,expected", [
    (["NVIDIA GeForce RTX 3050 Laptop GPU"], False),
    (["NVIDIA GeForce RTX 3050 Laptop GPU", "Intel(R) Iris(R) Xe Graphics"], True),
    (["AMD Radeon RX 6600"], True),
    (["Microsoft Basic Render Driver"], False),
    (["NVIDIA RTX A2000", "Microsoft Remote Display Adapter"], False),
    ([], False),
])
def test_only_a_real_non_nvidia_gpu_makes_pdh_necessary(names, expected):
    assert gpu.adapters_include_non_nvidia(names) is expected


def test_pdh_is_skipped_on_an_nvidia_only_machine(monkeypatch):
    called = []
    monkeypatch.setattr(gpu, "_run", lambda args, timeout: PMON_BUSY)
    monkeypatch.setattr(gpu, "other_gpu_present", lambda: False)
    monkeypatch.setattr(gpu, "_sample_pdh",
                        lambda: called.append(1) or ({}, {}))
    util, clients = gpu._sample_windows(set())
    assert util == {777: 91.0} and clients == set()
    assert called == []


def test_pdh_runs_alongside_pmon_when_there_is_a_second_gpu(monkeypatch):
    """The hole itself: pmon answering used to end the sample, so a job on the
    other GPU was never looked for."""
    monkeypatch.setattr(gpu, "_run", lambda args, timeout: PMON_BUSY)
    monkeypatch.setattr(gpu, "other_gpu_present", lambda: True)
    monkeypatch.setattr(gpu, "_sample_pdh", lambda: ({}, {555: 98.7, 556: 97.0}))
    monkeypatch.setattr(gpu, "has_compute_runtime", lambda pid: pid == 555)
    util, clients = gpu._sample_windows(set())
    assert util == {777: 91.0, 555: 98.7}, "the Intel-GPU job must be reported"
    assert clients == {555}
    assert 556 not in util, "a game on the same engine must not be"


def test_module_lookup_is_only_paid_for_busy_processes(monkeypatch):
    looked = []
    monkeypatch.setattr(gpu, "_run", lambda args, timeout: "")
    monkeypatch.setattr(gpu, "_sample_pdh",
                        lambda: ({}, {1: 2.0, 2: 14.9, 3: 80.0}))
    monkeypatch.setattr(gpu, "has_compute_runtime",
                        lambda pid: looked.append(pid) or False)
    gpu._sample_windows(set())
    assert looked == [3]


def test_a_pdh_compute_client_is_reported_as_holding_a_compute_context(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(gpu, "IS_WINDOWS", True)
    monkeypatch.setattr(gpu, "_sample_nvidia_ctx", lambda: {42})
    monkeypatch.setattr(gpu, "_sample_windows",
                        lambda ctx: ({555: 98.7}, {555}))
    monkeypatch.setattr(gpu, "window_owner_pids", lambda: set())
    _util, _windows, ctx = gpu.sample()
    assert ctx == {42, 555}


# == the real thing =======================================================
@pytest.mark.skipif(sys.platform != "win32", reason="Windows GPU sampling")
def test_a_real_opencl_job_on_a_non_nvidia_gpu_is_seen():
    """Runs the benign OpenCL load on a non-NVIDIA GPU and checks the sampler
    reports it. Skips where there is no such GPU or no OpenCL device on it."""
    import os
    if not gpu.other_gpu_present():
        pytest.skip("no non-NVIDIA GPU here")
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    last = "no non-NVIDIA OpenCL device started"
    for device in ("Intel", "AMD", "Radeon"):
        proc = subprocess.Popen(
            [sys.executable, os.path.join(root, "samples", "gpu_load.py"),
             "--seconds", "45", "--device", device],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        try:
            time.sleep(8)
            if proc.poll() is not None:
                continue
            if not gpu.has_compute_runtime(proc.pid):
                last = "the load process has no OpenCL runtime mapped"
                continue
            best = 0.0
            for _ in range(3):
                util, _windows, ctx = gpu.sample()
                best = max(best, util.get(proc.pid, 0.0))
                if best >= 30.0:
                    assert proc.pid in ctx
                    return
            # the job may have landed on the NVIDIA GPU despite the preference
            last = f"sampler saw {best:.0f}% for the {device} job"
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except Exception:  # noqa: BLE001
                proc.kill()
    pytest.skip(last)
