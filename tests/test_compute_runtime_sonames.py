"""Linux maps show the real file, not the soname that was requested (#69)."""

import pytest

from minersentry.gpu import has_compute_runtime


@pytest.mark.parametrize("path", [
    "/usr/lib/x86_64-linux-gnu/libOpenCL.so.1.0.0",      # ocl-icd, as maps shows it
    "/usr/lib/x86_64-linux-gnu/libcuda.so.535.104.05",
    "/opt/rocm/lib/libamdocl64.so",
    "/usr/lib/x86_64-linux-gnu/intel-opencl/libigdrcl.so",
    "/usr/lib/x86_64-linux-gnu/libnvidia-opencl.so.535.104.05",
    "/usr/lib/libOpenCL.so.1",
    r"C:\Windows\System32\OpenCL.dll",
])
def test_a_mapped_compute_runtime_is_recognised(path):
    assert has_compute_runtime(0, modules=[path]) is True


@pytest.mark.parametrize("path", [
    "/usr/lib/x86_64-linux-gnu/libvulkan.so.1.3.250",
    "/usr/lib/x86_64-linux-gnu/libGL.so.1.7.0",
    "/usr/lib/x86_64-linux-gnu/libcudart-helper.so.12",
    "/home/u/libopencl.so.notes.txt",
])
def test_unrelated_libraries_are_not(path):
    assert has_compute_runtime(0, modules=[path]) is False
