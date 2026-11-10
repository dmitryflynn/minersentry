"""Benign GPU compute load, driven through OpenCL with ctypes.

The GPU signal was the one thing the test target could not exercise: there was
no way to put real load on the compute engine without adding a dependency, so
`fake_miner --gpu` either had to be skipped or faked. Faking it would only test
our own stub. This drives the GPU for real through the OpenCL runtime that ships
with the graphics driver — no CUDA toolkit, no PyTorch, no pip install.

What it runs is an integer hash loop. It is NOT mining: it computes nothing of
value, talks to no network, and submits nothing anywhere. It exists so the
compute engine is genuinely busy and `score_gpu` can be watched doing its job.

If no OpenCL runtime or GPU device is present this says so and exits non-zero,
rather than pretending to have produced load.
"""

from __future__ import annotations

import ctypes
import sys
import time

# OpenCL constants we need
CL_DEVICE_TYPE_GPU = 1 << 2
CL_PLATFORM_NAME = 0x0902
CL_DEVICE_NAME = 0x102B
CL_PROGRAM_BUILD_LOG = 0x1183
CL_MEM_WRITE_ONLY = 1 << 1

# A deliberately memory- and ALU-heavy integer loop: enough to keep the compute
# engine busy, and nothing to do with any real hashing algorithm.
KERNEL = b"""
__kernel void burn(__global uint *out, const uint rounds) {
    uint i = get_global_id(0);
    uint x = i * 2654435761u + 1013904223u;
    for (uint r = 0; r < rounds; r++) {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        x = x * 1664525u + 1013904223u;
    }
    out[i] = x;
}
"""


class OpenCLUnavailable(RuntimeError):
    pass


def _load():
    for name in ("OpenCL.dll", "libOpenCL.so.1", "libOpenCL.so", "OpenCL"):
        try:
            return ctypes.CDLL(name)
        except OSError:
            continue
    raise OpenCLUnavailable(
        "no OpenCL runtime found (it normally ships with the GPU driver)")


def _check(rc: int, what: str) -> None:
    if rc != 0:
        raise OpenCLUnavailable(f"{what} failed with OpenCL error {rc}")


def _text(lib, obj, info, getter) -> str:
    size = ctypes.c_size_t(0)
    getter(obj, info, 0, None, ctypes.byref(size))
    buf = ctypes.create_string_buffer(size.value or 256)
    getter(obj, info, len(buf), buf, None)
    return buf.value.decode(errors="replace")


def pick_device(lib, prefer: str | None = None):
    """(platform, device, description) for a GPU, preferring a name substring."""
    count = ctypes.c_uint32(0)
    _check(lib.clGetPlatformIDs(0, None, ctypes.byref(count)), "clGetPlatformIDs")
    if not count.value:
        raise OpenCLUnavailable("no OpenCL platforms")
    platforms = (ctypes.c_void_p * count.value)()
    _check(lib.clGetPlatformIDs(count.value, platforms, None), "clGetPlatformIDs")
    found = []
    for p in platforms:
        dn = ctypes.c_uint32(0)
        if lib.clGetDeviceIDs(ctypes.c_void_p(p), CL_DEVICE_TYPE_GPU, 0, None,
                              ctypes.byref(dn)) != 0 or not dn.value:
            continue
        devices = (ctypes.c_void_p * dn.value)()
        lib.clGetDeviceIDs(ctypes.c_void_p(p), CL_DEVICE_TYPE_GPU, dn.value, devices, None)
        pname = _text(lib, ctypes.c_void_p(p), CL_PLATFORM_NAME, lib.clGetPlatformInfo)
        for d in devices:
            dname = _text(lib, ctypes.c_void_p(d), CL_DEVICE_NAME, lib.clGetDeviceInfo)
            found.append((p, d, f"{dname} ({pname})"))
    if not found:
        raise OpenCLUnavailable("no OpenCL GPU devices")
    if prefer:
        for item in found:
            if prefer.lower() in item[2].lower():
                return item
    return found[0]


def run(seconds: float, work_items: int = 1 << 20, rounds: int = 4096,
        prefer: str | None = None) -> str:
    """Keep a GPU busy for `seconds`. Returns the device description."""
    lib = _load()
    platform, device, desc = pick_device(lib, prefer)

    lib.clCreateContext.restype = ctypes.c_void_p
    lib.clCreateCommandQueue.restype = ctypes.c_void_p
    lib.clCreateBuffer.restype = ctypes.c_void_p
    lib.clCreateProgramWithSource.restype = ctypes.c_void_p
    lib.clCreateKernel.restype = ctypes.c_void_p

    err = ctypes.c_int32(0)
    dev = ctypes.c_void_p(device)
    ctx = lib.clCreateContext(None, 1, ctypes.byref(dev), None, None, ctypes.byref(err))
    _check(err.value, "clCreateContext")
    queue = lib.clCreateCommandQueue(ctypes.c_void_p(ctx), dev, 0, ctypes.byref(err))
    _check(err.value, "clCreateCommandQueue")

    src = ctypes.c_char_p(KERNEL)
    program = lib.clCreateProgramWithSource(ctypes.c_void_p(ctx), 1,
                                            ctypes.byref(src), None, ctypes.byref(err))
    _check(err.value, "clCreateProgramWithSource")
    rc = lib.clBuildProgram(ctypes.c_void_p(program), 1, ctypes.byref(dev), None, None, None)
    if rc != 0:
        log = _text(lib, ctypes.c_void_p(program), CL_PROGRAM_BUILD_LOG,
                    lambda o, i, n, b, s: lib.clGetProgramBuildInfo(o, dev, i, n, b, s))
        raise OpenCLUnavailable(f"kernel build failed ({rc}): {log[:200]}")
    kernel = lib.clCreateKernel(ctypes.c_void_p(program), b"burn", ctypes.byref(err))
    _check(err.value, "clCreateKernel")

    nbytes = work_items * 4
    buf = lib.clCreateBuffer(ctypes.c_void_p(ctx), CL_MEM_WRITE_ONLY,
                             ctypes.c_size_t(nbytes), None, ctypes.byref(err))
    _check(err.value, "clCreateBuffer")
    bufp = ctypes.c_void_p(buf)
    _check(lib.clSetKernelArg(ctypes.c_void_p(kernel), 0,
                              ctypes.sizeof(ctypes.c_void_p), ctypes.byref(bufp)),
           "clSetKernelArg(out)")
    rounds_arg = ctypes.c_uint32(rounds)
    _check(lib.clSetKernelArg(ctypes.c_void_p(kernel), 1, 4, ctypes.byref(rounds_arg)),
           "clSetKernelArg(rounds)")

    global_size = ctypes.c_size_t(work_items)
    end = time.time() + seconds
    batches = 0
    while time.time() < end:
        rc = lib.clEnqueueNDRangeKernel(ctypes.c_void_p(queue), ctypes.c_void_p(kernel),
                                        1, None, ctypes.byref(global_size), None,
                                        0, None, None)
        _check(rc, "clEnqueueNDRangeKernel")
        _check(lib.clFinish(ctypes.c_void_p(queue)), "clFinish")
        batches += 1
    print(f"[gpu_load] {batches} kernel batches on {desc}", flush=True)
    return desc


def main(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(
        description="Benign GPU compute load (no mining) so the GPU signal can be "
                    "exercised for real.")
    ap.add_argument("--seconds", type=float, default=60.0)
    ap.add_argument("--work-items", type=int, default=1 << 20)
    ap.add_argument("--rounds", type=int, default=4096)
    ap.add_argument("--device", default=None,
                    help="prefer a device whose name contains this (e.g. NVIDIA)")
    args = ap.parse_args(argv)
    try:
        desc = run(args.seconds, args.work_items, args.rounds, args.device)
    except OpenCLUnavailable as e:
        print(f"[gpu_load] cannot drive the GPU: {e}", file=sys.stderr)
        return 2
    print(f"[gpu_load] done on {desc}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
