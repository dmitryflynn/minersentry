"""ReadProcessMemory must never be asked to fill more than its buffer holds.

The buffer was sized from `mem_max_region_read`, while `sample_offsets` never
reads less than 4 KiB at a time. A small setting (the admin config accepts
anything from 0) made a 1,064-byte buffer that a 4,160-byte read overran,
writing into the interpreter's heap.
"""

import ctypes
import os
import sys

import pytest

from minersentry import memscan

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="ReadProcessMemory")


@pytest.mark.parametrize("region_read", [1, 1000, 4095, 4096, 70_000])
def test_no_read_is_larger_than_the_buffer(monkeypatch, region_read):
    real = memscan._k32.ReadProcessMemory
    asked = []

    def guarded(handle, address, buf, size, read):
        asked.append((size, ctypes.sizeof(buf)))
        assert size <= ctypes.sizeof(buf), "would write past the buffer"
        return real(handle, address, buf, size, read)

    monkeypatch.setattr(memscan._k32, "ReadProcessMemory", guarded)
    result = memscan._scan_windows(os.getpid(), budget_bytes=2 * 1024 * 1024,
                                   max_region_read=region_read,
                                   large_dataset_bytes=memscan.LARGE_DATASET_BYTES,
                                   full_walk=False, region_samples=4,
                                   other_budget_bytes=1024 * 1024)
    assert asked, "nothing was read"
    assert result.scanned


def test_sample_offsets_never_read_less_than_the_minimum_piece():
    pieces = memscan.sample_offsets(1_000_000, 1000, 4)
    assert all(length >= min(memscan.MIN_SAMPLE, 1_000_000) for _o, length in pieces)
