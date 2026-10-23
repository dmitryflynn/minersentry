"""Read-only process-memory fingerprinting for miner artifacts.

A miner can rename its binary, pack itself, or inject into svchost, but it
cannot avoid holding the constants and strings its hashing algorithm needs
in memory. We walk a process's committed, readable regions with
ReadProcessMemory and look for those fingerprints. Nothing is modified.
"""

from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes
from dataclasses import dataclass, field

# ---- Fingerprints --------------------------------------------------------
# ASCII/UTF-8 markers that mining software and the stratum protocol leave in
# memory. Matching is case-insensitive on a lowercased copy of each region.
STRING_MARKERS = {
    b"stratum+tcp": ("stratum pool URL scheme", 40),
    b"stratum+ssl": ("stratum pool URL scheme (TLS)", 40),
    b"xmrig": ("XMRig miner identifier", 45),
    # Algorithm NAMES are weak — they appear in crypto libraries, benchmark
    # tools, and even coincidentally in a plain interpreter's memory — so they
    # must never reach the memory conviction/hard-evidence thresholds on their
    # own. Only the stratum/xmrig/pool PROTOCOL strings (near-zero in legit
    # software) carry real weight.
    b"randomx": ("RandomX algorithm name", 10),
    b"rx/0": ("RandomX variant tag", 12),
    b"cryptonight": ("CryptoNight algorithm name", 10),
    b"\"method\":\"login\"": ("stratum login handshake", 40),
    b"\"method\":\"submit\"": ("stratum share submission", 45),
    b"\"job_id\"": ("stratum job payload", 30),
    b"nicehash": ("NiceHash pool reference", 30),
    b"minexmr": ("MineXMR pool reference", 35),
    b"supportxmr": ("SupportXMR pool reference", 35),
    b"donate.ssl": ("miner donation endpoint", 35),
    b"nbminer": ("NBMiner identifier", 40),
    b"t-rex": ("T-Rex miner identifier", 30),
    b"phoenixminer": ("PhoenixMiner identifier", 40),
    b"lolminer": ("lolMiner identifier", 40),
    b"ethminer": ("ethminer identifier", 35),
}

# Binary constants. Keccak/SHA-3 round constant[0] and Blake2b IV word[0] are
# used by RandomX / CryptoNight pipelines; finding them in a non-crypto app is
# a weak-but-real signal, so each is scored low and only matters in aggregate.
BINARY_MARKERS = {
    bytes.fromhex("0100000000000000"): ("Keccak round constant", 12),
    bytes.fromhex("08c9bcf367e6096a"): ("Blake2b IV word 0", 12),
    bytes.fromhex("d728ae22"): ("Argon2/Blake2b mix constant", 8),
}

# Win32 constants
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
PAGE_READABLE = 0x02 | 0x04 | 0x20 | 0x40  # RO, RW, EXEC_READ, EXEC_RW
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01

IS_WINDOWS = sys.platform == "win32"
IS_LINUX = sys.platform.startswith("linux")


@dataclass
class MemHit:
    label: str
    weight: int
    where: str  # "string" or "binary"


@dataclass
class MemScanResult:
    pid: int
    scanned: bool = False
    error: str | None = None
    bytes_scanned: int = 0
    regions_scanned: int = 0
    hits: list[MemHit] = field(default_factory=list)
    large_page_dataset: bool = False  # a committed region >= ~2 GiB (RandomX)

    @property
    def score(self) -> int:
        s = sum(h.weight for h in self.hits)
        if self.large_page_dataset:
            s += 30
        return min(100, s)


if IS_WINDOWS:
    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", wintypes.DWORD),
            ("__alignment1", wintypes.DWORD),
            ("RegionSize", ctypes.c_size_t),
            ("State", wintypes.DWORD),
            ("Protect", wintypes.DWORD),
            ("Type", wintypes.DWORD),
            ("__alignment2", wintypes.DWORD),
        ]

    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _k32.OpenProcess.restype = wintypes.HANDLE
    _k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _k32.VirtualQueryEx.restype = ctypes.c_size_t
    _k32.VirtualQueryEx.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p,
        ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t,
    ]
    _k32.ReadProcessMemory.restype = wintypes.BOOL
    _k32.ReadProcessMemory.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
        ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
    ]
    _k32.CloseHandle.argtypes = [wintypes.HANDLE]


# Keep per-process work bounded so a full-system deep scan stays responsive.
MAX_REGION_READ = 4 * 1024 * 1024          # read at most 4 MiB per region
MAX_BYTES_PER_PROC = 192 * 1024 * 1024     # stop a process after 192 MiB
LARGE_DATASET_BYTES = 2 * 1024 * 1024 * 1024 - (64 * 1024 * 1024)  # ~2 GiB


def _search_chunk(chunk: bytes, result: MemScanResult, seen: set[str]) -> None:
    lowered = chunk.lower()
    for marker, (label, weight) in STRING_MARKERS.items():
        if marker in lowered and label not in seen:
            seen.add(label)
            result.hits.append(MemHit(label, weight, "string"))
    for marker, (label, weight) in BINARY_MARKERS.items():
        if marker in chunk and label not in seen:
            seen.add(label)
            result.hits.append(MemHit(label, weight, "binary"))


def scan_process(pid: int, budget_bytes: int = MAX_BYTES_PER_PROC,
                 max_region_read: int = MAX_REGION_READ,
                 large_dataset_bytes: int = LARGE_DATASET_BYTES) -> MemScanResult:
    """Walk readable committed memory of `pid`, looking for miner fingerprints.

    Dispatches to the Windows (ReadProcessMemory) or Linux (/proc) backend.
    Budgets (per-process cap, per-region read, large-dataset threshold) are
    passed in so the engine can drive them from Config; defaults match the
    module constants.
    """
    if IS_WINDOWS:
        return _scan_windows(pid, budget_bytes, max_region_read, large_dataset_bytes)
    if IS_LINUX:
        return _scan_linux(pid, budget_bytes, max_region_read, large_dataset_bytes)
    r = MemScanResult(pid=pid)
    r.error = "memory scan unsupported on this platform"
    return r


def _scan_windows(pid: int, budget_bytes: int, max_region_read: int,
                  large_dataset_bytes: int) -> MemScanResult:
    result = MemScanResult(pid=pid)
    if pid <= 4:
        result.error = "system process"
        return result

    access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
    handle = _k32.OpenProcess(access, False, pid)
    if not handle:
        result.error = f"OpenProcess failed (err {ctypes.get_last_error()}; try running as admin)"
        return result

    seen: set[str] = set()
    try:
        mbi = MEMORY_BASIC_INFORMATION()
        addr = 0
        buf = ctypes.create_string_buffer(max_region_read)
        read = ctypes.c_size_t(0)
        while result.bytes_scanned < budget_bytes:
            ok = _k32.VirtualQueryEx(handle, ctypes.c_void_p(addr),
                                     ctypes.byref(mbi), ctypes.sizeof(mbi))
            if not ok:
                break
            region_size = mbi.RegionSize or 0x1000
            base = mbi.BaseAddress or 0
            committed = mbi.State == MEM_COMMIT
            readable = bool(mbi.Protect & PAGE_READABLE)
            guarded = bool(mbi.Protect & PAGE_GUARD) or mbi.Protect == PAGE_NOACCESS

            if committed and region_size >= large_dataset_bytes:
                result.large_page_dataset = True

            if committed and readable and not guarded:
                to_read = min(region_size, max_region_read)
                if _k32.ReadProcessMemory(handle, ctypes.c_void_p(base),
                                          buf, to_read, ctypes.byref(read)):
                    n = read.value
                    if n:
                        _search_chunk(buf.raw[:n], result, seen)
                        result.bytes_scanned += n
                        result.regions_scanned += 1

            next_addr = base + region_size
            if next_addr <= addr:
                break
            addr = next_addr
        result.scanned = True
    finally:
        _k32.CloseHandle(handle)
    return result


# -- Linux backend (/proc) --------------------------------------------------
def parse_maps(text: str) -> list[tuple[int, int, str, str]]:
    """Parse the contents of /proc/<pid>/maps into (start, end, perms, path)
    tuples. Pure, so it is unit-testable without a live process."""
    regions: list[tuple[int, int, str, str]] = []
    for line in text.splitlines():
        parts = line.split(None, 5)
        if len(parts) < 5 or "-" not in parts[0]:
            continue
        lo, _, hi = parts[0].partition("-")
        try:
            start, end = int(lo, 16), int(hi, 16)
        except ValueError:
            continue
        path = parts[5] if len(parts) >= 6 else ""
        regions.append((start, end, parts[1], path))
    return regions


def maps_has_large_dataset(regions: list[tuple[int, int, str, str]],
                           large_dataset_bytes: int) -> bool:
    """True if any private region is RandomX-dataset-sized (~2 GiB). Pure."""
    return any("p" in perms and (end - start) >= large_dataset_bytes
               for start, end, perms, _path in regions)


def _scan_linux(pid: int, budget_bytes: int, max_region_read: int,
                large_dataset_bytes: int) -> MemScanResult:
    result = MemScanResult(pid=pid)
    if pid <= 0:
        result.error = "invalid pid"
        return result
    try:
        with open(f"/proc/{pid}/maps", "r", encoding="utf-8", errors="replace") as f:
            regions = parse_maps(f.read())
    except FileNotFoundError:
        result.error = "no such process"
        return result
    except PermissionError:
        result.error = "permission denied (need same user / CAP_SYS_PTRACE / root)"
        return result
    except OSError as e:
        result.error = f"maps read failed: {e}"
        return result

    # The large-dataset flag comes from region SIZES in maps alone, so it is set
    # even when we lack permission to read the bytes.
    result.large_page_dataset = maps_has_large_dataset(regions, large_dataset_bytes)

    seen: set[str] = set()
    try:
        mem = open(f"/proc/{pid}/mem", "rb", buffering=0)
    except (PermissionError, OSError) as e:
        result.scanned = True  # maps-based large_dataset flag still valid
        result.error = f"mem read unavailable: {e}"
        return result
    try:
        for start, end, perms, _path in regions:
            if result.bytes_scanned >= budget_bytes:
                break  # budget spent; large_dataset flag already set from maps
            if "r" not in perms:
                continue
            to_read = min(end - start, max_region_read)
            try:
                mem.seek(start)
                data = mem.read(to_read)
            except (OSError, ValueError, OverflowError):
                continue
            if data:
                _search_chunk(data, result, seen)
                result.bytes_scanned += len(data)
                result.regions_scanned += 1
        result.scanned = True
    finally:
        mem.close()
    return result
