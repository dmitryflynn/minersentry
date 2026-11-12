"""Authenticode trust check for false-positive dampening.

A signed Microsoft/AV binary that legitimately carries miner-signature strings
in memory (security tools do this) must not alarm. We check whether a process's
image is validly signed; the engine then dampens the memory/name signals for
trusted images while leaving behavioral signals (cpu/probe) at full weight.

Primary check is WinVerifyTrust via ctypes (validates the Authenticode chain).
If that can't run, we fall back to a path-based heuristic: the image sits under
a standard trusted directory. Results are cached by path.
"""

from __future__ import annotations

import ctypes
import ntpath
import os
import posixpath
import sys
from ctypes import wintypes

IS_WINDOWS = sys.platform == "win32"
_cache: dict[tuple, bool] = {}

# WinVerifyTrust constants
_WTD_UI_NONE = 2
_WTD_REVOKE_NONE = 0
_WTD_CHOICE_FILE = 1
_WTD_STATEACTION_VERIFY = 1
_WTD_STATEACTION_CLOSE = 2
# GUID {00AAC56B-CD44-11D0-8CC2-00C04FC295EE}, little-endian serialized for
# _GUID.from_buffer_copy (Data1/Data2/Data3 little-endian, Data4 as-is). The
# previous bytes were wrong, so WinVerifyTrust failed for every file and trust
# dampening silently never fired.
_WINTRUST_ACTION_GENERIC_VERIFY_V2 = (
    b"\x6b\xc5\xaa\x00\x44\xcd\xd0\x11\x8c\xc2\x00\xc0\x4f\xc2\x95\xee"
)


if IS_WINDOWS:
    class _GUID(ctypes.Structure):
        _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                    ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]

    class _WINTRUST_FILE_INFO(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD),
                    ("pcwszFilePath", wintypes.LPCWSTR),
                    ("hFile", wintypes.HANDLE),
                    ("pgKnownSubject", ctypes.c_void_p)]

    class _WINTRUST_DATA(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD),
                    ("pPolicyCallbackData", ctypes.c_void_p),
                    ("pSIPClientData", ctypes.c_void_p),
                    ("dwUIChoice", wintypes.DWORD),
                    ("fdwRevocationChecks", wintypes.DWORD),
                    ("dwUnionChoice", wintypes.DWORD),
                    ("pFile", ctypes.POINTER(_WINTRUST_FILE_INFO)),
                    ("dwStateAction", wintypes.DWORD),
                    ("hWVTStateData", wintypes.HANDLE),
                    ("pwszURLReference", wintypes.LPCWSTR),
                    ("dwProvFlags", wintypes.DWORD),
                    ("dwUIContext", wintypes.DWORD),
                    ("pSignatureSettings", ctypes.c_void_p)]

    def _winverifytrust(path: str) -> bool | None:
        """True/False if the check ran; None if it couldn't run at all."""
        try:
            wintrust = ctypes.WinDLL("wintrust")
        except OSError:
            return None
        guid = _GUID.from_buffer_copy(_WINTRUST_ACTION_GENERIC_VERIFY_V2)
        fi = _WINTRUST_FILE_INFO(ctypes.sizeof(_WINTRUST_FILE_INFO), path, None, None)
        wd = _WINTRUST_DATA()
        wd.cbStruct = ctypes.sizeof(_WINTRUST_DATA)
        wd.dwUIChoice = _WTD_UI_NONE
        wd.fdwRevocationChecks = _WTD_REVOKE_NONE
        wd.dwUnionChoice = _WTD_CHOICE_FILE
        wd.pFile = ctypes.pointer(fi)
        wd.dwStateAction = _WTD_STATEACTION_VERIFY
        try:
            rc = wintrust.WinVerifyTrust(None, ctypes.byref(guid), ctypes.byref(wd))
        except OSError:
            return None
        wd.dwStateAction = _WTD_STATEACTION_CLOSE
        try:
            wintrust.WinVerifyTrust(None, ctypes.byref(guid), ctypes.byref(wd))
        except OSError:
            pass
        return rc == 0  # ERROR_SUCCESS -> validly signed


def _under(path: str, dirs: tuple[str, ...]) -> bool:
    r"""True if `path` sits inside one of `dirs`, matching whole path components.

    A bare prefix test let C:\Program Files2\x.exe count as being under
    C:\Program Files, and any user can create new folders in the root of C:\.
    Separator and case handling follow the path's own style (a path containing a
    backslash or drive colon is treated as Windows), so it is testable anywhere.

    The path is NORMALISED before the comparison, because a prefix test on a
    raw string is defeated by a traversal:

        C:\Windows\System32\..\..\Users\x\AppData\Local\Temp\miner.exe

    begins with a trusted directory while the file is in Temp. A Run key or
    service ImagePath holding that spelling scored 10 instead of 50 — below
    the reporting threshold — and the registry value is attacker-controlled,
    so this was reachable. Process images come from the OS already normalised,
    so this changes nothing for the behavioral signals.
    """
    win = "\\" in path or (len(path) > 1 and path[1] == ":")
    if win:
        p, sep = ntpath.normpath(path).lower().replace("/", "\\"), "\\"
    else:
        p, sep = posixpath.normpath(path), "/"
    for d in dirs:
        d = (d.lower().replace("/", "\\") if win else d).rstrip("\\/")
        if d and (p == d or p.startswith(d + sep)):
            return True
    return False


def in_trusted_dir(exe: str, trusted_dirs: tuple[str, ...]) -> bool:
    """True if `exe` lives under a system directory. Pure path logic, no
    signature check, so callers can use it on every process every pass."""
    return bool(exe) and _under(exe, trusted_dirs)


def is_trusted(exe: str, trusted_dirs: tuple[str, ...],
               untrusted_hints: tuple[str, ...] = ()) -> bool:
    """Return True if `exe` is trusted enough to dampen its memory/name signals.

    Trusted means EITHER validly embedded-signed (WinVerifyTrust) OR inside a
    standard system directory. The directory route is needed because Windows/AV
    binaries are usually catalog-signed, which a file-only WinVerifyTrust can't
    see. Writing into System32 / Program Files needs admin, and the behavioral
    signals (cpu/gpu/probe) are never dampened.

    A signature does NOT earn trust for a binary running from a user-writable
    drop location (`untrusted_hints`: Temp, AppData, ProgramData, /tmp ...).
    Code-signing certificates are cheap and miners ship signed; a signed binary
    in Temp gets no benefit of the doubt.
    """
    if not exe:
        return False
    key = exe.lower()
    ck = (key, trusted_dirs, untrusted_hints)
    if ck in _cache:
        return _cache[ck]
    if _under(exe, trusted_dirs):
        result = True
    elif any(h in key for h in untrusted_hints):
        result = False
    else:
        result = False
        if IS_WINDOWS and os.path.exists(exe):
            try:
                result = _winverifytrust(exe) is True
            except Exception:  # noqa: BLE001 - trust check must never crash a scan
                result = False
    _cache[ck] = result
    return result
