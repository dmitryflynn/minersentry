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
import os
import sys
from ctypes import wintypes

IS_WINDOWS = sys.platform == "win32"
_cache: dict[str, bool] = {}

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


def is_trusted(exe: str, trusted_dirs: tuple[str, ...]) -> bool:
    """Return True if `exe` is trusted enough to dampen its memory/name signals.

    A process is trusted if it is EITHER validly embedded-signed (WinVerifyTrust)
    OR lives under a standard trusted system directory. The directory signal is
    needed because Windows/AV binaries — exactly the processes this dampening
    protects — are usually *catalog*-signed (.cat files), which a file-only
    WinVerifyTrust can't see, so they'd otherwise read as unsigned. Writing into
    System32 / Program Files already requires admin (full compromise), and the
    behavioral signals (cpu/gpu/probe) are never dampened, so this is a safe
    trade. Non-signed binaries outside those dirs stay untrusted.
    """
    if not exe:
        return False
    key = exe.lower()
    if key in _cache:
        return _cache[key]
    embedded_signed = False
    if IS_WINDOWS and os.path.exists(exe):
        try:
            embedded_signed = _winverifytrust(exe) is True
        except Exception:  # noqa: BLE001 - trust check must never crash a scan
            embedded_signed = False
    result = embedded_signed or key.startswith(trusted_dirs)
    _cache[key] = result
    return result
