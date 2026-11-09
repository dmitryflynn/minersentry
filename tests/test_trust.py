"""Tests for trusted-signer detection (false-positive dampening)."""

import pytest

from minersentry import trust

TRUSTED = ("c:\\windows\\system32", "c:\\windows\\syswow64",
           "c:\\program files", "c:\\program files (x86)")


def test_empty_exe_untrusted():
    trust._cache.clear()
    assert trust.is_trusted("", TRUSTED) is False


def test_trusted_system_dir_is_trusted():
    # catalog-signed OS/AV binaries live here; the dir signal covers them even
    # though a file-only signature check cannot see catalog signatures
    trust._cache.clear()
    assert trust.is_trusted(r"C:\Windows\System32\svchost.exe", TRUSTED) is True


def test_unsigned_outside_trusted_dir_not_trusted():
    trust._cache.clear()
    assert trust.is_trusted(r"C:\Users\x\Downloads\miner.exe", TRUSTED) is False


def test_case_insensitive_dir_match():
    trust._cache.clear()
    assert trust.is_trusted(r"C:\WINDOWS\SYSTEM32\lsass.exe", TRUSTED) is True


def test_result_cached():
    trust._cache.clear()
    trust.is_trusted(r"C:\Windows\System32\svchost.exe", TRUSTED)
    assert any(k[0] == r"c:\windows\system32\svchost.exe" for k in trust._cache)


def test_lookalike_folder_is_not_a_trusted_folder():
    # any user can create C:\Program Files2 — a prefix match must not trust it
    assert trust.is_trusted(r"C:\Program Files2\xmrig.exe", TRUSTED) is False
    assert trust.is_trusted(r"C:\Program Files (x86)2\a.exe", TRUSTED) is False
    assert trust.is_trusted(r"C:\Program Files\Vendor\a.exe", TRUSTED) is True


def test_posix_lookalike_folder_is_not_trusted():
    assert trust.is_trusted("/usr/bin2/xmrig", ("/usr/bin",)) is False
    assert trust.is_trusted("/usr/bin/top", ("/usr/bin",)) is True


def test_signature_ignored_in_drop_locations(monkeypatch):
    # a validly signed binary in Temp/AppData earns no trust
    monkeypatch.setattr(trust, "_winverifytrust", lambda p: True, raising=False)
    monkeypatch.setattr(trust.os.path, "exists", lambda p: True)
    monkeypatch.setattr(trust, "IS_WINDOWS", True)
    hints = ("\\appdata\\local\\temp\\", "\\programdata\\")
    trust._cache.clear()
    assert trust.is_trusted(r"C:\Users\x\AppData\Local\Temp\a\miner.exe", TRUSTED, hints) is False
    assert trust.is_trusted(r"D:\tools\signed.exe", TRUSTED, hints) is True


def test_signed_defender_in_programdata_keeps_trust(monkeypatch):
    # Defender runs signed from ProgramData; that must not be treated as a drop spot
    from minersentry.config import Config
    monkeypatch.setattr(trust, "_winverifytrust", lambda p: True, raising=False)
    monkeypatch.setattr(trust.os.path, "exists", lambda p: True)
    monkeypatch.setattr(trust, "IS_WINDOWS", True)
    trust._cache.clear()
    hints = Config().signature_untrusted_dirs
    if r"\temp" + "\\" not in hints:
        pytest.skip("POSIX defaults")
    exe = r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe"
    assert trust.is_trusted(exe, TRUSTED, hints) is True
    assert trust.is_trusted(r"C:\Users\x\AppData\Roaming\svc\miner.exe", TRUSTED, hints) is False
