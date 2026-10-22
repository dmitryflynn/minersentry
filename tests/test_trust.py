"""Tests for trusted-signer detection (false-positive dampening)."""

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
    assert r"c:\windows\system32\svchost.exe" in trust._cache
