"""Balloon text must fit the WCHAR fields in UTF-16 units, not characters.

A process name of emoji (two UTF-16 units each) cut at 255 characters made
ctypes raise ValueError, and in the watcher that ended monitoring.
"""

import ctypes

import pytest

from minersentry.tray import fit_utf16

# The overflow is about UTF-16 fields. On Linux wchar_t is UTF-32, where an
# emoji is one unit, so the field checks only mean something on Windows.
UTF16 = ctypes.sizeof(ctypes.c_wchar) == 2
needs_utf16 = pytest.mark.skipif(not UTF16, reason="wchar_t is not UTF-16 here")


def _fits(text: str, units: int) -> bool:
    class Field(ctypes.Structure):
        _fields_ = [("s", ctypes.c_wchar * (units + 1))]
    try:
        Field().s = text
        return True
    except ValueError:
        return False


def test_emoji_are_counted_as_two_units():
    text = fit_utf16("\U0001F600" * 300, 255)
    assert len(text) == 127 and _fits(text, 255)


def test_a_surrogate_pair_is_never_split():
    text = fit_utf16("a" + "\U0001F600" * 10, 4)
    assert text == "a\U0001F600"


def test_short_text_is_unchanged_and_nul_is_dropped():
    assert fit_utf16("xmrig.exe", 255) == "xmrig.exe"
    assert fit_utf16("a\0b", 255) == "ab"


@needs_utf16
def test_the_old_character_cut_did_not_fit():
    assert not _fits(("\U0001F600" * 300)[:255], 255)
