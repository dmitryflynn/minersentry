"""Shared test fixtures."""

import pytest

from minersentry import quarantine

TEST_JOURNAL_KEY = b"k" * 32


@pytest.fixture(autouse=True)
def _journal_key_in_memory(monkeypatch):
    """The real journal key lives in Program Files, and Windows CI runners are
    elevated: without this, a test that journals anything would create it
    there. Every test signs with a fixed in-memory key instead; tests of the
    key handling itself undo this and point it at a temporary folder."""
    monkeypatch.setattr(quarantine, "_key_cache", None)
    monkeypatch.setattr(quarantine, "_journal_key",
                        lambda create=False: TEST_JOURNAL_KEY
                        if quarantine.is_elevated() else None)
