"""Issue #52: a damaged actions.jsonl must cost the damaged lines, not every undo."""

import pytest

from minersentry import persistence, quarantine

GOOD = (b'{"ts": "t1", "action": "remove_task", "task": "Evil"}\n'
        b'{"ts": "t2", "action": "block_ip", "ip": "203.0.113.9", "rule": "r"}\n')


@pytest.mark.parametrize("damage", [
    b"\xff\xfe torn write\n",      # not UTF-8: readlines() raised UnicodeDecodeError
    b"null\n",                     # valid JSON, not an object: .get() raised
    b"42\n",
    b'["a", "list"]\n',
])
def test_undo_survives_a_damaged_line(tmp_path, monkeypatch, damage):
    path = tmp_path / "actions.jsonl"
    path.write_bytes(damage + GOOD + damage)
    monkeypatch.setattr(quarantine, "journal_path", lambda: str(path))
    assert [r["action"] for r in quarantine.history()] == ["remove_task", "block_ip"]
    assert [r["task"] for r in persistence.removals()] == ["Evil"]
    assert quarantine.quarantined() == []
