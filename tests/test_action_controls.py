r"""Block, unblock and restore get real controls.

`block_ip`, `unblock_ip` and `restore_file` existed only in the Python API.
The README offered "Unblock" and "Restore", and neither the window nor the
command line could reach them. These tests cover the journal replay behind the
new lists, the guard rails on what may be blocked, the CLI flags, and the
combined undo list the GUI shows.
"""

import json
import os
from types import SimpleNamespace

import pytest

from minersentry import cli
from minersentry import quarantine as Q


def _journal(monkeypatch, *records):
    monkeypatch.setattr(Q, "history", lambda limit=50: list(records))


# == what may be blocked ====================================================
@pytest.mark.parametrize("ip", ["127.0.0.1", "::1", "0.0.0.0", "::",
                                "224.0.0.251", "ff02::1", "169.254.1.1",
                                "fe80::1", "not-an-ip", ""])
def test_addresses_that_must_not_be_blocked_are_refused(ip):
    assert Q.unblockable_reason(ip)


@pytest.mark.parametrize("ip", ["8.8.8.8", "192.168.1.20", "10.0.0.5",
                                "2001:db8::1"])
def test_ordinary_and_lan_addresses_may_be_blocked(ip):
    """A miner's proxy is often on the LAN, so private addresses stay
    blockable."""
    assert Q.unblockable_reason(ip) == ""


def test_a_loopback_block_is_refused_before_anything_runs(monkeypatch):
    ran = []
    monkeypatch.setattr(Q.subprocess, "run", lambda *a, **k: ran.append(a))
    monkeypatch.setattr(Q, "is_elevated", lambda: True)
    r = Q.block_ip("127.0.0.1")
    assert not r.ok and not ran


# == the firewall commands ==================================================
def test_linux_blocks_ipv6_with_ip6tables(monkeypatch):
    """iptables does not take IPv6 addresses; blocking one always failed."""
    monkeypatch.setattr(Q, "IS_WINDOWS", False)
    assert Q._firewall_args("2001:db8::1", add=True)[0] == "ip6tables"
    assert Q._firewall_args("8.8.8.8", add=True)[0] == "iptables"


def test_linux_add_and_delete_are_mirror_images(monkeypatch):
    monkeypatch.setattr(Q, "IS_WINDOWS", False)
    add = Q._firewall_args("8.8.8.8", add=True)
    delete = Q._firewall_args("8.8.8.8", add=False)
    assert add[1] == "-A" and delete[1] == "-D"
    assert add[2:] == delete[2:], "a delete must name exactly the rule added"


def test_windows_add_and_delete_use_the_same_rule_name(monkeypatch):
    monkeypatch.setattr(Q, "IS_WINDOWS", True)
    add = Q._firewall_args("8.8.8.8", add=True)
    delete = Q._firewall_args("8.8.8.8", add=False)
    name = f"name={Q.FIREWALL_RULE_PREFIX} 8.8.8.8"
    assert name in add and name in delete
    assert "dir=out" in add and "action=block" in add


# == the journal replay =====================================================
def test_blocked_replays_blocks_and_unblocks(monkeypatch):
    _journal(monkeypatch,
             {"ts": "t1", "action": "block_ip", "ip": "1.1.1.1"},
             {"ts": "t2", "action": "block_ip", "ip": "2.2.2.2"},
             {"ts": "t3", "action": "unblock_ip", "ip": "1.1.1.1"},
             {"ts": "t4", "action": "suspend", "pid": 5})
    assert Q.blocked() == [{"ip": "2.2.2.2", "ts": "t2"}]


def test_a_block_after_an_unblock_is_current_again(monkeypatch):
    _journal(monkeypatch,
             {"ts": "t1", "action": "block_ip", "ip": "1.1.1.1"},
             {"ts": "t2", "action": "unblock_ip", "ip": "1.1.1.1"},
             {"ts": "t3", "action": "block_ip", "ip": "1.1.1.1"})
    assert Q.blocked() == [{"ip": "1.1.1.1", "ts": "t3"}]


def test_blocking_twice_adds_no_second_rule(monkeypatch):
    """With two identical rules, the first unblock would remove one and leave
    the address blocked while the journal said it was not."""
    _journal(monkeypatch, {"ts": "t1", "action": "block_ip", "ip": "8.8.8.8"})
    ran = []
    monkeypatch.setattr(Q.subprocess, "run", lambda *a, **k: ran.append(a))
    monkeypatch.setattr(Q, "is_elevated", lambda: True)
    r = Q.block_ip("8.8.8.8")
    assert r.ok and "already" in r.message and not ran


def test_quarantined_reports_kind_and_time(monkeypatch, tmp_path):
    held = tmp_path / "miner.exe"
    held.write_bytes(b"x")
    gone = tmp_path / "restored.exe"            # not on disk any more
    _journal(monkeypatch,
             {"ts": "t1", "action": "quarantine_file", "original": "C:/a/miner.exe",
              "stored": str(held)},
             {"ts": "t2", "action": "quarantine_file", "original": "C:/b/x.lnk",
              "stored": str(gone), "kind": "startup-folder"})
    assert Q.quarantined() == [{"stored": str(held), "original": "C:/a/miner.exe",
                                "kind": "", "ts": "t1"}]


# == the CLI ================================================================
HELD = [
    {"original": os.path.join("dir1", "svc.exe"), "stored": os.path.join("q", "1_svc.exe")},
    {"original": os.path.join("dir2", "svc.exe"), "stored": os.path.join("q", "2_svc.exe")},
    {"original": os.path.join("dir3", "other.exe"), "stored": os.path.join("q", "3_other.exe")},
]


def test_restore_by_exact_original_path_wins():
    assert cli.match_quarantined(HELD, os.path.join("dir1", "svc.exe")) == [HELD[0]]


def test_restore_by_stored_path():
    assert cli.match_quarantined(HELD, os.path.join("q", "3_other.exe")) == [HELD[2]]


def test_restore_by_file_name_finds_every_file_of_that_name():
    assert cli.match_quarantined(HELD, "svc.exe") == HELD[:2]
    assert cli.match_quarantined(HELD, "other.exe") == [HELD[2]]
    assert cli.match_quarantined(HELD, "missing.exe") == []


def test_blocked_json(monkeypatch, capsys):
    monkeypatch.setattr(cli.quarantine_mod, "blocked",
                        lambda: [{"ip": "8.8.8.8", "ts": "t1"}])
    assert cli.main(["--blocked", "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == {
        "blocked": [{"ip": "8.8.8.8", "ts": "t1"}]}


def test_quarantined_json(monkeypatch, capsys):
    monkeypatch.setattr(cli.quarantine_mod, "quarantined", lambda: [])
    assert cli.main(["--quarantined", "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == {"quarantined": []}


def test_block_reports_failure_as_json(monkeypatch, capsys):
    monkeypatch.setattr(cli.quarantine_mod, "block_ip",
                        lambda ip: SimpleNamespace(ok=False, message="needs admin"))
    assert cli.main(["--block", " 8.8.8.8 ", "--json"]) == 1
    assert json.loads(capsys.readouterr().out) == {"ok": False, "message": "needs admin"}


def test_unblock_passes_the_address_through(monkeypatch, capsys):
    seen = []
    monkeypatch.setattr(cli.quarantine_mod, "unblock_ip",
                        lambda ip: seen.append(ip) or SimpleNamespace(ok=True, message="ok"))
    assert cli.main(["--unblock", "8.8.8.8"]) == 0
    assert seen == ["8.8.8.8"]


def test_an_ambiguous_restore_lists_the_candidates_and_restores_nothing(monkeypatch, capsys):
    monkeypatch.setattr(cli.quarantine_mod, "quarantined", lambda: HELD)
    restored = []
    monkeypatch.setattr(cli.quarantine_mod, "restore_file", restored.append)
    assert cli.main(["--restore", "svc.exe", "--json"]) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is False and len(out["matches"]) == 2
    assert not restored


def test_a_unique_restore_restores_the_stored_copy(monkeypatch, capsys):
    monkeypatch.setattr(cli.quarantine_mod, "quarantined", lambda: HELD)
    restored = []
    monkeypatch.setattr(cli.quarantine_mod, "restore_file",
                        lambda s: restored.append(s) or SimpleNamespace(ok=True, message="back"))
    assert cli.main(["--restore", "other.exe"]) == 0
    assert restored == [HELD[2]["stored"]]


# == the GUI's combined undo list ===========================================
def test_the_undo_list_merges_all_three_sources_newest_first(monkeypatch):
    from minersentry import gui
    monkeypatch.setattr(gui.persist_mod, "removals", lambda: [
        {"ts": "2026-01-01T10:00:00", "action": "remove_registry_value",
         "hive": "HKCU", "path": "Software\\X", "name": "Run1"}])
    monkeypatch.setattr(gui.quarantine_mod, "quarantined", lambda: [
        {"stored": "q/m.exe", "original": "C:/t/m.exe", "kind": "", "ts": "2026-01-01T12:00:00"},
        # Quarantined by an autostart removal: undone as that removal, so it
        # must not appear twice.
        {"stored": "q/e.lnk", "original": "C:/s/e.lnk", "kind": "startup-folder",
         "ts": "2026-01-01T09:00:00"}])
    monkeypatch.setattr(gui.quarantine_mod, "blocked", lambda: [
        {"ip": "8.8.8.8", "ts": "2026-01-01T11:00:00"}])
    actions = gui.reversible_actions()
    labels = [a["label"] for a in actions]
    assert len(actions) == 3
    assert "m.exe" in labels[0] and "8.8.8.8" in labels[1] and "Run1" in labels[2]


def test_each_undo_calls_the_right_function(monkeypatch):
    from minersentry import gui
    calls = []
    monkeypatch.setattr(gui.persist_mod, "removals", lambda: [])
    monkeypatch.setattr(gui.quarantine_mod, "quarantined", lambda: [
        {"stored": "q/m.exe", "original": "C:/t/m.exe", "kind": "", "ts": "b"}])
    monkeypatch.setattr(gui.quarantine_mod, "blocked", lambda: [{"ip": "8.8.8.8", "ts": "a"}])
    monkeypatch.setattr(gui.quarantine_mod, "restore_file", lambda s: calls.append(("restore", s)))
    monkeypatch.setattr(gui.quarantine_mod, "unblock_ip", lambda ip: calls.append(("unblock", ip)))
    for action in gui.reversible_actions():
        action["undo"]()
    assert calls == [("restore", "q/m.exe"), ("unblock", "8.8.8.8")]


def test_blockable_addresses_skips_listeners_loopback_and_duplicates():
    from minersentry import gui
    addr = lambda ip: SimpleNamespace(ip=ip, port=3333)  # noqa: E731
    conns = [SimpleNamespace(raddr=()),                    # a listening socket
             SimpleNamespace(raddr=addr("127.0.0.1")),
             SimpleNamespace(raddr=addr("45.1.2.3")),
             SimpleNamespace(raddr=addr("45.1.2.3")),
             SimpleNamespace(raddr=addr("2001:db8::7")),
             SimpleNamespace(raddr=None)]
    assert gui.blockable_addresses(conns) == ["45.1.2.3", "2001:db8::7"]
