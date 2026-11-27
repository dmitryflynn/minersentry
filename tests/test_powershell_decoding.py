"""PowerShell output is read as UTF-8, and file names never become script (#59).

Windows PowerShell writes redirected output in the OEM code page while
Python's `text=True` reads the ANSI one, so every non-ASCII character in a
path came back changed. Startup shortcuts were the visible case: the
`link -> target` map never matched, and the target was never scored.
"""

import os
import re
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from minersentry import persistence as P
from minersentry import powershell

PACKAGE = Path(P.__file__).resolve().parent
WINDOWS = pytest.mark.skipif(sys.platform != "win32", reason="Windows PowerShell")


# == the pure parts ==========================================================
def test_utf8_output_is_decoded_as_utf8():
    assert powershell.decode("Café Ünïcode’s".encode("utf-8")) == "Café Ünïcode’s"


def test_the_old_mismatch_is_what_this_replaces():
    """What used to happen, pinned so the reason for the helper stays visible:
    cp437 bytes read as cp1252 turn `é` into a low quote."""
    assert "Café".encode("cp437").decode("cp1252") == "Caf‚"


def test_undecodable_bytes_are_replaced_not_raised():
    # 0x81 is u-umlaut in cp437 and has no cp1252 character at all: under the
    # old decoding this byte raised UnicodeDecodeError.
    text = powershell.decode(b"ok\x81tail\r\nnext\r\n")
    assert text.startswith("ok") and "tail" in text
    assert text.splitlines()[1] == "next"


def test_a_byte_order_mark_does_not_reach_the_first_field():
    raw = "\ufeff\"Name\",\"State\"\r\n".encode("utf-8")
    assert powershell.decode(raw).startswith('"Name"')


def test_nothing_decodes_to_empty_text():
    assert powershell.decode(None) == ""
    assert powershell.decode(b"") == ""


def test_the_script_switches_output_to_utf8_before_anything_else():
    script = powershell.with_utf8_output("Get-Thing")
    assert script.startswith("[Console]::OutputEncoding = [System.Text.Encoding]::UTF8")
    assert script.endswith("Get-Thing")


def test_run_decodes_bytes_and_passes_env(monkeypatch):
    seen = {}

    def fake_run(args, **kw):
        seen["args"], seen["kw"] = args, kw
        return SimpleNamespace(args=args, returncode=0,
                               stdout="Tärget".encode("utf-8"), stderr=b"\x81")
    monkeypatch.setattr(powershell.subprocess, "run", fake_run)
    r = powershell.run("Get-Thing", timeout=5, env={"MS_TEST": "Ünï"})
    assert r.stdout == "Tärget" and isinstance(r.stderr, str)
    assert seen["args"][:4] == ["powershell", "-NoProfile", "-NonInteractive", "-Command"]
    assert seen["args"][4] == powershell.with_utf8_output("Get-Thing")
    # bytes come back, so Python's locale decoding never runs
    assert "text" not in seen["kw"] and "encoding" not in seen["kw"]
    assert seen["kw"]["env"]["MS_TEST"] == "Ünï"
    assert seen["kw"]["timeout"] == 5


def test_run_raises_what_subprocess_raises(monkeypatch):
    def boom(*a, **k):
        raise subprocess.TimeoutExpired("powershell", 1)
    monkeypatch.setattr(powershell.subprocess, "run", boom)
    with pytest.raises(subprocess.TimeoutExpired):
        powershell.run("x", timeout=1)


def test_every_collector_reads_powershell_through_the_helper():
    """So the decoding cannot drift again. Two exceptions, both deliberate:
    procevents streams a long-lived helper through Popen and sets UTF-8
    itself, and the service toast discards its output."""
    allowed = {"powershell.py", "procevents.py", "service.py"}
    direct = re.compile(r"""subprocess\.\w+\(\s*\[\s*["']powershell""")
    offenders = [p.name for p in PACKAGE.glob("*.py")
                 if p.name not in allowed
                 and direct.search(p.read_text(encoding="utf-8"))]
    assert offenders == []


# == shortcut paths are data, never script ===================================
def test_shortcut_paths_are_passed_in_the_environment_not_the_script(monkeypatch):
    if not P.IS_WINDOWS:
        monkeypatch.setattr(P, "IS_WINDOWS", True)
    names = [r"C:\S\it's.lnk", "C:\\S\\smart\u2019quote.lnk", r"C:\S\Café Ünïcode.lnk"]
    seen = {}

    def fake_run(script, timeout, env=None):
        seen["script"], seen["env"] = script, env
        out = "".join(f"{n}\tC:\\T\\{i}.exe\t-o x\n" for i, n in enumerate(names))
        return subprocess.CompletedProcess([], 0, out, "")
    monkeypatch.setattr(P.powershell, "run", fake_run)
    entries = [P.PersistEntry(kind="startup-folder", location="C:\\S", name=n,
                              command=n, exe=n, file=n) for n in names]
    P._resolve_shortcuts(entries)
    for n in names:
        assert n not in seen["script"]
    assert "\u2019" not in seen["script"] and "'" not in seen["script"].split("\n", 1)[1]
    assert seen["env"]["MINERSENTRY_SHORTCUTS"].split("\n") == names
    assert [e.exe for e in entries] == [f"C:\\T\\{i}.exe" for i in range(3)]


# == against the real PowerShell =============================================
@WINDOWS
def test_real_powershell_output_round_trips_non_ascii():
    r = powershell.run('"Caf" + [char]0xE9 + " " + [char]0xDC + [char]0x2019', timeout=60)
    assert r.returncode == 0
    assert r.stdout.strip() == "Café Ü\u2019"


def _make_shortcuts(pairs):
    script = ("$s = New-Object -ComObject WScript.Shell; "
              "$l = $env:MS59_LINKS -split \"`n\"; $t = $env:MS59_TARGETS -split \"`n\"; "
              "for ($i = 0; $i -lt $l.Count; $i++) { $k = $s.CreateShortcut($l[$i]); "
              "$k.TargetPath = $t[$i]; $k.Arguments = '-o stratum+tcp://x:1'; $k.Save() }")
    env = dict(os.environ, MS59_LINKS="\n".join(p[0] for p in pairs),
               MS59_TARGETS="\n".join(p[1] for p in pairs))
    return subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                          env=env, capture_output=True, timeout=60,
                          creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


@WINDOWS
def test_real_shortcuts_with_non_ascii_and_quotes_all_resolve(tmp_path):
    """Real .lnk files, in a scratch folder and never a Startup folder. Before
    the fix the non-ASCII and apostrophe cases stayed unresolved, and the
    typographic quote broke the script so that NONE of them resolved."""
    target_dir = tmp_path / "Tärget dir"
    target_dir.mkdir()
    plain = tmp_path / "plain.exe"
    uni = target_dir / "mïner Ü.exe"
    quoted = tmp_path / "o'brien\u2019s.exe"
    for t in (plain, uni, quoted):
        t.write_bytes(b"")
    pairs = [(str(tmp_path / n), str(t)) for n, t in (
        ("plain.lnk", plain),
        ("Café Ünïcode.lnk", plain),
        ("unicode-target.lnk", uni),
        ("it's here.lnk", plain),
        ("smart\u2019quote.lnk", plain),
        ("Ünï 'both'.lnk", quoted),
    )]
    made = _make_shortcuts(pairs)
    if made.returncode != 0 or not all(os.path.isfile(link) for link, _ in pairs):
        pytest.skip("could not create shortcuts: "
                    f"{powershell.decode(made.stderr).strip()[:120]}")

    entries = [P.PersistEntry(kind="startup-folder", location=str(tmp_path),
                              name=os.path.basename(link), command=link,
                              exe=link, file=link) for link, _ in pairs]
    P._resolve_shortcuts(entries)
    for entry, (link, target) in zip(entries, pairs):
        assert entry.exe.lower() == target.lower(), entry.name
        assert entry.command == f'"{entry.exe}" -o stratum+tcp://x:1'
        assert entry.file == link    # the shortcut is still what removal touches
