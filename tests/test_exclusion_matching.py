r"""Defender exclusion matching (issue #61).

An exclusion that covers a path MinerSentry has already flagged scores 95, so
"covers" has to mean what the filesystem means by it: whole path components,
case-insensitive, either separator, variables expanded. The original test was
a substring, which made `C:\Tools` cover `C:\ToolsX\miner.exe`.

The collectors are stubbed; nothing here reads Defender or the hosts file.
"""

import pytest

from minersentry import tamper

ENV = {"USERPROFILE": r"C:\Users\dmitr", "TEMP": r"C:\Users\dmitr\AppData\Local\Temp"}


@pytest.fixture
def stub(monkeypatch):
    """Point scan() at a given exclusion list and nothing else."""
    monkeypatch.setattr(tamper, "_defender_disabled", lambda: [])
    monkeypatch.setattr(tamper, "_read", lambda p: "")
    monkeypatch.setattr(tamper.drivers_mod, "loaded", lambda: [])
    for k, v in ENV.items():
        monkeypatch.setenv(k, v)

    def run(exclusions, flagged=()):
        monkeypatch.setattr(tamper, "_defender_exclusions", lambda: list(exclusions))
        return {f.detail: f for f in tamper.scan(flagged_paths=tuple(flagged))
                if f.kind == "defender-exclusion"}
    return run


def test_the_issue_reproduction(stub):
    found = stub([r"C:\Tools", "D:\\", r"%USERPROFILE%\Downloads"],
                 [r"C:\ToolsX\miner.exe", r"C:\Users\dmitr\Downloads\x\miner.exe"])
    assert found[r"C:\Tools"].score == 45                       # a different folder
    assert found["D:\\"].score == 70                              # a whole drive
    assert found[r"%USERPROFILE%\Downloads"].score == 95          # it does cover it


# -- 1. whole path components, not substrings ------------------------------
@pytest.mark.parametrize("flagged", [
    r"C:\ToolsX\miner.exe",          # sibling folder sharing a prefix
    r"C:\Tools.old\miner.exe",
    r"C:\Toolsminer.exe",            # a file in the parent sharing the prefix
    r"D:\Tools\miner.exe",           # same folder name on another drive
    r"C:\x\Tools\miner.exe",         # the name appearing deeper in the path
])
def test_a_folder_does_not_cover_a_neighbour(stub, flagged):
    assert stub([r"C:\Tools"], [flagged])[r"C:\Tools"].score == 45


@pytest.mark.parametrize("exclusion", [
    r"C:\Tools", "C:\\Tools\\", "c:\\tools", "C:/Tools", "C:/Tools/",
    r"C:\Tools.", r"C:\Tools ", r"C:\Tools\.", r"C:\Other\..\Tools",
    "C:\\\\Tools",
])
def test_spellings_of_the_same_folder_all_cover_its_contents(stub, exclusion):
    assert stub([exclusion], [r"C:\Tools\sub\miner.exe"])[exclusion].score == 95


def test_the_folder_itself_is_covered(stub):
    assert stub([r"C:\Tools"], [r"C:\Tools"])[r"C:\Tools"].score == 95


def test_a_flagged_path_spelled_differently_is_still_covered(stub):
    found = stub([r"C:\Tools"], ["c:/tools/Sub/MINER.EXE"])
    assert found[r"C:\Tools"].score == 95


def test_a_flagged_traversal_out_of_the_folder_is_not_covered(stub):
    found = stub([r"C:\Tools"], [r"C:\Tools\..\Temp2\miner.exe"])
    assert found[r"C:\Tools"].score == 45


def test_a_file_exclusion_covers_exactly_that_file(stub):
    ex = r"C:\Tools\miner.exe"
    assert stub([ex], [r"C:\Tools\miner.exe"])[ex].score == 95
    assert stub([ex], [r"C:\Tools\miner.exe2"])[ex].score == 45
    assert stub([ex], [r"C:\Tools\miner.exe.bak"])[ex].score == 45


# -- 2. any drive root is the whole drive ----------------------------------
@pytest.mark.parametrize("exclusion", ["C:\\", "C:", "D:\\", "d:", "E:/", "Z:\\"])
def test_any_drive_root_is_a_whole_drive(stub, exclusion):
    f = stub([exclusion])[exclusion]
    assert f.score == 70
    assert any("whole drive" in label for label in f.labels)


def test_a_whole_drive_covers_what_is_flagged_on_it_and_not_elsewhere(stub):
    assert stub(["D:\\"], [r"D:\anything\miner.exe"])["D:\\"].score == 95
    assert stub(["D:\\"], [r"C:\anything\miner.exe"])["D:\\"].score == 70


def test_a_folder_named_like_a_drive_is_not_a_drive(stub):
    # "c:\\" used to be in the drop-location hint list as a literal substring.
    f = stub([r"C:\Games"])[r"C:\Games"]
    assert f.score == 45
    assert not any("whole drive" in label for label in f.labels)


# -- 3. environment variables ----------------------------------------------
def test_an_exclusion_with_a_variable_covers_the_expanded_path(stub):
    ex = r"%USERPROFILE%\Downloads"
    assert stub([ex], [r"C:\Users\dmitr\Downloads\x\miner.exe"])[ex].score == 95
    assert stub([ex], [r"C:\Users\other\Downloads\x\miner.exe"])[ex].score == 45


def test_a_variable_naming_a_drop_location_is_scored_as_one(stub):
    assert stub(["%TEMP%"])["%TEMP%"].score == 70
    assert stub(["%temp%\\"], [r"C:\Users\dmitr\AppData\Local\Temp\m.exe"])[
        "%temp%\\"].score == 95


def test_an_unknown_variable_matches_nothing(stub):
    ex = r"%NOT_A_REAL_VAR_61%\x"
    assert stub([ex], [r"C:\x\miner.exe", r"%NOT_A_REAL_VAR_61%\x\m.exe"])[ex].score == 45


# -- drop locations --------------------------------------------------------
@pytest.mark.parametrize("exclusion", [
    r"C:\Windows\Temp", r"C:\Users\Public", r"C:\ProgramData",
    r"C:\Users\x\AppData\Roaming\svc", "/tmp",
])
def test_drop_locations_are_recognised_without_a_trailing_separator(stub, exclusion):
    assert stub([exclusion])[exclusion].score == 70


@pytest.mark.parametrize("exclusion", [r"C:\Users\PublicX", r"C:\Temperature",
                                       r"C:\tmpfiles"])
def test_names_that_merely_start_like_a_drop_location_are_not_one(stub, exclusion):
    assert stub([exclusion])[exclusion].score == 45


# -- wildcards -------------------------------------------------------------
def test_a_wildcard_matches_within_one_component(stub):
    ex = r"C:\Users\*\AppData\Local\svc"
    assert stub([ex], [r"C:\Users\bob\AppData\Local\svc\m.exe"])[ex].score == 95
    # `*` must not swallow separators, or it would cover everything below.
    assert stub([ex], [r"C:\Users\bob\x\AppData\Local\svc\m.exe"])[ex].score == 70
    assert stub([ex], [r"C:\Users\bob\AppData\Local\other\m.exe"])[ex].score == 70


def test_a_wildcard_does_not_match_everything(stub):
    ex = r"C:\Tools\*.tmp"
    assert stub([ex], [r"C:\Tools\miner.exe", r"D:\x.tmp"])[ex].score == 45
    assert stub([ex], [r"C:\Tools\a.tmp"])[ex].score == 95


def test_question_mark_and_brackets(stub):
    ex = r"C:\T?ols"
    assert stub([ex], [r"C:\Tools\m.exe"])[ex].score == 95
    assert stub([ex], [r"C:\Toools\m.exe"])[ex].score == 45
    # Brackets are literal for Defender and in Windows names; fnmatch would
    # read them as a character class.
    ex = r"C:\[ab]"
    assert stub([ex], [r"C:\a\m.exe"])[ex].score == 45
    assert stub([ex], [r"C:\[ab]\m.exe"])[ex].score == 95


def test_odd_entries_do_not_crash(stub):
    odd = ["*", "%", "%%", "\\\\", "\\\\server\\share", "C:\\*", "/"]
    found = stub(odd, [r"C:\x\miner.exe"])
    assert set(found) == set(odd)
    assert found["\\\\server\\share"].score == 45
    # A relative pattern names no place, so it covers nothing in particular.
    assert found["*"].score == 45 and found["%%"].score == 45
    # The root of a drive with a wildcard is still the whole drive.
    assert found["C:\\*"].score == 95
    assert any("whole drive" in label for label in found["C:\\*"].labels)


def test_a_relative_name_covers_nothing(stub):
    found = stub(["miner.exe", "Tools"], [r"C:\Tools\miner.exe"])
    assert found["miner.exe"].score == 45 and found["Tools"].score == 45


def test_a_unc_share_covers_its_own_contents(stub):
    ex = r"\\server\share"
    assert stub([ex], [r"\\server\share\x\m.exe"])[ex].score == 95
    assert stub([ex], [r"\\server\shareX\m.exe"])[ex].score == 45
