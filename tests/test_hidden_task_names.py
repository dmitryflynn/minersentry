r"""A hidden task is matched against the listing by its full name (issue #54).

The task-file walk exists to find tasks `schtasks` does not list. It used to
treat a file as listed when its LEAF name matched any listed task, so a
hidden `\Evil\OneDrive Standalone Update Task` was skipped because the
visible `\OneDrive Standalone Update Task` exists.
"""

from minersentry import persistence as P

TASK_XML = ('<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
            '<Actions><Exec><Command>C:\\Temp\\x.exe</Command>'
            '<Arguments>-o stratum+tcp://p:3333</Arguments></Exec></Actions></Task>')
LEAF = "OneDrive Standalone Update Task"


def listed(*names):
    return [P.PersistEntry(kind="scheduled-task", location=n,
                           name=n.rsplit("\\", 1)[-1], command="x")
            for n in names]


def test_a_hidden_task_sharing_a_leaf_name_with_a_listed_one_is_reported(tmp_path):
    (tmp_path / "Evil").mkdir()
    (tmp_path / "Evil" / LEAF).write_text(TASK_XML, encoding="utf-8")
    visible = P.listed_task_names(listed("\\" + LEAF))

    found = P._collect_task_files(visible, root=str(tmp_path))

    assert [e.location for e in found] == ["\\Evil\\" + LEAF]
    assert found[0].kind == "hidden-task"


def test_a_bare_leaf_name_never_counts_as_listed(tmp_path):
    # the set the collector used to build: full names AND leaf names
    (tmp_path / "Evil").mkdir()
    (tmp_path / "Evil" / LEAF).write_text(TASK_XML, encoding="utf-8")
    visible = {"\\" + LEAF.lower(), LEAF.lower()}
    found = P._collect_task_files(visible, root=str(tmp_path))
    assert [e.location for e in found] == ["\\Evil\\" + LEAF]


def test_the_listed_task_itself_is_still_not_reported_twice(tmp_path):
    (tmp_path / "Microsoft").mkdir()
    (tmp_path / "Microsoft" / LEAF).write_text(TASK_XML, encoding="utf-8")
    visible = P.listed_task_names(listed("\\MICROSOFT\\" + LEAF))   # any case
    assert P._collect_task_files(visible, root=str(tmp_path)) == []


def test_listed_names_are_full_names_only():
    assert P.listed_task_names(listed("\\A\\B", "\\C")) == {"\\a\\b", "\\c"}
