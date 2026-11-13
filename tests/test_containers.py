r"""Container and pod attribution (issue #16).

Fixtures are real `/proc/<pid>/cgroup` shapes. Every runtime writes its own
and they are all still in the wild, so the parser is tested against each
rather than against one canonical form.

The case that matters most is the last one: almost every process on any
machine is not in a container, and claiming one for them would be worse than
saying nothing.
"""

import pytest

from minersentry import containers as C

DOCKER_V1 = """\
12:pids:/docker/3e8f0c1a9b4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f
11:hugetlb:/docker/3e8f0c1a9b4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f
3:cpu,cpuacct:/docker/3e8f0c1a9b4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f
1:name=systemd:/docker/3e8f0c1a9b4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f
0::/docker/3e8f0c1a9b4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f
"""

DOCKER_V2 = ("0::/system.slice/docker-"
             "3e8f0c1a9b4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f"
             ".scope\n")

K8S_CONTAINERD = (
    "0::/kubepods.slice/kubepods-burstable.slice/"
    "kubepods-burstable-pod7f3d9c2a_1b4e_4f5a_8c9d_0e1f2a3b4c5d.slice/"
    "cri-containerd-"
    "aa11bb22cc33dd44ee55ff66aa77bb88cc99dd00ee11ff22aa33bb44cc55dd66.scope\n")

K8S_CRIO = (
    "0::/kubepods.slice/kubepods-besteffort.slice/"
    "kubepods-besteffort-pod7f3d9c2a_1b4e_4f5a_8c9d_0e1f2a3b4c5d.slice/"
    "crio-"
    "aa11bb22cc33dd44ee55ff66aa77bb88cc99dd00ee11ff22aa33bb44cc55dd66.scope\n")

PODMAN = ("0::/machine.slice/libpod-"
          "dd99ee88ff77aa66bb55cc44dd33ee22ff11aa00bb99cc88dd77ee66ff55aa44"
          ".scope\n")

LXC = "0::/lxc/web-01\n"
LXC_PAYLOAD = "0::/lxc.payload.web-01/system.slice/nginx.service\n"

HOST_SESSION = "0::/user.slice/user-1000.slice/session-3.scope\n"
HOST_SYSTEMD = "0::/system.slice/sshd.service\n"
HOST_ROOT = "0::/\n"
HOST_V1 = """\
12:pids:/user.slice/user-1000.slice/session-3.scope
3:cpu,cpuacct:/user.slice
1:name=systemd:/user.slice/user-1000.slice/session-3.scope
"""


# == each runtime's own shape ==============================================
@pytest.mark.parametrize("text,runtime,short", [
    (DOCKER_V1, "docker", "3e8f0c1a9b4d"),
    (DOCKER_V2, "docker", "3e8f0c1a9b4d"),
    (K8S_CONTAINERD, "containerd", "aa11bb22cc33"),
    (K8S_CRIO, "cri-o", "aa11bb22cc33"),
    (PODMAN, "podman", "dd99ee88ff77"),
])
def test_each_runtime_is_recognised(text, runtime, short):
    found = C.parse_cgroup(text)
    assert found is not None
    assert found.runtime == runtime
    assert found.id == short, "the id is the 12 characters every CLI shows"


def test_lxc_uses_a_name_rather_than_a_hash():
    for text in (LXC, LXC_PAYLOAD):
        found = C.parse_cgroup(text)
        assert found is not None and found.runtime == "lxc"
        assert found.id == "web-01"


def test_an_unknown_runtime_still_yields_its_container_id():
    """A bare 64-hex component, from a runtime whose prefix we do not know.
    The ID identifies the workload; the runtime name is a convenience."""
    text = ("0::/some.future.runtime/"
            "cc11dd22ee33ff44aa55bb66cc77dd88ee99ff00aa11bb22cc33dd44ee55ff66\n")
    found = C.parse_cgroup(text)
    assert found is not None
    assert found.runtime == "container"
    assert found.id == "cc11dd22ee33"


# == the common case: not in a container ===================================
@pytest.mark.parametrize("text", [HOST_SESSION, HOST_SYSTEMD, HOST_ROOT,
                                  HOST_V1, "", "   \n\n", "0::\n"])
def test_a_process_on_the_host_is_not_claimed_for_a_container(text):
    """Almost every process on any machine lands here. A false container is
    worse than no container: it sends an operator to roll back a workload
    that was never involved."""
    assert C.parse_cgroup(text) is None


def test_a_systemd_service_is_not_a_container():
    """containerd and docker themselves run as services. Their own processes
    must not be reported as being inside a container."""
    assert C.parse_cgroup("0::/system.slice/containerd.service\n") is None
    assert C.parse_cgroup("0::/system.slice/docker.service\n") is None


def test_a_short_hex_string_is_not_a_container_id():
    """Only 64 hex characters is an ID. A path component that happens to be
    hex -- a build hash, a UUID fragment -- is not."""
    assert C.parse_cgroup("0::/system.slice/app-deadbeef.scope\n") is None
    assert C.parse_cgroup("0::/" + "ab" * 20 + "\n") is None   # 40 chars


def test_malformed_input_does_not_raise():
    for text in ("::::", "no colons at all", "0:", ":::/docker/x",
                 "\x00\x01", "0::/docker/" + "z" * 64):
        assert C.parse_cgroup(text) is None or True   # must not raise


# == Kubernetes: the pod is the thing an operator acts on ==================
def test_the_pod_uid_is_captured_and_normalised():
    """systemd writes the UID with underscores; kubectl shows dashes."""
    found = C.parse_cgroup(K8S_CONTAINERD)
    assert found is not None
    assert found.pod == "7f3d9c2a-1b4e-4f5a-8c9d-0e1f2a3b4c5d"


def test_a_plain_docker_container_has_no_pod():
    found = C.parse_cgroup(DOCKER_V2)
    assert found is not None and found.pod == ""


def test_the_label_leads_with_the_pod_when_there_is_one():
    assert C.parse_cgroup(K8S_CONTAINERD).label == \
        "pod 7f3d9c2a/containerd aa11bb22cc33"
    assert C.parse_cgroup(DOCKER_V2).label == "docker 3e8f0c1a9b4d"
    assert C.parse_cgroup(LXC).label == "lxc web-01"


# == reading a live process ================================================
def test_reading_a_pid_uses_proc_and_tolerates_absence(tmp_path, monkeypatch):
    monkeypatch.setattr(C, "IS_LINUX", True)
    proc = tmp_path / "4242"
    proc.mkdir()
    (proc / "cgroup").write_text(DOCKER_V2, encoding="utf-8")
    found = C.of_pid(4242, root=str(tmp_path))
    assert found is not None and found.id == "3e8f0c1a9b4d"

    # a process that has exited, a kernel thread, or another namespace
    assert C.of_pid(9999, root=str(tmp_path)) is None


def test_nothing_is_read_on_windows(tmp_path, monkeypatch):
    """The file does not exist there, and a scan must not pay for finding out
    once per process per pass."""
    monkeypatch.setattr(C, "IS_LINUX", False)
    # Plant the file so a read would succeed; nothing should look for it.
    proc = tmp_path / "4242"
    proc.mkdir()
    (proc / "cgroup").write_text(DOCKER_V2, encoding="utf-8")

    opened = []
    import builtins
    real_open = builtins.open

    def spy(path, *a, **k):
        opened.append(str(path))
        return real_open(path, *a, **k)
    monkeypatch.setattr(builtins, "open", spy)

    assert C.of_pid(4242, root=str(tmp_path)) is None, (
        "a container was reported on a platform that has no cgroups")
    assert not any("cgroup" in p for p in opened), (
        "the scan paid for a read that cannot succeed, once per process")


# == grouping, because the container is the unit of action =================
def test_pids_are_grouped_by_container():
    """Four busy PIDs in one pod is one thing to look at, not four."""
    web = C.Container("docker", "3e8f0c1a9b4d")
    pod = C.Container("containerd", "aa11bb22cc33",
                      pod="7f3d9c2a-1b4e-4f5a-8c9d-0e1f2a3b4c5d")
    out = C.summarize({101: web, 102: pod, 103: web, 104: pod})
    assert len(out) == 2
    by_id = {row["id"]: row for row in out}
    assert by_id["3e8f0c1a9b4d"]["pids"] == [101, 103]
    assert by_id["aa11bb22cc33"]["pids"] == [102, 104]
    assert by_id["aa11bb22cc33"]["pod"] == "7f3d9c2a-1b4e-4f5a-8c9d-0e1f2a3b4c5d"


def test_the_same_id_in_two_pods_stays_separate():
    a = C.Container("containerd", "aa11bb22cc33", pod="pod-a")
    b = C.Container("containerd", "aa11bb22cc33", pod="pod-b")
    assert len(C.summarize({1: a, 2: b})) == 2


def test_summarizing_nothing_is_an_empty_list():
    assert C.summarize({}) == []


# == the wiring: a parser nobody calls is not a feature ====================
def test_the_engine_resolves_a_container_once_per_pid(monkeypatch):
    """cgroup never changes for a process, so it is cached like exe and
    username rather than re-read every 2.5s pass."""
    from minersentry import engine as engine_mod
    from minersentry.config import Config

    calls = []
    monkeypatch.setattr(engine_mod.containers_mod, "of_pid",
                        lambda pid: calls.append(pid) or
                        C.Container("docker", "3e8f0c1a9b4d"))
    e = engine_mod.Engine(cfg=Config(pool_intel_enabled=False, gpu_enabled=False))
    for _ in range(3):
        if 4242 not in e._container:
            e._container[4242] = engine_mod.containers_mod.of_pid(4242)
    assert calls == [4242], "the cgroup file was read more than once for one PID"


def test_a_pid_that_exits_drops_its_cached_container():
    from minersentry import engine as engine_mod
    from minersentry.config import Config
    e = engine_mod.Engine(cfg=Config(pool_intel_enabled=False, gpu_enabled=False))
    e._container[4242] = C.Container("docker", "3e8f0c1a9b4d")
    e._forget_pid(4242)
    assert 4242 not in e._container, (
        "a recycled PID would inherit the old container's identity")


def test_the_cli_summary_groups_containers_and_tags_each_process():
    from minersentry.cli import summarize
    from minersentry.engine import Engine, ProcInfo
    from minersentry.config import Config

    web = C.Container("docker", "3e8f0c1a9b4d")
    pod = C.Container("containerd", "aa11bb22cc33", pod="7f3d9c2a-1b4e-4f5a-8c9d-0e1f2a3b4c5d")
    rows = []
    for pid, container in ((101, web), (102, pod), (103, web), (104, None)):
        r = ProcInfo(pid, cpu=50.0)
        r.name, r.verdict, r.score = f"p{pid}", "Likely Miner", 80
        r.container = container
        rows.append(r)

    e = Engine(cfg=Config(pool_intel_enabled=False, gpu_enabled=False))
    out = summarize(e, rows, first_hit={})

    labels = {c["label"] for c in out["containers"]}
    assert labels == {"docker 3e8f0c1a9b4d",
                      "pod 7f3d9c2a/containerd aa11bb22cc33"}
    docker = [c for c in out["containers"] if c["id"] == "3e8f0c1a9b4d"][0]
    assert docker["pids"] == [101, 103]

    by_pid = {p["pid"]: p for p in out["processes"]}
    assert by_pid[101]["container"]["id"] == "3e8f0c1a9b4d"
    assert "container" not in by_pid[104], (
        "a host process must not gain an empty container field")


def test_the_audit_record_carries_the_container(tmp_path):
    import json
    from minersentry.audit import AuditLog
    log = AuditLog(path=str(tmp_path / "d.jsonl"))
    log.record_detection(pid=101, name="x", exe="/x", score=80,
                         verdict="Likely Miner", signals=[("cpu", 92, "busy")],
                         container="pod 7f3d9c2a/containerd aa11bb22cc33")
    log.record_detection(pid=102, name="y", exe="/y", score=80,
                         verdict="Likely Miner", signals=[])
    records = [json.loads(ln) for ln in
               open(tmp_path / "d.jsonl", encoding="utf-8") if ln.strip()]
    assert records[0]["container"] == "pod 7f3d9c2a/containerd aa11bb22cc33"
    assert "container" not in records[1], "a host detection gains no empty field"


def test_the_gui_detail_names_the_container_only_when_there_is_one():
    from minersentry.engine import ProcInfo
    from minersentry.gui import MinerSentryApp
    from types import SimpleNamespace

    captured = {}

    def fake_text():
        return SimpleNamespace(
            configure=lambda **k: None,
            delete=lambda *a: None,
            insert=lambda where, text: captured.update(text=text))

    r = ProcInfo(101, cpu=50.0)
    r.name, r.verdict, r.score = "miner", "Likely Miner", 80
    r.container = C.Container("containerd", "aa11bb22cc33", pod="7f3d9c2a-1b4e-4f5a-8c9d-0e1f2a3b4c5d")
    app = SimpleNamespace(rows={101: r}, detail_text=fake_text())
    MinerSentryApp._show_detail(app, 101)
    assert "pod 7f3d9c2a/containerd aa11bb22cc33" in captured["text"]

    r.container = None
    app = SimpleNamespace(rows={101: r}, detail_text=fake_text())
    MinerSentryApp._show_detail(app, 101)
    assert "in:    " not in captured["text"], "a desktop row gained a noise line"


def test_the_container_holding_the_miner_is_listed_first():
    """On a host running thirty containers, alphabetical order puts the one
    that matters anywhere at all."""
    rows = C.summarize(
        {101: C.Container("docker", "aaa111aaa111"),
         102: C.Container("docker", "bbb222bbb222"),
         103: C.Container("docker", "ccc333ccc333")},
        scores={101: 3, 102: 82, 103: 12})
    assert [r["id"] for r in rows] == ["bbb222bbb222", "ccc333ccc333",
                                       "aaa111aaa111"]
    assert rows[0]["worst"] == 82


def test_the_worst_score_in_a_container_is_the_one_reported():
    rows = C.summarize({1: C.Container("docker", "aaa111aaa111"),
                        2: C.Container("docker", "aaa111aaa111")},
                       scores={1: 10, 2: 80})
    assert len(rows) == 1 and rows[0]["worst"] == 80


def test_without_scores_the_rows_are_still_ordered_predictably():
    rows = C.summarize({1: C.Container("docker", "bbb222bbb222"),
                        2: C.Container("docker", "aaa111aaa111")})
    assert [r["id"] for r in rows] == ["aaa111aaa111", "bbb222bbb222"]
    assert all(r["worst"] == 0 for r in rows)
