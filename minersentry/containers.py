r"""Attribute a process to its container or pod (issue #16).

On a server the useful answer is not "PID 4242" but "which container". Cloud
cryptojacking lives in containers: the compromise is usually a workload, and
the host PID is the one number nobody can act on — it is gone the moment the
container restarts, and it does not tell an operator which deployment to roll
back.

Everything needed is in `/proc/<pid>/cgroup`, which is a read with no
privileges, so this costs one small file read per process and nothing on
Windows.

The parsing is deliberately pattern-based rather than clever. Every runtime
writes its own shape and they are all still in the wild:

    cgroup v1, Docker        3:cpu,cpuacct:/docker/<64 hex>
    cgroup v2, Docker        0::/system.slice/docker-<64 hex>.scope
    Kubernetes + containerd  0::/kubepods.slice/kubepods-burstable.slice/
                               kubepods-burstable-pod<uid>.slice/
                               cri-containerd-<64 hex>.scope
    Kubernetes + CRI-O       0::/kubepods.slice/.../crio-<64 hex>.scope
    Podman                   0::/machine.slice/libpod-<64 hex>.scope
    LXC                      0::/lxc/<name>
    plain host process       0::/user.slice/user-1000.slice/session-3.scope

The last of those is the case that matters most: the overwhelming majority of
processes on any machine are not in a container, and reporting one for them
would be worse than reporting nothing.

What this does NOT do is name the container. A human-readable name lives in
the runtime's own API (the Docker socket, the kubelet), not in cgroup, and
reaching for it would mean talking to a daemon, authenticating, and failing
differently on every platform. The container ID and pod UID are what the
kernel knows, and both are enough to find the workload with one `docker
inspect` or `kubectl get pod`.
"""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass

IS_LINUX = sys.platform.startswith("linux")

# A container ID is 64 hex characters; 12 is what every CLI shows.
_HEX64 = r"[0-9a-f]{64}"
_SHORT = 12

# (runtime, pattern). Order matters: the scope forms are more specific than
# the bare-hex fallback, and must be tried first.
_PATTERNS: tuple[tuple[str, "re.Pattern[str]"], ...] = (
    ("containerd", re.compile(rf"cri-containerd[-:]({_HEX64})")),
    ("cri-o", re.compile(rf"crio[-:]({_HEX64})")),
    ("docker", re.compile(rf"docker[-/]({_HEX64})")),
    ("podman", re.compile(rf"libpod[-/]({_HEX64})")),
    ("containerd", re.compile(rf"containerd[-:]({_HEX64})")),
    # GitHub Actions runs job steps in Docker under this path
    ("docker", re.compile(rf"/actions_job/({_HEX64})")),
)

# LXC and LXD use a name rather than a hash.
_LXC = re.compile(r"/lxc(?:\.payload)?[./]([^/\s]+)")

# kubepods-burstable-pod<uid>.slice, where the UID has underscores for dashes.
_POD = re.compile(r"pod([0-9a-fA-F]{8}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{4}"
                  r"[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{12})")
# A systemd user session or the root cgroup: explicitly NOT a container.
_NOT_A_CONTAINER = ("/user.slice", "/system.slice", "/init.scope", "/")


@dataclass(frozen=True)
class Container:
    runtime: str          # "docker", "containerd", "cri-o", "podman", "lxc"
    id: str               # short id (12 chars) or the LXC name
    pod: str = ""         # Kubernetes pod UID, when there is one

    @property
    def label(self) -> str:
        """One short string for a table cell or a log line."""
        if self.pod:
            return f"pod {self.pod[:8]}/{self.runtime} {self.id}"
        return f"{self.runtime} {self.id}"


def parse_cgroup(text: str) -> Container | None:
    """The container a `/proc/<pid>/cgroup` body describes, or None. Pure."""
    pod = ""
    best: Container | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        # hierarchy-ID:controllers:path — the path can itself contain colons
        parts = line.split(":", 2)
        path = parts[2] if len(parts) == 3 else line
        if not path:
            continue

        found = _POD.search(path)
        if found and not pod:
            pod = found.group(1).replace("_", "-")

        if best is not None:
            continue
        for runtime, pattern in _PATTERNS:
            match = pattern.search(path)
            if match:
                best = Container(runtime=runtime, id=match.group(1)[:_SHORT])
                break
        if best is None:
            match = _LXC.search(path)
            if match and match.group(1) not in (".", ".."):
                best = Container(runtime="lxc", id=match.group(1))
        if best is None:
            # A bare 64-hex component, from a runtime whose prefix we do not
            # know yet. Still worth reporting: the ID is what identifies the
            # workload, the runtime name is only a convenience.
            for component in path.split("/"):
                component = component.strip()
                if re.fullmatch(_HEX64, component):
                    best = Container(runtime="container", id=component[:_SHORT])
                    break

    if best is None:
        return None
    return Container(runtime=best.runtime, id=best.id, pod=pod) if pod else best


def of_pid(pid: int, root: str = "/proc") -> Container | None:
    """The container a live process belongs to, or None.

    Returns None rather than raising for a process that has exited, a kernel
    thread, or a PID in another namespace that cannot be read — any of which
    happen routinely during a scan.
    """
    if not IS_LINUX:
        return None
    try:
        with open(os.path.join(root, str(pid), "cgroup"),
                  "r", encoding="utf-8", errors="replace") as f:
            return parse_cgroup(f.read(16 * 1024))
    except (OSError, ValueError):
        return None


def summarize(containers: dict[int, Container],
              scores: dict[int, int] | None = None) -> list[dict]:
    """Containers seen in a pass, with the PIDs attributed to each.

    Grouped by container because that is the unit an operator acts on: four
    busy PIDs in one pod is one thing to go and look at, not four.

    With `scores`, each row carries the worst score inside it and the list is
    ordered worst first. Without that ordering the container holding the miner
    sits in alphabetical order among containers holding nothing of interest,
    which is the opposite of useful on a host running thirty of them.
    """
    scores = scores or {}
    grouped: dict[tuple[str, str, str], list[int]] = {}
    for pid, container in containers.items():
        grouped.setdefault(
            (container.runtime, container.id, container.pod), []).append(pid)
    rows = [{"runtime": runtime, "id": cid, "pod": pod,
             "label": Container(runtime, cid, pod).label,
             "pids": sorted(pids),
             "worst": max((scores.get(p, 0) for p in pids), default=0)}
            for (runtime, cid, pod), pids in grouped.items()]
    rows.sort(key=lambda row: (-row["worst"], row["label"]))
    return rows
