"""The per-PID container cache is pruned with every other per-PID cache (#67)."""

from contextlib import nullcontext
from types import SimpleNamespace

from minersentry import engine as engine_module
from minersentry.audit import AuditLog
from minersentry.config import Config
from minersentry.containers import Container
from minersentry.engine import Engine


def _fake_proc(pid, ctime):
    mem = SimpleNamespace(rss=0)
    return SimpleNamespace(
        pid=pid,
        info={"pid": pid, "name": "worker", "cpu_percent": 0,
              "memory_info": mem, "create_time": ctime},
        name=lambda: "worker", exe=lambda: "/srv/worker", username=lambda: "",
        oneshot=nullcontext, memory_info=lambda: mem, num_threads=lambda: 1)


def test_a_reused_pid_does_not_inherit_a_dead_processs_container(monkeypatch, tmp_path):
    e = Engine(cfg=Config(pool_intel_enabled=False),
               audit=AuditLog(path=str(tmp_path / "a.jsonl")))
    pid = 777101
    procs = [_fake_proc(pid, 100.0)]
    where = {pid: Container(runtime="docker", id="aaaaaaaaaaaa")}
    monkeypatch.setattr(engine_module.psutil, "process_iter", lambda *a, **k: iter(procs))
    monkeypatch.setattr(engine_module.psutil, "net_connections", lambda **k: [])
    monkeypatch.setattr(engine_module.psutil, "cpu_percent", lambda *a: 0)
    monkeypatch.setattr(engine_module.containers_mod, "of_pid", lambda p: where.get(p))
    try:
        row = e.scan_once()[0]
        assert row.container.id == "aaaaaaaaaaaa"

        procs[:] = []                       # the containerised process exits
        e.scan_once()
        assert pid not in e._container, "a dead PID's container was kept"

        where.pop(pid)                      # the PID comes back, on the host
        procs[:] = [_fake_proc(pid, 200.0)]
        row = e.scan_once()[0]
        assert row.container is None
    finally:
        e.close()
