"""Response actions beyond killing the process.

Killing a miner destroys the thing you would want to look at, and it comes
straight back from whatever autostart entry put it there. These are the gentler
and the more final options, and every one of them is reversible:

- **suspend / resume** — freeze the process. It stops earning and stays intact
  for inspection, which is what you want before deciding anything.
- **block / unblock a pool address** — a firewall rule by IP. The miner keeps
  running and keeps failing to submit shares.
- **quarantine / restore a binary** — move the file somewhere it cannot be
  launched and record where it came from, so putting it back is one call.

Each action writes a journal entry under %LOCALAPPDATA%\\MinerSentry so an undo
never depends on remembering what was done. Suspending needs no privileges for
your own processes; firewall rules and moving a file out of a system directory
need Administrator, and the functions say so rather than failing obscurely.

Nothing here runs automatically. The GUI asks first, every time.
"""

from __future__ import annotations

import ctypes
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass

import psutil

IS_WINDOWS = sys.platform == "win32"
FIREWALL_RULE_PREFIX = "MinerSentry block"


def journal_path() -> str:
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    return os.path.join(base, "MinerSentry", "actions.jsonl")


def quarantine_dir() -> str:
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    return os.path.join(base, "MinerSentry", "quarantine")


@dataclass
class Result:
    ok: bool
    message: str
    undo: str = ""          # how to reverse it, in words


def _record(action: str, **fields) -> None:
    rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "action": action, **fields}
    try:
        os.makedirs(os.path.dirname(journal_path()), exist_ok=True)
        with open(journal_path(), "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
    except OSError:
        pass


def record_action(action: str, **fields) -> None:
    """Journal an action taken by another module (autostart removals)."""
    _record(action, **fields)


def history(limit: int = 50) -> list[dict]:
    """Recent actions, newest last. Used to offer an undo."""
    try:
        with open(journal_path(), "r", encoding="utf-8") as f:
            lines = f.readlines()[-limit:]
    except OSError:
        return []
    out = []
    for line in lines:
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def is_elevated() -> bool:
    if IS_WINDOWS:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:  # noqa: BLE001
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


# -- suspend / resume -------------------------------------------------------
def suspend(pid: int) -> Result:
    """Freeze a process: it stops hashing but stays available to inspect."""
    try:
        p = psutil.Process(pid)
        name = p.name()
        p.suspend()
    except psutil.NoSuchProcess:
        return Result(False, f"PID {pid} is already gone.")
    except psutil.AccessDenied:
        return Result(False, f"Not allowed to suspend PID {pid} — it belongs to "
                             f"another user or to the system. Run elevated.")
    except Exception as e:  # noqa: BLE001
        return Result(False, f"Could not suspend PID {pid}: {type(e).__name__}: {e}")
    _record("suspend", pid=pid, name=name)
    return Result(True, f"Suspended {name} (PID {pid}). It is frozen, not killed.",
                  undo=f"resume({pid})")


def resume(pid: int) -> Result:
    try:
        p = psutil.Process(pid)
        name = p.name()
        p.resume()
    except psutil.NoSuchProcess:
        return Result(False, f"PID {pid} is gone.")
    except psutil.AccessDenied:
        return Result(False, f"Not allowed to resume PID {pid}.")
    except Exception as e:  # noqa: BLE001
        return Result(False, f"Could not resume PID {pid}: {type(e).__name__}: {e}")
    _record("resume", pid=pid, name=name)
    return Result(True, f"Resumed {name} (PID {pid}).")


# -- firewall --------------------------------------------------------------
def _valid_ip(ip: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def block_ip(ip: str) -> Result:
    """Block one remote address outbound, by IP.

    The miner stays up and keeps failing to submit, which is both less
    disruptive than killing it and useful evidence that the address mattered.
    """
    if not _valid_ip(ip):
        return Result(False, f"{ip!r} is not an IP address.")
    if not is_elevated():
        return Result(False, "Blocking an address needs Administrator / root.")
    rule = f"{FIREWALL_RULE_PREFIX} {ip}"
    if IS_WINDOWS:
        args = ["netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule}", "dir=out", "action=block", f"remoteip={ip}"]
    else:
        args = ["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"]
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=30)
    except Exception as e:  # noqa: BLE001
        return Result(False, f"Could not add the rule: {type(e).__name__}: {e}")
    if r.returncode != 0:
        return Result(False, f"Firewall refused the rule: {(r.stderr or r.stdout).strip()[:200]}")
    _record("block_ip", ip=ip, rule=rule)
    return Result(True, f"Blocked outbound traffic to {ip}.", undo=f"unblock_ip('{ip}')")


def unblock_ip(ip: str) -> Result:
    if not _valid_ip(ip):
        return Result(False, f"{ip!r} is not an IP address.")
    if not is_elevated():
        return Result(False, "Removing the rule needs Administrator / root.")
    rule = f"{FIREWALL_RULE_PREFIX} {ip}"
    if IS_WINDOWS:
        args = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule}"]
    else:
        args = ["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"]
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=30)
    except Exception as e:  # noqa: BLE001
        return Result(False, f"Could not remove the rule: {type(e).__name__}: {e}")
    if r.returncode != 0:
        return Result(False, f"Firewall refused: {(r.stderr or r.stdout).strip()[:200]}")
    _record("unblock_ip", ip=ip, rule=rule)
    return Result(True, f"Removed the block on {ip}.")


def list_blocks() -> list[str]:
    """Addresses currently blocked by rules this tool created."""
    return sorted({r["ip"] for r in history(500)
                   if r.get("action") == "block_ip" and r.get("ip")} -
                  {r["ip"] for r in history(500)
                   if r.get("action") == "unblock_ip" and r.get("ip")})


# -- binary quarantine -----------------------------------------------------
def quarantine_file(path: str, kill_first: bool = False,
                    kind: str = "") -> Result:
    """Move a binary where it cannot be launched, remembering where it was.

    A running image is locked on Windows, so the owning processes have to be
    gone first — `kill_first` does that only when the caller asks.

    `kind` records what the file WAS, when the caller knows: an autostart
    removal passes the entry kind so the record can be told apart from a
    quarantined process binary. Without it `persistence.removals()` could not
    see a startup-folder removal at all, and "undo the last removal" restored
    an older, unrelated entry instead.
    """
    if not os.path.isfile(path):
        return Result(False, f"{path} is not a file.")
    target_dir = quarantine_dir()
    stamp = time.strftime("%Y%m%d-%H%M%S")
    dest = os.path.join(target_dir, f"{stamp}-{os.path.basename(path)}")
    if kill_first:
        for p in processes_using(path):
            try:
                p.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        psutil.wait_procs(processes_using(path), timeout=5)
    still = [p.pid for p in processes_using(path)]
    if still:
        return Result(False, f"{os.path.basename(path)} is still running as PID(s) "
                             f"{still}; suspend or stop it first (or ask to kill it).")
    try:
        os.makedirs(target_dir, exist_ok=True)
        shutil.move(path, dest)
    except OSError as e:
        hint = "" if is_elevated() else " Moving a file out of a system directory needs Administrator."
        return Result(False, f"Could not quarantine {path}: {e}.{hint}")
    _record("quarantine_file", original=path, stored=dest,
            **({"kind": kind} if kind else {}))
    return Result(True, f"Moved {os.path.basename(path)} to the quarantine folder.",
                  undo=f"restore_file({dest!r})")


def restore_file(stored: str) -> Result:
    """Put a quarantined binary back where it came from."""
    original = None
    for rec in reversed(history(500)):
        if rec.get("action") == "quarantine_file" and rec.get("stored") == stored:
            original = rec.get("original")
            break
    if not original:
        return Result(False, f"No record of {stored} being quarantined, so where it "
                             f"belongs is unknown. Move it back by hand.")
    if not os.path.isfile(stored):
        return Result(False, f"{stored} is no longer in the quarantine folder.")
    if os.path.exists(original):
        return Result(False, f"{original} exists again; not overwriting it.")
    try:
        os.makedirs(os.path.dirname(original), exist_ok=True)
        shutil.move(stored, original)
    except OSError as e:
        return Result(False, f"Could not restore: {e}")
    _record("restore_file", original=original, stored=stored)
    return Result(True, f"Restored {os.path.basename(original)} to {os.path.dirname(original)}.")


def processes_using(path: str) -> list[psutil.Process]:
    """Live processes running this exact image."""
    want = os.path.normcase(os.path.abspath(path))
    out = []
    for p in psutil.process_iter(["exe"]):
        try:
            exe = p.info.get("exe") or ""
            if exe and os.path.normcase(os.path.abspath(exe)) == want:
                out.append(p)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return out


def quarantined() -> list[dict]:
    """What is in quarantine now, with where each file came from."""
    stored = {}
    for rec in history(500):
        if rec.get("action") == "quarantine_file":
            stored[rec.get("stored")] = rec.get("original")
        elif rec.get("action") == "restore_file":
            stored.pop(rec.get("stored"), None)
    return [{"stored": s, "original": o} for s, o in stored.items() if s and os.path.isfile(s)]
