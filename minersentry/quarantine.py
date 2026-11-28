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
import hashlib
import hmac
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


# -- journal integrity -------------------------------------------------------
# The journal lives under the user's profile, so anything running as that user
# can write to it, malware included. Replaying a record is harmless when the
# replay runs with the same rights as the writer: whatever it does, the writer
# could have done itself. An ELEVATED replay is different. A forged
# `remove_task` record carrying a task XML with a SYSTEM principal made an
# administrator's `--autostart-undo` (which takes the newest record without
# showing it) create a SYSTEM task: a UAC bypass. So records written by an
# elevated session are signed with a key only administrators can read, and an
# elevated session replays only records whose signature checks out.
_KEY_BYTES = 32
_key_cache: bytes | None = None


def journal_key_path() -> str:
    """Where the signing key lives: somewhere only an administrator can create
    files. Not under %ProgramData% (users may create folders there), and the
    Program Files location comes from HKLM, not the environment (#101)."""
    if IS_WINDOWS:
        from .config import program_files
        return os.path.join(program_files(), "MinerSentry", "journal.key")
    return "/var/lib/minersentry/journal.key"


def _lock_down(path: str) -> bool:
    """Make `path` readable and writable by Administrators and SYSTEM only.
    By SID, so it works on a non-English install."""
    if IS_WINDOWS:
        try:
            r = subprocess.run(["icacls", path, "/inheritance:r", "/grant:r",
                                "*S-1-5-32-544:F", "*S-1-5-18:F"],
                               capture_output=True, text=True, timeout=30,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except (OSError, subprocess.SubprocessError):
            return False
        return r.returncode == 0
    try:
        os.chmod(path, 0o600)
        return True
    except OSError:
        return False


def _posix_key_is_private(path: str) -> bool:
    try:
        st = os.stat(path)
        parent = os.stat(os.path.dirname(path))
    except OSError:
        return False
    return (st.st_uid == 0 and not st.st_mode & 0o077
            and parent.st_uid == 0 and not parent.st_mode & 0o022)


def _journal_key(create: bool = False) -> bytes | None:
    """The signing key, or None when this process may not have it.

    Only an elevated process reads or creates it. An unelevated one gets None
    even if the file happens to be readable, so nothing it writes is signed.
    """
    global _key_cache
    if not is_elevated():
        return None
    if _key_cache:
        return _key_cache
    path = journal_key_path()
    try:
        with open(path, "rb") as f:
            key = f.read()
    except OSError:
        key = None
    if key is not None and len(key) == _KEY_BYTES:
        if IS_WINDOWS:
            # Re-applied once per process: if the ACL was ever loosened, at
            # least it stops being readable now.
            _lock_down(path)
        elif not _posix_key_is_private(path):
            return None
        _key_cache = key
        return key
    if not create:
        return None
    try:
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        if os.path.exists(path):
            os.remove(path)             # wrong length: unusable, replace it
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | getattr(os, "O_BINARY", 0), 0o600)
        try:
            # Locked before the key is written, so it is never readable.
            if not _lock_down(path):
                raise OSError("could not restrict the key file")
            key = os.urandom(_KEY_BYTES)
            if os.write(fd, key) != _KEY_BYTES:
                raise OSError("short write")
        finally:
            os.close(fd)
    except OSError:
        try:
            os.remove(path)
        except OSError:
            pass
        return None
    if len(key) != _KEY_BYTES:
        return None
    _key_cache = key
    return key


def _signature(key: bytes, rec: dict) -> str:
    body = {k: v for k, v in rec.items() if k != "sig"}
    blob = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hmac.new(key, blob.encode("ascii"), hashlib.sha256).hexdigest()


def is_trusted(rec: dict) -> bool:
    """Was this record written by an elevated MinerSentry? Only answerable
    from an elevated process; anywhere else it is False."""
    sig = rec.get("sig")
    if not isinstance(sig, str):
        return False
    key = _journal_key()
    return bool(key) and hmac.compare_digest(sig, _signature(key, rec))


def replay_refusal(rec: dict) -> str:
    """Why an elevated process will not act on this record, or "" if it may.

    An unelevated replay can do nothing the record's writer could not have
    done itself, so it is always allowed.
    """
    if not is_elevated() or is_trusted(rec):
        return ""
    return ("That record was not written by MinerSentry running as "
            "Administrator, so it is not replayed with Administrator rights: "
            "anything running as you can write to the actions journal. Undo it "
            "from a normal (non-elevated) MinerSentry, or by hand.")


def _record(action: str, **fields) -> None:
    rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "action": action, **fields}
    key = _journal_key(create=True)
    if key:
        rec["sig"] = _signature(key, rec)
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
    """Recent actions, newest last. Used to offer an undo.

    A damaged line costs that line only. A byte that is not UTF-8 used to
    raise out of readlines(), and a line that parsed to something other than
    an object reached callers that all do `record.get(...)` — either way
    every undo stopped working.
    """
    try:
        with open(journal_path(), "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()[-limit:]
    except OSError:
        return []
    out = []
    for line in lines:
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if isinstance(record, dict):
            out.append(record)
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


def unblockable_reason(ip: str) -> str:
    """Why an address must not be blocked, or "" if it may be. Pure.

    Loopback, unspecified, multicast and link-local addresses are refused:
    blocking 127.0.0.1 or ::1 breaks local services (MinerSentry's own helper
    included), and none of them is where a pool lives. Private LAN addresses
    are allowed, because a miner's proxy often is one.
    """
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return f"{ip!r} is not an IP address."
    if addr.is_loopback:
        return f"{ip} is a loopback address; blocking it breaks local services."
    if addr.is_unspecified:
        return f"{ip} is the unspecified address."
    if addr.is_multicast:
        return f"{ip} is a multicast address."
    if addr.is_link_local:
        return f"{ip} is a link-local address."
    return ""


def blocked() -> list[dict]:
    """Addresses this tool currently has a firewall block on, oldest first.

    Replayed from the journal: a block_ip adds, an unblock_ip removes. The
    firewall itself is not consulted, so a rule someone deleted by hand still
    shows here until it is unblocked; unblocking it then fails harmlessly.
    """
    current: dict[str, dict] = {}
    for rec in history(500):
        ip = rec.get("ip")
        if not ip:
            continue
        if rec.get("action") == "block_ip":
            current.setdefault(ip, {"ip": ip, "ts": rec.get("ts", "")})
        elif rec.get("action") == "unblock_ip":
            current.pop(ip, None)
    return list(current.values())


def _firewall_args(ip: str, add: bool) -> list[str]:
    import ipaddress
    rule = f"{FIREWALL_RULE_PREFIX} {ip}"
    if IS_WINDOWS:
        if add:
            return ["netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule}", "dir=out", "action=block", f"remoteip={ip}"]
        return ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule}"]
    # iptables only handles IPv4; an IPv6 address needs ip6tables, which the
    # old code never used, so blocking one always failed on Linux.
    tool = "ip6tables" if ipaddress.ip_address(ip).version == 6 else "iptables"
    return [tool, "-A" if add else "-D", "OUTPUT", "-d", ip, "-j", "DROP"]


def block_ip(ip: str) -> Result:
    """Block one remote address outbound, by IP.

    The miner stays up and keeps failing to submit, which is both less
    disruptive than killing it and useful evidence that the address mattered.
    Blocking an address that is already blocked adds no second rule: the
    first unblock would otherwise remove one copy and leave the other.
    """
    why = unblockable_reason(ip)
    if why:
        return Result(False, why)
    if any(b["ip"] == ip for b in blocked()):
        return Result(True, f"{ip} is already blocked.", undo=f"unblock_ip('{ip}')")
    if not is_elevated():
        return Result(False, "Blocking an address needs Administrator / root.")
    rule = f"{FIREWALL_RULE_PREFIX} {ip}"
    args = _firewall_args(ip, add=True)
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
    args = _firewall_args(ip, add=False)
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=30)
    except Exception as e:  # noqa: BLE001
        return Result(False, f"Could not remove the rule: {type(e).__name__}: {e}")
    if r.returncode != 0:
        return Result(False, f"Firewall refused: {(r.stderr or r.stdout).strip()[:200]}")
    _record("unblock_ip", ip=ip, rule=rule)
    return Result(True, f"Removed the block on {ip}.")


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
    dest = _free_name(target_dir, os.path.basename(path))
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
        digest = _sha256(path)
        os.makedirs(target_dir, exist_ok=True)
        shutil.move(path, dest)
    except OSError as e:
        hint = "" if is_elevated() else " Moving a file out of a system directory needs Administrator."
        return Result(False, f"Could not quarantine {path}: {e}.{hint}")
    _record("quarantine_file", original=path, stored=dest, sha256=digest,
            **({"kind": kind} if kind else {}))
    return Result(True, f"Moved {os.path.basename(path)} to the quarantine folder.",
                  undo=f"restore_file({dest!r})")


def _free_name(folder: str, name: str) -> str:
    """A path in `folder` nothing is using yet.

    The name used to be a timestamp to the second plus the file name, so two
    files called `svc.exe` quarantined in the same second got the same path.
    On Windows the second move failed; on Linux it silently replaced the first
    file, which was then gone for good.
    """
    stamp = time.strftime("%Y%m%d-%H%M%S")
    dest = os.path.join(folder, f"{stamp}-{name}")
    n = 1
    while os.path.exists(dest):
        n += 1
        dest = os.path.join(folder, f"{stamp}-{n}-{name}")
    return dest


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _inside(path: str, folder: str) -> bool:
    try:
        real = os.path.normcase(os.path.realpath(path))
        base = os.path.normcase(os.path.realpath(folder))
        return os.path.commonpath([real, base]) == base
    except ValueError:              # different drives
        return False


def restore_file(stored: str) -> Result:
    """Put a quarantined binary back where it came from.

    The quarantine folder is under the user's profile, so the file can change
    while it is held. An elevated restore that put back whatever was there
    would let anything running as the user plant a binary in System32. The
    content is checked against the hash taken when it was quarantined, again
    after it lands, and it is moved back out if they differ.
    """
    found = None
    for rec in reversed(history(500)):
        if rec.get("action") == "quarantine_file" and rec.get("stored") == stored:
            found = rec
            break
    original = found.get("original") if found else None
    if not original:
        return Result(False, f"No record of {stored} being quarantined, so where it "
                             f"belongs is unknown. Move it back by hand.")
    why = replay_refusal(found)
    if why:
        return Result(False, why)
    if not _inside(stored, quarantine_dir()):
        return Result(False, f"{stored} is not in the quarantine folder; not moving it.")
    if not os.path.isfile(stored):
        return Result(False, f"{stored} is no longer in the quarantine folder.")
    if os.path.exists(original):
        return Result(False, f"{original} exists again; not overwriting it.")
    want = found.get("sha256")
    try:
        if want and _sha256(stored) != want:
            return Result(False, f"{os.path.basename(stored)} changed while it was in "
                                 f"quarantine; not putting it back.")
        os.makedirs(os.path.dirname(original), exist_ok=True)
        shutil.move(stored, original)
        if want and _sha256(original) != want:
            # Swapped between the check and the move.
            shutil.move(original, stored)
            return Result(False, f"{os.path.basename(stored)} changed while it was "
                                 f"being restored; it is back in quarantine.")
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
    """What is in quarantine now, with where each file came from.

    `kind` is set when the file came from an autostart removal; those are
    undone through persistence.removals(), so a caller offering undos can
    skip them here and not list the same file twice.
    """
    stored: dict[str, dict] = {}
    for rec in history(500):
        if rec.get("action") == "quarantine_file":
            stored[rec.get("stored")] = {"stored": rec.get("stored"),
                                         "original": rec.get("original"),
                                         "kind": rec.get("kind", ""),
                                         "ts": rec.get("ts", "")}
        elif rec.get("action") == "restore_file":
            stored.pop(rec.get("stored"), None)
    return [r for s, r in stored.items() if s and os.path.isfile(s)]
