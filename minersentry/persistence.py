"""Autostart (persistence) scanning: miners that aren't running yet.

Every signal in the engine judges a process that is already executing. A miner
that is merely *installed* — a Run key, a scheduled task, a service, a cron
line, a systemd unit — is invisible to all of them until it next starts, and
arranging to come back after a reboot is something practically every real
cryptojacker does. This module reads those locations and scores each entry with
the evidence we already trust: the command line indicators from `cmdline`, a
known miner name, a drop-location path, and whether the binary is signed.

Nothing is modified and nothing is executed: every collector is a read. The
parsers are pure (text in, entries out) so they can be tested against captured
real output; the collectors around them are thin.
"""

from __future__ import annotations

import csv
import glob
import io
import ntpath
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field

from . import cmdline as cmdline_mod
from . import quarantine
from . import trust
from .config import Config
from .scoring import is_miner_name, name_stem

IS_WINDOWS = sys.platform == "win32"

# Weights for autostart-specific evidence. Command-line indicators carry their
# own score (0-100) and dominate, as they should: a stratum URL in a Run key is
# about as conclusive as this module gets.
W_MINER_NAME = 55
W_DROP_DIR = 25
W_UNSIGNED = 15
W_HIDDEN_LAUNCHER = 20
# Locations almost nothing legitimate uses, and that miners reach for exactly
# because the usual autostart lists do not show them.
W_RARE_LOCATION = 35
RARE_KINDS = {"ifeo-debugger", "appinit-dll", "winlogon", "wmi-consumer",
              "hidden-task", "com-hijack", "ld-preload", "ssh-forced-command"}


@dataclass
class PersistEntry:
    kind: str                 # "run-key", "startup-folder", "service", "task", ...
    location: str             # where it lives, so the user can go and look
    name: str                 # the entry's own name
    command: str              # the command line it runs
    exe: str = ""             # the executable, extracted from the command
    # The file this entry IS, when that differs from what it runs. A shortcut
    # in the Startup folder is the .lnk; the command is its target. Removing
    # the entry must touch the .lnk, never the application it points at.
    file: str = ""
    score: int = 0
    labels: list[str] = field(default_factory=list)

    @property
    def summary(self) -> str:
        return f"{self.kind}: {self.name} -> {self.exe or self.command[:60]}"


def command_exe(command: str, isfile=os.path.isfile) -> str:
    """Pull the executable out of a command line.

    Handles quoted paths, the `cmd /c "x.exe"` wrappers autostart entries love,
    and — the one that matters — UNQUOTED paths containing spaces. Splitting
    those on whitespace gave `C:\\ProgramData\\Microsoft\\Windows` for Defender's
    own task, which exists as a FOLDER, so the entry was then judged an
    unsigned binary in a drop location. Longer prefixes are tried until one is
    a real file. Pure apart from the injected existence check.
    """
    s = (command or "").strip()
    if not s:
        return ""
    if s[0] in "\"'":
        end = s.find(s[0], 1)
        if end > 0:
            return s[1:end]
    # strip a shell wrapper so the real payload is scored, not cmd.exe
    m = re.match(r'(?i)^(?:cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh|sh|bash)\s+'
                 r'(?:/c|/k|-c|-File)\s+(.+)$', s)
    if m:
        inner = m.group(1).strip()
        if inner and inner[0] in "\"'":
            end = inner.find(inner[0], 1)
            if end > 0:
                return inner[1:end]
        return inner.split()[0] if inner.split() else ""
    parts = s.split()
    if not parts:
        return ""
    # Walk the words, longest plausible path first: ".../Windows Defender/x.exe"
    # must win over ".../Windows", which is merely a folder that exists.
    for n in range(len(parts), 0, -1):
        candidate = " ".join(parts[:n])
        if isfile(candidate):
            return candidate
        if candidate.lower().endswith((".exe", ".bat", ".cmd", ".com", ".scr",
                                       ".ps1", ".vbs", ".js", ".sh")):
            return candidate
    return parts[0]


def score_entry(entry: PersistEntry, cfg: Config,
                is_trusted=trust.is_trusted, isfile=os.path.isfile) -> PersistEntry:
    """Score one autostart entry.

    The filesystem checks are injected so this can be tested against installs
    that are not on the machine running the tests.
    """
    score = 0
    labels: list[str] = []

    hits = cmdline_mod.indicators(entry.command, cfg)
    cmd_score = cmdline_mod.score_of(hits, cfg.cmdline_generic_cap)
    if cmd_score:
        score += cmd_score
        labels += cmdline_mod.labels(hits, 3)

    base = ntpath.basename(entry.exe or entry.name)
    if is_miner_name(base, cfg) or is_miner_name(entry.exe, cfg):
        score += W_MINER_NAME
        labels.append("known miner binary name")

    exe_l = (entry.exe or "").lower()
    if exe_l:
        # Trust is decided first: a SIGNED binary gets neither the drop-location
        # nor the unsigned weight. Defender genuinely lives in ProgramData, and
        # charging it for that put its own scheduled tasks one point under the
        # reporting threshold on a clean machine.
        trusted = isfile(entry.exe) and is_trusted(
            entry.exe, cfg.trusted_dirs, cfg.signature_untrusted_dirs)
        if not trusted:
            for hint in cfg.suspicious_dir_hints:
                if hint in exe_l:
                    score += W_DROP_DIR
                    labels.append(f"runs from {hint.strip(chr(92)) or hint}")
                    break
            if isfile(entry.exe):
                score += W_UNSIGNED
                labels.append("unsigned binary outside the system directories")
        if len(name_stem(base)) <= 3 and not exe_l.startswith(cfg.trusted_dirs):
            labels.append("very short name")

    if entry.kind in RARE_KINDS:
        score += W_RARE_LOCATION
        labels.append({
            "ifeo-debugger": "Image File Execution Options debugger hijack",
            "appinit-dll": "AppInit_DLLs: loaded into every process that links user32",
            "winlogon": "Winlogon Shell/Userinit hijack",
            "wmi-consumer": "WMI event subscription (fileless persistence)",
            "hidden-task": "scheduled task hidden from the task list",
            "com-hijack": "COM server hijack under HKCU",
            "ld-preload": "loaded into every process that starts (ld.so.preload)",
            "ssh-forced-command": "runs on every login with that SSH key",
        }.get(entry.kind, entry.kind))

    low = (entry.command or "").lower()
    if any(k in low for k in ("-w hidden", "-windowstyle hidden", "-enc",
                              "-encodedcommand", "/min", "vbscript:", "mshta")):
        score += W_HIDDEN_LAUNCHER
        labels.append("starts hidden or through an encoded launcher")

    entry.score = max(0, min(100, score))
    entry.labels = labels
    return entry


# -- pure parsers -----------------------------------------------------------
def parse_schtasks_csv(text: str) -> list[PersistEntry]:
    """Parse `schtasks /query /fo csv /v` into task entries.

    The format repeats its header between folders and pads with blank lines, so
    rows are matched on the header columns rather than position.
    """
    out: list[PersistEntry] = []
    seen: set[tuple[str, str]] = set()
    header: list[str] | None = None
    for row in csv.reader(io.StringIO(text)):
        if not row or not any(c.strip() for c in row):
            continue
        if "TaskName" in row:
            header = [c.strip() for c in row]
            continue
        if not header or len(row) != len(header):
            continue
        d = dict(zip(header, [c.strip() for c in row]))
        name = d.get("TaskName", "")
        command = d.get("Task To Run", "")
        if not name or not command or command.upper() == "COM HANDLER":
            continue
        if d.get("Scheduled Task State", "").lower() == "disabled":
            continue
        # One row per TRIGGER: a task that runs at logon and on a schedule is
        # listed several times, identically. Report the task once.
        if (name, command) in seen:
            continue
        seen.add((name, command))
        out.append(PersistEntry(kind="scheduled-task", location=name,
                                name=ntpath.basename(name) or name,
                                command=command, exe=command_exe(command)))
    return out


def parse_crontab(text: str, location: str) -> list[PersistEntry]:
    """Parse a crontab (user table, /etc/crontab or /etc/cron.d). Pure.

    System tables carry a user field between the schedule and the command; a
    user table does not, so the two shapes are told apart by the field count.
    """
    out: list[PersistEntry] = []
    system_table = location != "crontab" and (
        "/etc/crontab" in location or "/etc/cron.d" in location)
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or re.match(r"^[A-Z_]+\s*=", line):
            continue
        if line.startswith("@"):
            parts = line.split(None, 2 if system_table else 1)
            command = parts[-1] if len(parts) > 1 else ""
            when = parts[0]
        else:
            fields = line.split(None, 6 if system_table else 5)
            if len(fields) < (7 if system_table else 6):
                continue
            command = fields[-1]
            when = " ".join(fields[:5])
        if not command:
            continue
        out.append(PersistEntry(kind="cron", location=location,
                                name=when, command=command,
                                exe=command_exe(command)))
    return out


def parse_systemd_unit(text: str, path: str) -> list[PersistEntry]:
    """Parse ExecStart lines out of a systemd unit. Pure."""
    out: list[PersistEntry] = []
    for line in text.splitlines():
        line = line.strip()
        if not line.lower().startswith("execstart"):
            continue
        _, _, command = line.partition("=")
        command = command.strip().lstrip("-@+!:")
        if command:
            out.append(PersistEntry(kind="systemd-unit", location=path,
                                    name=os.path.basename(path),
                                    command=command, exe=command_exe(command)))
    return out


# -- collectors -------------------------------------------------------------
_RUN_KEYS = (
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
)


def _collect_windows(cfg: Config) -> list[PersistEntry]:
    import winreg
    hives = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}
    out: list[PersistEntry] = []
    for hive_name, path in _RUN_KEYS:
        try:
            key = winreg.OpenKey(hives[hive_name], path)
        except OSError:
            continue
        try:
            count = winreg.QueryInfoKey(key)[1]
            for i in range(count):
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                except OSError:
                    continue
                if not isinstance(value, str) or not value.strip():
                    continue
                out.append(PersistEntry(
                    kind="run-key", location=f"{hive_name}\\{path}",
                    name=name, command=value, exe=command_exe(value)))
        finally:
            key.Close()

    links: list[PersistEntry] = []
    for folder in _startup_folders():
        for item in glob.glob(os.path.join(folder, "*")):
            base = os.path.basename(item)
            # desktop.ini is folder metadata, not an autostart entry
            if os.path.isdir(item) or base.lower() == "desktop.ini":
                continue
            entry = PersistEntry(kind="startup-folder", location=folder,
                                 name=base, command=item, exe=item, file=item)
            if base.lower().endswith(".lnk"):
                entry.exe = ""      # the shortcut's TARGET is what runs
                links.append(entry)
            out.append(entry)
    _resolve_shortcuts(links)

    # Services: the registry is readable unelevated, unlike the SCM for some
    # service types, and ImagePath is what actually runs.
    try:
        import winreg as wr
        svc_root = wr.OpenKey(wr.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services")
    except OSError:
        svc_root = None
    if svc_root is not None:
        try:
            for i in range(wr.QueryInfoKey(svc_root)[0]):
                try:
                    svc = wr.EnumKey(svc_root, i)
                    with wr.OpenKey(svc_root, svc) as k:
                        image, _ = wr.QueryValueEx(k, "ImagePath")
                        try:
                            start, _ = wr.QueryValueEx(k, "Start")
                        except OSError:
                            start = 2
                except OSError:
                    continue
                if not isinstance(image, str) or start == 4:   # 4 = disabled
                    continue
                image = image.strip()
                if image.lower().startswith("\\systemroot\\"):
                    image = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                                         image[len("\\systemroot\\"):])
                out.append(PersistEntry(kind="service",
                                        location=r"HKLM\SYSTEM\CurrentControlSet\Services",
                                        name=svc, command=image,
                                        exe=command_exe(image)))
        finally:
            svc_root.Close()

    tasks = _collect_tasks()
    out += tasks
    visible = {os.path.basename(t.location).lower() for t in tasks}
    visible |= {t.name.lower() for t in tasks}
    for extra in (lambda: _collect_task_files(visible), _collect_service_dlls,
                  _collect_hijacks, _collect_wmi, _collect_bits):
        try:
            out += extra()
        except Exception:  # noqa: BLE001 - one unreadable area must not stop the scan
            continue
    return out


def parse_shortcut_targets(text: str) -> dict[str, str]:
    """Parse `link<TAB>target<TAB>arguments` lines into {link: command}. Pure."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.rstrip("\r").split("\t")
        if len(parts) < 2 or not parts[0] or not parts[1]:
            continue
        link, target = parts[0], parts[1]
        args = parts[2].strip() if len(parts) > 2 else ""
        out[link] = f'"{target}" {args}'.strip() if args else target
    return out


def _resolve_shortcuts(links: list[PersistEntry]) -> None:
    """Fill in what each .lnk actually launches, in one shell call.

    A shortcut in the Startup folder runs its target, so scoring the .lnk file
    itself says nothing. Resolving it needs the shell, so all links are
    resolved together rather than one subprocess each.
    """
    if not links or not IS_WINDOWS:
        return
    script = ("$s=New-Object -ComObject WScript.Shell; " +
              "@(" + ",".join(f"'{e.command}'" for e in links if "'" not in e.command) +
              ") | ForEach-Object { try { $l=$s.CreateShortcut($_); "
              "\"$_`t$($l.TargetPath)`t$($l.Arguments)\" } catch {} }")
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                           capture_output=True, text=True, timeout=45,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except Exception:  # noqa: BLE001 - unresolved shortcuts are not a failure
        return
    targets = parse_shortcut_targets(r.stdout or "")
    for e in links:
        command = targets.get(e.command)
        if command:
            e.command = command
            e.exe = command_exe(command)


def task_name_from_path(path: str, tasks_root: str) -> str:
    r"""The scheduler's name for a task file: \Folder\Name. Pure.

    schtasks identifies a task by that name, not by its file. Passing the bare
    file name instead would miss a task in a folder - or, worse, match a
    DIFFERENT task with the same leaf name at the root and delete that one.
    """
    # ntpath, not os.path: these are Windows paths, and on Linux os.path sees
    # the whole thing as one file name and hands the entire path back.
    try:
        relative = ntpath.relpath(path, tasks_root)
    except ValueError:
        return "\\" + ntpath.basename(path)
    if relative.startswith(".."):
        return "\\" + ntpath.basename(path)
    return "\\" + relative.replace("/", "\\")


def parse_task_xml(text: str, path: str, visible: bool,
                   task_name: str = "") -> list[PersistEntry]:
    """Parse a Windows task XML file into entries. Pure.

    Reading the task files directly matters because `schtasks` only lists tasks
    it is allowed to see: stripping a task's security descriptor hides it from
    the listing while it keeps running, which is a documented miner trick. A
    task present on disk but absent from the listing is scored as hidden.
    """
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []

    def strip(tag: str) -> str:
        return tag.rsplit("}", 1)[-1]

    enabled = True
    settings = next((n for n in root.iter() if strip(n.tag) == "Settings"), None)
    if settings is not None:
        flag = next((n for n in settings if strip(n.tag) == "Enabled"), None)
        if flag is not None and (flag.text or "").strip().lower() == "false":
            enabled = False
    if not enabled:
        return []
    out: list[PersistEntry] = []
    name = os.path.basename(path)
    for exec_node in (n for n in root.iter() if strip(n.tag) == "Exec"):
        command = arguments = ""
        for child in exec_node:
            if strip(child.tag) == "Command":
                command = (child.text or "").strip().strip('"')
            elif strip(child.tag) == "Arguments":
                arguments = (child.text or "").strip()
        if not command:
            continue
        full = f'"{command}" {arguments}'.strip() if arguments else command
        out.append(PersistEntry(
            kind="scheduled-task" if visible else "hidden-task",
            location=task_name or path, name=name, command=full,
            exe=command_exe(full), file=path))
    return out


def tasks_root() -> str:
    return os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "Tasks")


def _collect_task_files(visible_names: set[str], root: str | None = None
                        ) -> list[PersistEntry]:
    """Scheduled tasks read from their XML on disk (needs Administrator).

    `root` is injectable so this can be tested against a directory that is not
    the real one.
    """
    root = root or tasks_root()
    out: list[PersistEntry] = []
    for dirpath, _dirs, files in os.walk(root):
        for fname in files:
            path = os.path.join(dirpath, fname)
            text = _read(path)
            if not text.lstrip().startswith("<"):
                continue
            name = task_name_from_path(path, root)
            # A task the scheduler already listed is not reported twice: the
            # file walk exists to find the ones it did NOT list.
            if fname.lower() in visible_names or name.lower() in visible_names:
                continue
            out += parse_task_xml(text, path, False, name)
    return out


def _collect_service_dlls() -> list[PersistEntry]:
    r"""Service payloads that live in Parameters\ServiceDll.

    A service hosted by svchost has `svchost.exe -k netsvcs` as its ImagePath;
    the code that actually runs is the DLL named here. Reading only ImagePath
    meant 232 services on this machine were checked by the wrong file.
    """
    import winreg as wr
    out: list[PersistEntry] = []
    try:
        root = wr.OpenKey(wr.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services")
    except OSError:
        return out
    try:
        for i in range(wr.QueryInfoKey(root)[0]):
            try:
                svc = wr.EnumKey(root, i)
                with wr.OpenKey(root, svc + r"\Parameters") as pk:
                    dll, _ = wr.QueryValueEx(pk, "ServiceDll")
            except OSError:
                continue
            if not isinstance(dll, str) or not dll.strip():
                continue
            dll = os.path.expandvars(dll.strip())
            out.append(PersistEntry(
                kind="service-dll",
                location=rf"HKLM\SYSTEM\CurrentControlSet\Services\{svc}\Parameters",
                name=svc, command=dll, exe=dll))
    finally:
        root.Close()
    return out


_HIJACK_KEYS = (
    ("ifeo-debugger", "HKLM",
     r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
     "Debugger", True),
    ("appinit-dll", "HKLM",
     r"Software\Microsoft\Windows NT\CurrentVersion\Windows", "AppInit_DLLs", False),
    ("winlogon", "HKLM",
     r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "Shell", False),
    ("winlogon", "HKLM",
     r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "Userinit", False),
)


def _collect_hijacks() -> list[PersistEntry]:
    """Execution hijacks: IFEO debuggers, AppInit_DLLs, Winlogon Shell/Userinit."""
    import winreg as wr
    hives = {"HKCU": wr.HKEY_CURRENT_USER, "HKLM": wr.HKEY_LOCAL_MACHINE}
    out: list[PersistEntry] = []
    for kind, hive, path, value_name, per_subkey in _HIJACK_KEYS:
        try:
            key = wr.OpenKey(hives[hive], path)
        except OSError:
            continue
        try:
            if per_subkey:          # IFEO: one subkey per hijacked image
                for i in range(wr.QueryInfoKey(key)[0]):
                    try:
                        image = wr.EnumKey(key, i)
                        with wr.OpenKey(key, image) as sub:
                            value, _ = wr.QueryValueEx(sub, value_name)
                    except OSError:
                        continue
                    if isinstance(value, str) and value.strip():
                        out.append(PersistEntry(
                            kind=kind, location=f"{hive}\\{path}\\{image}",
                            name=f"{image} -> {value_name}", command=value.strip(),
                            exe=command_exe(value.strip())))
            else:
                try:
                    value, _ = wr.QueryValueEx(key, value_name)
                except OSError:
                    continue
                value = (value or "").strip() if isinstance(value, str) else ""
                # Userinit and Shell have known-good defaults; only deviations matter
                default = {"userinit": "userinit.exe", "shell": "explorer.exe"}.get(
                    value_name.lower())
                if not value:
                    continue
                if default and value.lower().rstrip(",").endswith(default):
                    continue
                out.append(PersistEntry(
                    kind=kind, location=f"{hive}\\{path}", name=value_name,
                    command=value, exe=command_exe(value)))
        finally:
            key.Close()
    return out


def parse_wmi_consumers(text: str) -> list[PersistEntry]:
    """Parse `Name<TAB>command` lines from the WMI consumer query. Pure."""
    out: list[PersistEntry] = []
    for line in text.splitlines():
        parts = line.rstrip("\r").split("\t")
        if len(parts) < 2 or not parts[1].strip():
            continue
        name, command = parts[0].strip(), parts[1].strip()
        out.append(PersistEntry(kind="wmi-consumer", location="root\\subscription",
                                name=name or "(unnamed)", command=command,
                                exe=command_exe(command)))
    return out


def parse_bits_jobs(text: str) -> list[PersistEntry]:
    """Parse `name<TAB>command` lines from the BITS job query. Pure.

    A BITS job survives reboots and runs under the service, which is why it is
    used both to fetch the payload and to re-run it.
    """
    out: list[PersistEntry] = []
    for line in text.splitlines():
        parts = line.rstrip("\r").split("\t")
        if len(parts) < 2 or not parts[1].strip():
            continue
        out.append(PersistEntry(kind="bits-job", location="BITS",
                                name=parts[0].strip() or "(unnamed)",
                                command=parts[1].strip(),
                                exe=command_exe(parts[1].strip())))
    return out


def _collect_bits() -> list[PersistEntry]:
    script = ("Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue | "
              "ForEach-Object { \"$($_.DisplayName)`t$($_.NotifyCmdLine)\" }")
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive",
                            "-Command", script], capture_output=True, text=True,
                           timeout=60,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except Exception:  # noqa: BLE001
        return []
    if r.returncode != 0:
        return []
    return parse_bits_jobs(r.stdout or "")


def _collect_wmi() -> list[PersistEntry]:
    """WMI event-subscription persistence: no file on disk, survives reboots."""
    script = (
        r"Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer "
        r"-ErrorAction SilentlyContinue | ForEach-Object { "
        r'"$($_.Name)`t$($_.CommandLineTemplate)" };'
        r"Get-WmiObject -Namespace root\subscription -Class ActiveScriptEventConsumer "
        r"-ErrorAction SilentlyContinue | ForEach-Object { "
        r'"$($_.Name)`t$($_.ScriptText)" }')
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                           capture_output=True, text=True, timeout=60,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except Exception:  # noqa: BLE001
        return []
    if r.returncode != 0:
        return []
    return parse_wmi_consumers(r.stdout or "")


def _startup_folders() -> list[str]:
    folders = []
    appdata = os.environ.get("APPDATA")
    programdata = os.environ.get("ProgramData")
    if appdata:
        folders.append(os.path.join(appdata, r"Microsoft\Windows\Start Menu\Programs\Startup"))
    if programdata:
        folders.append(os.path.join(programdata, r"Microsoft\Windows\Start Menu\Programs\Startup"))
    return [f for f in folders if os.path.isdir(f)]


def _collect_tasks() -> list[PersistEntry]:
    try:
        r = subprocess.run(["schtasks", "/query", "/fo", "csv", "/v"],
                           capture_output=True, text=True, timeout=60,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except Exception:  # noqa: BLE001 - a missing scheduler must not break the scan
        return []
    if r.returncode != 0:
        return []
    return parse_schtasks_csv(r.stdout or "")


def _collect_posix(cfg: Config) -> list[PersistEntry]:
    out: list[PersistEntry] = []
    for path in ["/etc/crontab"] + sorted(glob.glob("/etc/cron.d/*")):
        text = _read(path)
        if text:
            out += parse_crontab(text, path)
    for path in sorted(glob.glob("/var/spool/cron/crontabs/*")) + \
            sorted(glob.glob("/var/spool/cron/*")):
        text = _read(path)
        if text and os.path.isfile(path):
            out += parse_crontab(text, path)
    try:
        r = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=20)
        if r.returncode == 0 and r.stdout:
            out += parse_crontab(r.stdout, "crontab")
    except Exception:  # noqa: BLE001
        pass
    unit_dirs = ["/etc/systemd/system", "/usr/lib/systemd/system",
                 "/lib/systemd/system",
                 os.path.expanduser("~/.config/systemd/user")]
    for d in unit_dirs:
        # .timer units start a service on a schedule, which is cron by another
        # name and was not being read at all.
        for pattern in ("*.service", "*.timer"):
            for path in sorted(glob.glob(os.path.join(d, pattern))):
                text = _read(path)
                if text:
                    out += parse_systemd_unit(text, path)
    for d in (os.path.expanduser("~/.config/autostart"), "/etc/xdg/autostart"):
        for path in sorted(glob.glob(os.path.join(d, "*.desktop"))):
            text = _read(path)
            if text:
                out += parse_desktop_entry(text, path)
    for path in ("/etc/ld.so.preload",):
        # a library listed here is loaded into EVERY process that starts
        text = _read(path)
        for line in text.splitlines():
            lib = line.strip()
            if lib and not lib.startswith("#"):
                out.append(PersistEntry(kind="ld-preload", location=path,
                                        name=os.path.basename(lib),
                                        command=lib, exe=lib))
    for pattern in (os.path.expanduser("~/.ssh/authorized_keys"),
                    "/root/.ssh/authorized_keys", "/home/*/.ssh/authorized_keys"):
        for path in sorted(glob.glob(pattern)):
            text = _read(path)
            if text:
                out += parse_authorized_keys(text, path)
    for rc in ("~/.bashrc", "~/.bash_profile", "~/.profile", "~/.zshrc",
               "/etc/rc.local", "/etc/profile"):
        path = os.path.expanduser(rc)
        text = _read(path)
        if not text:
            continue
        for line in text.splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            hits = cmdline_mod.indicators(s, cfg)
            # shell rc files are long and full of harmless lines; only keep a
            # line that already looks miner-specific
            if any(h.specific for h in hits):
                out.append(PersistEntry(kind="shell-profile", location=path,
                                        name=os.path.basename(path), command=s,
                                        exe=command_exe(s)))
    return out


def parse_desktop_entry(text: str, path: str) -> list[PersistEntry]:
    """Parse an XDG autostart .desktop file into an entry. Pure.

    ~/.config/autostart runs at login on every desktop Linux, needs no
    privileges to write, and is not covered by cron or systemd.
    """
    exec_line = ""
    hidden = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.lower().startswith("exec="):
            exec_line = line.split("=", 1)[1].strip()
        elif line.lower().replace(" ", "") in ("hidden=true", "x-gnome-autostart-enabled=false"):
            hidden = True
    if not exec_line or hidden:
        return []
    return [PersistEntry(kind="xdg-autostart", location=path,
                         name=os.path.basename(path), command=exec_line,
                         exe=command_exe(exec_line))]


def parse_authorized_keys(text: str, path: str) -> list[PersistEntry]:
    """SSH keys that force a command when used. Pure.

    `command="..."` in authorized_keys runs on every login with that key, which
    is persistence that survives a package reinstall and looks like nothing.
    """
    out: list[PersistEntry] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "command=" not in line:
            continue
        start = line.index("command=") + len("command=")
        if start < len(line) and line[start] == '"':
            end = line.find('"', start + 1)
            command = line[start + 1:end] if end > start else ""
        else:
            command = line[start:].split()[0]
        if command:
            out.append(PersistEntry(kind="ssh-forced-command", location=path,
                                    name=os.path.basename(path), command=command,
                                    exe=command_exe(command)))
    return out


def _read(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(256 * 1024)
    except OSError:
        return ""


def scan(cfg: Config | None = None, min_score: int | None = None) -> list[PersistEntry]:
    """Every autostart entry worth reporting, most suspicious first.

    Reads only. Entries below `min_score` (default `cfg.persistence_min_score`)
    are left out, because a desktop has dozens of legitimate ones and a list
    nobody reads is the same as no list.
    """
    cfg = cfg or Config.load()
    if not cfg.persistence_enabled:
        return []
    threshold = cfg.persistence_min_score if min_score is None else min_score
    try:
        entries = _collect_windows(cfg) if IS_WINDOWS else _collect_posix(cfg)
    except Exception:  # noqa: BLE001 - never let a scan crash the caller
        entries = []
    scored = [score_entry(e, cfg) for e in entries]
    keep = [e for e in scored if e.score >= threshold]
    keep.sort(key=lambda e: e.score, reverse=True)
    return keep


def summarize(entries: list[PersistEntry]) -> list[dict]:
    """JSON-ready findings, for the CLI and the service."""
    return [{"kind": e.kind, "name": e.name, "location": e.location,
             "exe": e.exe, "score": e.score, "labels": e.labels[:4]}
            for e in entries]


# -- removing an entry ------------------------------------------------------
# Finding the task that revives a miner on reboot is only half the job; leaving
# it there means the miner comes back. Every removal below writes what it did to
# the same journal the response actions use, so it can be put back exactly.


def remove_entry(entry: PersistEntry) -> "quarantine.Result":
    """Disable or remove one autostart entry, reversibly.

    What "remove" means depends on the kind, and the safe choice is taken:
    a registry value is deleted after its exact value and type are saved; a
    startup file is moved to quarantine; a scheduled task is exported before it
    is deleted; a service is DISABLED rather than deleted, because deleting a
    service that something else depends on breaks more than it fixes.
    """
    kind = entry.kind
    registry_kinds = ("run-key", "ifeo-debugger", "appinit-dll", "winlogon",
                      "service", "service-dll")
    if kind in registry_kinds and not IS_WINDOWS:
        # `import winreg` raises ModuleNotFoundError off Windows; answer
        # instead of letting that escape to the caller.
        return quarantine.Result(
            False, f"{kind} entries live in the Windows registry; there is "
                   f"nothing of that kind to remove on this platform.")
    if kind in ("run-key", "ifeo-debugger", "appinit-dll", "winlogon"):
        return _remove_registry_value(entry)
    if kind == "startup-folder":
        # entry.file is the item in the Startup folder. For a shortcut the
        # command is its TARGET, and quarantining that would move the
        # legitimate application instead of the shortcut.
        return quarantine.quarantine_file(entry.file or entry.command)
    if kind in ("scheduled-task", "hidden-task"):
        return _remove_task(entry)
    if kind in ("service", "service-dll"):
        return _disable_service(entry)
    if kind in ("cron", "systemd-unit", "shell-profile"):
        return quarantine.Result(
            False, f"{kind} entries are edited by hand on purpose: open "
                   f"{entry.location} and remove the line. Automatic edits to a "
                   f"shared crontab or unit file risk losing unrelated entries.")
    return quarantine.Result(
        False, f"{kind} entries are reported only. Removing a WMI subscription "
               f"needs care that is better taken deliberately: see {entry.location}.")


def _split_hive(location: str):
    import winreg as wr
    hives = {"HKCU": wr.HKEY_CURRENT_USER, "HKLM": wr.HKEY_LOCAL_MACHINE}
    head, _, path = location.partition("\\")
    return hives.get(head.upper()), head.upper(), path


def _remove_registry_value(entry: PersistEntry) -> "quarantine.Result":
    import winreg as wr
    hive, hive_name, path = _split_hive(entry.location)
    if hive is None:
        return quarantine.Result(False, f"Unrecognised registry location: {entry.location}")
    value_name = entry.name.split(" -> ")[-1] if " -> " in entry.name else entry.name
    try:
        with wr.OpenKey(hive, path, 0, wr.KEY_READ | wr.KEY_SET_VALUE) as key:
            try:
                value, value_type = wr.QueryValueEx(key, value_name)
            except FileNotFoundError:
                return quarantine.Result(False, f"{value_name} is already gone.")
            wr.DeleteValue(key, value_name)
    except PermissionError:
        return quarantine.Result(
            False, f"Not allowed to change {hive_name}\\{path}. HKLM needs Administrator.")
    except OSError as e:
        return quarantine.Result(False, f"Could not remove {value_name}: {e}")
    quarantine.record_action("remove_registry_value", hive=hive_name, path=path,
                             name=value_name, value=value, value_type=int(value_type),
                             kind=entry.kind)
    return quarantine.Result(
        True, f"Removed {value_name} from {hive_name}\\{path}.",
        undo="restore from the actions journal")


def _remove_task(entry: PersistEntry) -> "quarantine.Result":
    name = entry.location if entry.location.startswith("\\") else entry.name
    try:
        dump = subprocess.run(["schtasks", "/query", "/tn", name, "/xml"],
                              capture_output=True, text=True, timeout=30,
                              creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        xml = dump.stdout if dump.returncode == 0 else ""
        r = subprocess.run(["schtasks", "/delete", "/tn", name, "/f"],
                           capture_output=True, text=True, timeout=30,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except Exception as e:  # noqa: BLE001
        return quarantine.Result(False, f"Could not delete the task: {type(e).__name__}: {e}")
    if r.returncode != 0:
        detail = (r.stderr or r.stdout).strip()[:200]
        return quarantine.Result(False, f"The scheduler refused: {detail}")
    quarantine.record_action("remove_task", task=name, xml=xml, kind=entry.kind)
    return quarantine.Result(True, f"Deleted the scheduled task {name}.",
                             undo="re-create it from the XML in the actions journal")


def _disable_service(entry: PersistEntry) -> "quarantine.Result":
    import winreg as wr
    path = rf"SYSTEM\CurrentControlSet\Services\{entry.name}"
    try:
        with wr.OpenKey(wr.HKEY_LOCAL_MACHINE, path, 0,
                        wr.KEY_READ | wr.KEY_SET_VALUE) as key:
            try:
                previous, _ = wr.QueryValueEx(key, "Start")
            except FileNotFoundError:
                previous = 2
            if previous == 4:
                return quarantine.Result(False, f"{entry.name} is already disabled.")
            wr.SetValueEx(key, "Start", 0, wr.REG_DWORD, 4)
    except PermissionError:
        return quarantine.Result(False, "Disabling a service needs Administrator.")
    except OSError as e:
        return quarantine.Result(False, f"Could not disable {entry.name}: {e}")
    quarantine.record_action("disable_service", service=entry.name,
                             previous_start=int(previous), kind=entry.kind)
    return quarantine.Result(
        True, f"Disabled the service {entry.name} (it was start type {previous}). "
              f"It stays installed and stops at the next boot.",
        undo="restore its start type from the actions journal")


def undo_removal(record: dict) -> "quarantine.Result":
    """Reverse one removal, from its journal record."""
    action = record.get("action")
    try:
        if action == "remove_registry_value":
            import winreg as wr
            hive = {"HKCU": wr.HKEY_CURRENT_USER,
                    "HKLM": wr.HKEY_LOCAL_MACHINE}[record["hive"]]
            with wr.OpenKey(hive, record["path"], 0, wr.KEY_SET_VALUE) as key:
                wr.SetValueEx(key, record["name"], 0, record["value_type"],
                              record["value"])
            return quarantine.Result(True, f"Restored {record['name']}.")
        if action == "remove_task":
            xml = record.get("xml") or ""
            if not xml.strip():
                return quarantine.Result(False, "No XML was captured for that task.")
            import tempfile
            with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False,
                                             encoding="utf-16") as f:
                f.write(xml)
                temp = f.name
            try:
                r = subprocess.run(["schtasks", "/create", "/tn", record["task"],
                                    "/xml", temp, "/f"], capture_output=True,
                                   text=True, timeout=30)
            finally:
                os.unlink(temp)
            if r.returncode != 0:
                return quarantine.Result(False, (r.stderr or r.stdout).strip()[:200])
            return quarantine.Result(True, f"Re-created the task {record['task']}.")
        if action == "disable_service":
            import winreg as wr
            path = rf"SYSTEM\CurrentControlSet\Services\{record['service']}"
            with wr.OpenKey(wr.HKEY_LOCAL_MACHINE, path, 0, wr.KEY_SET_VALUE) as key:
                wr.SetValueEx(key, "Start", 0, wr.REG_DWORD, record["previous_start"])
            return quarantine.Result(True, f"Re-enabled {record['service']}.")
    except Exception as e:  # noqa: BLE001
        return quarantine.Result(False, f"Could not undo: {type(e).__name__}: {e}")
    return quarantine.Result(False, f"Nothing to undo for {action!r}.")


def removals(limit: int = 200) -> list[dict]:
    """Removals recorded so far, newest last."""
    kinds = {"remove_registry_value", "remove_task", "disable_service"}
    return [r for r in quarantine.history(limit) if r.get("action") in kinds]
