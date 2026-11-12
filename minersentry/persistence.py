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
import hashlib
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
              "hidden-task", "com-hijack", "ld-preload", "ssh-forced-command",
              "netsh-helper", "appcert-dll", "active-setup", "print-monitor",
              "lsa-package", "gpo-script", "pam-module", "udev-rule"}
# A kernel driver is how a miner gets at the MSRs it wants to tune, and
# loading one needs a service entry, which this module already reads. Of the
# 461 driver services on the development machine, 460 sit under
# System32\drivers or the DriverStore. The single exception is a VPN's driver
# under Program Files, which is signed and therefore trusted, so this weight
# is gated on the file NOT being trusted and that exception costs nothing.
#
# It is a weight rather than a floor because the file still has to be
# untrusted, and 30 is chosen so an unsigned driver clears the threshold (45)
# on the location alone: nothing legitimate loads a driver from a user-
# writable directory, and waiting for a second indicator would mean waiting
# for the driver to already be in use.
W_ROGUE_DRIVER = 30
_DRIVER_SUBDIRS = (r"System32\drivers", r"System32\DriverStore",
                   r"SysWOW64\drivers")


def driver_dirs(system_root: str | None = None) -> tuple[str, ...]:
    """The directories a kernel driver legitimately loads from."""
    root = system_root or os.environ.get("SystemRoot", r"C:\Windows")
    return tuple(ntpath.join(root, sub) for sub in _DRIVER_SUBDIRS)


def is_rogue_driver(exe: str, system_root: str | None = None,
                    under=trust.in_trusted_dir) -> bool:
    r"""True if `exe` is a .sys outside the directories drivers load from.

    The containment test is `trust.in_trusted_dir`, which matches whole path
    components against an absolute root, rather than a substring test. A
    substring test would accept `C:\Users\x\system32\drivers\evil.sys` —
    anyone can create a folder with that name — which is the same mistake that
    once let `C:\Program Files2` count as being under `C:\Program Files`.
    """
    if not exe or not exe.lower().endswith(".sys"):
        return False
    # normpath first, or a traversal defeats the containment test:
    # C:\Windows\System32\drivers\..\..\Users\x\evil.sys starts with the
    # driver directory as a string while the file is somewhere else entirely.
    return not under(ntpath.normpath(exe), driver_dirs(system_root))


# An accessibility binary replaced by a shell is not a matter of degree: the
# file in System32 IS cmd.exe. Nothing legitimate does this, so it gets a floor
# rather than a weight, and the floor alone is enough to report.
W_SYSTEM_SWAP = 75


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


_DEVICE_PREFIX = "\\??\\"
_SYSROOT_PREFIX = "\\systemroot\\"


_WIN_VAR = re.compile(r"%([^%\s]+)%")


def expand_win_vars(text: str, environ: dict | None = None) -> str:
    r"""Expand `%VAR%` the way Windows does, on any platform. Pure.

    `os.path.expandvars` is `posixpath.expandvars` off Windows, and that knows
    only `$VAR` — so `%SystemRoot%\system32\x.sys` came back untouched on
    Linux, which is 276 of this machine's 793 service entries left unresolved
    for anyone running the scan or the tests there. Lookup is
    case-insensitive, as it is on Windows. An unset variable is left as it
    stands rather than becoming an empty string, so a path never silently
    collapses to something that happens to exist.
    """
    env = os.environ if environ is None else environ
    lowered = {k.lower(): v for k, v in env.items()}

    def replace(match: "re.Match[str]") -> str:
        return lowered.get(match.group(1).lower(), match.group(0))

    return _WIN_VAR.sub(replace, text)


def resolve_image_path(command: str, system_root: str | None = None,
                       environ: dict | None = None) -> str:
    r"""Normalise a service `ImagePath` so the path inside it names a real file.

    The service control manager accepts four spellings and this module was
    only handling one of them. Surveyed across the 793 service entries on the
    development machine:

        %var%                  276
        \SystemRoot\ prefix    251
        RELATIVE               214
        absolute                51
        \??\ prefix              1

    Only the `\SystemRoot\` form was expanded, and nothing called
    `expandvars`, so **490 of 793 service entries (62%) had an `exe` that
    resolved to no file at all**. That is not a cosmetic problem: with no file
    to look at, `isfile` fails, so the unsigned weight never applies,
    `trust.is_trusted` is handed a path that does not exist, and the
    drop-location hints are matched against a string with no directory in it.
    A driver registered as `System32\drivers\x.sys` scored 15 where the same
    driver written absolutely scored 50.

    Arguments are preserved, because an ImagePath often carries them
    (`svchost.exe -k netsvcs`), and a relative path is joined to the system
    root rather than the working directory, which is what the SCM does.
    Pure: no filesystem access, `system_root` injectable.
    """
    s = (command or "").strip()
    if not s:
        return ""
    env = os.environ if environ is None else environ
    root = system_root or env.get("SystemRoot") or r"C:\Windows"

    quote = ""
    if s[0] in "\"'":
        end = s.find(s[0], 1)
        if end > 0:
            quote, inner, rest = s[0], s[1:end], s[end + 1:]
        else:
            quote, inner, rest = s[0], s[1:], ""
    else:
        inner, rest = s, ""

    inner = expand_win_vars(inner, env)
    low = inner.lower()
    if low.startswith(_DEVICE_PREFIX):
        inner = inner[len(_DEVICE_PREFIX):]
    elif low.startswith(_SYSROOT_PREFIX):
        inner = ntpath.join(root, inner[len(_SYSROOT_PREFIX):])
    elif not _looks_absolute(inner):
        inner = ntpath.join(root, inner)

    return f"{quote}{inner}{quote}{rest}" if quote else inner


def _looks_absolute(path: str) -> bool:
    r"""True for `C:\...`, `\\server\share\...` and `/...`.

    A single leading backslash (`\Windows\x.sys`) is deliberately NOT absolute:
    it is rooted on the current drive, and `ntpath.join` against the system
    root resolves it to that drive, which is what the SCM does.
    """
    return bool(path) and (
        path.startswith("\\\\") or path.startswith("/")
        or (len(path) > 1 and path[1] == ":"))


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
        # .sys and .dll are here because services and ServiceDll entries point
        # at them; without them a kernel driver whose path contains a space
        # fell through to parts[0] and was truncated at the space.
        if candidate.lower().endswith((".exe", ".bat", ".cmd", ".com", ".scr",
                                       ".ps1", ".vbs", ".js", ".sh", ".sys",
                                       ".dll")):
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
            if is_rogue_driver(entry.exe):
                score += W_ROGUE_DRIVER
                labels.append("kernel driver loaded from outside the driver "
                              "directories")
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
            "netsh-helper": "DLL loaded by netsh.exe every time it runs",
            "appcert-dll": "AppCertDlls: loaded into every process that starts one",
            "active-setup": "Active Setup StubPath: runs at logon before the desktop",
            "print-monitor": "print monitor DLL, loaded by spoolsv.exe as SYSTEM",
            "lsa-package": "LSA package, loaded into lsass.exe at boot",
            "gpo-script": "Group Policy startup/logon script",
            "pam-module": "PAM module, loaded on every authentication",
            "udev-rule": "udev rule that runs a program on a device event",
        }.get(entry.kind, entry.kind))

    if entry.kind == "accessibility-swap":
        score = max(score, W_SYSTEM_SWAP)
        labels.append("an accessibility binary in System32 has been replaced "
                      "by a shell")

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
                # Four spellings reach here, not one: see resolve_image_path.
                image = resolve_image_path(image)
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
                  _collect_hijacks, _collect_wmi, _collect_bits,
                  _collect_load_points, _collect_lsa, _collect_gpo_scripts,
                  _collect_office_addins, _collect_accessibility):
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
            # A ServiceDll is stored the same four ways an ImagePath is; this
            # path previously only called expandvars.
            dll = resolve_image_path(dll)
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


# -- the less-travelled Windows load points ---------------------------------
# None of these show up in Task Manager's Startup tab, msconfig, or `schtasks`,
# which is the whole reason they get used. They are all cheap registry reads.
#
# There is deliberately no allowlist of known-good DLLs here. Every machine has
# a dozen legitimate netsh helpers and print monitors, and keeping a list of
# their names current is a losing game. Instead the existing trust-first
# scoring does the work: a signed DLL under System32 earns only the
# rare-location weight (35), which is below the reporting threshold (45), so it
# stays silent — while an unsigned DLL, or one in a drop directory, clears it.

# (kind, hive, path, subkey_value, payload)
#   subkey_value None  -> every value under the key is a payload
#   subkey_value "X"   -> each subkey's value "X" is the payload
#   payload "dll"      -> the value is a module name, resolved against System32
#   payload "command"  -> the value is a command line, parsed by command_exe
# The distinction matters: command_exe("AppMon.dll") happily returns
# "AppMon.dll", so treating a print monitor as a command line left the path
# unresolved, and an unresolved path means the trust and signature checks have
# no file to look at.
_LOAD_POINT_KEYS = (
    ("netsh-helper", "HKLM", r"SOFTWARE\Microsoft\NetSh", None, "dll"),
    ("appcert-dll", "HKLM",
     r"System\CurrentControlSet\Control\Session Manager\AppCertDlls", None, "dll"),
    ("active-setup", "HKLM",
     r"SOFTWARE\Microsoft\Active Setup\Installed Components", "StubPath",
     "command"),
    ("print-monitor", "HKLM",
     r"SYSTEM\CurrentControlSet\Control\Print\Monitors", "Driver", "dll"),
)


def resolve_system_dll(value: str, isfile=os.path.isfile,
                       system_root: str | None = None) -> str:
    r"""Resolve a DLL reference from one of these keys to a full path. Pure
    apart from the injected `isfile`.

    Most of these values are a bare file name — `dhcpcmonitor.dll`, not a path
    — because the loader finds them in System32. Left bare, `command_exe`
    returns nothing, the trust and signature checks have no file to look at,
    and a malicious DLL would score only the rare-location weight and never be
    reported. So a bare name is resolved against System32 before scoring.
    """
    value = (value or "").strip().strip('"')
    if not value:
        return ""
    value = os.path.expandvars(value)
    if "\\" in value or "/" in value or (len(value) > 1 and value[1] == ":"):
        return value
    root = system_root or os.environ.get("SystemRoot", r"C:\Windows")
    candidate = ntpath.join(root, "System32", value)
    return candidate if isfile(candidate) else value


def _collect_load_points() -> list[PersistEntry]:
    """netsh helpers, AppCertDlls, Active Setup StubPath, print monitors."""
    import winreg as wr
    hives = {"HKCU": wr.HKEY_CURRENT_USER, "HKLM": wr.HKEY_LOCAL_MACHINE}
    out: list[PersistEntry] = []
    for kind, hive, path, subkey_value, payload in _LOAD_POINT_KEYS:
        resolve = (command_exe if payload == "command" else resolve_system_dll)
        try:
            key = wr.OpenKey(hives[hive], path)
        except OSError:
            continue
        try:
            if subkey_value is None:
                for i in range(wr.QueryInfoKey(key)[1]):
                    try:
                        name, value, _ = wr.EnumValue(key, i)
                    except OSError:
                        continue
                    if not isinstance(value, str) or not value.strip():
                        continue
                    out.append(PersistEntry(
                        kind=kind, location=f"{hive}\\{path}", name=name,
                        command=value.strip(), exe=resolve(value.strip())))
            else:
                for i in range(wr.QueryInfoKey(key)[0]):
                    try:
                        sub_name = wr.EnumKey(key, i)
                        with wr.OpenKey(key, sub_name) as sub:
                            value, _ = wr.QueryValueEx(sub, subkey_value)
                    except OSError:
                        continue
                    if not isinstance(value, str) or not value.strip():
                        continue
                    value = value.strip()
                    exe = resolve(value)
                    out.append(PersistEntry(
                        kind=kind, location=f"{hive}\\{path}\\{sub_name}",
                        name=f"{sub_name} -> {subkey_value}", command=value,
                        exe=exe))
        finally:
            key.Close()
    return out


_LSA_KEY = r"SYSTEM\CurrentControlSet\Control\Lsa"
_LSA_VALUES = ("Authentication Packages", "Notification Packages",
               "Security Packages")


def _collect_lsa() -> list[PersistEntry]:
    """LSA packages: DLLs loaded into lsass.exe at boot, as SYSTEM.

    The values are REG_MULTI_SZ lists, so each element becomes its own entry —
    which also means removal has to rewrite the list rather than delete the
    value, and `remove_entry` refuses on purpose.
    """
    import winreg as wr
    out: list[PersistEntry] = []
    try:
        key = wr.OpenKey(wr.HKEY_LOCAL_MACHINE, _LSA_KEY)
    except OSError:
        return out
    try:
        for value_name in _LSA_VALUES:
            try:
                value, _ = wr.QueryValueEx(key, value_name)
            except OSError:
                continue
            items = value if isinstance(value, (list, tuple)) else [value]
            for item in items:
                if not isinstance(item, str):
                    continue
                # Windows stores an empty list as a single element of two
                # quote characters: `Security Packages` reads as '""' on a
                # stock install. Left alone that became an entry named ".dll".
                item = item.strip().strip('"').strip()
                if not item:
                    continue
                name = item if item.lower().endswith(".dll") else item + ".dll"
                out.append(PersistEntry(
                    kind="lsa-package", location=f"HKLM\\{_LSA_KEY}",
                    name=f"{value_name} -> {item}", command=item,
                    exe=resolve_system_dll(name)))
    finally:
        key.Close()
    return out


def parse_ini_scripts(text: str, path: str) -> list[PersistEntry]:
    """Parse a Group Policy `scripts.ini` into entries. Pure.

    The format is `[Startup]` / `[Logon]` sections holding numbered pairs:
    `0CmdLine=\\\\dc\\share\\x.exe` and `0Parameters=`. A startup script runs as
    SYSTEM before anyone logs in, and it is a file on disk rather than a
    registry value, so nothing else in this module would see it.
    """
    out: list[PersistEntry] = []
    section = ""
    commands: dict[str, str] = {}
    params: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip().lstrip("\ufeff")
        if not line or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            continue
        key, sep, value = line.partition("=")
        if not sep:
            continue
        key, value = key.strip(), value.strip()
        low = key.lower()
        if low.endswith("cmdline"):
            commands[f"{section}:{low[:-len('cmdline')]}"] = value
        elif low.endswith("parameters"):
            params[f"{section}:{low[:-len('parameters')]}"] = value
    for ref, command in commands.items():
        if not command:
            continue
        full = command
        extra = params.get(ref, "")
        if extra:
            full = f"{command} {extra}"
        sect = ref.split(":", 1)[0] or "script"
        out.append(PersistEntry(kind="gpo-script", location=path,
                                name=f"{sect} {ref.split(':', 1)[1]}".strip(),
                                command=full, exe=command_exe(command)))
    return out


def _collect_gpo_scripts() -> list[PersistEntry]:
    root = os.environ.get("SystemRoot", r"C:\Windows")
    out: list[PersistEntry] = []
    for who in ("Machine", "User"):
        path = ntpath.join(root, "System32", "GroupPolicy", who, "Scripts",
                           "scripts.ini")
        text = _read(path)
        if text:
            out += parse_ini_scripts(text, path)
    return out


_OFFICE_ADDIN_ROOTS = (
    ("HKCU", r"Software\Microsoft\Office"),
    ("HKLM", r"Software\Microsoft\Office"),
)


def _first_string(key, names: tuple[str, ...]) -> str:
    """The first of `names` that holds a non-empty string, or ""."""
    import winreg as wr
    for name in names:
        try:
            value, _ = wr.QueryValueEx(key, name)
        except OSError:
            continue
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _collect_office_addins() -> list[PersistEntry]:
    r"""Office add-ins: `Software\Microsoft\Office\<app>\Addins\<id>`.

    These are NOT in RARE_KINDS. Plenty of real add-ins are unsigned and live
    in %APPDATA% (every corporate XLAM does), so the rare-location weight would
    turn each one into a finding. An add-in therefore has to earn its score the
    ordinary way: a miner name, a stratum URL, a hidden launcher.
    """
    import winreg as wr
    hives = {"HKCU": wr.HKEY_CURRENT_USER, "HKLM": wr.HKEY_LOCAL_MACHINE}
    out: list[PersistEntry] = []
    for hive, office in _OFFICE_ADDIN_ROOTS:
        try:
            root = wr.OpenKey(hives[hive], office)
        except OSError:
            continue
        try:
            apps = []
            for i in range(wr.QueryInfoKey(root)[0]):
                try:
                    apps.append(wr.EnumKey(root, i))
                except OSError:
                    continue
        finally:
            root.Close()
        for app in apps:
            addins_path = f"{office}\\{app}\\Addins"
            try:
                addins = wr.OpenKey(hives[hive], addins_path)
            except OSError:
                continue
            try:
                for i in range(wr.QueryInfoKey(addins)[0]):
                    try:
                        ident = wr.EnumKey(addins, i)
                        with wr.OpenKey(addins, ident) as sub:
                            try:
                                behaviour, _ = wr.QueryValueEx(sub, "LoadBehavior")
                            except OSError:
                                behaviour = 3
                            manifest = _first_string(
                                sub, ("Manifest", "FriendlyName"))
                    except OSError:
                        continue
                    # 0 = never load, 1 = loaded but not at startup
                    if isinstance(behaviour, int) and behaviour in (0, 1):
                        continue
                    command = manifest if isinstance(manifest, str) else ""
                    out.append(PersistEntry(
                        kind="office-addin",
                        location=f"{hive}\\{addins_path}\\{ident}",
                        name=ident, command=command or ident,
                        exe=command_exe(command) if command else ""))
            finally:
                addins.Close()
    return out


# A sticky-keys backdoor replaces one of these with a shell, so that the
# shortcut on the logon screen opens a SYSTEM command prompt. The replacement
# is the shell binary itself, byte for byte.
_ACCESSIBILITY_BINARIES = ("sethc.exe", "utilman.exe", "osk.exe",
                           "Magnify.exe", "Narrator.exe", "DisplaySwitch.exe",
                           "AtBroker.exe")
_SHELL_BINARIES = ("cmd.exe", "powershell.exe", "taskmgr.exe", "explorer.exe")


def file_digest(path: str) -> str:
    """sha256 of a file, or "" if it cannot be read."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


def swapped_binaries(accessibility: dict[str, str],
                     shells: dict[str, str]) -> list[tuple[str, str]]:
    """Accessibility binaries whose digest matches a shell's. Pure.

    A signature check would not do here: Windows system binaries are
    catalog-signed, so WinVerifyTrust on the file alone fails for the genuine
    article too — the same reason `trust.is_trusted` falls back to the
    directory. Comparing digests against the shells instead gives an answer
    with no false positives: either the file in System32 *is* cmd.exe or it is
    not.
    """
    by_digest = {digest: name for name, digest in shells.items() if digest}
    out = []
    for name, digest in sorted(accessibility.items()):
        if digest and digest in by_digest:
            out.append((name, by_digest[digest]))
    return out


def _collect_accessibility() -> list[PersistEntry]:
    root = ntpath.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
    shells = {name: file_digest(ntpath.join(root, name))
              for name in _SHELL_BINARIES}
    targets = {name: file_digest(ntpath.join(root, name))
               for name in _ACCESSIBILITY_BINARIES}
    out = []
    for name, shell in swapped_binaries(targets, shells):
        path = ntpath.join(root, name)
        out.append(PersistEntry(kind="accessibility-swap", location=root,
                                name=name, command=f"{path} (identical to {shell})",
                                exe=path, file=path))
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
    for path in sorted(glob.glob("/etc/pam.d/*")):
        text = _read(path)
        if text:
            out += parse_pam_config(text, path)
    for path in sorted(glob.glob("/etc/udev/rules.d/*.rules")) + \
            sorted(glob.glob("/run/udev/rules.d/*.rules")):
        text = _read(path)
        if text:
            out += parse_udev_rules(text, path)
    # /etc/profile.d is sourced by every login shell and is a directory, so a
    # new file there needs no edit to an existing one; /etc/init.d still runs
    # on anything with a sysv-compatible init.
    shell_files = ["~/.bashrc", "~/.bash_profile", "~/.profile", "~/.zshrc",
                   "/etc/rc.local", "/etc/profile"]
    shell_files += sorted(glob.glob("/etc/profile.d/*.sh"))
    shell_files += [p for p in sorted(glob.glob("/etc/init.d/*"))
                    if os.path.isfile(p)]
    for rc in shell_files:
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


_PAM_STANDARD_DIRS = ("/lib/security/", "/lib64/security/",
                      "/usr/lib/security/", "/usr/lib64/security/",
                      "/lib/x86_64-linux-gnu/security/",
                      "/usr/lib/x86_64-linux-gnu/security/",
                      "/usr/lib/aarch64-linux-gnu/security/",
                      "/lib/aarch64-linux-gnu/security/")


def parse_pam_config(text: str, path: str,
                     standard_dirs: tuple[str, ...] = _PAM_STANDARD_DIRS
                     ) -> list[PersistEntry]:
    """PAM modules loaded from outside the standard module directories. Pure.

    A line in /etc/pam.d names a module, normally by bare name, and PAM finds
    it in the system module directory. An absolute path to somewhere else means
    somebody pointed authentication at their own code: it is then loaded into
    sshd, login, sudo and su on every authentication, as root.

    Only off-path modules are reported. A bare name is the normal case and
    there are hundreds of them per machine, so reporting those would bury the
    one line that matters.
    """
    out: list[PersistEntry] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        # type control module-path [args]; `-` prefix means "optional"
        if parts and parts[0] == "-":
            parts = parts[1:]
        if len(parts) < 3:
            continue
        module = next((p for p in parts[2:] if p.endswith(".so")), "")
        if not module or not module.startswith("/"):
            continue
        if module.startswith(standard_dirs):
            continue
        out.append(PersistEntry(kind="pam-module", location=path,
                                name=os.path.basename(module), command=module,
                                exe=module))
    return out


_UDEV_RUN = re.compile(r'(?:RUN|PROGRAM|IMPORT)(?:\{[^}]*\})?\s*(?:\+?=)\s*'
                       r'"([^"]*)"')


def parse_udev_rules(text: str, path: str) -> list[PersistEntry]:
    """udev rules that run a program. Pure.

    `RUN+="..."` runs as root when a device event matches, and a rule matching
    something that happens at every boot is persistence that no autostart list
    shows. PROGRAM and IMPORT{program} execute too, so all three are read.
    """
    out: list[PersistEntry] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        for command in _UDEV_RUN.findall(line):
            command = command.strip()
            if not command:
                continue
            out.append(PersistEntry(kind="udev-rule", location=path,
                                    name=os.path.basename(path),
                                    command=command,
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
                      "service", "service-dll", "netsh-helper", "appcert-dll",
                      "active-setup", "lsa-package", "print-monitor",
                      "office-addin")
    if kind in registry_kinds and not IS_WINDOWS:
        # `import winreg` raises ModuleNotFoundError off Windows; answer
        # instead of letting that escape to the caller.
        return quarantine.Result(
            False, f"{kind} entries live in the Windows registry; there is "
                   f"nothing of that kind to remove on this platform.")
    if kind in ("run-key", "ifeo-debugger", "appinit-dll", "winlogon",
                "netsh-helper", "appcert-dll", "active-setup"):
        # All plain single-string values: deleting one removes the entry and
        # nothing else. _remove_registry_value saves the value and its type
        # first, so the journal can put it back.
        return _remove_registry_value(entry)
    if kind == "lsa-package":
        # REG_MULTI_SZ. Deleting the value would remove every package in the
        # list, and an lsass that cannot load its authentication packages does
        # not boot. Rewriting one element of the list in place is possible but
        # not something to do automatically on the strength of a score.
        return quarantine.Result(
            False, f"{entry.name} is one element of a REG_MULTI_SZ list at "
                   f"{entry.location}. Deleting the whole value stops Windows "
                   f"booting, so remove just that element by hand after "
                   f"checking what the DLL is.")
    if kind == "print-monitor":
        return quarantine.Result(
            False, f"A print monitor is a registry SUBKEY ({entry.location}), "
                   f"not a value. Stop the Print Spooler, delete that subkey, "
                   f"then start it again — done in the wrong order the spooler "
                   f"rewrites it.")
    if kind == "gpo-script":
        return quarantine.Result(
            False, f"This runs from {entry.location}, which Group Policy "
                   f"rewrites from the domain on the next refresh. Removing "
                   f"the line locally would not hold: fix the GPO, or detach "
                   f"the machine first.")
    if kind == "office-addin":
        return quarantine.Result(
            False, f"Set LoadBehavior to 0 under {entry.location} to stop the "
                   f"add-in loading, rather than deleting the key — Office "
                   f"recreates a deleted add-in key from its own cache.")
    if kind == "accessibility-swap":
        return quarantine.Result(
            False, f"{entry.name} is a Windows system binary that has been "
                   f"REPLACED, not something added. Quarantining it would "
                   f"leave System32 short a file; restore the real one with "
                   f"`sfc /scannow` instead.")
    if kind == "startup-folder":
        # entry.file is the item in the Startup folder. For a shortcut the
        # command is its TARGET, and quarantining that would move the
        # legitimate application instead of the shortcut.
        # `kind` is passed so `removals()` can see this as a removal; without
        # it an "undo the last removal" skipped straight past a startup-folder
        # removal to an older, unrelated entry.
        return quarantine.quarantine_file(entry.file or entry.command,
                                          kind=entry.kind)
    if kind in ("scheduled-task", "hidden-task"):
        return _remove_task(entry)
    if kind in ("service", "service-dll"):
        return _disable_service(entry)
    if kind == "pam-module":
        return quarantine.Result(
            False, f"{entry.location} controls authentication. A broken file "
                   f"there locks every account out, including root, so this is "
                   f"never edited automatically: keep a root shell open, "
                   f"comment the line referring to {entry.name}, and test "
                   f"`sudo true` before closing it.")
    if kind in ("cron", "systemd-unit", "shell-profile", "udev-rule"):
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
        if action == "quarantine_file":
            # a startup-folder removal; the file goes back where it came from
            return quarantine.restore_file(record.get("stored", ""))
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
    """Removals recorded so far, newest last.

    A startup-folder removal is journalled by `quarantine_file`, and leaving
    that action out had a worse consequence than an incomplete list: "undo the
    last removal" takes the newest record here, so after removing a malicious
    shortcut it skipped past it and restored an older, unrelated registry
    entry — an entry the user never asked to bring back, while the shortcut
    stayed quarantined.

    Only quarantines that came from an autostart removal count; one carries
    `kind`. A process binary quarantined from the dashboard is undone through
    `quarantine.restore_file`, which is a different action with a different
    meaning, and it is not a removal of an autostart entry.
    """
    actions = {"remove_registry_value", "remove_task", "disable_service"}
    out = []
    for record in quarantine.history(limit):
        action = record.get("action")
        if action in actions:
            out.append(record)
        elif action == "quarantine_file" and record.get("kind"):
            out.append(record)
        elif action == "restore_file":
            # already undone: drop the quarantine it reversed, so an undo
            # never offers the same record twice
            out = [r for r in out
                   if not (r.get("action") == "quarantine_file"
                           and r.get("stored") == record.get("stored"))]
    return out
