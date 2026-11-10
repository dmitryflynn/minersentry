"""Defensive tampering: what a miner changes so it will not be found.

Before a miner settles in it usually clears the way — a Defender exclusion for
the folder it drops into, real-time protection turned off by policy, and `hosts`
entries that stop antivirus and update traffic. None of that is mining, so none
of it belongs in a process score, but all of it is cheap to read and an
exclusion covering a folder MinerSentry has already flagged is close to
conclusive on its own.

Everything here is read-only. Parsers are pure so they can be tested against
real captured output; the collectors around them are thin and degrade to an
empty list when a key needs privileges we do not have.
"""

from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass, field

IS_WINDOWS = sys.platform == "win32"

# Domains worth noticing in a hosts file: if these are redirected, something
# wanted updates and scanners to stop working.
SECURITY_DOMAINS = (
    "windowsupdate", "update.microsoft", "msftncsi", "defender", "wdcp",
    "virustotal", "malwarebytes", "avast", "avg.com", "bitdefender", "kaspersky",
    "sophos", "eset", "mcafee", "norton", "symantec", "trendmicro", "clamav",
    "sucuri", "comodo", "drweb", "f-secure", "gdatasoftware", "pandasecurity",
)
BLACKHOLE_IPS = ("0.0.0.0", "127.0.0.1", "::1", "localhost")


@dataclass
class TamperFinding:
    kind: str          # "defender-exclusion", "defender-disabled", "hosts-blackhole"
    detail: str        # what was found, in words
    where: str         # the file or key it came from
    score: int = 0
    labels: list[str] = field(default_factory=list)


def parse_hosts(text: str) -> list[tuple[str, str]]:
    """(ip, hostname) pairs from a hosts file, comments and blanks dropped. Pure."""
    out: list[tuple[str, str]] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        ip = parts[0]
        for host in parts[1:]:
            out.append((ip, host.lower()))
    return out


def blackholed_security_domains(entries: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Entries that point a security or update domain at nowhere. Pure."""
    return [(ip, host) for ip, host in entries
            if ip in BLACKHOLE_IPS and any(d in host for d in SECURITY_DOMAINS)]


def looks_like_a_path(value: str) -> bool:
    """True if this is a filesystem path rather than a message. Pure.

    Needed because `Get-MpPreference` answers an unprivileged caller with the
    sentence "N/A: Must be an administrator to view exclusions" in the field
    where paths go — which was reported as an excluded folder.
    """
    v = (value or "").strip()
    if not v or " " in v.split(":", 1)[0]:
        return False
    if len(v) >= 3 and v[1] == ":" and v[2] in "\\/":      # C:\... or C:/...
        return True
    return v.startswith(("\\\\", "/", "%"))


def parse_mppreference(text: str) -> list[str]:
    """Exclusion paths from `Get-MpPreference | Select -Expand ExclusionPath`."""
    return [line.strip() for line in text.splitlines()
            if looks_like_a_path(line)]


def _read(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(256 * 1024)
    except OSError:
        return ""


def _hosts_path() -> str:
    if IS_WINDOWS:
        return os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                            "System32", "drivers", "etc", "hosts")
    return "/etc/hosts"


def _defender_exclusions() -> list[str]:
    """Folders Defender has been told to ignore.

    The registry copy needs Administrator, so `Get-MpPreference` is tried as
    well — it answers for the current user where the key will not.
    """
    paths: list[str] = []
    if not IS_WINDOWS:
        return paths
    try:
        import winreg as wr
        key = wr.OpenKey(wr.HKEY_LOCAL_MACHINE,
                         r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths")
        try:
            for i in range(wr.QueryInfoKey(key)[1]):
                name, _value, _type = wr.EnumValue(key, i)
                if name:
                    paths.append(name)
        finally:
            key.Close()
    except OSError:
        pass
    if not paths:
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                 "Get-MpPreference -ErrorAction SilentlyContinue | "
                 "Select-Object -ExpandProperty ExclusionPath"],
                capture_output=True, text=True, timeout=60,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            if r.returncode == 0:
                out = r.stdout or ""
                paths = parse_mppreference(out)
                if not paths and "administrator" in out.lower():
                    raise PermissionError(out.strip().splitlines()[0][:80])
        except PermissionError:
            raise
        except Exception:  # noqa: BLE001
            pass
    return paths


_DISABLE_VALUES = (
    (r"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware",
     "Defender is disabled by policy"),
    (r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
     "DisableRealtimeMonitoring", "Defender real-time protection is off by policy"),
    (r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
     "DisableBehaviorMonitoring", "Defender behaviour monitoring is off by policy"),
)


def _defender_disabled() -> list[tuple[str, str]]:
    """(where, what) for protection that has been switched off by policy."""
    out: list[tuple[str, str]] = []
    if not IS_WINDOWS:
        return out
    import winreg as wr
    for path, value_name, description in _DISABLE_VALUES:
        try:
            with wr.OpenKey(wr.HKEY_LOCAL_MACHINE, path) as key:
                value, _ = wr.QueryValueEx(key, value_name)
        except OSError:
            continue
        if value:
            out.append((f"HKLM\\{path}\\{value_name}", description))
    return out


def scan(cfg=None, flagged_paths: tuple[str, ...] = ()) -> list[TamperFinding]:
    """Everything worth reporting about weakened defences.

    `flagged_paths` are places MinerSentry has already found something; an
    exclusion that covers one of them is reported far more strongly, because
    the two findings only line up that way on purpose.
    """
    findings: list[TamperFinding] = []

    try:
        exclusions = _defender_exclusions()
    except PermissionError as why:
        # Saying "no exclusions" when we were not allowed to look would be a
        # clean bill of health we did not earn.
        exclusions = []
        findings.append(TamperFinding(
            "defender-unreadable", f"exclusions could not be read ({why})",
            "Windows Defender exclusions", 0,
            ["run as Administrator to check whether a folder is excluded"]))

    for path in exclusions:
        lowered = path.lower().rstrip("\\/")
        labels = ["a folder antivirus has been told to ignore"]
        score = 45
        if any(lowered and lowered in p.lower() for p in flagged_paths):
            score = 95
            labels.append("and MinerSentry has already flagged something inside it")
        for hint in ("\\temp\\", "\\appdata\\", "\\programdata\\", "\\users\\public",
                     "c:\\\\", "/tmp"):
            if hint in lowered or lowered in ("c:\\", "c:"):
                score = max(score, 70)
                labels.append("covering a drop location, or the whole drive")
                break
        findings.append(TamperFinding("defender-exclusion", path,
                                      "Windows Defender exclusions", score, labels))

    for where, description in _defender_disabled():
        findings.append(TamperFinding(
            "defender-disabled", description, where, 80,
            ["protection switched off by policy, which malware does for itself"]))

    entries = blackholed_security_domains(parse_hosts(_read(_hosts_path())))
    for ip, host in entries:
        findings.append(TamperFinding(
            "hosts-blackhole", f"{host} -> {ip}", _hosts_path(), 70,
            ["a security or update domain is redirected to nowhere"]))

    findings.sort(key=lambda f: f.score, reverse=True)
    return findings


def summarize(findings: list[TamperFinding]) -> list[dict]:
    return [{"kind": f.kind, "detail": f.detail, "where": f.where,
             "score": f.score, "labels": f.labels} for f in findings]
