r"""Loaded kernel drivers that miners are known to abuse (issue #20).

XMRig loads the signed WinRing0 driver to write the MSRs that speed RandomX up,
and miner campaigns more generally bring a legitimately signed but vulnerable
driver along ("bring your own vulnerable driver") to switch antivirus off from
the kernel. A driver load is rare, needs Administrator, and is not something a
user-mode process can hide: the service control manager lists it.

**This is a name list, and that is a real limitation.** It sits against the
grain of a behavioural tool, it only knows the drivers on it, and a renamed
file walks past it. It is here because the alternative is reporting nothing
about the one kernel-level step a miner commonly takes. Hashes would be
stronger than names and are deliberately not included: a list of hashes typed
from memory is worse than no list.

**Every driver on the list also has an innocent explanation**, which is why a
hit on its own is a low-scoring note and never a verdict. WinRing0 ships with
hardware monitors; RTCore64 *is* MSI Afterburner. What turns a note into a
finding is where the file is: the same driver loaded from a temp or user
directory was not put there by an installer. Location is judged with
`persistence.is_rogue_driver`, which measured 460 of 461 real driver services
under `System32\drivers` or the DriverStore.

What this cannot see: `EnumDeviceDrivers` returns zeroed addresses without
Administrator, so the list comes from the service control manager (through
WMI, whose property names are not localised the way `driverquery`'s CSV
headers are). A driver mapped without a service entry — which takes a kernel
exploit already — is not in it.
"""

from __future__ import annotations

import csv
import io
import ntpath
import subprocess
import sys
from dataclasses import dataclass

from . import persistence
from . import powershell

IS_WINDOWS = sys.platform == "win32"

# file name -> (what legitimately ships it, what it is abused for).
# Matched on the exact file name, never a substring: "gdrv" as a substring
# matches Windows' own EhStorTcgDrv.
KNOWN_ABUSED: dict[str, tuple[str, str]] = {
    "winring0x64.sys": ("hardware monitors and fan-control tools",
                        "XMRig loads it to write MSRs for RandomX"),
    "winring0.sys": ("hardware monitors and fan-control tools",
                     "XMRig loads it to write MSRs for RandomX"),
    "rtcore64.sys": ("MSI Afterburner",
                     "arbitrary kernel memory access, used to disable security products"),
    "rtcore32.sys": ("MSI Afterburner",
                     "arbitrary kernel memory access, used to disable security products"),
    "gdrv.sys": ("Gigabyte utilities",
                 "arbitrary kernel memory access, used to disable driver signing"),
    "dbutil_2_3.sys": ("Dell firmware update utilities",
                       "arbitrary kernel memory access (CVE-2021-21551)"),
    "aswarpot.sys": ("Avast's anti-rootkit component",
                     "terminating security products from the kernel"),
    "mhyprot2.sys": ("an anti-cheat component",
                     "terminating security products from the kernel"),
    "kprocesshacker.sys": ("Process Hacker",
                           "terminating protected processes"),
    "iqvw64e.sys": ("Intel network diagnostics",
                    "arbitrary kernel memory access, used to map unsigned drivers"),
}

SCORE_IN_PLACE = 30       # where an installer would have put it: a note
SCORE_MSR_DRIVER = 35     # WinRing0 specifically is the mining-relevant one
SCORE_DROPPED = 80        # the same driver from a directory no installer uses


@dataclass(frozen=True)
class LoadedDriver:
    name: str        # the service name
    path: str        # resolved path of the .sys
    running: bool


@dataclass(frozen=True)
class AbusedDriver:
    driver: LoadedDriver
    shipped_by: str
    abused_for: str
    dropped: bool
    score: int


def parse_system_drivers(csv_text: str, system_root: str | None = None,
                         environ: dict | None = None) -> list[LoadedDriver]:
    """`Win32_SystemDriver | ConvertTo-Csv` into drivers. Pure."""
    out: list[LoadedDriver] = []
    try:
        for row in csv.DictReader(io.StringIO(csv_text)):
            name = (row.get("Name") or "").strip()
            path = (row.get("PathName") or "").strip()
            if not name or not path:
                continue
            resolved = persistence.command_exe(
                persistence.resolve_image_path(path, system_root=system_root,
                                               environ=environ),
                isfile=lambda p: False)
            out.append(LoadedDriver(
                name=name, path=resolved or path,
                running=(row.get("State") or "").strip().lower() == "running"))
    except (csv.Error, ValueError):
        return out
    return out


def abused(drivers: list[LoadedDriver],
           system_root: str | None = None) -> list[AbusedDriver]:
    """The running drivers that are on the list, worst first. Pure."""
    out: list[AbusedDriver] = []
    for d in drivers:
        if not d.running:
            continue
        base = ntpath.basename(d.path).lower()
        info = KNOWN_ABUSED.get(base)
        if info is None:
            continue
        dropped = persistence.is_rogue_driver(d.path, system_root=system_root)
        if dropped:
            score = SCORE_DROPPED
        elif base.startswith("winring0"):
            score = SCORE_MSR_DRIVER
        else:
            score = SCORE_IN_PLACE
        out.append(AbusedDriver(d, info[0], info[1], dropped, score))
    out.sort(key=lambda a: (-a.score, a.driver.name.lower()))
    return out


def loaded(timeout: float = 30.0) -> list[LoadedDriver] | None:
    """Kernel drivers known to the service control manager, or None if they
    could not be read — which is not the same as there being none."""
    if not IS_WINDOWS:
        return None
    try:
        proc = powershell.run(
            "Get-CimInstance Win32_SystemDriver | "
            "Select-Object Name,State,PathName | ConvertTo-Csv -NoTypeInformation",
            timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    return parse_system_drivers(proc.stdout)
