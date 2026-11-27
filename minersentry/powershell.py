"""Run a Windows PowerShell script and read what it prints, as text.

Every collector that shells out to PowerShell goes through `run`, so the
encoding is decided in one place.

Left to the defaults, the two ends disagree. Windows PowerShell writes a
redirected stdout in the console's OEM code page (cp437 on a US install),
while Python's `text=True` decodes it in the ANSI one (cp1252). ASCII
survives, nothing else does: `Café` came back as `Caf‚`, so a startup
shortcut under a non-ASCII profile folder never matched its own path and its
target was never scored (issue #59). Some bytes have no cp1252 character at
all, and those raised UnicodeDecodeError instead. `run` makes the script
switch its output to UTF-8 and decodes UTF-8, replacing anything that is not.

The script itself needs no such care: Windows passes a command line as
UTF-16, so non-ASCII text in the script reaches PowerShell intact. Values that
come from the filesystem or anywhere else outside MinerSentry still should not
be pasted into the script. Pass them in `env` and read them as `$env:NAME`;
see `persistence._resolve_shortcuts` for why.
"""

from __future__ import annotations

import os
import subprocess

# First statement of every script. Setting it before anything is written is
# what matters; it has no effect on output already produced.
UTF8_PREAMBLE = "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8\n"


def with_utf8_output(script: str) -> str:
    """The script, made to write its output as UTF-8. Pure."""
    return UTF8_PREAMBLE + script


def decode(data: bytes | str | None) -> str:
    """PowerShell's output bytes as text. Pure.

    UTF-8, with anything that does not decode replaced rather than raised:
    one bad byte must not cost the whole answer. A leading byte-order mark is
    dropped so it cannot end up inside the first field of a CSV header.
    """
    if data is None:
        return ""
    if isinstance(data, str):
        text = data
    else:
        text = data.decode("utf-8", errors="replace")
    return text[1:] if text.startswith("﻿") else text


def run(script: str, timeout: float,
        env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    """Run `script` with powershell.exe; stdout and stderr come back as str.

    Raises what `subprocess.run` raises (OSError when PowerShell is missing,
    subprocess.TimeoutExpired on a timeout), so each caller keeps its own
    error handling. `env` entries are added to the inherited environment.
    """
    full_env = None
    if env:
        full_env = dict(os.environ)
        full_env.update(env)
    proc = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command",
         with_utf8_output(script)],
        capture_output=True, timeout=timeout, env=full_env,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    return subprocess.CompletedProcess(proc.args, proc.returncode,
                                       decode(proc.stdout), decode(proc.stderr))
