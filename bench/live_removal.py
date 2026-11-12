r"""Run the live removal tests and write the record of what was verified.

Issue #25: every removal path had unit tests that monkeypatched the thing
doing the work, so they asserted the right command was *constructed*. Both
destructive bugs the #22 review found were well-formed commands pointed at the
wrong thing, which that style of test cannot catch.

This plants a real autostart entry per kind, runs the real removal, checks the
entry is gone from the authoritative source, runs the real undo, and checks it
came back. It mutates the machine it runs on and cleans up after itself.

    python bench/live_removal.py            # -> bench/live_removal.md
    python bench/live_removal.py --elevated-note

Run it from an Administrator shell to include the service case; without
elevation that one is skipped rather than half-run.
"""

from __future__ import annotations

import io
import os
import platform
import re
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORT = os.path.join(ROOT, "bench", "live_removal.md")

# Removal paths that exist, and whether this harness can exercise them.
COVERAGE = [
    ("run-key", "covered", "HKCU Run value, planted and restored"),
    ("startup-folder (plain file)", "covered", "quarantined and restored"),
    ("startup-folder (.lnk)", "covered",
     "destructive bug (A): the target must survive"),
    ("scheduled-task", "covered",
     "destructive bug (B): XML captured before deletion"),
    ("service / service-dll", "needs Administrator",
     "disabled not deleted, then re-enabled"),
    ("hidden-task", "not covered",
     "needs a task written straight into the Tasks folder as SYSTEM"),
    ("active-setup, netsh-helper, appcert-dll", "not covered — deliberately",
     "system-wide load points; planting one to watch it go is how you lose "
     "the machine"),
    ("lsa-package, print-monitor, gpo-script, office-addin, "
     "accessibility-swap, pam-module", "n/a",
     "these refuse by design; the refusal is unit-tested"),
]


def run_tests() -> tuple[int, str]:
    env = dict(os.environ, MINERSENTRY_LIVE_REMOVAL="1")
    proc = subprocess.run(
        # -rs so a SKIPPED row can say WHY. An unexplained skip in a
        # verification report reads like coverage.
        [sys.executable, "-m", "pytest", "tests/test_live_removal.py",
         "-v", "-rs", "--no-header", "-p", "no:cacheprovider"],
        cwd=ROOT, env=env, capture_output=True, text=True)
    return proc.returncode, proc.stdout + proc.stderr


def parse(output: str) -> list[tuple[str, str, str]]:
    """(test name, outcome, reason) from pytest's verbose lines."""
    rows = []
    pattern = re.compile(
        r"^tests[/\\]test_live_removal\.py::(\S+)\s+(PASSED|FAILED|SKIPPED|ERROR)"
        r"(?:\s*\((.*)\))?")
    for line in output.splitlines():
        m = pattern.match(line.strip())
        if m:
            rows.append((m.group(1), m.group(2), (m.group(3) or "").strip()))

    # pytest's -rs block carries the skip reasons, which the verbose lines
    # do not: "SKIPPED [1] tests/test_live_removal.py:231: <reason>"
    reasons = re.findall(
        r"^SKIPPED \[\d+\] tests[/\\]test_live_removal\.py:\d+:\s*(.+)$",
        output, re.MULTILINE)
    skipped = [i for i, r in enumerate(rows) if r[1] == "SKIPPED"]
    for i, reason in zip(skipped, reasons):
        rows[i] = (rows[i][0], rows[i][1], reason.strip())
    return rows


def elevated() -> bool:
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


def main() -> int:
    if sys.platform != "win32":
        print("The removal paths these tests cover are Windows-only.")
        return 0

    print("Planting real autostart entries and removing them. "
          "Everything is cleaned up afterwards.\n")
    code, output = run_tests()
    rows = parse(output)

    lines = ["# Live removal verification", ""]
    lines.append("Each row planted a real entry, ran the real removal, checked "
                 "the entry was gone from the authoritative source (the "
                 "registry, the Startup folder, `schtasks /query`), ran the "
                 "real undo, and checked it came back unchanged. Nothing here "
                 "is monkeypatched.")
    lines.append("")
    lines.append(f"- Host: {platform.system()} {platform.release()}, "
                 f"Python {platform.python_version()}")
    lines.append(f"- Administrator: {'yes' if elevated() else 'no'}")
    lines.append(f"- Run: {time.strftime('%Y-%m-%d %H:%M')}")
    lines.append("")

    if rows:
        lines += ["| Test | Outcome | Note |", "|---|---|---|"]
        for name, outcome, reason in rows:
            readable = name.replace("test_", "").replace("_", " ")
            mark = {"PASSED": "pass", "FAILED": "**FAIL**",
                    "SKIPPED": "skipped", "ERROR": "**ERROR**"}[outcome]
            lines.append(f"| {readable} | {mark} | {reason} |")
    else:
        lines.append("No tests were collected. Output:")
        lines += ["", "```", output[-2000:], "```"]
    lines.append("")

    lines += ["## Coverage of the removal paths", "",
              "| Removal path | Status | Note |", "|---|---|---|"]
    for path, status, note in COVERAGE:
        lines.append(f"| `{path}` | {status} | {note} |")
    lines += ["",
              "The paths marked *deliberately* not covered are system-wide "
              "load points: an AppCertDll is loaded into every process that "
              "starts one, and an LSA package into `lsass` at boot. Planting "
              "one on a working machine to watch it being removed is not a "
              "test. Their removal either refuses by design or is a plain "
              "registry value whose deletion is the same code path the "
              "`run-key` row exercises.", ""]

    with io.open(REPORT, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines))

    failures = [r for r in rows if r[1] in ("FAILED", "ERROR")]
    print("\n".join(lines[-len(COVERAGE) - 8:]))
    print(f"\nWrote {REPORT}")
    if failures:
        print(f"\n{len(failures)} failing:\n")
        print(output[-4000:])
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
