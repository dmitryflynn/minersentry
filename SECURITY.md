# Security policy

MinerSentry is a defensive tool that reads other processes' memory, arguments
and network connections, and can suspend processes, move files and add firewall
rules. That is a lot of reach, so this file says what it does with it, what it
deliberately does not do, and how to report something.

## Reporting a vulnerability

Use GitHub's **Report a vulnerability** button under
[Security → Advisories](https://github.com/dmitryflynn/minersentry/security/advisories),
which keeps the report private until there is a fix. If that is not available
to you, open an issue with no detail beyond "security report, please contact me"
and a way to reach you.

Please include what you ran, what happened, and what you expected. A proof of
concept helps; a reproduction on a clean machine helps most.

Expect an acknowledgement within a week. I maintain this on my own time, so a
fix may take longer than that, and I will tell you where it stands rather than
leave you waiting. If you want credit in the release notes, say so.

**In scope:** anything that lets a non-administrator weaken or silence
detection, read data MinerSentry collects, escalate privileges through the
service, or make a response action destroy something it should not.

**Out of scope:** missing a miner. Evasion is a detection limitation, not a
vulnerability — the README lists the ones I know about, and I would still
like to hear about new ones as a normal issue.

## What it reads, and what it keeps

- **Process memory**, read-only, for the fingerprint scan. Only the *labels* of
  what matched are kept, never the bytes.
- **Command lines**, which routinely contain secrets. Only matched indicator
  labels are kept. Wallet addresses, passwords and worker names are read and
  discarded, and a test asserts they never reach a label. Pool endpoints are
  the one exception, because the host and port are the actionable part.
- **Connections, GPU telemetry, autostart entries**: metadata only.
- **Nothing leaves the machine.** There is no telemetry, no update check and no
  network call other than resolving the bundled pool domains through DNS, which
  `pool_intel_enabled: false` turns off.

Everything persistent lives under `%LOCALAPPDATA%\MinerSentry` (`~` on Linux):
`detections.log` (rotated at 5 MiB), `actions.jsonl` (what a response action
did, so it can be undone) and the `quarantine` folder. All three are safe to
delete.

## Trust boundaries

- **The per-user config file cannot weaken detection.** Anything running as you
  can write it, so it may only tune scan timing within bounds and *add* miner
  names and pool ports. Everything else is ignored and reported. Full tuning
  requires the admin config, honoured only from a location a normal user cannot
  write (Program Files, or root-owned `/etc/minersentry`).
- **MinerSentry identifies itself by process ID**, and by its own file path when
  packaged — never by name. Naming a miner `MinerSentry.exe` does not hide it.
- **Signed does not mean trusted.** A signature earns nothing in Temp, Roaming,
  the Recycle Bin or Fonts, and interpreters and injection hosts (`python`,
  `node`, `svchost`, `explorer`, …) are never dampened at all.
- **Response actions never run on their own.** Suspend, terminate, quarantine
  and firewall rules are each confirmed, journalled, and reversible.
- **The background service runs as SYSTEM or root** so a miner running as you
  cannot stop it. That is also the honest limit of its self-protection: against
  something that is already administrator, it has none.

## Known weaknesses

These are documented rather than hidden, with the reasoning in the README:
RandomX light mode avoids the dataset signal; padding a process past 128 MiB can
hide strings in the sampling gaps; Linux exposes no TCP connection age; reading
another user's memory or arguments needs elevation; and the probe's decoys are
distinguishable by a determined miner.

## Supported versions

The latest tag is what gets fixes. There are no backports.
