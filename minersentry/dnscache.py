r"""Pool lookups in the OS resolver cache (issue #13).

Pool-IP intelligence is defeated by any private proxy, and a pool reachable on
443 leaves only the command line as evidence. A DNS lookup for a pool domain
happens *before* any connection exists and is much harder to avoid: the miner
has to find the pool somehow.

**This is a host-level finding, not a process signal, and that is a deliberate
limitation rather than an oversight.** The resolver cache records that
*something on this machine* resolved a name. It does not record which process
asked — Windows does not keep the requesting PID in the client cache, and
neither does systemd-resolved. So a hit here cannot convict a process; it says
"a pool domain was looked up on this host, go and find out by whom". It is
reported the way `tamper` findings are, for the same reason.

Two honest caveats:

- **DNS-over-HTTPS bypasses the OS resolver entirely.** A miner using DoH, or
  a browser with DoH enabled on behalf of a page, leaves nothing here. This
  closes one door, not the corridor.
- **The cache is shared with everything else.** A human reading a mining-pool
  website, or a security tool fetching a blocklist, puts pool domains in the
  cache too. The score reflects that: a hit is corroboration, and the detail
  says what was resolved so a person can judge it.

**The trap this has to avoid, and what it cost to get right.** MinerSentry's
own pool-IP resolution looks up every known pool domain, and those lookups land
in this very cache. Reporting them is the tool citing itself as evidence — the
same mistake as flagging its own benchmark.

Two earlier attempts were not enough, and the second produced eleven false
findings on a working machine:

1. Recording what *this process* resolved. Useless across restarts: a freshly
   started scan knows nothing about the lookups the previous run made, and a
   DNS entry outlives the process that caused it.
2. Excluding the known-pool list while `pool_intel_enabled` is on. Wrong
   condition — whether we resolved those domains ten minutes ago has nothing to
   do with the current setting. Turning pool intel *off* unmasked nine domains
   we had resolved ourselves. Worse, two of the eleven were CNAME *targets* of
   our lookups (`pool-phx.supportxmr.com` behind `pool.supportxmr.com`) and so
   were not on the list at all — an exact-name exclusion could never have
   caught them.

What works is stateless and does not depend on configuration: never report a
hostname under a domain we are capable of resolving ourselves. The whole
registrable domain of every known pool is excluded, which covers the names we
ask for and the CNAME chains they drag in.

Nothing of value is lost. A miner talking to a *listed* pool is already caught
by the network signal, at a higher score, through the IPs that resolution
produced. What this check uniquely adds is a pool-shaped hostname on a domain
we have never heard of — which is also the case the bundled list can never
cover.
"""

from __future__ import annotations

import csv
import io
import re
import subprocess
import sys
from dataclasses import dataclass, field

from . import poolintel
from .config import Config

IS_WINDOWS = sys.platform == "win32"

# Every finding here is a keyword match on a domain we do not resolve
# ourselves (see the module docstring on why the known list is excluded
# outright). The keywords are substrings — "randomx", "xmr-" — that a
# legitimate hostname can carry, and the cache cannot say which process
# asked, so this corroborates and never convicts on its own.
SCORE_KEYWORD = 40


@dataclass
class DnsFinding:
    kind: str                 # "pool-lookup"
    hostname: str
    detail: str
    where: str                # which cache it came from
    score: int = 0
    labels: list[str] = field(default_factory=list)


def parse_dns_client_cache(csv_text: str) -> list[tuple[str, str]]:
    """(entry, data) pairs from `Get-DnsClientCache | ConvertTo-Csv`. Pure.

    `Entry` is the name that was looked up; `Name` is the name of the record,
    which differs for a CNAME chain. Both are worth matching: a miner
    resolving a short alias that CNAMEs to a pool shows the pool in `Name`.
    """
    out: list[tuple[str, str]] = []
    try:
        reader = csv.DictReader(io.StringIO(csv_text))
        for row in reader:
            entry = (row.get("Entry") or "").strip().strip('"').lower()
            name = (row.get("Name") or "").strip().strip('"').lower()
            data = (row.get("Data") or "").strip().strip('"')
            for host in (entry, name):
                if host:
                    out.append((host.rstrip("."), data))
    except (csv.Error, ValueError):
        return out
    return out


_RESOLVECTL = re.compile(r"^\s*(\S+?)\.?\s+IN\s+(?:A|AAAA|CNAME)\s+(\S+)",
                         re.IGNORECASE)


def parse_resolvectl_cache(text: str) -> list[tuple[str, str]]:
    """(hostname, data) pairs from `resolvectl show-cache`. Pure."""
    out: list[tuple[str, str]] = []
    for line in text.splitlines():
        match = _RESOLVECTL.match(line)
        if match:
            out.append((match.group(1).lower().rstrip("."), match.group(2)))
    return out


def _run(args: list[str], timeout: float = 30.0) -> str:
    try:
        proc = subprocess.run(args, capture_output=True, text=True,
                              timeout=timeout,
                              creationflags=getattr(subprocess,
                                                    "CREATE_NO_WINDOW", 0))
    except (OSError, subprocess.SubprocessError):
        return ""
    return proc.stdout or ""


def read_cache() -> tuple[list[tuple[str, str]], str]:
    """Everything in the OS resolver cache, and where it came from."""
    if IS_WINDOWS:
        text = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                     "Get-DnsClientCache | ConvertTo-Csv -NoTypeInformation"])
        return parse_dns_client_cache(text), "Get-DnsClientCache"
    text = _run(["resolvectl", "show-cache"])
    if text:
        return parse_resolvectl_cache(text), "resolvectl show-cache"
    return [], "resolvectl show-cache"


def registrable_domain(hostname: str) -> str:
    """The last two labels of a hostname. Pure.

    An approximation of the registrable domain — it treats `example.co.uk` as
    `co.uk` — and that is acceptable here because it is only ever used to
    decide what to EXCLUDE. Over-excluding costs a finding; under-excluding
    reports our own lookups as evidence, which is far worse.
    """
    parts = [p for p in (hostname or "").lower().rstrip(".").split(".") if p]
    return ".".join(parts[-2:]) if len(parts) >= 2 else ".".join(parts)


def our_domains(known=None) -> set[str]:
    """Registrable domains MinerSentry resolves itself, so never reports."""
    known = poolintel.KNOWN_POOL_DOMAINS if known is None else known
    return {registrable_domain(d) for d in known}


def findings_for(entries: list[tuple[str, str]], where: str,
                 ours: dict[str, float] | None = None,
                 is_pool=poolintel.is_pool_hostname,
                 known=None) -> list[DnsFinding]:
    """Score the cache contents. Pure, so it is tested against captured output.

    Excludes every hostname under a domain we resolve ourselves, and anything
    this process is recorded as having looked up. See the module docstring:
    without the domain-level rule the tool reports its own lookups, including
    the CNAME targets behind them.
    """
    ours = ours or {}
    skip_domains = our_domains(known)
    seen: dict[str, DnsFinding] = {}
    for host, data in entries:
        if not host or host in ours:
            continue
        if registrable_domain(host) in skip_domains:
            continue        # ours, or a CNAME target dragged in by ours
        if not is_pool(host):
            continue
        if host in seen:
            continue
        seen[host] = DnsFinding(
            kind="pool-lookup", hostname=host,
            detail=f"{host} was resolved" + (f" -> {data}" if data else ""),
            where=where, score=SCORE_KEYWORD,
            labels=["hostname carries a mining-pool keyword",
                    "the resolver cache does not record which process asked"])
    return sorted(seen.values(), key=lambda f: (-f.score, f.hostname))


def scan(cfg: Config | None = None) -> list[DnsFinding]:
    """Pool domains in the resolver cache, excluding our own lookups."""
    cfg = cfg or Config.load()
    if not getattr(cfg, "dns_cache_enabled", True):
        return []
    # Not conditioned on pool_intel_enabled: whether we resolved those domains
    # ten minutes ago has nothing to do with the current setting, and making
    # that mistake produced eleven false findings. findings_for() excludes the
    # registrable domains outright.
    ours = dict(poolintel.our_lookups())
    entries, where = read_cache()
    if not entries:
        # Say nothing rather than implying the cache was clean: on Linux
        # without systemd-resolved there is no cache to read at all.
        return [DnsFinding(kind="dns-unreadable", hostname="",
                           detail="no resolver cache could be read, so pool "
                                  "lookups were not checked",
                           where=where, score=0)]
    return findings_for(entries, where, ours=ours)


def summarize(findings: list[DnsFinding]) -> list[dict]:
    return [{"kind": f.kind, "hostname": f.hostname, "detail": f.detail,
             "where": f.where, "score": f.score, "labels": f.labels}
            for f in findings]
