"""Known mining-pool threat intelligence.

Port heuristics miss a miner whose pool listens on 443; reputation does not. We
keep a bundled list of well-known mining-pool domains, resolve them to their
current IPs on a background cadence, and flag any process whose established
connection goes to one of those IPs — on ANY port. A connection to a live pool
IP is close to conclusive (ordinary software has no reason to talk to
supportxmr), so it is a strong network signal.

Resolution is best-effort and fully offline-safe: if DNS fails the set is simply
empty and the signal doesn't fire. The pure helpers (`is_pool_hostname`, the
domain list) are unit-tested; the resolver is a thin wrapper.
"""

from __future__ import annotations

import socket

# Well-known mining pools (Monero-heavy, since RandomX/CPU mining is the common
# cryptojacking case, plus a few multi-coin pools). Extend via config if needed.
KNOWN_POOL_DOMAINS: frozenset[str] = frozenset({
    "pool.supportxmr.com", "supportxmr.com",
    "pool.minexmr.com", "minexmr.com",
    "xmr.nanopool.org", "nanopool.org",
    "xmr.2miners.com", "2miners.com",
    "pool.hashvault.pro", "hashvault.pro",
    "gulf.moneroocean.stream", "moneroocean.stream",
    "xmrpool.eu", "monerohash.com",
    "cryptonight.net", "xmr.crypto-pool.fr",
    "mine.c3pool.com", "c3pool.com",
    "fr.minexmr.com", "de.minexmr.com", "sg.minexmr.com",
    "rx.unmineable.com", "unmineable.com",
    "pool.monero.hashvault.pro", "randomxmonero.hashvault.pro",
    "us-east.cryptonight-hub.miningpoolhub.com",
    "eth.2miners.com", "rvn.2miners.com",
})

# Substrings that mark a reverse-DNS / SNI hostname as a mining pool.
POOL_HOST_KEYWORDS: tuple[str, ...] = (
    "supportxmr", "minexmr", "nanopool", "2miners", "hashvault",
    "moneroocean", "xmrpool", "monerohash", "c3pool", "unmineable",
    "cryptonight", "miningpool", "xmr-", "-xmr", "randomx",
)


def is_pool_hostname(hostname: str) -> bool:
    """True if a hostname (reverse-DNS PTR or SNI) looks like a mining pool."""
    h = (hostname or "").lower()
    if not h:
        return False
    if h in KNOWN_POOL_DOMAINS:
        return True
    return any(k in h for k in POOL_HOST_KEYWORDS)


def resolve_pool_ips(domains: frozenset[str] = KNOWN_POOL_DOMAINS,
                     timeout: float = 3.0) -> set[str]:
    """Resolve the known pool domains to their current IPs (best-effort)."""
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    ips: set[str] = set()
    try:
        for dom in domains:
            try:
                for info in socket.getaddrinfo(dom, None):
                    ips.add(info[4][0])
            except (socket.gaierror, OSError, UnicodeError):
                continue
    finally:
        socket.setdefaulttimeout(old)
    return ips
