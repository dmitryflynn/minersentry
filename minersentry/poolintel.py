"""Known mining-pool threat intelligence.

Port heuristics miss a miner whose pool listens on 443; reputation does not. We
keep a bundled list of mining-pool *stratum endpoints*, resolve them to their
current IPs on a background cadence, and flag any process whose established
connection goes to one of those IPs, on ANY port. A connection to a live pool
endpoint is close to conclusive, so it is a strong network signal. That only
holds if the IP really belongs to the pool, which is why two kinds of entry
are deliberately absent:

- Pool *websites* (supportxmr.com, 2miners.com, ...). Reading a pool's homepage
  in a browser is not mining. Only the hosts miners connect to are listed.
- Shared-hosting IPs. Several pools sit behind Cloudflare, whose edge IPs serve
  thousands of unrelated sites. Any resolved IP inside a published shared-CDN
  range is dropped, otherwise a busy browser tab on some other site behind the
  same edge scores as a known-pool connection.

Resolution is best-effort and fully offline-safe: if DNS fails the set is simply
empty and the signal doesn't fire.
"""

from __future__ import annotations

import ipaddress
import socket

# Stratum endpoints of well-known pools (Monero-heavy, since RandomX CPU mining
# is the common cryptojacking case, plus a few multi-coin pools). minexmr shut
# down in 2022 and is gone. Some hosts fail to resolve through filtering DNS
# resolvers (many block mining pools); that only means the signal can't fire.
KNOWN_POOL_DOMAINS: frozenset[str] = frozenset({
    "pool.supportxmr.com",
    "xmr.nanopool.org", "xmr-eu1.nanopool.org", "xmr-eu2.nanopool.org",
    "xmr-us-east1.nanopool.org", "xmr-us-west1.nanopool.org", "xmr-asia1.nanopool.org",
    "xmr.2miners.com", "eth.2miners.com", "rvn.2miners.com",
    "pool.hashvault.pro", "pool.monero.hashvault.pro", "randomxmonero.hashvault.pro",
    "gulf.moneroocean.stream",
    "mine.c3pool.com",
    "rx.unmineable.com",
    "xmr.crypto-pool.fr",
    "us-east.cryptonight-hub.miningpoolhub.com",
})

# Substrings that mark a reverse-DNS / SNI hostname as a mining pool.
POOL_HOST_KEYWORDS: tuple[str, ...] = (
    "supportxmr", "nanopool", "2miners", "hashvault",
    "moneroocean", "xmrpool", "monerohash", "c3pool", "unmineable",
    "cryptonight", "miningpool", "xmr-", "-xmr", "randomx",
)

# Published shared-CDN ranges (Cloudflare: cloudflare.com/ips; Fastly:
# api.fastly.com/public-ip-list). An IP in here is shared by unrelated sites.
SHARED_HOSTING_RANGES: tuple[str, ...] = (
    # Cloudflare IPv4
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    # Cloudflare IPv6
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
    # Fastly IPv4 / IPv6
    "23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24", "103.245.222.0/23",
    "103.245.224.0/24", "104.156.80.0/20", "140.248.64.0/18", "140.248.128.0/17",
    "146.75.0.0/17", "151.101.0.0/16", "157.52.64.0/18", "167.82.0.0/17",
    "167.82.128.0/20", "167.82.160.0/20", "167.82.224.0/20", "172.111.64.0/18",
    "185.31.16.0/22", "199.27.72.0/21", "199.232.0.0/16",
    "2a04:4e40::/32", "2a04:4e42::/32",
)
_SHARED = tuple(ipaddress.ip_network(r) for r in SHARED_HOSTING_RANGES)


def is_shared_hosting_ip(ip: str) -> bool:
    """True if `ip` falls inside a published shared-CDN range."""
    try:
        addr = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return False
    if getattr(addr, "ipv4_mapped", None):
        addr = addr.ipv4_mapped
    return any(addr.version == n.version and addr in n for n in _SHARED)


def is_pool_hostname(hostname: str) -> bool:
    """True if a hostname (reverse-DNS PTR or SNI) looks like a mining pool."""
    h = (hostname or "").lower()
    if not h:
        return False
    if h in KNOWN_POOL_DOMAINS:
        return True
    return any(k in h for k in POOL_HOST_KEYWORDS)


def resolve_pool_ips(domains: frozenset[str] = KNOWN_POOL_DOMAINS) -> set[str]:
    """Resolve the known pool endpoints to their current IPs (best-effort),
    leaving out any IP that belongs to shared hosting."""
    ips: set[str] = set()
    for dom in domains:
        try:
            for info in socket.getaddrinfo(dom, None):
                ip = info[4][0]
                if not is_shared_hosting_ip(ip):
                    ips.add(ip)
        except (socket.gaierror, OSError, UnicodeError):
            continue
    return ips
