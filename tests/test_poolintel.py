"""Tests for the known-mining-pool threat intel (pure helpers)."""

from minersentry import poolintel


def test_known_pool_domain_matches():
    assert poolintel.is_pool_hostname("pool.supportxmr.com")
    assert poolintel.is_pool_hostname("xmr.nanopool.org")


def test_pool_keyword_substring_matches():
    # a reverse-DNS PTR that embeds a pool name
    assert poolintel.is_pool_hostname("node7.hashvault.pro.example.net")
    assert poolintel.is_pool_hostname("srv-moneroocean-12.hosting.com")


def test_ordinary_hostname_not_a_pool():
    assert not poolintel.is_pool_hostname("www.google.com")
    assert not poolintel.is_pool_hostname("cdn.cloudflare.net")
    assert not poolintel.is_pool_hostname("")


def test_resolver_offline_safe(monkeypatch):
    # if DNS is unavailable the set is simply empty, never an exception
    import socket

    def boom(*a, **k):
        raise socket.gaierror("no dns")

    monkeypatch.setattr(socket, "getaddrinfo", boom)
    assert poolintel.resolve_pool_ips(frozenset({"pool.supportxmr.com"})) == set()


def test_pool_websites_are_not_listed():
    # reading a pool's homepage is not mining; only stratum endpoints are listed
    for site in ("supportxmr.com", "2miners.com", "nanopool.org", "hashvault.pro",
                 "moneroocean.stream", "c3pool.com", "unmineable.com", "minexmr.com"):
        assert site not in poolintel.KNOWN_POOL_DOMAINS


def test_shared_hosting_ips_detected():
    # the Cloudflare edge IPs that 2miners.com / nanopool.org resolved to
    for ip in ("104.26.4.192", "172.67.73.5", "172.66.135.157", "2606:4700::1",
               "151.101.1.69", "::ffff:104.26.4.192"):
        assert poolintel.is_shared_hosting_ip(ip), ip
    for ip in ("107.167.83.34", "205.172.58.170", "not-an-ip"):
        assert not poolintel.is_shared_hosting_ip(ip), ip


def test_resolver_drops_shared_hosting(monkeypatch):
    import socket
    answers = {"a.example": ["104.26.4.192", "107.167.83.34"]}
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda d, *_: [(0, 0, 0, "", (ip, 0)) for ip in answers[d]])
    assert poolintel.resolve_pool_ips(frozenset({"a.example"})) == {"107.167.83.34"}


def test_browser_on_cloudflare_edge_is_not_a_known_pool_hit():
    # end to end: the exact false positive found in the audit
    import time
    from minersentry.config import Config
    from minersentry.engine import Engine, ProcInfo
    from minersentry.scoring import combine
    e = Engine(cfg=Config(pool_intel_enabled=False))
    e.set_pool_ips({ip for ip in ["104.26.4.192", "107.167.83.34"]
                    if not poolintel.is_shared_hosting_ip(ip)})
    info = ProcInfo(5150); info.name = "chrome.exe"; info.trusted = True
    now = time.time()
    for i in range(8):
        e._cpu_hist[5150].append((now - i, 40.0))
    signals = e._build_signals(info, [("104.26.4.192", 443)], now)
    assert combine(signals, e.cfg)[1] == "Clean"
