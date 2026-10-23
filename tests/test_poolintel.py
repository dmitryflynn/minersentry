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
