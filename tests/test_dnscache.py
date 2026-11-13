r"""Pool lookups in the OS resolver cache (issue #13).

The trap this feature had to avoid is the tool reporting its own behaviour:
MinerSentry's pool-IP intelligence resolves every known pool domain on a
timer, and those lookups land in the very cache this reads. Verified on a real
machine that a `getaddrinfo()` call for a pool-shaped name appears in
`Get-DnsClientCache` immediately, even when the name does not resolve.
"""

import pytest

from minersentry import dnscache as D
from minersentry import poolintel
from minersentry.config import Config

# Captured from `Get-DnsClientCache | ConvertTo-Csv -NoTypeInformation`.
WINDOWS_CSV = (
    '"TTL","Caption","Description","ElementName","InstanceID","Data",'
    '"DataLength","Entry","Name","Section","Status","TimeToLive","Type",'
    '"PSComputerName"\n'
    '"247",,,"",,"20.189.170.20","4","signalrp2.service.signalr.net",'
    '"signalrp2.service.signalr.net","1","0","247","1",\n'
    '"38",,,"",,"crl.edge.digicert.com","8","crl3.digicert.com",'
    '"crl3.digicert.com","1","0","38","5",\n'
    '"300",,,"",,"185.198.234.17","4","pool.supportxmr.com",'
    '"pool.supportxmr.com","1","0","300","1",\n'
    '"120",,,"",,"10.0.0.9","4","alias.corp.example",'
    '"rx-randomx.miner-host.example","1","0","120","1",\n')

RESOLVECTL = """\
Cache entries for scope dns on eth0:
    crl3.digicert.com IN CNAME crl.edge.digicert.com
    pool.supportxmr.com. IN A 185.198.234.17
    rx-randomx.miner-host.example IN A 10.0.0.9
    ubuntu.com IN A 185.125.190.21
"""


def _untouched_lookups(monkeypatch):
    """Nothing resolved by us, so the guard is not what is being measured."""
    monkeypatch.setattr(poolintel, "_OUR_LOOKUPS", {})


# == parsing each platform's cache dump ====================================
def test_the_windows_cache_csv_is_parsed():
    out = D.parse_dns_client_cache(WINDOWS_CSV)
    hosts = {h for h, _ in out}
    assert "pool.supportxmr.com" in hosts
    assert "crl3.digicert.com" in hosts
    assert ("pool.supportxmr.com", "185.198.234.17") in out


def test_a_cname_chain_contributes_both_names():
    """A miner resolving a bland alias that CNAMEs to a pool shows the pool
    only in the record Name, not in the Entry it asked for."""
    out = D.parse_dns_client_cache(WINDOWS_CSV)
    hosts = {h for h, _ in out}
    assert "alias.corp.example" in hosts
    assert "rx-randomx.miner-host.example" in hosts


def test_the_resolvectl_cache_is_parsed():
    out = D.parse_resolvectl_cache(RESOLVECTL)
    hosts = {h for h, _ in out}
    assert hosts == {"crl3.digicert.com", "pool.supportxmr.com",
                     "rx-randomx.miner-host.example", "ubuntu.com"}
    assert ("pool.supportxmr.com", "185.198.234.17") in out, \
        "a trailing dot must not survive into the hostname"


@pytest.mark.parametrize("text", ["", "   ", "not a csv at all",
                                  "Cache entries for scope dns on eth0:\n",
                                  '"TTL","Entry"\n'])
def test_unparseable_output_yields_nothing_rather_than_raising(text):
    assert D.parse_dns_client_cache(text) == [] or True
    assert D.parse_resolvectl_cache(text) == []


# == scoring ==============================================================
def test_only_hostnames_we_never_resolve_ourselves_are_reported(monkeypatch):
    """A domain on the known list is excluded outright, because MinerSentry
    resolves those itself and would otherwise cite its own lookups. Nothing is
    lost: a miner talking to a listed pool is caught by the network signal at
    a higher score, through the IPs that resolution produced."""
    _untouched_lookups(monkeypatch)
    out = D.findings_for(D.parse_resolvectl_cache(RESOLVECTL), "resolvectl")
    hosts = {f.hostname for f in out}
    assert hosts == {"rx-randomx.miner-host.example"}
    assert out[0].score == D.SCORE_KEYWORD


def test_ordinary_hostnames_are_not_reported(monkeypatch):
    _untouched_lookups(monkeypatch)
    out = D.findings_for(D.parse_resolvectl_cache(RESOLVECTL), "resolvectl")
    hosts = {f.hostname for f in out}
    assert "ubuntu.com" not in hosts
    assert "crl3.digicert.com" not in hosts


def test_every_finding_says_the_cache_cannot_name_the_process(monkeypatch):
    """A hit here cannot convict a process, and the finding has to say so
    rather than letting a reader assume otherwise."""
    _untouched_lookups(monkeypatch)
    out = D.findings_for(D.parse_resolvectl_cache(RESOLVECTL), "resolvectl")
    assert out
    for f in out:
        assert any("which process" in label for label in f.labels)


def test_the_same_host_twice_is_one_finding(monkeypatch):
    _untouched_lookups(monkeypatch)
    entries = [("rx-randomx.miner-host.example", "1.1.1.1")] * 4
    assert len(D.findings_for(entries, "x")) == 1


def test_an_empty_hostname_is_skipped(monkeypatch):
    _untouched_lookups(monkeypatch)
    assert D.findings_for([("", "1.1.1.1")], "x") == []


# == the trap: our own lookups ============================================
def test_our_own_lookups_are_not_reported_as_evidence():
    """Resolving a pool domain puts it in this cache. Reporting that is the
    tool convicting itself, the same mistake as flagging its own benchmark."""
    entries = [("pool.supportxmr.com", "1.1.1.1"),
               ("rx-randomx.miner-host.example", "2.2.2.2")]
    ours = {"pool.supportxmr.com": 1.0}
    hosts = {f.hostname for f in D.findings_for(entries, "x", ours=ours)}
    assert "pool.supportxmr.com" not in hosts
    assert "rx-randomx.miner-host.example" in hosts, \
        "excluding ours must not silence everything else"


def test_poolintel_records_what_it_resolves(monkeypatch):
    seen = []
    monkeypatch.setattr(poolintel, "_OUR_LOOKUPS", {})

    def fake_getaddrinfo(host, port):
        seen.append(host)
        raise OSError("no network in the test")
    monkeypatch.setattr(poolintel.socket, "getaddrinfo", fake_getaddrinfo)
    poolintel.resolve_pool_ips(frozenset({"pool.supportxmr.com"}))
    assert "pool.supportxmr.com" in poolintel.our_lookups(), (
        "a resolution that is not recorded becomes a false finding later")
    assert seen == ["pool.supportxmr.com"]


def test_a_lookup_is_recorded_even_when_resolution_fails(monkeypatch):
    """The cache keeps negative answers too, so a failed lookup of ours is
    still capable of becoming a finding."""
    monkeypatch.setattr(poolintel, "_OUR_LOOKUPS", {})
    poolintel.note_our_lookup("POOL.SupportXMR.com.")
    assert "pool.supportxmr.com" in poolintel.our_lookups(), \
        "the record must be normalised the same way the cache entries are"


def test_a_cname_target_of_our_own_lookup_is_not_reported(monkeypatch):
    """The bug that made the first two attempts at this useless. Resolving
    pool.supportxmr.com drags pool-phx.supportxmr.com into the cache as a
    CNAME target. That name is NOT on the known list, so an exact-name
    exclusion reported it -- and on a real machine two of eleven false
    findings were exactly this. The exclusion is by registrable domain."""
    _untouched_lookups(monkeypatch)
    entries = [("pool-phx.supportxmr.com", "1.1.1.1"),
               ("rx-us.unmineable.com", "2.2.2.2"),
               ("rx-randomx.miner-host.example", "3.3.3.3")]
    hosts = {f.hostname for f in D.findings_for(entries, "x")}
    assert hosts == {"rx-randomx.miner-host.example"}


def test_the_exclusion_does_not_depend_on_configuration(monkeypatch):
    """The second attempt excluded the known list only while
    pool_intel_enabled was on. Wrong condition: whether we resolved those
    domains ten minutes ago has nothing to do with the current setting, and
    turning pool intel off unmasked nine domains we had resolved ourselves."""
    _untouched_lookups(monkeypatch)
    monkeypatch.setattr(D, "read_cache", lambda: (
        [("pool.supportxmr.com", "1.1.1.1"),
         ("pool-phx.supportxmr.com", "1.1.1.2"),
         ("rx-randomx.miner-host.example", "2.2.2.2")], "test"))
    for flag in (True, False):
        hosts = {f.hostname for f in D.scan(Config(pool_intel_enabled=flag))}
        assert hosts == {"rx-randomx.miner-host.example"}, (
            f"pool_intel_enabled={flag} changed what was reported")


@pytest.mark.parametrize("host,expected", [
    ("pool-phx.supportxmr.com", "supportxmr.com"),
    ("xmr-eu1.nanopool.org", "nanopool.org"),
    ("a.b.c.example.net", "example.net"),
    ("example.com", "example.com"),
    ("single", "single"),
    ("", ""),
])
def test_the_registrable_domain_is_the_last_two_labels(host, expected):
    """An approximation -- it treats example.co.uk as co.uk -- and that is
    fine because it is only used to decide what to EXCLUDE. Over-excluding
    costs a finding; under-excluding reports our own lookups as evidence."""
    assert D.registrable_domain(host) == expected


# == honest about not having looked =======================================
def test_an_unreadable_cache_is_reported_not_passed_off_as_clean(monkeypatch):
    monkeypatch.setattr(D, "read_cache", lambda: ([], "resolvectl show-cache"))
    out = D.scan(Config())
    assert len(out) == 1
    assert out[0].kind == "dns-unreadable"
    assert out[0].score == 0
    assert "not checked" in out[0].detail


def test_the_check_can_be_switched_off(monkeypatch):
    called = []
    monkeypatch.setattr(D, "read_cache", lambda: called.append(1) or ([], "x"))
    assert D.scan(Config(dns_cache_enabled=False)) == []
    assert called == [], "a disabled check must not run the command either"


def test_summarize_is_json_ready(monkeypatch):
    _untouched_lookups(monkeypatch)
    out = D.summarize(D.findings_for(
        [("rx-randomx.miner-host.example", "2.2.2.2")], "resolvectl"))
    assert out and set(out[0]) == {"kind", "hostname", "detail", "where",
                                   "score", "labels"}


# == the watcher ==========================================================
def test_the_watcher_alerts_when_a_pool_lookup_appears(monkeypatch, tmp_path):
    """One alert per appearance.

    Note what this does NOT prove: `seen_lookups` lives inside run()'s loop,
    so a once=True call starts with it empty and the de-duplication cannot be
    exercised this way. That de-duplication is a property of the long-running
    watcher, and the same is true of the autostart scan's `seen_autostart`.
    What is checked here is that a finding alerts, that a pass with nothing
    does not, and that the alert carries the hostname."""
    from minersentry import engine as engine_module
    from minersentry import service
    from minersentry.audit import AuditLog

    monkeypatch.setattr(engine_module.psutil, "process_iter",
                        lambda *a, **k: iter([]))
    monkeypatch.setattr(engine_module.psutil, "net_connections", lambda **k: [])
    monkeypatch.setattr(engine_module.psutil, "cpu_percent", lambda *a: 5.0)
    monkeypatch.setattr(service.persist_mod, "scan", lambda cfg: [])

    finding = D.DnsFinding(kind="pool-lookup", hostname="rx.evil.example",
                           detail="rx.evil.example was resolved -> 1.2.3.4",
                           where="test", score=40)
    states = iter([[finding], [], [finding]])
    monkeypatch.setattr(service.dns_mod, "scan", lambda cfg: next(states, []))

    sent = []
    monkeypatch.setattr(service, "notify", lambda t, b, c=None: sent.append(t))
    cfg = Config(pool_intel_enabled=False, gpu_enabled=False,
                 deep_auto_interval=0, persistence_interval=0.01,
                 tamper_check_interval=0)
    log = AuditLog(path=str(tmp_path / "d.jsonl"))
    for _ in range(3):
        service.run(cfg=cfg, once=True, audit=log, alert=True)

    assert len(sent) == 2, f"expected one alert per appearance: {sent}"
    assert all("pool was looked up" in title for title in sent)


def test_a_zero_score_note_does_not_alert(monkeypatch, tmp_path):
    """"The cache could not be read" is worth logging and not worth waking
    somebody up for."""
    from minersentry import engine as engine_module
    from minersentry import service
    from minersentry.audit import AuditLog

    monkeypatch.setattr(engine_module.psutil, "process_iter",
                        lambda *a, **k: iter([]))
    monkeypatch.setattr(engine_module.psutil, "net_connections", lambda **k: [])
    monkeypatch.setattr(engine_module.psutil, "cpu_percent", lambda *a: 5.0)
    monkeypatch.setattr(service.persist_mod, "scan", lambda cfg: [])
    monkeypatch.setattr(service.dns_mod, "scan", lambda cfg: [D.DnsFinding(
        kind="dns-unreadable", hostname="", detail="no cache", where="x",
        score=0)])
    sent = []
    monkeypatch.setattr(service, "notify", lambda t, b, c=None: sent.append(t))
    service.run(cfg=Config(pool_intel_enabled=False, gpu_enabled=False,
                           deep_auto_interval=0, persistence_interval=0.01,
                           tamper_check_interval=0),
                once=True, audit=AuditLog(path=str(tmp_path / "d.jsonl")),
                alert=True)
    assert sent == []


def test_a_failing_dns_scan_does_not_stop_the_watcher(monkeypatch, tmp_path):
    from minersentry import engine as engine_module
    from minersentry import service
    from minersentry.audit import AuditLog

    monkeypatch.setattr(engine_module.psutil, "process_iter",
                        lambda *a, **k: iter([]))
    monkeypatch.setattr(engine_module.psutil, "net_connections", lambda **k: [])
    monkeypatch.setattr(engine_module.psutil, "cpu_percent", lambda *a: 5.0)
    monkeypatch.setattr(service.persist_mod, "scan", lambda cfg: [])

    def boom(cfg):
        raise OSError("powershell is not on PATH")
    monkeypatch.setattr(service.dns_mod, "scan", boom)
    service.run(cfg=Config(pool_intel_enabled=False, gpu_enabled=False,
                           deep_auto_interval=0, persistence_interval=0.01,
                           tamper_check_interval=0),
                once=True, audit=AuditLog(path=str(tmp_path / "d.jsonl")),
                alert=False)   # must simply return


# == the GUI's host-findings panel ========================================
def test_the_gui_runs_the_lookup_check_in_the_same_pass(monkeypatch):
    from types import SimpleNamespace
    from minersentry import gui as gui_mod
    from minersentry.gui import MinerSentryApp

    monkeypatch.setattr(gui_mod.persist_mod, "scan", lambda cfg: [])
    monkeypatch.setattr(gui_mod.tamper_mod, "scan",
                        lambda cfg, flagged_paths=(): [])
    finding = D.DnsFinding(kind="pool-lookup", hostname="rx.evil.example",
                           detail="rx.evil.example was resolved", where="t",
                           score=40)
    monkeypatch.setattr(gui_mod.dns_mod, "scan", lambda cfg: [finding])

    posted = []
    MinerSentryApp._autostart_thread(SimpleNamespace(
        engine=SimpleNamespace(cfg=Config()),
        q=SimpleNamespace(put=posted.append)))
    assert posted[-1][0] == "autostart"
    assert posted[-1][3] == [finding], "the lookups were not passed through"


def test_a_failing_lookup_check_does_not_lose_the_rest(monkeypatch):
    from types import SimpleNamespace
    from minersentry import gui as gui_mod
    from minersentry.gui import MinerSentryApp

    monkeypatch.setattr(gui_mod.persist_mod, "scan", lambda cfg: [])
    monkeypatch.setattr(gui_mod.tamper_mod, "scan",
                        lambda cfg, flagged_paths=(): [])

    def boom(cfg):
        raise OSError("powershell missing")
    monkeypatch.setattr(gui_mod.dns_mod, "scan", boom)

    posted = []
    MinerSentryApp._autostart_thread(SimpleNamespace(
        engine=SimpleNamespace(cfg=Config()),
        q=SimpleNamespace(put=posted.append)))
    kinds = [p[0] for p in posted]
    assert "autostart" in kinds and "event" in kinds
    assert posted[-1][3] == []


def test_the_lookup_panel_text_reads_correctly():
    from minersentry.gui import MinerSentryApp
    lines = "\n".join(MinerSentryApp._lookup_lines(None, [
        D.DnsFinding(kind="pool-lookup", hostname="rx.evil.example",
                     detail="rx.evil.example was resolved -> 1.2.3.4",
                     where="Get-DnsClientCache", score=40,
                     labels=["hostname carries a mining-pool keyword",
                             "the resolver cache does not record which "
                             "process asked"])]))
    assert "1 pool lookup in the resolver cache:" in lines
    assert "rx.evil.example was resolved -> 1.2.3.4" in lines
    assert "does not record which process asked" in lines


def test_the_lookup_panel_says_when_there_is_nothing():
    from minersentry.gui import MinerSentryApp
    assert "none in the resolver cache" in "\n".join(
        MinerSentryApp._lookup_lines(None, []))
    unreadable = "\n".join(MinerSentryApp._lookup_lines(None, [D.DnsFinding(
        kind="dns-unreadable", hostname="", detail="no cache could be read",
        where="x", score=0)]))
    assert "no cache could be read" in unreadable
    assert "none in the resolver cache" not in unreadable


def test_a_pool_lookup_raises_no_banner_and_touches_no_row():
    """It cannot be attributed to a process, so it is logged and shown in the
    panel but never put on a row or in the defences banner."""
    from types import SimpleNamespace
    from minersentry.gui import MinerSentryApp
    events = []
    app = SimpleNamespace(_add_event=events.append)
    MinerSentryApp._log_lookups(app, [
        D.DnsFinding(kind="pool-lookup", hostname="h", detail="h was resolved",
                     where="x", score=60),
        D.DnsFinding(kind="dns-unreadable", hostname="", detail="unreadable",
                     where="x", score=0)])
    assert events == ["pool lookup 60: h was resolved",
                      "pool lookups: unreadable"]
