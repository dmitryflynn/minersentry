"""Per-connection TCP counters for the cadence signal (#14): the `ss` parser,
the Linux and Windows collectors, and the engine wiring.

The `ss` fixtures follow iproute2's documented layout: one header line per
socket, then a tab-indented tcp_info line. They cover the current format
(`ss -tni state established`, no State column, bracketed IPv6), the older one
(State column, unbracketed IPv6), kernels 4.1-4.18 (bytes_acked but no
bytes_sent), kernels before 4.1 (no byte counters) and TIME-WAIT sockets,
which have no info line at all.

The Windows EStats path is tested against a fake API. The elevated path has
NOT been run on a real elevated machine; the unelevated refusal has, below.
"""

import socket
import sys
import threading
import time

import pytest

from minersentry import cadence, tcpstats
from minersentry.config import Config
from minersentry.engine import Engine, ProcInfo

# `ss -tni state established` (iproute2 6.x, kernel 6.x)
SS_CURRENT = (
    "Recv-Q Send-Q          Local Address:Port            Peer Address:Port Process\n"
    "0      0                   10.0.2.15:22                   10.0.2.2:51544\n"
    "\t cubic wscale:6,7 rto:204 rtt:0.31/0.093 ato:40 mss:1460 pmtu:1500 rcvmss:1460"
    " advmss:1460 cwnd:10 bytes_sent:73845 bytes_acked:73845 bytes_received:9413"
    " segs_out:412 segs_in:528 data_segs_out:396 data_segs_in:186 send 377Gbps"
    " lastsnd:4 lastrcv:8 lastack:4 pacing_rate 750Gbps delivery_rate 89.2Gbps"
    " delivered:397 app_limited busy:204ms rcv_space:29200 rcv_ssthresh:64076"
    " minrtt:0.067 snd_wnd:65535\n"
    "0      0                   10.0.2.15:48212            203.0.113.40:443\n"
    "\t cubic wscale:7,7 rto:232 rtt:30.513/2.11 ato:40 mss:1448 pmtu:1500 rcvmss:1448"
    " advmss:1448 cwnd:10 bytes_sent:18632 bytes_acked:18633 bytes_received:41077"
    " segs_out:131 segs_in:140 data_segs_out:74 data_segs_in:80 send 3.8Mbps"
    " lastsnd:21780 lastrcv:21748 lastack:21748 pacing_rate 7.59Mbps"
    " delivery_rate 1.17Mbps delivered:75 app_limited busy:2356ms rcv_space:14480"
    " rcv_ssthresh:64088 minrtt:28.1 snd_wnd:65280\n"
    "0      0            [2001:db8:10::5]:50322      [2001:db8:feed::7]:3333\n"
    "\t cubic wscale:7,7 rto:248 rtt:44.2/5.5 ato:40 mss:1428 pmtu:1500 rcvmss:1428"
    " advmss:1428 cwnd:10 bytes_sent:5120 bytes_acked:5121 bytes_received:2210"
    " segs_out:60 segs_in:58 data_segs_out:30 data_segs_in:29 send 2.6Mbps"
    " lastsnd:40112 lastrcv:40070 lastack:40070 pacing_rate 5.2Mbps"
    " delivered:31 rcv_space:14280 rcv_ssthresh:64400 minrtt:41.9\n"
    "0      0          [::ffff:10.0.2.15]:43000  [::ffff:198.51.100.9]:14433\n"
    "\t cubic wscale:7,7 rto:216 rtt:15.1/1.2 ato:40 mss:1448 cwnd:10"
    " bytes_sent:900 bytes_acked:901 bytes_received:300 segs_out:12 segs_in:11"
    " send 7.7Mbps lastsnd:12000 lastrcv:11980 lastack:11980 minrtt:14.2\n"
    "0      0     [fe80::1%eth0]:41000      [fe80::2%eth0]:8080\n"
    "\t cubic rto:204 rtt:0.2/0.1 mss:1428 cwnd:10 bytes_sent:77 bytes_acked:78"
    " bytes_received:12 segs_out:3 segs_in:3 minrtt:0.1\n"
    "36     0                   127.0.0.1:631                 127.0.0.1:41870\n"
    "\t cubic rto:200 rtt:0.02/0.01 ato:40 mss:32768 cwnd:10 bytes_sent:1200"
    " bytes_acked:1200 bytes_received:3400 segs_out:9 segs_in:9 minrtt:0.01\n"
)

# Older iproute2 with a State column, unbracketed IPv6, kernel 4.9 (no
# bytes_sent), a pre-4.1 socket with no counters, and a TIME-WAIT socket.
SS_OLD = (
    "State      Recv-Q Send-Q        Local Address:Port          Peer Address:Port\n"
    "ESTAB      0      0              192.168.1.20:39114        198.51.100.23:4444\n"
    "\t cubic wscale:7,7 rto:236 rtt:35.2/4.1 ato:40 mss:1448 rcvmss:536 advmss:1448"
    " cwnd:10 bytes_acked:11025 bytes_received:6230 segs_out:120 segs_in:118"
    " send 3.3Mbps lastsnd:3020 lastrcv:3016 lastack:3016 pacing_rate 6.6Mbps"
    " rcv_space:29200\n"
    "TIME-WAIT  0      0              192.168.1.20:39000        198.51.100.23:80\n"
    "ESTAB      0      0        2001:db8::20:51000      2001:db8::99:443\n"
    "\t cubic wscale:7,7 rto:240 rtt:38/6 ato:40 mss:1428 cwnd:10 bytes_acked:700"
    " bytes_received:150 segs_out:10 segs_in:9 send 3.0Mbps rcv_space:28560\n"
    "ESTAB      0      0              192.168.1.20:22           192.168.1.5:60001\n"
    "\t cubic wscale:7,7 rto:204 rtt:1.5/0.7 ato:40 mss:1448 cwnd:10 send 77.2Mbps"
    " rcv_space:29200\n"
)


# -- ss parser ------------------------------------------------------------------

def test_parse_current_ss_output():
    got = tcpstats.parse_ss(SS_CURRENT)
    assert got[("10.0.2.15", 22, "10.0.2.2", 51544)] == (73845, 9413)
    assert got[("10.0.2.15", 48212, "203.0.113.40", 443)] == (18632, 41077)
    assert got[("2001:db8:10::5", 50322, "2001:db8:feed::7", 3333)] == (5120, 2210)
    # IPv4-mapped IPv6 is keyed as plain IPv4, like psutil reports it after
    # normalisation, and a zone index is dropped.
    assert got[("10.0.2.15", 43000, "198.51.100.9", 14433)] == (900, 300)
    assert got[("fe80::1", 41000, "fe80::2", 8080)] == (77, 12)
    assert got[("127.0.0.1", 631, "127.0.0.1", 41870)] == (1200, 3400)
    assert len(got) == 6


def test_parse_old_ss_output():
    got = tcpstats.parse_ss(SS_OLD)
    # bytes_acked stands in for bytes_sent on kernels before 4.19
    assert got[("192.168.1.20", 39114, "198.51.100.23", 4444)] == (11025, 6230)
    assert got[("2001:db8::20", 51000, "2001:db8::99", 443)] == (700, 150)
    # no counters at all: left out, not guessed; TIME-WAIT has no info line
    assert ("192.168.1.20", 22, "192.168.1.5", 60001) not in got
    assert ("192.168.1.20", 39000, "198.51.100.23", 80) not in got
    assert len(got) == 2


def test_parse_garbage_and_empty():
    assert tcpstats.parse_ss("") == {}
    assert tcpstats.parse_ss("\t bytes_sent:5 bytes_received:5\n") == {}
    assert tcpstats.parse_ss("Cannot open netlink socket: Protocol not supported\n") == {}


def test_norm_ip_and_loopback():
    assert tcpstats.norm_ip("[::FFFF:1.2.3.4]") == "1.2.3.4"
    assert tcpstats.norm_ip("fe80::1%eth0") == "fe80::1"
    assert tcpstats.is_loopback("127.0.0.53") and tcpstats.is_loopback("[::1]")
    assert not tcpstats.is_loopback("10.0.0.1")


def test_ss_collector_filters_to_targets():
    col = tcpstats.SsCollector(runner=lambda: SS_CURRENT)
    key = ("10.0.2.15", 48212, "203.0.113.40", 443)
    assert col.available
    assert col.sample({key}) == {key: (18632, 41077)}
    assert col.sample(set()) == {}


def test_ss_collector_unavailable_without_ss(monkeypatch):
    monkeypatch.setattr(tcpstats.shutil, "which", lambda name: None)
    col = tcpstats.SsCollector()
    assert not col.available and "ss" in col.error
    assert col.sample({("a", 1, "b", 2)}) == {}


def test_ss_collector_survives_a_failing_command():
    def boom():
        raise OSError("ss exploded")
    col = tcpstats.SsCollector(runner=boom)
    assert col.sample({("a", 1, "b", 2)}) == {}
    assert "ss exploded" in col.error


# -- Windows EStats collector (fake API) ----------------------------------------

K1 = ("10.0.0.5", 50000, "203.0.113.7", 443)
K2 = ("10.0.0.5", 50001, "203.0.113.8", 3333)


class FakeEStats:
    def __init__(self, rows, enable_rc=0, readings=None):
        self._rows = rows                 # list of keys currently open
        self.enable_rc = enable_rc
        self.readings = readings or {}    # key -> (rc, flag, out, in)
        self.calls = []

    def rows(self):
        self.calls.append(("rows",))
        return [(k, ("row", k)) for k in self._rows]

    def set_collection(self, row, on):
        self.calls.append(("set", row[1], on))
        return self.enable_rc

    def read(self, row):
        self.calls.append(("read", row[1]))
        return self.readings.get(row[1], (0, 1, 100, 50))


def test_estats_unelevated_is_unavailable_and_touches_nothing():
    api = FakeEStats([K1])
    col = tcpstats.EStatsCollector(api=api, is_admin=False)
    assert not col.available and "Administrator" in col.error
    assert col.sample({K1}) == {}
    assert api.calls == []


def test_estats_enables_once_and_reads():
    api = FakeEStats([K1, K2])
    col = tcpstats.EStatsCollector(api=api, is_admin=True)
    assert col.sample({K1}) == {K1: (100, 50)}
    assert col.sample({K1}) == {K1: (100, 50)}
    enables = [c for c in api.calls if c[0] == "set"]
    assert enables == [("set", K1, True)]          # once, and only the target


def test_estats_refuses_garbage_when_collection_is_off():
    # The #14 spike: the read succeeds but EnableCollection is 0 and the
    # numbers are garbage. They must never reach the analyser.
    api = FakeEStats([K1], readings={K1: (0, 0, 12884901896, 98784247814)})
    col = tcpstats.EStatsCollector(api=api, is_admin=True)
    assert col.sample({K1}) == {}
    assert col.refused == 1
    col.sample({K1})                                 # re-enable is attempted
    assert [c for c in api.calls if c[0] == "set"] == [("set", K1, True)] * 2


def test_estats_failed_enable_is_not_read():
    api = FakeEStats([K1], enable_rc=5)              # ERROR_ACCESS_DENIED
    col = tcpstats.EStatsCollector(api=api, is_admin=True)
    assert col.sample({K1}) == {}
    assert not [c for c in api.calls if c[0] == "read"]


def test_estats_failed_read_is_refused():
    api = FakeEStats([K1], readings={K1: (87, 1, 5, 5)})
    col = tcpstats.EStatsCollector(api=api, is_admin=True)
    assert col.sample({K1}) == {}
    assert col.refused == 1


def test_estats_close_switches_collection_off_for_open_connections():
    api = FakeEStats([K1, K2])
    col = tcpstats.EStatsCollector(api=api, is_admin=True)
    col.sample({K1, K2})
    api._rows = [K2]                                 # K1 closed
    col.sample({K1, K2})
    col.close()
    offs = [c for c in api.calls if c[0] == "set" and c[2] is False]
    assert offs == [("set", K2, False)]


def test_estats_api_construction_failure_is_unavailable(monkeypatch):
    def boom():
        raise OSError("no iphlpapi")
    monkeypatch.setattr(tcpstats, "_WinEStatsApi", boom)
    col = tcpstats.EStatsCollector()
    assert not col.available and "no iphlpapi" in col.error


# -- Windows EStats against the REAL API (no admin needed for these) ------------

def _loopback_pair():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    cli = socket.create_connection(srv.getsockname())
    acc, _ = srv.accept()
    srv.close()
    return cli, acc


def _is_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


@pytest.mark.skipif(sys.platform != "win32", reason="Windows API")
def test_real_estats_unelevated_refuses_garbage():
    if _is_admin():
        pytest.skip("elevated: the refusal path needs an unelevated run")
    cli, acc = _loopback_pair()
    try:
        cli.sendall(b"x" * 1500)
        acc.recv(4096)
        lip, lport = cli.getsockname()
        rip, rport = cli.getpeername()
        key = tcpstats.conn_key(lip, lport, rip, rport)
        api = tcpstats._WinEStatsApi()
        rows = dict(api.rows())
        assert key in rows                          # the table read works unelevated
        assert api.set_collection(rows[key], True) == 5     # ERROR_ACCESS_DENIED
        rc, flag, _out, _in = api.read(rows[key])
        assert rc == 0 and flag == 0                # succeeds, but collection is off
        # Even told it is elevated, the collector drops that reading.
        col = tcpstats.EStatsCollector(api=api, is_admin=True)
        assert col.sample({key}) == {}
        # And honestly unelevated, it does not even try.
        assert not tcpstats.EStatsCollector(api=api).available
    finally:
        cli.close()
        acc.close()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows API")
def test_real_estats_elevated_counts_bytes():
    # The path this machine could not run. Left here so an elevated run of the
    # suite exercises it for real.
    if not _is_admin():
        pytest.skip("needs an elevated (Administrator) run")
    cli, acc = _loopback_pair()
    col = tcpstats.EStatsCollector()
    try:
        lip, lport = cli.getsockname()
        rip, rport = cli.getpeername()
        key = tcpstats.conn_key(lip, lport, rip, rport)
        assert col.available
        col.sample({key})                            # enables collection
        cli.sendall(b"x" * 1500)
        acc.recv(4096)
        time.sleep(0.2)
        got = col.sample({key})
        assert key in got and got[key][0] >= 1500
    finally:
        col.close()
        cli.close()
        acc.close()


# -- engine wiring --------------------------------------------------------------

class FakeCollector:
    mode = "fake"
    available = True
    error = ""

    def __init__(self):
        self.counters = {}
        self.closed = False

    def sample(self, targets):
        return {k: v for k, v in self.counters.items() if k in targets}

    def close(self):
        self.closed = True


def _feed_beat(e, col, key, seconds=900, period=60, t0=1_000_000.0):
    out = inn = 0
    for i in range(int(seconds / 5) + 1):
        t = i * 5.0
        if i and (t % period) < 5.0:
            out += 260
            inn += 90
        col.counters[key] = (out, inn)
        e.sample_cadence(now=t0 + t)


def test_engine_reports_a_beat_as_a_corroborating_signal():
    e = Engine(cfg=Config())
    col = FakeCollector()
    assert e.start_cadence(collector=col, thread=False)
    key = ("10.0.0.5", 50000, "203.0.113.7", 443)
    e._set_cadence_targets({4242: [key]})
    _feed_beat(e, col, key)
    info = ProcInfo(4242)
    info.name = "updater.exe"
    sigs = e._build_signals(info, [("203.0.113.7", 443)], time.time(), [key])
    cad = next(s for s in sigs if s.name == "cadence")
    assert cad.score == e.cfg.cadence_score
    assert "203.0.113.7:443" in cad.detail and "corroborating" in cad.detail
    e.close()


def test_engine_cadence_off_by_default_changes_nothing():
    e = Engine(cfg=Config())
    info = ProcInfo(4243)
    info.name = "app.exe"
    sigs = e._build_signals(info, [], time.time(), [K1])
    cad = next(s for s in sigs if s.name == "cadence")
    assert cad.score == 0 and "not observable" in cad.detail
    assert e.cadence_mode == "off"
    e._set_cadence_targets({4243: [K1]})            # no collector: no targets
    assert e._cadence_targets == set()


def test_engine_loopback_excluded_unless_configured():
    loop = ("127.0.0.1", 50000, "127.0.0.1", 3333)
    e = Engine(cfg=Config())
    e.start_cadence(collector=FakeCollector(), thread=False)
    e._set_cadence_targets({1: [loop, K1]})
    assert e._cadence_targets == {K1}
    e2 = Engine(cfg=Config(cadence_include_loopback=True))
    e2.start_cadence(collector=FakeCollector(), thread=False)
    e2._set_cadence_targets({1: [loop, K1]})
    assert e2._cadence_targets == {loop, K1}


def test_engine_target_cap_keeps_connections_with_history():
    e = Engine(cfg=Config(cadence_max_connections=1))
    col = FakeCollector()
    e.start_cadence(collector=col, thread=False)
    e._set_cadence_targets({1: [K2]})
    col.counters[K2] = (1, 1)
    e.sample_cadence(now=1.0)
    e._set_cadence_targets({1: [K1, K2]})
    assert e._cadence_targets == {K2}


def test_engine_drops_history_of_closed_connections_and_old_samples():
    e = Engine(cfg=Config(cadence_history_seconds=60))
    col = FakeCollector()
    e.start_cadence(collector=col, thread=False)
    e._set_cadence_targets({1: [K1, K2]})
    col.counters = {K1: (1, 1), K2: (1, 1)}
    for t in range(0, 200, 5):
        e.sample_cadence(now=float(t))
    assert e._cadence_hist[K1][0][0] >= 195 - 60
    del col.counters[K2]
    e.sample_cadence(now=205.0)
    assert K2 not in e._cadence_hist


def test_engine_unavailable_collector_is_reported():
    from minersentry.audit import AuditLog
    lines = []
    e = Engine(cfg=Config(), audit=AuditLog(on_event=lines.append))
    col = tcpstats.Unavailable("needs Administrator")
    assert not e.start_cadence(collector=col)
    assert e.cadence_mode == "unavailable: needs Administrator"
    assert lines == ["share-cadence watch unavailable: needs Administrator"]


def test_engine_disabled_by_config():
    e = Engine(cfg=Config(cadence_enabled=False))
    assert not e.start_cadence(collector=FakeCollector(), thread=False)
    assert e.cadence_mode == "off"


def test_beat_pids_are_memory_scanned():
    e = Engine(cfg=Config())
    e._cadence_beats = {9191}
    assert 9191 in e.deep_scan_targets()


def test_close_releases_the_collector_without_a_thread():
    e = Engine(cfg=Config())
    col = FakeCollector()
    e.start_cadence(collector=col, thread=False)
    e.close()
    assert col.closed


def test_sampler_thread_closes_the_collector_on_exit():
    e = Engine(cfg=Config(cadence_sample_interval=1.0))
    col = FakeCollector()
    assert e.start_cadence(collector=col)
    e.close()
    e._cadence_thread.join(5)
    assert col.closed


# -- end to end on real loopback traffic ----------------------------------------
# The collectors cannot run here (Windows, unelevated), so this validates the
# ANALYSER on real timing: a loopback client writes small "submissions" on a
# beat, its own byte counts are sampled on a separate thread, and the series
# goes through analyse(). Time is scaled by 1/100 (a 40 s beat becomes 0.4 s);
# the thresholds are scaled to match.

def _scaled_cfg(k=0.01):
    base = Config()
    return Config(
        cadence_min_window=base.cadence_min_window * k,
        cadence_min_interval=base.cadence_min_interval * k,
        cadence_max_interval=base.cadence_max_interval * k,
        cadence_max_gap=base.cadence_max_gap * k,
        cadence_max_in_rate=base.cadence_max_in_rate / k,
    )


def _run_loopback(writer, seconds=4.0, sample_every=0.05):
    cli, acc = _loopback_pair()
    counts = {"out": 0, "in": 0}
    stop = threading.Event()

    def server():
        acc.settimeout(0.2)
        while not stop.is_set():
            try:
                data = acc.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                return
            if not data:
                return
            acc.sendall(b"{\"result\":true}\n")      # small pool reply

    def reader():
        cli.settimeout(0.2)
        while not stop.is_set():
            try:
                data = cli.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                return
            if not data:
                return
            counts["in"] += len(data)

    threads = [threading.Thread(target=f, daemon=True) for f in (server, reader)]
    for t in threads:
        t.start()
    samples = []

    def sampler():
        while not stop.is_set():
            samples.append((time.monotonic(), counts["out"], counts["in"]))
            time.sleep(sample_every)

    st = threading.Thread(target=sampler, daemon=True)
    st.start()
    try:
        writer(cli, counts, time.monotonic() + seconds)
    finally:
        stop.set()
        st.join(2)
        cli.close()
        acc.close()
        for t in threads:
            t.join(2)
    return samples


def test_loopback_share_beat_is_detected():
    submit = (b'{"id":4,"method":"submit","params":{"id":"x","job_id":"y",'
              b'"nonce":"0a1b2c3d","result":"' + b"f" * 64 + b'"}}\n')

    def writer(sock, counts, until):
        while time.monotonic() < until:
            sock.sendall(submit)
            counts["out"] += len(submit)
            time.sleep(0.4)

    samples = _run_loopback(writer)
    r = cadence.analyse(samples, _scaled_cfg())
    assert r.beat, r


def test_loopback_bulk_upload_is_not_a_beat():
    chunk = b"z" * 8192

    def writer(sock, counts, until):
        while time.monotonic() < until:
            sock.sendall(chunk)
            counts["out"] += len(chunk)
            time.sleep(0.005)

    samples = _run_loopback(writer)
    r = cadence.analyse(samples, _scaled_cfg())
    assert not r.beat, r
