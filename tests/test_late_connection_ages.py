"""OS connection ages are used even when they arrive after the first pass (#68)."""

import time

from minersentry.config import Config
from minersentry.engine import Engine
from minersentry.scoring import score_network

PID, IP, PORT = 4242, "203.0.113.7", 3333


def test_an_age_that_arrives_late_still_makes_the_connection_long_lived():
    e = Engine(cfg=Config(pool_intel_enabled=False))
    try:
        now = time.time()
        first = score_network(e._pool_hits(PID, [(IP, PORT)], now), e.cfg)
        assert "port-only" in first.detail     # nothing known yet: fresh

        # the background sampler reports the connection is an hour old
        e._conn_ages = {(PID, IP, PORT): now - 3600}
        later = score_network(e._pool_hits(PID, [(IP, PORT)], now + 2.5), e.cfg)
        assert later.score == e.cfg.net_score_stratum_persisted, later.detail
    finally:
        e.close()


def test_a_younger_os_age_never_resets_what_we_already_watched():
    e = Engine(cfg=Config(pool_intel_enabled=False))
    try:
        now = time.time()
        e._pool_hits(PID, [(IP, PORT)], now - 100)
        e._conn_ages = {(PID, IP, PORT): now - 5}
        e._pool_hits(PID, [(IP, PORT)], now)
        assert e._conn_hist[(PID, IP, PORT)][0] == now - 100
    finally:
        e.close()
