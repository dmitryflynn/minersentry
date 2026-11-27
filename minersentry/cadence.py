"""Share-submission cadence: is one connection uploading small bursts on a beat?

A miner holds one long-lived connection to its pool and writes a small share
submission to it every so often, while reading little back. That shape survives
TLS and port 443, which is the point: it says something about a connection the
port-based network signal has nothing to say about.

It also describes plenty of honest software. A chat client's keepalive, a sync
agent's status ping and an IDE's telemetry beacon all write a few hundred bytes
on a timer. So this is a CORROBORATING signal only: it never enters the weighted
blend, and it convicts only beside something miner-specific (see the cadence
rules in `Config.conviction_rules`). What it does not catch is listed in the
README.

This module is pure: it takes a time series of cumulative byte counters for ONE
connection and returns a decision. The platform collectors that produce the
series live in `tcpstats`.

A note on "regular". Shares are found at random, so the gaps between
submissions are roughly exponential (coefficient of variation near 1) rather
than clockwork, and a timer heartbeat is the clockwork one. The test here is
therefore deliberately loose about jitter (`cadence_max_cv`) and strict about
the things both share submission and heartbeats have in common with a miner
and that bulk or interactive traffic does not: the uploads are small, they
keep coming, the gaps between them sit in the 30-120 s band, the connection is
quiet in between, and little comes back.
"""

from __future__ import annotations

from dataclasses import dataclass
import statistics


Sample = tuple[float, int, int]   # (timestamp, cumulative bytes out, cumulative bytes in)


@dataclass
class CadenceResult:
    beat: bool
    reason: str
    bursts: int = 0
    median_interval: float | None = None
    cv: float | None = None
    mean_burst_bytes: float | None = None
    in_rate: float | None = None          # bytes/s inbound over the analysed span
    span: float = 0.0                      # seconds covered by the samples
    resets: int = 0                        # counter decreases that were skipped

    def describe(self) -> str:
        if not self.beat:
            return self.reason
        return (f"small uploads about every {self.median_interval:.0f}s "
                f"({self.bursts} bursts of ~{self.mean_burst_bytes:.0f} B, "
                f"{self.in_rate:.0f} B/s inbound)")


def _clean(samples) -> list[Sample]:
    """Sort by time and drop samples that repeat or rewind a timestamp."""
    out: list[Sample] = []
    for t, o, i in sorted(samples, key=lambda s: s[0]):
        if out and t <= out[-1][0]:
            continue
        out.append((float(t), int(o), int(i)))
    return out


def analyse(samples, cfg) -> CadenceResult:
    """Decide whether `samples` show a regular small-upload beat.

    `samples` is an iterable of (timestamp, cumulative bytes_out, cumulative
    bytes_in) for one connection. Counters are cumulative, as both the Linux
    tcp_info and the Windows EStats counters are; a counter that goes DOWN is a
    reset (a reused socket, a re-enabled EStats collection, a wrap) and that one
    interval is skipped rather than read as a huge negative or positive burst.

    `cfg` supplies the cadence_* thresholds (a `Config`).
    """
    s = _clean(samples)
    if len(s) < cfg.cadence_min_samples:
        return CadenceResult(False, f"gathering samples ({len(s)} so far)")
    span = s[-1][0] - s[0][0]
    if span < cfg.cadence_min_window:
        return CadenceResult(False, f"gathering samples ({span:.0f}s of "
                                    f"{cfg.cadence_min_window:.0f}s)", span=span)

    # Per-interval deltas. A decrease in either counter is a reset: skip it.
    deltas: list[tuple[float, int, int]] = []   # (interval end time, d_out, d_in)
    resets = 0
    for (t0, o0, i0), (t1, o1, i1) in zip(s, s[1:]):
        d_out, d_in = o1 - o0, i1 - i0
        if d_out < 0 or d_in < 0:
            resets += 1
            continue
        deltas.append((t1, d_out, d_in))
    if not deltas:
        return CadenceResult(False, "no usable intervals (counters kept resetting)",
                             span=span, resets=resets)

    total_in = sum(d for _t, _o, d in deltas)
    in_rate = total_in / span
    active = [d for d in deltas if d[1] > 0]

    # Group consecutive active intervals into bursts: one submission can
    # straddle a sample boundary. Runs smaller than the minimum are pings
    # (WebSocket/MQTT keepalives are a handful of bytes) and are ignored.
    runs: list[tuple[float, int]] = []          # (burst time, bytes)
    cur_t, cur_b, prev_active = 0.0, 0, False
    for t, d_out, _d_in in deltas:
        if d_out > 0:
            if prev_active:
                cur_b += d_out
            else:
                cur_t, cur_b = t, d_out
            prev_active = True
        else:
            if prev_active:
                runs.append((cur_t, cur_b))
            prev_active = False
    if prev_active:
        runs.append((cur_t, cur_b))
    bursts = [(t, b) for t, b in runs if b >= cfg.cadence_burst_min_bytes]

    base = dict(bursts=len(bursts), in_rate=in_rate, span=span, resets=resets)
    # Busy, not beating: a stream or an interactive session writes in most
    # intervals. A beat leaves the connection quiet between submissions.
    if len(active) / len(deltas) > cfg.cadence_max_active_fraction:
        return CadenceResult(False, "uploads in most intervals (streaming, not a beat)",
                             **base)

    if not bursts:
        return CadenceResult(False, "no upload bursts", **base)
    mean_b = sum(b for _t, b in bursts) / len(bursts)
    base["mean_burst_bytes"] = mean_b
    if len(bursts) < cfg.cadence_min_bursts:
        return CadenceResult(False, f"too few upload bursts ({len(bursts)})", **base)

    small = sum(1 for _t, b in bursts if b <= cfg.cadence_burst_max_bytes)
    if small / len(bursts) < cfg.cadence_small_fraction:
        return CadenceResult(False, "uploads are not small", **base)

    if in_rate > cfg.cadence_max_in_rate:
        return CadenceResult(False, f"too much inbound ({in_rate:.0f} B/s)", **base)

    times = [t for t, _b in bursts]
    gaps = [b - a for a, b in zip(times, times[1:])]
    med = statistics.median(gaps)
    mean = statistics.fmean(gaps)
    cv = statistics.pstdev(gaps) / mean if mean > 0 else 0.0
    base.update(median_interval=med, cv=cv)
    if not cfg.cadence_min_interval <= med <= cfg.cadence_max_interval:
        return CadenceResult(False, f"uploads every ~{med:.0f}s (outside "
                                    f"{cfg.cadence_min_interval:.0f}-"
                                    f"{cfg.cadence_max_interval:.0f}s)", **base)
    if cv > cfg.cadence_max_cv:
        return CadenceResult(False, f"irregular uploads (cv {cv:.2f})", **base)
    # Sustained: no long silence inside the window, and still going now.
    longest = max(max(gaps), s[-1][0] - times[-1])
    if longest > cfg.cadence_max_gap:
        return CadenceResult(False, f"beat stopped for {longest:.0f}s", **base)
    return CadenceResult(True, "regular small-upload beat", **base)
