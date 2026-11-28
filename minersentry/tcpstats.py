"""Per-connection TCP byte counters, for the share-cadence signal.

Each collector returns cumulative (bytes_out, bytes_in) per connection, keyed by
the normalised 4-tuple `(local_ip, local_port, remote_ip, remote_port)`. The
engine already knows which PID owns which 4-tuple (psutil.net_connections), so
the collectors never have to attribute sockets to processes themselves.

Where the numbers come from, and why it is not simpler:

- psutil's per-process io_counters do not see socket traffic on Windows at all
  (measured in issue #14), so there is no portable route.
- **Linux**: tcp_info, read with `ss -tni`. `bytes_sent` needs kernel 4.19+;
  older kernels have `bytes_acked`, which is used instead (it trails by what is
  in flight, which does not matter for a beat measured in tens of seconds).
  `ss` lists every socket in the network namespace, but the engine can only
  attribute a socket to a process whose /proc/<pid>/fd it can read, so in
  practice an unprivileged run covers the user's own processes. Sockets in
  another network namespace (most containers) are not listed at all.
- **Windows**: `GetPerTcpConnectionEStats`. Collection must first be switched on
  per connection with `SetPerTcpConnectionEStats`, which needs Administrator;
  unelevated it fails with ERROR_ACCESS_DENIED, and a read on a connection that
  was never enabled still SUCCEEDS and returns garbage. So this collector only
  runs elevated, enables each tracked connection, and refuses any reading whose
  EnableCollection flag did not come back as 1. IPv4 only.

The elevated Windows path is UNTESTED on a real elevated machine: it was built
and unit-tested against a mocked API on an unelevated one. The unelevated
behaviour (access denied on enable, EnableCollection 0 on read) is exercised for
real in the tests.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys

ConnKey = tuple[str, int, str, int]


def norm_ip(ip: str) -> str:
    """One spelling per address, so ss, EStats and psutil keys compare equal:
    no brackets, no %scope, lower case, and IPv4-mapped IPv6 as plain IPv4."""
    ip = (ip or "").strip()
    if ip.startswith("[") and ip.endswith("]"):
        ip = ip[1:-1]
    ip = ip.split("%", 1)[0].lower()
    if ip.startswith("::ffff:") and "." in ip:
        ip = ip[7:]
    return ip


def conn_key(lip: str, lport: int, rip: str, rport: int) -> ConnKey:
    return (norm_ip(lip), int(lport), norm_ip(rip), int(rport))


def is_loopback(ip: str) -> bool:
    ip = norm_ip(ip)
    return ip.startswith("127.") or ip == "::1"


# -- Linux: ss -tni ----------------------------------------------------------

def _split_addr(token: str) -> tuple[str, int] | None:
    """'10.0.0.5:443', '[2001:db8::1]:443' or old-style '2001:db8::1:443'."""
    host, sep, port = token.rpartition(":")
    if not sep or not host or not port.isdecimal():
        return None
    return norm_ip(host), int(port)


def _info_value(fields: list[str], name: str) -> int | None:
    prefix = name + ":"
    for f in fields:
        if f.startswith(prefix):
            v = f[len(prefix):]
            return int(v) if v.isdecimal() else None
    return None


def parse_ss(text: str) -> dict[ConnKey, tuple[int, int]]:
    """Parse `ss -tni` output into {4-tuple: (bytes_out, bytes_in)}.

    ss prints one header line per socket followed by an indented tcp_info line.
    The header has a State column unless the command filtered to one state
    (`ss -tni state established` drops it), so the address columns are found
    after the two queue counters either way. A socket whose info line carries
    no byte counters (kernels before 4.1) is left out rather than guessed.
    """
    out: dict[ConnKey, tuple[int, int]] = {}
    cur: ConnKey | None = None
    for line in text.splitlines():
        if not line.strip():
            continue
        if line[0] in " \t":
            if cur is None:
                continue
            fields = line.split()
            sent = _info_value(fields, "bytes_sent")
            if sent is None:
                sent = _info_value(fields, "bytes_acked")
            recv = _info_value(fields, "bytes_received")
            if sent is not None and recv is not None:
                out[cur] = (sent, recv)
            cur = None
            continue
        cur = None
        toks = line.split()
        # Recv-Q and Send-Q are the first two numeric columns.
        off = 0 if toks[0].isdecimal() else 1
        if len(toks) < off + 4 or not (toks[off].isdecimal() and toks[off + 1].isdecimal()):
            continue          # the column header, or something unrecognised
        local, remote = _split_addr(toks[off + 2]), _split_addr(toks[off + 3])
        if local and remote:
            cur = (local[0], local[1], remote[0], remote[1])
    return out


class SsCollector:
    """tcp_info via `ss -tni state established` (Linux, unprivileged)."""

    mode = "ss tcp_info"

    def __init__(self, runner=None) -> None:
        self._runner = runner or self._run
        self.error = ""
        self.available = True
        if runner is None and not shutil.which("ss"):
            self.available = False
            self.error = "the ss command (iproute2) is not installed"

    @staticmethod
    def _run() -> str:
        env = dict(os.environ, LC_ALL="C")
        return subprocess.run(["ss", "-tni", "state", "established"],
                              capture_output=True, text=True, timeout=5,
                              env=env, check=False).stdout

    def sample(self, targets: set[ConnKey]) -> dict[ConnKey, tuple[int, int]]:
        if not self.available:
            return {}
        try:
            stats = parse_ss(self._runner())
        except (OSError, subprocess.SubprocessError, ValueError) as e:
            self.error = f"{type(e).__name__}: {e}"
            return {}
        return {k: v for k, v in stats.items() if k in targets}

    def close(self) -> None:
        pass


# -- Windows: GetPerTcpConnectionEStats --------------------------------------

class _WinEStatsApi:
    """Thin ctypes wrapper. Kept separate so the collector logic can be tested
    with a fake; nothing in here makes a decision."""

    TcpConnectionEstatsData = 1
    MIB_TCP_STATE_ESTAB = 5

    def __init__(self) -> None:
        import ctypes
        from ctypes import wintypes
        self._ct = ctypes
        DWORD, ULONG = wintypes.DWORD, wintypes.ULONG
        ULONG64 = ctypes.c_uint64

        class MIB_TCPROW(ctypes.Structure):
            _fields_ = [("dwState", DWORD), ("dwLocalAddr", DWORD),
                        ("dwLocalPort", DWORD), ("dwRemoteAddr", DWORD),
                        ("dwRemotePort", DWORD)]

        class MIB_TCPROW_OWNER_PID(ctypes.Structure):
            _fields_ = MIB_TCPROW._fields_ + [("dwOwningPid", DWORD)]

        class TCP_ESTATS_DATA_RW_v0(ctypes.Structure):
            _fields_ = [("EnableCollection", ctypes.c_ubyte)]

        class TCP_ESTATS_DATA_ROD_v0(ctypes.Structure):
            _fields_ = [("DataBytesOut", ULONG64), ("DataSegsOut", ULONG64),
                        ("DataBytesIn", ULONG64), ("DataSegsIn", ULONG64),
                        ("SegsOut", ULONG64), ("SegsIn", ULONG64),
                        ("SoftErrors", ULONG), ("SoftErrorReason", ULONG),
                        ("SndUna", ULONG), ("SndNxt", ULONG), ("SndMax", ULONG),
                        ("ThruBytesAcked", ULONG64), ("RcvNxt", ULONG),
                        ("ThruBytesReceived", ULONG64)]

        self.MIB_TCPROW = MIB_TCPROW
        self.MIB_TCPROW_OWNER_PID = MIB_TCPROW_OWNER_PID
        self.RW = TCP_ESTATS_DATA_RW_v0
        self.ROD = TCP_ESTATS_DATA_ROD_v0
        self._iphlp = ctypes.WinDLL("iphlpapi")

    @staticmethod
    def is_admin() -> bool:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:  # noqa: BLE001
            return False

    def rows(self) -> list[tuple[ConnKey, object]]:
        """ESTABLISHED IPv4 connections as (key, MIB_TCPROW)."""
        import socket
        import struct
        ct = self._ct
        size = ct.c_ulong(0)
        AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS = 2, 4
        get = self._iphlp.GetExtendedTcpTable
        buf = None
        for _ in range(4):
            buf = ct.create_string_buffer(max(size.value, 4))
            rc = get(buf, ct.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS, 0)
            if rc == 0:
                break
            if rc != 122:            # ERROR_INSUFFICIENT_BUFFER: grow and retry
                return []
        else:
            return []
        n = ct.c_ulong.from_buffer(buf).value
        row_t = self.MIB_TCPROW_OWNER_PID
        first = ct.sizeof(ct.c_ulong)
        out = []
        for i in range(n):
            r = row_t.from_buffer(buf, first + i * ct.sizeof(row_t))
            if r.dwState != self.MIB_TCP_STATE_ESTAB:
                continue
            row = self.MIB_TCPROW(r.dwState, r.dwLocalAddr, r.dwLocalPort,
                                  r.dwRemoteAddr, r.dwRemotePort)
            key = conn_key(socket.inet_ntoa(struct.pack("<I", r.dwLocalAddr)),
                           socket.ntohs(r.dwLocalPort & 0xFFFF),
                           socket.inet_ntoa(struct.pack("<I", r.dwRemoteAddr)),
                           socket.ntohs(r.dwRemotePort & 0xFFFF))
            out.append((key, row))
        return out

    def set_collection(self, row, on: bool) -> int:
        ct = self._ct
        rw = self.RW(1 if on else 0)
        return self._iphlp.SetPerTcpConnectionEStats(
            ct.byref(row), self.TcpConnectionEstatsData, ct.byref(rw), 0,
            ct.sizeof(rw), 0)

    def read(self, row) -> tuple[int, int, int, int]:
        """(return code, EnableCollection flag, bytes out, bytes in)."""
        ct = self._ct
        rw, rod = self.RW(0), self.ROD()
        rc = self._iphlp.GetPerTcpConnectionEStats(
            ct.byref(row), self.TcpConnectionEstatsData,
            ct.byref(rw), 0, ct.sizeof(rw),
            None, 0, 0,
            ct.byref(rod), 0, ct.sizeof(rod))
        return rc, int(rw.EnableCollection), int(rod.DataBytesOut), int(rod.DataBytesIn)


class EStatsCollector:
    """Per-connection byte counts from the Windows TCP stack (Administrator).

    UNTESTED on a real elevated machine. The logic is unit-tested with a fake
    API; the unelevated refusal is tested against the real API.

    Rules, in order:
    - Not elevated: unavailable, and nothing is enabled or read.
    - A tracked connection is enabled once. Only a successful enable is
      remembered; a failure is retried on the next sample.
    - A reading counts only if the call succeeded AND it reports
      EnableCollection == 1. Anything else is garbage by the spike in #14 and
      is dropped, and the connection is re-enabled next time.
    - close() switches collection back off on connections still open.
    """

    mode = "EStats (Administrator)"

    def __init__(self, api=None, is_admin=None) -> None:
        self.error = ""
        self.refused = 0          # readings dropped because collection was off
        self._enabled: dict[ConnKey, object] = {}
        try:
            self._api = api if api is not None else _WinEStatsApi()
        except Exception as e:  # noqa: BLE001 - no iphlpapi, not Windows
            self._api = None
            self.available = False
            self.error = f"EStats API unavailable: {type(e).__name__}: {e}"
            return
        admin = is_admin() if callable(is_admin) else (
            is_admin if is_admin is not None else _WinEStatsApi.is_admin())
        self.available = bool(admin)
        if not admin:
            self.error = ("needs Administrator: enabling per-connection TCP "
                          "statistics is refused unelevated")

    def sample(self, targets: set[ConnKey]) -> dict[ConnKey, tuple[int, int]]:
        if not self.available or self._api is None:
            return {}
        out: dict[ConnKey, tuple[int, int]] = {}
        try:
            rows = self._api.rows()
        except Exception as e:  # noqa: BLE001
            self.error = f"{type(e).__name__}: {e}"
            return {}
        live = set()
        for key, row in rows:
            live.add(key)
            if key not in targets:
                continue
            if key not in self._enabled:
                if self._api.set_collection(row, True) != 0:
                    continue
                self._enabled[key] = row
            rc, flag, bytes_out, bytes_in = self._api.read(row)
            if rc != 0 or flag != 1:
                self.refused += 1
                self._enabled.pop(key, None)
                continue
            out[key] = (bytes_out, bytes_in)
        # A connection that closed takes its collection state with it.
        for key in set(self._enabled) - live:
            self._enabled.pop(key, None)
        return out

    def close(self) -> None:
        if self._api is None:
            return
        for row in list(self._enabled.values()):
            try:
                self._api.set_collection(row, False)
            except Exception:  # noqa: BLE001
                pass
        self._enabled.clear()


class Unavailable:
    mode = "unavailable"
    available = False

    def __init__(self, error: str) -> None:
        self.error = error

    def sample(self, targets):
        return {}

    def close(self) -> None:
        pass


def make_collector():
    if sys.platform.startswith("linux"):
        return SsCollector()
    if sys.platform == "win32":
        return EStatsCollector()
    return Unavailable(f"no per-connection TCP counters on {sys.platform}")
