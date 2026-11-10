"""Command-line indicators of mining.

A miner can rename its binary and strip its strings, but it still has to be
told *where to send the money*. In practice that happens on the command line:
a pool URL, a wallet, an algorithm, and the pool-specific flags a miner needs
(`--donate-level`, `--randomx-1gb-pages`, `--nicehash`). Those arguments are
readable for any process of the same user at ~0.1 ms each, which makes this the
cheapest miner-specific evidence available — and it works on a process that is
sitting idle, before it ever burns a core.

Two rules keep this from becoming a false-positive machine:

- **Generic arguments can never convict.** Ordinary software is full of `-o`,
  `-u`, `-p`, `-t`, `--tls`. Those are weighted low and capped below the
  hard-evidence line (exactly like the generic memory markers), so only
  miner-specific indicators — a stratum URL, a known pool host, a miner-only
  flag, a wallet next to a pool endpoint — can push the signal high.
- **Nothing sensitive is retained.** Only short labels for what matched are
  kept, never the command line itself. A wallet address, a password or a
  `-u` value is matched and then discarded; the label just says one was there.
  Pool endpoints are the exception: the host:port is the actionable part, is
  infrastructure rather than personal data, and is what the user needs in
  order to block it.

Everything here is pure (text in, labels out), so it is unit-tested directly.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from . import poolintel

MAX_CHARS = 16 * 1024   # bound regex work; the longest real cmdline seen was ~10 KiB


@dataclass(frozen=True)
class CmdHit:
    label: str
    weight: int
    specific: bool   # miner-specific (can convict) vs. generic (capped)


# Ceiling for a score built only from generic indicators. Kept below
# Config.hard_cmdline so generic flags alone can never be hard evidence.
GENERIC_SCORE_CAP = 30

# -- miner-specific ---------------------------------------------------------
_STRATUM_RE = re.compile(r"\bstratum[0-9]*\+(?:tcp|ssl|tcps)://([^\s\"']+)", re.I)

# Flags that essentially only exist in mining software.
_MINER_FLAGS = {
    "--donate-level": 45, "--donate-over-proxy": 45,
    "--randomx-1gb-pages": 45, "--randomx-wrmsr": 45, "--randomx-no-rdmsr": 45,
    "--randomx-mode": 40, "--randomx-init": 40, "--randomx-no-numa": 40,
    "--huge-pages-jit": 35, "--hugepage-size": 30,
    "--nicehash": 40, "--coin": 35, "--rig-id": 30, "--cpu-max-threads-hint": 35,
    "--cpu-priority": 25, "--max-cpu-usage": 30, "--cpu-affinity": 25,
    "--cuda-devices": 30, "--opencl-devices": 30, "--cuda-bfactor": 35,
    "--cuda-loader": 30, "--opencl-loader": 30, "--opencl-platform": 30,
    "--dag-mode": 35, "--eth-stratum": 40, "--ethstratum": 40,
    "--dual-mode": 35, "--lhr": 35, "--mt": 25, "--pec": 25,
    "--no-watchdog": 25, "--daemon-rpc-port": 35, "--self-select": 35,
    "--submit-stale": 30, "--worker-name": 25, "--no-cpu": 25,
}

# Algorithms, matched only as the value of an algo/coin flag or as a bare token.
_ALGOS = {
    "rx/0", "rx/wow", "rx/arq", "rx/graft", "rx/sfx", "rx/keva", "randomx",
    "cn/r", "cn/0", "cn/1", "cn/2", "cn/fast", "cn/half", "cn/rwz", "cn/zls",
    "cn/double", "cn-heavy", "cn-lite", "cn-pico", "cryptonight",
    "cryptonight-r", "cryptonight-lite", "cryptonight-heavy", "cryptonight-pico",
    "argon2/chukwa", "argon2/chukwav2", "argon2/ninja", "astrobwt",
    "kawpow", "ethash", "etchash", "autolykos2", "autolykos", "zelhash",
    "beamv3", "equihash", "octopus", "verushash", "ghostrider", "gr",
    "flex", "yespower", "yescrypt", "progpow", "firopow", "sha256d",
    "scrypt", "x16r", "x16rv3", "blake3", "ironfish", "zksnark",
}
_ALGO_FLAGS = ("-a", "--algo", "--algorithm", "--coin", "--currency")

# Wallet shapes. Monero's is near-unmistakable; the others are weaker, so they
# only carry weight next to a pool endpoint (see `_pair_bonus`).
_WALLETS = (
    ("Monero wallet address in arguments", 45, True,
     re.compile(r"\b[48][1-9A-HJ-NP-Za-km-z]{94}(?:[1-9A-HJ-NP-Za-km-z]{11})?\b")),
    ("Bitcoin bech32 address in arguments", 20, False,
     re.compile(r"\bbc1[a-z0-9]{25,62}\b")),
    ("Ethereum-style address in arguments", 15, False,
     re.compile(r"\b0x[a-fA-F0-9]{40}\b")),
    ("pool worker spec in arguments (COIN:address.worker)", 25, False,
     re.compile(r"\b[A-Z]{3,5}:[1-9A-HJ-NP-Za-km-z]{20,}\.[\w-]{1,20}\b")),
)

# -- generic (capped) -------------------------------------------------------
# Short flags every CLI tool uses. Meaningless alone; they only ever add up to
# the generic cap, and exist so a miner using only short flags still corroborates.
_GENERIC_FLAGS = {
    "-o": 8, "--url": 10, "--pool": 12, "-u": 6, "--user": 6, "--username": 6,
    "-p": 4, "--pass": 6, "--password": 6, "-k": 6, "--keepalive": 8,
    "--tls": 6, "--tls-fingerprint": 10, "-t": 4, "--threads": 6,
    "--background": 8, "--no-color": 4, "--print-time": 6, "--retries": 4,
    "--retry-pause": 6, "--api-port": 6, "--http-port": 6, "--config": 4,
}
# Launchers hiding what they run. Not mining-specific (an admin script looks the
# same), so capped — but a real tell when it sits next to compute.
_OBFUSCATION = (
    ("hidden-window PowerShell launch", 12, re.compile(r"-w(?:indowstyle)?\s+hidden", re.I)),
    ("base64-encoded PowerShell command", 14, re.compile(r"-e(?:nc|ncodedcommand)\b", re.I)),
    ("in-memory script execution", 14,
     re.compile(r"\b(?:iex|invoke-expression|frombase64string|downloadstring|downloadfile)\b", re.I)),
    ("script piped from the network into a shell", 14,
     re.compile(r"\b(?:curl|wget)\b[^|]{0,200}\|\s*(?:ba|z|d|)?sh\b", re.I)),
    ("execution from a temp/shared-memory path", 10,
     re.compile(r"(?:/tmp/|/dev/shm/|\\temp\\|\\appdata\\local\\temp\\)", re.I)),
)


def _tokens(argv: list[str] | str) -> list[str]:
    text = " ".join(argv) if isinstance(argv, (list, tuple)) else (argv or "")
    return text[:MAX_CHARS].split()


def _flag_name(token: str) -> str:
    """`--algo=rx/0` -> `--algo`; `-t4` -> `-t`."""
    name = token.split("=", 1)[0]
    if name.startswith("--"):
        return name.lower()
    if len(name) > 2 and name[0] == "-" and name[1] != "-":
        return name[:2].lower()
    return name.lower()


def _flag_value(token: str, nxt: str | None) -> str:
    if "=" in token:
        return token.split("=", 1)[1]
    name = token.split("=", 1)[0]
    if len(name) > 2 and name[0] == "-" and name[1] != "-":
        return name[2:]
    return nxt or ""


def _endpoints(tokens: list[str], cfg) -> list[tuple[str, bool]]:
    """(host:port, is_pool_port) for `host:port` arguments that look like an
    endpoint. Used to decide whether a weak wallet/flag hit is really mining."""
    out = []
    for tok in tokens:
        m = re.fullmatch(r"(?:[a-z0-9]+://)?([A-Za-z0-9._-]+\.[A-Za-z]{2,}|\d{1,3}(?:\.\d{1,3}){3})"
                         r":(\d{1,5})(?:/.*)?", tok.strip("\"'"))
        if not m:
            continue
        host, port = m.group(1), int(m.group(2))
        if 0 < port < 65536:
            out.append((f"{host}:{port}", port in getattr(cfg, "pool_ports", frozenset())))
    return out


def indicators(argv: list[str] | str, cfg) -> list[CmdHit]:
    """Mining indicators in a command line, as labels only.

    The command line itself is never returned or stored: wallet addresses,
    passwords and `-u` values are matched and discarded.
    """
    tokens = _tokens(argv)
    if not tokens:
        return []
    text = " ".join(tokens)
    low = text.lower()
    hits: list[CmdHit] = []
    seen: set[str] = set()

    def add(label: str, weight: int, specific: bool) -> None:
        if label not in seen:
            seen.add(label)
            hits.append(CmdHit(label, weight, specific))

    # stratum:// URLs — nothing but a miner speaks stratum
    for host in _STRATUM_RE.findall(text):
        add(f"stratum URL in arguments ({host.strip('/')[:60]})", 60, True)

    # a known mining pool as a hostname anywhere in the arguments
    for tok in tokens:
        bare = tok.strip("\"'")
        if "=" in bare:                      # --url=host:port -> host:port
            bare = bare.split("=", 1)[1]
        if bare.startswith("-"):             # a flag, not a host (--randomx-... )
            continue
        bare = re.sub(r"^[a-z0-9]+://", "", bare, flags=re.I).split("/")[0]
        host = bare.rsplit(":", 1)[0] if ":" in bare else bare
        # Only real hostname/IP shapes, so a flag name can't be reported as a pool.
        if not re.fullmatch(r"[A-Za-z0-9._-]+\.[A-Za-z0-9-]{2,}|\d{1,3}(?:\.\d{1,3}){3}", host):
            continue
        if poolintel.is_pool_hostname(host):
            add(f"known mining pool in arguments ({host[:60]})", 60, True)

    endpoints = _endpoints(tokens, cfg)
    pool_endpoint = next((e for e, is_pool in endpoints if is_pool), None)
    if pool_endpoint:
        add(f"pool-port endpoint in arguments ({pool_endpoint[:60]})", 35, False)

    # flags
    for i, tok in enumerate(tokens):
        name = _flag_name(tok)
        nxt = tokens[i + 1] if i + 1 < len(tokens) else None
        if name in _MINER_FLAGS:
            add(f"miner-only flag {name}", _MINER_FLAGS[name], True)
        elif name in _GENERIC_FLAGS:
            add(f"generic flag {name}", _GENERIC_FLAGS[name], False)
        if name in _ALGO_FLAGS:
            val = _flag_value(tok, nxt).strip("\"'").lower()
            if val in _ALGOS:
                add(f"mining algorithm requested ({val})", 50, True)

    # a bare algorithm token (e.g. `miner rx/0 ...`)
    for tok in tokens:
        t = tok.strip("\"'").lower()
        if t in _ALGOS and "/" in t:      # only the distinctive slashed forms
            add(f"mining algorithm in arguments ({t})", 40, True)

    # wallets — the address itself is dropped, only the label is kept
    for label, weight, specific, rx in _WALLETS:
        if rx.search(text):
            add(label, weight, specific)

    for label, weight, rx in _OBFUSCATION:
        if rx.search(low):
            add(label, weight, False)

    return hits


def score_of(hits: list[CmdHit], generic_cap: int = GENERIC_SCORE_CAP) -> int:
    """Summed weight, capped at `generic_cap` when nothing miner-specific matched."""
    total = sum(h.weight for h in hits)
    specific = any(h.specific for h in hits)
    return min(100 if specific else generic_cap, total)


def labels(hits: list[CmdHit], limit: int = 4) -> list[str]:
    """Most telling labels first (specific before generic, heaviest first)."""
    return [h.label for h in sorted(hits, key=lambda h: (not h.specific, -h.weight))][:limit]
