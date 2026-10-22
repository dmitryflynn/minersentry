"""BENIGN test target for MinerSentry — NOT a miner.

This does no mining and connects to nothing external. It only reproduces the
*behaviors* a CPU miner shows, so you can watch MinerSentry light up without
running real malware:

  1. sustained, steady CPU load on a worker thread (no bursty dips),
  2. miner-signature strings held in its own memory (stratum, xmrig, RandomX),
  3. optionally, it throttles when a process named taskmgr.exe appears, to
     exercise the evasion probe.

Run it in a second terminal:
    python samples/fake_miner.py            # steady load + memory markers
    python samples/fake_miner.py --evade    # also throttle under taskmgr.exe

Stop it with Ctrl+C or by terminating it from MinerSentry.
"""

import argparse
import os
import sys
import threading
import time

# Marker strings kept resident in memory on purpose. These are the exact kinds
# of tokens MinerSentry's memory scanner looks for. They are inert data.
_MARKERS = [
    b"stratum+tcp://pool.fake-test.invalid:3333",
    b"xmrig/6.21.0 RandomX rx/0",
    b'{"method":"login","params":{"login":"TEST","agent":"xmrig"}}',
    b'{"method":"submit","params":{"job_id":"deadbeef"}}',
    b"cryptonight supportxmr donate.ssl",
]
# Hold references so the bytes stay committed in the process address space.
_RESIDENT = [m * 64 for m in _MARKERS]

_throttle = threading.Event()


def _is_taskmgr_open() -> bool:
    try:
        import psutil
    except ImportError:
        return False
    for p in psutil.process_iter(["name"]):
        try:
            if (p.info["name"] or "").lower() == "taskmgr.exe" and p.pid != 0:
                return True
        except Exception:
            pass
    return False


def _evasion_watch():
    while True:
        _throttle.set() if _is_taskmgr_open() else _throttle.clear()
        time.sleep(0.4)


def _burn(evade: bool, cap: float = 0.0):
    """cap: target fraction (0..1) of one core; 0 = full. Mimics a CPU-capped
    miner that holds a steady but sub-threshold load via a busy/sleep duty cycle."""
    x = 1.000001
    chunk = 50_000
    while True:
        if evade and _throttle.is_set():
            # Classic evasion: go quiet while a monitor is open.
            time.sleep(0.25)
            continue
        t0 = time.perf_counter()
        # Tight FP loop -> CPU work on this core.
        for _ in range(chunk):
            x = (x * 1.0000001) % 97.0 + 1.0
        if 0.0 < cap < 1.0:
            # Sleep so busy/(busy+sleep) averages to `cap` of one core.
            busy = time.perf_counter() - t0
            time.sleep(busy * (1.0 - cap) / cap)


def _net_pool_sim(port: int):
    """Hold a long-lived ESTABLISHED connection to a stratum-typical port, all on
    localhost (no external traffic). Exercises the network + persistence signals."""
    import socket
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("127.0.0.1", port))
    except OSError:
        print(f"[fake_miner] could not bind 127.0.0.1:{port} (in use?) — skipping --net")
        return
    srv.listen(1)
    srv.settimeout(5.0)
    try:
        cli = socket.create_connection(("127.0.0.1", port), timeout=5.0)
        conn, _ = srv.accept()
    except OSError as e:
        print(f"[fake_miner] --net connect failed ({e}); skipping")
        srv.close()
        return
    print(f"[fake_miner] holding ESTABLISHED 127.0.0.1:{port} (benign, localhost)")
    while True:  # keep it alive, trickle a byte occasionally
        try:
            cli.sendall(b".")
            conn.recv(16)
        except OSError:
            break
        time.sleep(5)


def _reexec_unsigned():
    """Re-launch this target under a signature-invalidated copy of the Python
    interpreter, so the running process reads as UNTRUSTED — a faithful stand-in
    for a real (unsigned) miner. Without this the target runs under signed
    python.exe, which MinerSentry correctly trusts and dampens. The copy lives in
    a temp dir and is deleted on exit (fully reversible); appending one byte
    invalidates the embedded Authenticode signature while the copy still runs."""
    import shutil
    import subprocess
    import tempfile
    d = tempfile.mkdtemp(prefix="msentry_target_")
    exe = os.path.join(d, "msentry_target.exe")
    try:
        shutil.copy2(sys.executable, exe)
        with open(exe, "ab") as f:
            f.write(b"\x00")
        env = dict(os.environ, MSENTRY_TARGET_CHILD="1")
        args = [exe] + [a for a in sys.argv if a != "--unsigned"]
        print(f"[fake_miner] re-exec under unsigned target {exe}")
        subprocess.run(args, env=env)
    finally:
        shutil.rmtree(d, ignore_errors=True)
    raise SystemExit(0)


def _memory_hard(evade: bool, cap: float, dataset: bytearray):
    """Benign RandomX-style worker: random-access reads + writes across a large
    dataset, hashed with the stdlib. Reproduces a Monero miner's RUNTIME
    fingerprint (steady core load + a ~GB working set touched randomly, i.e. the
    cache-miss / memory-hard pattern) without computing a single valid share or
    contacting anything. The dataset is plain RAM, freed the instant the process
    exits — nothing is written to disk, registry, or anywhere persistent."""
    import hashlib
    n = len(dataset)
    acc = b"\x00" * 32
    while True:
        if evade and _throttle.is_set():
            time.sleep(0.25)
            continue
        t0 = time.perf_counter()
        for _ in range(2000):
            off = int.from_bytes(acc[:4], "little") % max(1, n - 64)
            acc = hashlib.blake2b(acc + bytes(dataset[off:off + 64]), digest_size=32).digest()
            dataset[off:off + 32] = acc  # write back -> truly memory-hard
        if 0.0 < cap < 1.0:
            busy = time.perf_counter() - t0
            time.sleep(busy * (1.0 - cap) / cap)


def main():
    ap = argparse.ArgumentParser(description="Benign MinerSentry test target (NOT a miner).")
    ap.add_argument("--evade", action="store_true",
                    help="throttle when a taskmgr.exe process appears")
    ap.add_argument("--threads", type=int, default=1, help="worker threads")
    ap.add_argument("--net", action="store_true",
                    help="hold a long-lived connection to a stratum-typical port (localhost)")
    ap.add_argument("--net-port", type=int, default=3333, help="pool-typical port for --net")
    ap.add_argument("--cap", type=float, default=0.0,
                    help="throttle each worker to this %% of one core (mimics a CPU-capped miner)")
    ap.add_argument("--dataset", type=int, default=0, metavar="MB",
                    help="allocate an MB RAM dataset and do memory-hard hashing over it "
                         "(use ~2048 to exercise the RandomX ~2 GiB dataset signal)")
    ap.add_argument("--unsigned", action="store_true",
                    help="run under a signature-stripped interpreter copy so the target "
                         "is UNTRUSTED like a real miner (else signed python is dampened)")
    args = ap.parse_args()

    if args.unsigned and os.environ.get("MSENTRY_TARGET_CHILD") != "1":
        _reexec_unsigned()

    cap = max(0.0, min(1.0, args.cap / 100.0)) if args.cap else 0.0
    print("[fake_miner] BENIGN test target running. This does not mine anything.")
    print(f"[fake_miner] threads={args.threads} evade={args.evade} net={args.net} "
          f"cap={args.cap or 'none'} dataset={args.dataset or 'none'}MB  (Ctrl+C to stop)")
    print(f"[fake_miner] {len(_RESIDENT)} miner-signature strings resident in memory.")

    dataset = None
    if args.dataset > 0:
        nbytes = args.dataset * 1024 * 1024
        print(f"[fake_miner] allocating {args.dataset} MB dataset (RAM only, freed on exit)…")
        dataset = bytearray(nbytes)
        for i in range(0, nbytes, 4096):  # touch every page so it is committed
            dataset[i] = 1

    if args.evade:
        threading.Thread(target=_evasion_watch, daemon=True).start()
    if args.net:
        threading.Thread(target=_net_pool_sim, args=(args.net_port,), daemon=True).start()

    for _ in range(max(1, args.threads)):
        if dataset is not None:
            threading.Thread(target=_memory_hard, args=(args.evade, cap, dataset),
                             daemon=True).start()
        else:
            threading.Thread(target=_burn, args=(args.evade, cap), daemon=True).start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[fake_miner] stopped.")
        sys.exit(0)


if __name__ == "__main__":
    main()
