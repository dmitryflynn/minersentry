"""Background monitoring: a headless watcher, alerts, and install/uninstall.

Until now MinerSentry only protected you while its window was open, and only
saw what the logged-in user can see. Two consequences, both found by attacking
it: close the window and detection stops, and a miner running as SYSTEM or as
another user hands over neither its memory nor its arguments, so it is judged
on CPU shape alone (170 of 352 processes on one desktop were unreadable
unelevated).

This module fixes both by running the engine continuously, and by installing it
to start at boot as SYSTEM (Windows) or root (Linux) — which is also the only
honest form of self-protection available: a miner running as the user cannot
kill a SYSTEM service, while a user-level watchdog it can kill is theatre.

No new dependencies. Installation drives `schtasks` on Windows and writes a
systemd unit on Linux; alerting prefers a Windows toast, falls back to `msg`,
and always records to the detection log.
"""

from __future__ import annotations

import argparse
import ctypes
import os
import shlex
import subprocess
import sys
import time

from . import persistence as persist_mod
from . import tray as tray_mod
from .audit import AuditLog
from .config import Config
from .engine import Engine
from . import gpu as gpu_mod

TASK_NAME = "MinerSentry"
SYSTEMD_UNIT = "minersentry.service"


# -- alerting ---------------------------------------------------------------
def _toast_script(title: str, body: str) -> str:
    """PowerShell that raises a Windows toast. Pure, so it is unit-tested."""
    # Single-quoted PowerShell strings: ' is escaped by doubling it.
    t = title.replace("'", "''")
    b = body.replace("'", "''")
    return (
        "[void][Windows.UI.Notifications.ToastNotificationManager,"
        "Windows.UI.Notifications,ContentType=WindowsRuntime];"
        "$x=[Windows.UI.Notifications.ToastNotificationManager]::"
        "GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02);"
        "$n=$x.GetElementsByTagName('text');"
        f"$n[0].AppendChild($x.CreateTextNode('{t}'))|Out-Null;"
        f"$n[1].AppendChild($x.CreateTextNode('{b}'))|Out-Null;"
        "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("
        "'Microsoft.WindowsPowerShell').Show("
        "[Windows.UI.Notifications.ToastNotification]::new($x))"
    )


def notify(title: str, body: str, cfg: Config | None = None) -> str:
    """Raise a desktop alert, best effort. Returns which channel was used.

    A detection is always in the log already; this is the part that reaches
    someone who is not looking at the log.
    """
    cfg = cfg or Config()
    cmd = (cfg.notify_command or "").strip()
    if cmd:
        try:
            subprocess.run(shlex.split(cmd) + [title, body], timeout=15,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return "command"
        except Exception:  # noqa: BLE001 - alerting must never break monitoring
            pass
    if sys.platform == "win32":
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive",
                                "-Command", _toast_script(title, body)],
                               timeout=20, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, creationflags=flags)
            if r.returncode == 0:
                return "toast"
        except Exception:  # noqa: BLE001
            pass
        try:
            subprocess.run(["msg", "*", f"{title}: {body}"], timeout=15,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           creationflags=flags)
            return "msg"
        except Exception:  # noqa: BLE001
            pass
    else:
        for args in (["notify-send", title, body],
                     ["wall", f"{title}: {body}"]):
            try:
                subprocess.run(args, timeout=15, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
                return args[0]
            except Exception:  # noqa: BLE001
                continue
    return "log-only"


# -- the watcher ------------------------------------------------------------
def is_elevated() -> bool:
    if sys.platform == "win32":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:  # noqa: BLE001
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def should_alert(verdict: str, min_verdict: str) -> bool:
    """Is `verdict` at least as serious as `min_verdict`? Pure."""
    rank = {"Clean": 0, "Suspicious": 1, "Likely Miner": 2}
    return rank.get(verdict, 0) >= rank.get(min_verdict, 2) > 0


def run(cfg: Config | None = None, once: bool = False,
        alert: bool = True, audit: AuditLog | None = None, icon=None) -> int:
    """Monitor until stopped. Returns the number of alerts raised."""
    cfg = cfg or Config.load()
    log = audit or AuditLog()
    engine = Engine(cfg=cfg, audit=log)
    engine.start_pool_intel()
    engine.start_connection_ages()
    for w in cfg.load_warnings:
        log.event("config: " + w)
    if not is_elevated():
        log.event("not elevated: memory and arguments of other users' processes "
                  "are unreadable, so those are judged on behaviour alone")
    alerted: dict[int, str] = {}
    seen_autostart: set[str] = set()
    alerts = 0
    next_deep = 0.0
    next_gpu = 0.0
    next_persist = 0.0
    next_tamper = 0.0            # check on the first pass: no blind window
    installed_at_start = status().startswith("installed")
    while True:
        now = time.time()
        if cfg.gpu_enabled and now >= next_gpu:
            try:
                util, windows, ctxs = gpu_mod.sample()
                engine.set_gpu_util(util, windows, ctxs)
            except Exception as e:  # noqa: BLE001
                log.event(f"gpu sampler: {type(e).__name__}: {e}")
            next_gpu = now + max(2.0, cfg.gpu_sample_interval)
        if cfg.persistence_enabled and cfg.persistence_interval > 0 and now >= next_persist:
            next_persist = now + cfg.persistence_interval
            try:
                current = set()
                for e in persist_mod.scan(cfg):
                    key = f"{e.kind}:{e.location}:{e.name}"
                    current.add(key)
                    if key in seen_autostart:
                        continue
                    seen_autostart.add(key)
                    alerts += 1
                    log.record_detection(pid=0, name=e.name, exe=e.exe, score=e.score,
                                         verdict="Autostart", signals=[
                                             (e.kind, e.score, "; ".join(e.labels[:3]))])
                    if alert:
                        notify("MinerSentry: miner-like autostart entry",
                               f"{e.summary} (score {e.score}/100)", cfg)
                # Forget entries that are gone, so one that is RE-CREATED
                # alerts again. A miner that rewrites its Run key after you
                # delete it is exactly what a watcher should keep saying.
                seen_autostart &= current
            except Exception as e:  # noqa: BLE001
                log.event(f"autostart scan: {type(e).__name__}: {e}")
        # Tamper check: if our own autostart entry disappears while we are
        # running, something removed it. Say so instead of dying quietly.
        if installed_at_start and cfg.tamper_check_interval > 0 and now >= next_tamper:
            next_tamper = now + cfg.tamper_check_interval
            if not status().startswith("installed"):
                installed_at_start = False
                log.event("tamper: MinerSentry's autostart entry was removed while running")
                if alert:
                    notify("MinerSentry: autostart entry removed",
                           "Something deleted the scheduled task / unit that starts "
                           "MinerSentry at boot. Reinstall with --install.", cfg)
        deep = cfg.deep_auto_interval > 0 and now >= next_deep
        if deep:
            next_deep = now + cfg.deep_auto_interval
        try:
            results = engine.scan_once(deep=deep)
        except Exception as e:  # noqa: BLE001 - a bad pass must not end the watch
            log.event(f"scan error: {type(e).__name__}: {e}")
            results = []
        for r in results:
            if not should_alert(r.verdict, cfg.notify_min_verdict):
                continue
            if alerted.get(r.pid) == r.verdict:
                continue           # already told them about this process
            alerted[r.pid] = r.verdict
            alerts += 1
            if alert:
                title = f"MinerSentry: {r.verdict}"
                body = f"{r.name} (pid {r.pid}) scored {r.score}/100 — {r.signal_summary}"
                if not (icon and icon.notify(title, body)):
                    notify(title, body, cfg)
        live = {r.pid for r in results}
        for pid in [p for p in alerted if p not in live]:
            alerted.pop(pid, None)
        if once:
            return alerts
        time.sleep(max(0.5, cfg.scan_interval))


# -- installation -----------------------------------------------------------
def _run_target() -> list[str]:
    """How to start the watcher again, as an argv list."""
    if getattr(sys, "frozen", False):
        return [sys.executable, "--service"]
    return [sys.executable, "-m", "minersentry.service", "--run"]


def schtasks_create_args(task: str = TASK_NAME) -> list[str]:
    """The schtasks command used to install. Pure, so it is unit-tested."""
    target = " ".join(f'"{a}"' if " " in a else a for a in _run_target())
    return ["schtasks", "/create", "/tn", task, "/tr", target,
            "/sc", "onstart", "/ru", "SYSTEM", "/rl", "HIGHEST", "/f"]


def systemd_unit(exec_start: str | None = None) -> str:
    """The systemd unit written on Linux. Pure, so it is unit-tested."""
    target = exec_start or " ".join(_run_target())
    return (
        "[Unit]\n"
        "Description=MinerSentry behavioral cryptominer detector\n"
        "After=network.target\n\n"
        "[Service]\n"
        "Type=simple\n"
        f"ExecStart={target}\n"
        "Restart=always\n"
        "RestartSec=10\n"
        "User=root\n\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )


def install() -> tuple[bool, str]:
    """Install the watcher to start at boot with full privileges."""
    if not is_elevated():
        return False, ("Installing the background service needs Administrator "
                       "(Windows) or root (Linux): it runs as SYSTEM/root so a "
                       "miner running as you cannot stop it, and so it can read "
                       "other users' processes.")
    if sys.platform == "win32":
        try:
            r = subprocess.run(schtasks_create_args(), capture_output=True, text=True,
                               timeout=30)
        except Exception as e:  # noqa: BLE001
            return False, f"schtasks failed: {type(e).__name__}: {e}"
        if r.returncode != 0:
            return False, f"schtasks failed: {(r.stderr or r.stdout).strip()[:300]}"
        return True, (f"Installed scheduled task '{TASK_NAME}' (runs as SYSTEM at "
                      f"startup). Start it now with: schtasks /run /tn {TASK_NAME}")
    path = os.path.join("/etc/systemd/system", SYSTEMD_UNIT)
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(systemd_unit())
    except OSError as e:
        return False, f"could not write {path}: {e}"
    return True, (f"Wrote {path}. Enable it with: systemctl daemon-reload && "
                  f"systemctl enable --now {SYSTEMD_UNIT}")


def uninstall() -> tuple[bool, str]:
    if not is_elevated():
        return False, "Removing the background service needs Administrator / root."
    if sys.platform == "win32":
        try:
            r = subprocess.run(["schtasks", "/delete", "/tn", TASK_NAME, "/f"],
                               capture_output=True, text=True, timeout=30)
        except Exception as e:  # noqa: BLE001
            return False, f"schtasks failed: {type(e).__name__}: {e}"
        if r.returncode != 0:
            return False, f"schtasks failed: {(r.stderr or r.stdout).strip()[:300]}"
        return True, f"Removed scheduled task '{TASK_NAME}'."
    path = os.path.join("/etc/systemd/system", SYSTEMD_UNIT)
    try:
        subprocess.run(["systemctl", "disable", "--now", SYSTEMD_UNIT],
                       capture_output=True, timeout=30)
    except Exception:  # noqa: BLE001
        pass
    try:
        os.remove(path)
    except FileNotFoundError:
        return True, "Nothing installed."
    except OSError as e:
        return False, f"could not remove {path}: {e}"
    return True, f"Removed {path}."


def status() -> str:
    if sys.platform == "win32":
        try:
            r = subprocess.run(["schtasks", "/query", "/tn", TASK_NAME],
                               capture_output=True, text=True, timeout=20)
            return ("installed" if r.returncode == 0 else "not installed") + \
                (f" (elevated={is_elevated()})")
        except Exception as e:  # noqa: BLE001
            return f"unknown: {type(e).__name__}: {e}"
    return ("installed" if os.path.exists(os.path.join("/etc/systemd/system", SYSTEMD_UNIT))
            else "not installed") + f" (root={is_elevated()})"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="MinerSentry background monitoring (install, remove, or run).")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--run", action="store_true", help="monitor in the foreground")
    g.add_argument("--install", action="store_true",
                   help="start at boot as SYSTEM/root (needs admin)")
    g.add_argument("--uninstall", action="store_true", help="remove it (needs admin)")
    g.add_argument("--status", action="store_true", help="is it installed?")
    ap.add_argument("--no-alerts", action="store_true", help="log detections only")
    ap.add_argument("--no-tray", action="store_true", help="run without a tray icon")
    ap.add_argument("--config", default=None, help="load tuning from this file")
    args = ap.parse_args(argv)

    if args.status:
        print(status())
        return 0
    if args.install:
        ok, msg = install()
        print(msg, file=sys.stdout if ok else sys.stderr)
        return 0 if ok else 1
    if args.uninstall:
        ok, msg = uninstall()
        print(msg, file=sys.stdout if ok else sys.stderr)
        return 0 if ok else 1

    cfg = Config.load(args.config)
    for w in cfg.load_warnings:
        print(f"config: {w}", file=sys.stderr)
    print(f"MinerSentry watching (elevated={is_elevated()}); "
          f"detections go to {AuditLog().path}", file=sys.stderr)
    icon = None
    if not args.no_tray:
        icon = _tray(cfg)
    try:
        run(cfg=cfg, alert=not args.no_alerts, icon=icon)
    except KeyboardInterrupt:
        return 0
    finally:
        if icon:
            icon.stop()
    return 0


def _tray(cfg: Config):
    """A tray icon with the few things worth doing from there."""
    stop = []

    def open_log():
        path = AuditLog().path
        if sys.platform == "win32" and os.path.exists(path):
            os.startfile(path)  # noqa: S606 - the user asked to see their own log

    def scan_autostart():
        found = persist_mod.scan(cfg)
        notify("MinerSentry: autostart scan",
               f"{len(found)} miner-like entr{'y' if len(found) == 1 else 'ies'} found"
               if found else "No miner-like autostart entries.", cfg)

    icon = tray_mod.TrayIcon(tooltip="MinerSentry — watching", items=[
        tray_mod.MenuItem("Open detection log", open_log),
        tray_mod.MenuItem("Scan autostart now", scan_autostart),
        tray_mod.MenuItem("", None),
        tray_mod.MenuItem("Stop watching", lambda: stop.append(True) or os._exit(0)),
    ])
    if not icon.start():
        print(f"note: no tray icon ({icon.error})", file=sys.stderr)
        return None
    return icon


if __name__ == "__main__":
    raise SystemExit(main())
