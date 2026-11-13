"""MinerSentry desktop GUI (tkinter).

Live process table scored by the behavioral engine, with periodic background
deep (memory) scanning, the evasion probe, and a guarded terminate action.
"""

from __future__ import annotations

import ctypes
import os
import queue
import sys
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox

import psutil

from . import __app_name__, __version__
from .audit import AuditLog
from .engine import Engine, ProcInfo
from . import gpu as gpu_mod
from . import persistence as persist_mod
from . import dnscache as dns_mod
from . import probe as probe_mod
from . import quarantine as quarantine_mod
from . import tamper as tamper_mod


def _describe_removal(record: dict) -> str:
    """One line for the undo list: what was removed, and from where."""
    action = record.get("action", "")
    when = str(record.get("ts", ""))[:19].replace("T", " ")
    if action == "remove_registry_value":
        what = f"{record.get('name', '?')} in {record.get('hive', '')}\\{record.get('path', '')}"
    elif action == "remove_task":
        what = f"scheduled task {record.get('task', '?')}"
    elif action == "disable_service":
        what = f"service {record.get('service', '?')} (disabled)"
    elif action == "quarantine_file":
        what = f"{os.path.basename(record.get('original', '?'))} " \
               f"from {os.path.dirname(record.get('original', ''))}"
    else:
        what = action or "unknown action"
    return f"{when or '(no timestamp)':<19}  {what}"


def _is_elevated() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


def _relaunch_as_admin() -> bool:
    """Relaunch MinerSentry elevated via the UAC prompt. Returns True on launch."""
    try:
        if getattr(sys, "frozen", False):
            exe, params = sys.executable, ""
        else:
            exe = sys.executable
            params = os.path.join(os.path.dirname(os.path.dirname(__file__)), "main.py")
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
        return rc > 32
    except Exception:  # noqa: BLE001
        return False

# Palette
BG = "#0e1116"
PANEL = "#161b22"
FG = "#e6edf3"
MUTED = "#8b949e"
ACCENT = "#2f81f7"
GREEN = "#3fb950"
AMBER = "#d29922"
RED = "#f85149"

VERDICT_COLOR = {
    "Clean": GREEN,
    "Suspicious": AMBER,
    "Likely Miner": RED,
}


class MinerSentryApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.q: queue.Queue = queue.Queue()
        # Audit log forwards detections + events to the in-app event panel.
        self.audit = AuditLog(on_event=lambda line: self.q.put(("event", line)))
        self.engine = Engine(audit=self.audit)
        self.engine.start_pool_intel()
        self.engine.start_connection_ages()
        self.monitoring = False
        self.rows: dict[int, ProcInfo] = {}
        self.worker: threading.Thread | None = None
        self.stop_flag = threading.Event()
        self.scan_interval = self.engine.cfg.scan_interval
        self.deep_running = False  # a background deep-scan thread is active
        self.probe_running = False
        self.elevated = _is_elevated()
        self._gpu_stop = threading.Event()

        self._build_ui()
        for w in self.engine.cfg.load_warnings:   # e.g. a tampered per-user config
            self.q.put(("event", "config: " + w))
        self._poll_queue()
        # Kick off an immediate first scan so the table isn't empty.
        self.start_monitor()
        # Memory-scan candidates on a timer. Without this the memory, dataset and
        # perf signals (the ones that catch a throttled miner) only ever fired
        # if someone clicked "Deep scan".
        if self.engine.cfg.deep_auto_interval > 0:
            self.root.after(int(self.engine.cfg.deep_auto_interval * 1000), self._auto_deep)
        # Background GPU-compute sampler (independent of the pause toggle).
        if self.engine.cfg.gpu_enabled:
            threading.Thread(target=self._gpu_loop, daemon=True).start()

    def _gpu_loop(self) -> None:
        interval = self.engine.cfg.gpu_sample_interval
        while not self._gpu_stop.is_set():
            try:
                util, windows, ctx = gpu_mod.sample()
                self.engine.set_gpu_util(util, windows, ctx)
            except Exception as e:  # noqa: BLE001
                self.q.put(("event", f"gpu sampler: {type(e).__name__}: {e}"))
            waited = 0.0
            while waited < interval and not self._gpu_stop.is_set():
                time.sleep(0.2)
                waited += 0.2

    # -- UI construction ----------------------------------------------------
    def _build_ui(self) -> None:
        self.root.title(f"{__app_name__} {__version__} — behavioral cryptominer detector")
        self.root.geometry("1120x680")
        self.root.configure(bg=BG)
        self.root.minsize(900, 520)

        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Treeview", background=PANEL, fieldbackground=PANEL,
                        foreground=FG, rowheight=26, borderwidth=0)
        style.configure("Treeview.Heading", background="#1f2630", foreground=MUTED,
                        relief="flat", font=("Segoe UI", 9, "bold"))
        style.map("Treeview.Heading", background=[("active", "#28303c")])
        style.map("Treeview", background=[("selected", "#1f6feb")],
                  foreground=[("selected", "#ffffff")])

        # Header
        header = tk.Frame(self.root, bg=BG)
        header.pack(fill="x", padx=16, pady=(14, 6))
        tk.Label(header, text="MinerSentry", bg=BG, fg=FG,
                 font=("Segoe UI Semibold", 18)).pack(side="left")
        tk.Label(header, text="  behavioral detection — catches miners by the work they do",
                 bg=BG, fg=MUTED, font=("Segoe UI", 10)).pack(side="left", pady=(6, 0))
        self.cpu_lbl = tk.Label(header, text="", bg=BG, fg=MUTED, font=("Segoe UI", 10))
        self.cpu_lbl.pack(side="right", pady=(6, 0))

        # Privilege banner — memory coverage is limited without elevation.
        if not self.elevated:
            banner = tk.Frame(self.root, bg="#3a2d12")
            banner.pack(fill="x", padx=16, pady=(0, 6))
            tk.Label(banner, bg="#3a2d12", fg="#e3b341", font=("Segoe UI", 9),
                     text="  Not running as Administrator — memory scanning can't reach "
                          "protected / other-user processes.").pack(side="left", pady=4)
            tk.Button(banner, text="Relaunch as admin", command=self._relaunch,
                      bg="#bb8009", fg="#fff", relief="flat", bd=0, padx=10, pady=3,
                      font=("Segoe UI", 8, "bold"), cursor="hand2").pack(side="right", padx=6, pady=3)

        # Toolbar
        bar = tk.Frame(self.root, bg=BG)
        bar.pack(fill="x", padx=16, pady=(0, 8))
        self.btn_monitor = self._btn(bar, "⏸  Pause monitoring", self.toggle_monitor, ACCENT)
        self.btn_monitor.pack(side="left")
        self._btn(bar, "🔬  Deep scan (memory)", self.request_deep, "#6e40c9").pack(side="left", padx=(8, 0))
        self._btn(bar, "🪤  Run evasion probe", self.run_probe, "#bb8009").pack(side="left", padx=(8, 0))
        self._btn(bar, "🧷  Scan autostart", self.scan_autostart, "#1f6feb").pack(
            side="left", padx=(8, 0))
        self._btn(bar, "⏸  Suspend selected", self.suspend_selected, "#8957e5").pack(
            side="left", padx=(8, 0))
        self.btn_kill = self._btn(bar, "⛔  Terminate selected", self.kill_selected, RED)
        self.btn_kill.pack(side="left", padx=(8, 0))
        self._btn(bar, "🔒  Quarantine binary", self.quarantine_selected, "#9e6a03").pack(
            side="left", padx=(8, 0))
        self._btn(bar, "↩  Undo a removal", self.undo_removal, "#30363d").pack(
            side="left", padx=(8, 0))

        # Weakened-defences banner (shown only when the tamper scan finds
        # something). A Defender exclusion covering a flagged folder is close
        # to conclusive and belongs at the top of the window, not in a log.
        self.tamper_banner = tk.Frame(self.root, bg="#3a1d1d")
        self.tamper_lbl = tk.Label(self.tamper_banner, bg="#3a1d1d",
                                   fg="#f0a0a0", font=("Segoe UI", 9),
                                   anchor="w", justify="left")
        self.tamper_lbl.pack(side="left", padx=10, pady=4)

        # Hidden-compute banner (shown only when flagged).
        self.hidden_banner = tk.Frame(self.root, bg="#3a1d1d")
        self.hidden_lbl = tk.Label(self.hidden_banner, bg="#3a1d1d", fg="#f0a0a0",
                                   font=("Segoe UI", 9), anchor="w")
        self.hidden_lbl.pack(side="left", padx=10, pady=4)
        # not packed yet; _render packs/unpacks it

        # Main split
        main = tk.Frame(self.root, bg=BG)
        main.pack(fill="both", expand=True, padx=16, pady=(0, 8))

        cols = ("pid", "name", "cpu", "gpu", "mem", "score", "verdict", "signals")
        headers = {
            "pid": ("PID", 64), "name": ("Process", 200), "cpu": ("CPU%", 64),
            "gpu": ("GPU%", 64), "mem": ("Mem MB", 76), "score": ("Score", 64),
            "verdict": ("Verdict", 104), "signals": ("Signals", 280),
        }
        tree_wrap = tk.Frame(main, bg=PANEL)
        tree_wrap.pack(side="left", fill="both", expand=True)
        self.tree = ttk.Treeview(tree_wrap, columns=cols, show="headings", selectmode="browse")
        for c in cols:
            text, w = headers[c]
            self.tree.heading(c, text=text)
            anchor = "w" if c in ("name", "signals") else "center"
            self.tree.column(c, width=w, anchor=anchor,
                             stretch=(c in ("name", "signals")))
        vs = ttk.Scrollbar(tree_wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vs.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")
        self.tree.tag_configure("Clean", foreground=FG)
        self.tree.tag_configure("Suspicious", foreground=AMBER)
        self.tree.tag_configure("Likely Miner", foreground=RED)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        # Detail panel
        detail = tk.Frame(main, bg=PANEL, width=320)
        detail.pack(side="right", fill="y", padx=(10, 0))
        detail.pack_propagate(False)
        tk.Label(detail, text="DETAIL", bg=PANEL, fg=MUTED,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=14, pady=(12, 4))
        self.detail_text = tk.Text(detail, bg=PANEL, fg=FG, bd=0, wrap="word",
                                   font=("Consolas", 9), width=40, height=30,
                                   highlightthickness=0)
        self.detail_text.pack(fill="both", expand=True, padx=14, pady=(0, 8))
        self.detail_text.insert("1.0", "Select a process to see why it scored "
                                        "the way it did.\n\nMinerSentry combines "
                                        "independent signals; a process only reaches "
                                        "\"Likely Miner\" when several agree, and work "
                                        "alone (CPU or GPU load) never convicts.")
        self.detail_text.configure(state="disabled")

        # Event log (detections + scan events), newest at the bottom.
        tk.Label(detail, text="EVENTS", bg=PANEL, fg=MUTED,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=14, pady=(2, 2))
        self.event_text = tk.Text(detail, bg="#0b0e13", fg=MUTED, bd=0, wrap="word",
                                  font=("Consolas", 8), width=40, height=8,
                                  highlightthickness=0)
        self.event_text.pack(fill="x", padx=14, pady=(0, 12))
        self.event_text.configure(state="disabled")

        # Status bar
        self.status = tk.Label(self.root, text="Starting…", bg="#0b0e13", fg=MUTED,
                               anchor="w", font=("Segoe UI", 9))
        self.status.pack(fill="x", side="bottom", ipady=4)

    def _btn(self, parent, text, cmd, color):
        b = tk.Button(parent, text=text, command=cmd, bg=color, fg="#ffffff",
                      activebackground=color, activeforeground="#ffffff",
                      relief="flat", bd=0, padx=12, pady=7,
                      font=("Segoe UI", 9, "bold"), cursor="hand2")
        return b

    # -- monitoring loop ----------------------------------------------------
    def start_monitor(self) -> None:
        if self.monitoring:
            return
        self.monitoring = True
        self.stop_flag.clear()
        self.worker = threading.Thread(target=self._worker_loop, daemon=True)
        self.worker.start()

    def toggle_monitor(self) -> None:
        if self.monitoring:
            self.monitoring = False
            self.stop_flag.set()
            self.btn_monitor.configure(text="▶  Resume monitoring", bg=GREEN)
            self._set_status("Monitoring paused.")
        else:
            self.btn_monitor.configure(text="⏸  Pause monitoring", bg=ACCENT)
            self.start_monitor()
            self._set_status("Monitoring resumed.")

    def request_deep(self, auto: bool = False) -> None:
        # Deep (memory) scanning runs on its OWN thread so the live monitor loop
        # keeps sampling CPU at its normal cadence and the table never freezes.
        if self.deep_running:
            if not auto:
                self._set_status("Deep scan already running…")
            return
        self.deep_running = True
        if not auto:
            self._set_status("Deep memory scan started (busy processes), in background…")
        threading.Thread(target=self._deep_thread, args=(auto,), daemon=True).start()
        if not auto and not self.monitoring:
            self.start_monitor()

    def _auto_deep(self) -> None:
        if self.monitoring:
            self.request_deep(auto=True)
        self.root.after(int(self.engine.cfg.deep_auto_interval * 1000), self._auto_deep)

    def _deep_thread(self, auto: bool = False) -> None:
        try:
            # Read the snapshot the scan thread computed; don't walk the engine's
            # live dicts from this thread.
            pids = list(self.engine._deep_targets)
            if not pids:
                self.q.put(("deepdone", 0, 0, auto))
                return
            errors = 0
            for pid in pids:
                r = self.engine.deep_probe(pid)
                if r.error and "OpenProcess" in (r.error or ""):
                    errors += 1
            self.q.put(("deepdone", len(pids), errors, auto))
        except Exception as e:  # noqa: BLE001
            self.q.put(("error", f"deep scan failed: {type(e).__name__}: {e}"))
        finally:
            self.deep_running = False

    def _worker_loop(self) -> None:
        while not self.stop_flag.is_set():
            t0 = time.time()
            try:
                results = self.engine.scan_once(deep=False)  # always light + fast
                self.q.put(("results", results, False, time.time() - t0))
            except Exception as e:  # noqa: BLE001
                self.q.put(("error", f"{type(e).__name__}: {e}"))
            # Sleep what is left of the interval (a pass can take seconds), in
            # small slices so pause is responsive.
            waited = time.time() - t0
            while waited < self.scan_interval and not self.stop_flag.is_set():
                time.sleep(0.1)
                waited += 0.1

    # -- probe --------------------------------------------------------------
    def run_probe(self) -> None:
        if self.probe_running:  # two probes at once would measure each other
            self._set_status("Evasion probe already running…")
            return
        self.probe_running = True
        self._set_status("Running evasion probe (launching monitor decoys)…")
        threading.Thread(target=self._probe_thread, daemon=True).start()

    def _probe_thread(self) -> None:
        cfg = self.engine.cfg
        decoys = cfg.probe_decoys_windows if sys.platform == "win32" else cfg.probe_decoys_posix
        try:
            drops, msg = probe_mod.run_probe(decoys=decoys)
            self.q.put(("probe", drops, msg))
        except Exception as e:  # noqa: BLE001
            self.q.put(("probe", {}, f"probe failed: {type(e).__name__}: {e}"))
        finally:
            self.probe_running = False

    # -- queue pump ---------------------------------------------------------
    def _poll_queue(self) -> None:
        try:
            while True:
                item = self.q.get_nowait()
                kind = item[0]
                if kind == "results":
                    _, results, deep, dt = item
                    self._render(results, deep, dt)
                elif kind == "probe":
                    _, drops, msg = item
                    self.engine.set_probe_drops(drops)
                    self._set_status("Evasion probe: " + msg)
                    self._add_event("probe: " + msg)
                    if drops:
                        names = []
                        for pid in drops:
                            try:
                                names.append(f"{psutil.Process(pid).name()} (pid {pid})")
                            except Exception:  # noqa: BLE001
                                names.append(f"pid {pid}")
                        messagebox.showwarning(
                            "Evasion detected",
                            msg + "\n\nThrottled under the decoy:\n  " +
                            "\n  ".join(names) +
                            "\n\nThese are now scored on the 'probe' signal.")
                elif kind == "deepdone":
                    _, n, errors, auto = item
                    note = f"Deep memory scan complete: {n} process(es) scanned"
                    if errors:
                        note += f", {errors} inaccessible (run as admin for full coverage)"
                    if not auto:  # the timed sweep runs quietly
                        self._set_status(note)
                        self._add_event(note)
                elif kind == "autostart":
                    self._show_autostart(item[1],
                                         item[2] if len(item) > 2 else [],
                                         item[3] if len(item) > 3 else [])
                elif kind == "event":
                    self._add_event(item[1])
                elif kind == "error":
                    self._set_status("Scan error: " + item[1])
                    self._add_event("error: " + item[1])
        except queue.Empty:
            pass
        self.root.after(200, self._poll_queue)

    # -- rendering ----------------------------------------------------------
    def _render(self, results: list[ProcInfo], deep: bool, dt: float) -> None:
        self.rows = {r.pid: r for r in results}
        selected = self.tree.selection()
        sel_pid = int(selected[0]) if selected else None

        existing = set(self.tree.get_children())
        wanted = []
        for r in results:
            # Hide the long tail of idle, clean processes to keep focus.
            if r.score == 0 and r.cpu < 2.0 and r.gpu < 2.0:
                continue
            wanted.append(r)

        wanted_ids = {str(r.pid) for r in wanted}
        for iid in existing - wanted_ids:
            self.tree.delete(iid)

        for r in wanted:
            iid = str(r.pid)
            gpu_txt = f"{r.gpu:.0f}" if r.gpu >= 1.0 else "-"
            vals = (r.pid, r.name[:26], f"{r.cpu:.0f}", gpu_txt, f"{r.mem_mb:.0f}",
                    r.score, r.verdict, r.signal_summary[:60])
            if iid in existing:
                self.tree.item(iid, values=vals, tags=(r.verdict,))
            else:
                self.tree.insert("", "end", iid=iid, values=vals, tags=(r.verdict,))

        if sel_pid is not None and str(sel_pid) in wanted_ids:
            self.tree.selection_set(str(sel_pid))
            self._show_detail(sel_pid)

        # Hidden-compute banner.
        rep = self.engine.hidden_report
        if rep.flagged:
            self.hidden_lbl.configure(text="⚠  Hidden compute: " + rep.note)
            # winfo_manager() for the same reason as the tamper banner: this
            # asks whether the banner is packed, not whether it is on screen.
            if not self.hidden_banner.winfo_manager():
                self.hidden_banner.pack(fill="x", padx=16, pady=(0, 6))
        elif self.hidden_banner.winfo_manager():
            self.hidden_banner.pack_forget()

        miners = [r for r in results if r.verdict == "Likely Miner"]
        susp = [r for r in results if r.verdict == "Suspicious"]
        # Read the engine's single-owner system CPU reading; calling
        # psutil.cpu_percent(None) here too would steal the engine's sampling
        # window and make both readings erratic.
        total_cpu = self.engine.system_cpu_pct
        self.cpu_lbl.configure(text=f"system CPU {total_cpu:.0f}%  •  {self.engine.ncpu} logical cores")
        tag = f"{len(miners)} likely miner(s), {len(susp)} suspicious"
        self._set_status(f"Scanned {len(results)} processes in {dt:.1f}s — {tag}")

    def _on_select(self, _event) -> None:
        sel = self.tree.selection()
        if sel:
            self._show_detail(int(sel[0]))

    def _show_detail(self, pid: int) -> None:
        r = self.rows.get(pid)
        if not r:
            return
        lines = [
            f"{r.name}   (PID {r.pid})",
            f"user:  {r.username or '—'}",
            f"path:  {r.exe or '—'}",
        ]
        # Only when it is in one: a line reading "container: —" on every row of
        # a desktop scan is noise, and on a server it is the line that matters.
        if getattr(r, "container", None):
            lines.append(f"in:    {r.container.label}")
        lines += [
            f"cpu:   {r.cpu:.0f}%  (mean {r.cpu_mean:.0f}% / floor {r.cpu_min:.0f}%)",
            f"mem:   {r.mem_mb:.0f} MB   threads: {r.threads}",
            "",
            f"VERDICT:  {r.verdict}   (score {r.score}/100)",
            "─" * 38,
        ]
        for s in r.signals:
            bar = "█" * (s.score // 10) + "·" * (10 - s.score // 10)
            lines.append(f"{s.name:>8}  {s.score:3d} [{bar}]")
            lines.append(f"          {s.detail}")
        if r.mem_result and r.mem_result.scanned:
            lines.append("")
            lines.append(f"memory: {r.mem_result.bytes_scanned // (1024*1024)} MiB scanned, "
                         f"{len(r.mem_result.hits)} fingerprint(s)")
        self.detail_text.configure(state="normal")
        self.detail_text.delete("1.0", "end")
        self.detail_text.insert("1.0", "\n".join(lines))
        self.detail_text.configure(state="disabled")

    # -- actions ------------------------------------------------------------
    def kill_selected(self) -> None:
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Terminate", "Select a process first.")
            return
        pid = int(sel[0])
        r = self.rows.get(pid)
        name = r.name if r else str(pid)
        if not messagebox.askyesno(
                "Terminate process",
                f"Terminate {name} (PID {pid})?\n\n"
                f"Verdict: {r.verdict if r else '?'}  (score {r.score if r else '?'})\n\n"
                "This ends the process immediately. Make sure it is not something "
                "you need before confirming."):
            return
        try:
            p = psutil.Process(pid)
            # The row can be a few seconds old. If the PID now belongs to a
            # different process (it exited and Windows reused the number), stop.
            if r is None or r.ctime is None or abs(p.create_time() - r.ctime) > 0.01:
                messagebox.showwarning(
                    "Process changed",
                    f"PID {pid} no longer belongs to {name}; nothing was terminated.")
                return
            p.terminate()
            try:
                p.wait(timeout=3)
            except psutil.TimeoutExpired:
                p.kill()
            self._set_status(f"Terminated {name} (PID {pid}).")
        except psutil.NoSuchProcess:
            self._set_status(f"{name} (PID {pid}) already gone.")
        except psutil.AccessDenied:
            messagebox.showerror(
                "Access denied",
                f"Could not terminate {name} (PID {pid}).\n\n"
                "Run MinerSentry as Administrator to act on protected processes.")

    # -- autostart ----------------------------------------------------------
    def scan_autostart(self) -> None:
        """Scan the autostart locations, and the defences, in one pass."""
        self._set_status("Scanning autostart locations and defences…")
        threading.Thread(target=self._autostart_thread, daemon=True).start()

    def _autostart_thread(self) -> None:
        try:
            found = persist_mod.scan(self.engine.cfg)
            # The tamper scan takes the paths the autostart scan just flagged,
            # because an exclusion that covers one of them is close to
            # conclusive. Running the two separately is what made that
            # correlation impossible to see.
            flagged = tuple(e.exe for e in found if e.exe)
            try:
                weakened = tamper_mod.scan(self.engine.cfg, flagged_paths=flagged)
            except Exception as e:  # noqa: BLE001 - a scan is not worth losing
                weakened = []
                self.q.put(("event", f"defence check failed: "
                                     f"{type(e).__name__}: {e}"))
            # Pool lookups in the resolver cache are the third host-level
            # check and belong in the same pass. They are host-level on
            # purpose: no resolver cache records which process asked, so these
            # are reported as findings and never attached to a row.
            try:
                lookups = dns_mod.scan(self.engine.cfg)
            except Exception as e:  # noqa: BLE001
                lookups = []
                self.q.put(("event", f"pool-lookup check failed: "
                                     f"{type(e).__name__}: {e}"))
            # Kept as its own list rather than appended to `weakened`: the two
            # share a shape, but the banner would then say "Defences
            # weakened: x.example was resolved", which is not what happened.
            self.q.put(("autostart", found, weakened, lookups))
        except Exception as e:  # noqa: BLE001
            self.q.put(("error", f"autostart scan failed: {type(e).__name__}: {e}"))

    def _show_autostart(self, found: list, weakened: list | None = None,
                        lookups: list | None = None) -> None:
        weakened = weakened or []
        lookups = lookups or []
        self._show_tamper(weakened)
        self._log_lookups(lookups)
        if not found:
            note = "Autostart: no miner-like entries."
            if weakened:
                note += f" Defences: {len(weakened)} finding(s) — see the detail panel."
            real_lookups = [f for f in lookups if f.score > 0]
            if real_lookups:
                note += f" Pool lookups: {len(real_lookups)}."
            self._set_status(note)
            self._add_event("autostart: nothing miner-like found")
            if weakened or lookups:
                self.detail_text.configure(state="normal")
                self.detail_text.delete("1.0", "end")
                self.detail_text.insert(
                    "1.0", "\n".join(self._tamper_lines(weakened)
                                     + self._lookup_lines(lookups)))
                self.detail_text.configure(state="disabled")
            return
        lines = [f"{len(found)} miner-like autostart entr"
                 f"{'y' if len(found) == 1 else 'ies'}:", ""]
        for e in found:
            lines.append(f"{e.score:>3}  {e.kind}")
            lines.append(f"     {e.name}")
            if e.exe:
                lines.append(f"     {e.exe}")
            for label in e.labels[:3]:
                lines.append(f"       - {label}")
            lines.append(f"     in {e.location}")
            lines.append("")
            self._add_event(f"autostart {e.score}: {e.summary}")
        lines += self._tamper_lines(weakened)
        lines += self._lookup_lines(lookups)
        self.detail_text.configure(state="normal")
        self.detail_text.delete("1.0", "end")
        self.detail_text.insert("1.0", "\n".join(lines))
        self.detail_text.configure(state="disabled")
        status = f"Autostart: {len(found)} miner-like entry(ies)"
        real = [f for f in weakened if f.score > 0]
        if real:
            status += f", {len(real)} defence finding(s)"
        self._set_status(status + " — see the detail panel.")
        self._offer_removal(found)

    # -- weakened defences --------------------------------------------------
    def _tamper_lines(self, weakened: list) -> list[str]:
        """The defence findings, as detail-panel text."""
        real = [f for f in weakened if f.score > 0]
        notes = [f for f in weakened if f.score == 0]
        out: list[str] = ["", "-" * 48, ""]
        if not real:
            out.append("Defences: nothing tampered with."
                       if not notes else f"Defences: {notes[0].detail}")
            return out
        out.append(f"{len(real)} defence finding"
                   f"{'' if len(real) == 1 else 's'}:")
        out.append("")
        for f in real:
            out.append(f"{f.score:>3}  {f.kind}")
            out.append(f"     {f.detail}")
            for label in f.labels[:3]:
                out.append(f"       - {label}")
            out.append(f"     in {f.where}")
            out.append("")
        for f in notes:
            out.append(f"     note: {f.detail}")
        return out

    # -- pool lookups in the resolver cache --------------------------------
    def _lookup_lines(self, lookups: list) -> list[str]:
        """The resolver-cache findings, as detail-panel text."""
        real = [f for f in lookups if f.score > 0]
        notes = [f for f in lookups if f.score == 0]
        out: list[str] = ["", "-" * 48, ""]
        if not real:
            out.append("Pool lookups: none in the resolver cache."
                       if not notes else f"Pool lookups: {notes[0].detail}")
            return out
        out.append(f"{len(real)} pool lookup{'' if len(real) == 1 else 's'} "
                   f"in the resolver cache:")
        out.append("")
        for f in real:
            out.append(f"{f.score:>3}  {f.detail}")
            for label in f.labels[:2]:
                out.append(f"       - {label}")
            out.append(f"     from {f.where}")
            out.append("")
        return out

    def _log_lookups(self, lookups: list) -> None:
        """Log each finding. No banner and no row: the resolver cache does not
        record which process asked, so there is nothing to attribute this to —
        putting it on a process would attach a score to the wrong PID."""
        for f in lookups:
            if f.score > 0:
                self._add_event(f"pool lookup {f.score}: {f.detail}")
            else:
                self._add_event(f"pool lookups: {f.detail}")

    def _show_tamper(self, weakened: list) -> None:
        """Log every finding, and raise a banner for the serious ones.

        Until this existed the GUI never mentioned defence tampering at all:
        a machine whose Defender was switched off by policy, with the miner's
        folder excluded, showed a clean dashboard.
        """
        real = [f for f in weakened if f.score > 0]
        for f in real:
            self._add_event(f"defences {f.score}: {f.kind} — {f.detail}")
        for f in (f for f in weakened if f.score == 0):
            self._add_event(f"defences: {f.detail}")
        if not real:
            self._hide_tamper_banner()
            return
        worst = max(real, key=lambda f: f.score)
        self.tamper_lbl.configure(
            text=f"  Defences weakened: {worst.detail}"
                 + (f"  (+{len(real) - 1} more)" if len(real) > 1 else ""))
        # winfo_manager(), not winfo_ismapped(): the question is whether the
        # banner is PACKED, and ismapped answers whether it is currently drawn.
        # While the window is minimised or not yet drawn, ismapped is 0 for a
        # packed widget, so a hide would be skipped and a stale banner left
        # behind, and a show would re-pack on every render.
        if not self.tamper_banner.winfo_manager():
            self.tamper_banner.pack(fill="x", padx=16, pady=(0, 6))

    def _hide_tamper_banner(self) -> None:
        if self.tamper_banner.winfo_manager():
            self.tamper_banner.pack_forget()

    # -- undoing a removal --------------------------------------------------
    def undo_removal(self) -> None:
        """Put back an autostart entry that was removed.

        The removal dialog says the action is recorded so it can be undone.
        It was true of the journal and false of this window: nothing here
        called `undo_removal`, and the only way back was the command line.
        """
        records = persist_mod.removals()
        if not records:
            messagebox.showinfo("Undo a removal",
                                "Nothing has been removed yet, so there is "
                                "nothing to put back.")
            return

        win = tk.Toplevel(self.root)
        win.title("Undo a removal")
        win.configure(bg=BG)
        win.transient(self.root)
        tk.Label(win, bg=BG, fg=FG, font=("Segoe UI", 10), justify="left",
                 text="Newest first. Restoring puts the entry back exactly as "
                      "it was.").pack(anchor="w", padx=14, pady=(12, 6))
        box = tk.Listbox(win, bg=PANEL, fg=FG, width=92, height=10,
                         font=("Consolas", 9), selectbackground=ACCENT,
                         relief="flat", highlightthickness=0, activestyle="none")
        box.pack(fill="both", expand=True, padx=14)
        newest_first = list(reversed(records))
        for record in newest_first:
            box.insert("end", "  " + _describe_removal(record))
        box.selection_set(0)

        def restore() -> None:
            selection = box.curselection()
            if not selection:
                return
            record = newest_first[selection[0]]
            result = persist_mod.undo_removal(record)
            self._add_event(("removal undone: " if result.ok
                             else "undo failed: ") + result.message)
            self._set_status(result.message)
            if result.ok:
                messagebox.showinfo("Undo a removal", result.message, parent=win)
                win.destroy()
            else:
                messagebox.showerror("Undo a removal", result.message, parent=win)

        row = tk.Frame(win, bg=BG)
        row.pack(fill="x", padx=14, pady=12)
        self._btn(row, "Restore selected", restore, "#1f6feb").pack(side="left")
        self._btn(row, "Close", win.destroy, "#30363d").pack(side="right")

    def _offer_removal(self, found: list) -> None:
        """Ask, per entry, whether to disable it. Every removal is reversible.

        Finding the task that revives a miner on reboot is only half the job:
        left in place, the miner comes back. Each removal records what it did
        to the actions journal so it can be put back exactly.
        """
        for e in found:
            what = {"run-key": "delete this registry value",
                    "startup-folder": "move this file to quarantine",
                    "scheduled-task": "delete this scheduled task",
                    "hidden-task": "delete this hidden scheduled task",
                    "service": "disable this service",
                    "service-dll": "disable this service"}.get(
                        e.kind, f"act on this {e.kind} entry")
            if not messagebox.askyesno(
                    "Remove autostart entry",
                    f"{e.name}\n{e.exe or e.command[:70]}\n\nIn: {e.location}\n"
                    f"Score: {e.score}/100\n\nMinerSentry can {what}. "
                    f"It is recorded so it can be undone. Proceed?"):
                continue
            r = persist_mod.remove_entry(e)
            self._add_event(("autostart removed: " if r.ok else "autostart removal failed: ")
                            + r.message)
            self._set_status(r.message)
            if not r.ok:
                messagebox.showerror("Autostart", r.message)

    # -- response actions ---------------------------------------------------
    def _selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Select a process", "Select a process first.")
            return None, None
        pid = int(sel[0])
        return pid, self.rows.get(pid)

    def suspend_selected(self) -> None:
        """Freeze a process instead of killing it: it stops, evidence survives."""
        pid, row = self._selected()
        if pid is None:
            return
        name = row.name if row else str(pid)
        if not messagebox.askyesno(
                "Suspend process",
                f"Suspend {name} (PID {pid})?\n\n"
                f"It stops running but is not killed, so it can still be inspected. "
                f"Use Resume to undo."):
            return
        r = quarantine_mod.suspend(pid)
        self._set_status(r.message)
        self._add_event(("suspended: " if r.ok else "suspend failed: ") + r.message)
        if r.ok and messagebox.askyesno("Suspended", r.message + "\n\nResume it now?"):
            back = quarantine_mod.resume(pid)
            self._set_status(back.message)
            self._add_event("resumed: " + back.message)
        elif not r.ok:
            messagebox.showerror("Suspend", r.message)

    def quarantine_selected(self) -> None:
        """Move the selected process's binary somewhere it cannot launch."""
        pid, row = self._selected()
        if pid is None:
            return
        exe = (row.exe if row else "") or ""
        if not exe or not os.path.isfile(exe):
            messagebox.showinfo("Quarantine", "The binary for that process can't be "
                                              "located (it may need Administrator).")
            return
        if not messagebox.askyesno(
                "Quarantine binary",
                f"Move this file to the MinerSentry quarantine folder?\n\n{exe}\n\n"
                f"The process must be stopped first, so it will be terminated. "
                f"The original location is recorded, so this can be undone."):
            return
        r = quarantine_mod.quarantine_file(exe, kill_first=True)
        self._set_status(r.message)
        self._add_event(("quarantined: " if r.ok else "quarantine failed: ") + r.message)
        if not r.ok:
            messagebox.showerror("Quarantine", r.message)
        else:
            messagebox.showinfo("Quarantined", r.message +
                                "\n\nUndo it from the quarantine folder under "
                                "%LOCALAPPDATA%\\MinerSentry.")

    def _set_status(self, text: str) -> None:
        self.status.configure(text="  " + text)

    def _add_event(self, line: str) -> None:
        ts = time.strftime("%H:%M:%S")
        self.event_text.configure(state="normal")
        self.event_text.insert("end", f"{ts}  {line}\n")
        # keep the log bounded
        if int(self.event_text.index("end-1c").split(".")[0]) > 200:
            self.event_text.delete("1.0", "50.0")
        self.event_text.see("end")
        self.event_text.configure(state="disabled")

    def _relaunch(self) -> None:
        if _relaunch_as_admin():
            self.stop_flag.set()
            self.root.after(300, self.root.destroy)
        else:
            messagebox.showinfo("Relaunch", "Could not relaunch elevated (UAC declined?).")


def main() -> None:
    root = tk.Tk()
    MinerSentryApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
