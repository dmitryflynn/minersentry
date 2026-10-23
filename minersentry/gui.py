"""MinerSentry desktop GUI (tkinter).

Live process table scored by the behavioral engine, with on-demand deep
(memory) scanning, the evasion probe, and a guarded terminate action.
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
from . import probe as probe_mod


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
        self.monitoring = False
        self.rows: dict[int, ProcInfo] = {}
        self.worker: threading.Thread | None = None
        self.stop_flag = threading.Event()
        self.scan_interval = self.engine.cfg.scan_interval
        self.deep_running = False  # a background deep-scan thread is active
        self.elevated = _is_elevated()
        self._gpu_stop = threading.Event()

        self._build_ui()
        self._poll_queue()
        # Kick off an immediate first scan so the table isn't empty.
        self.start_monitor()
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
        self.btn_kill = self._btn(bar, "⛔  Terminate selected", self.kill_selected, RED)
        self.btn_kill.pack(side="left", padx=(8, 0))

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
                                        "the way it did.\n\nMinerSentry combines five "
                                        "independent signals; a process only reaches "
                                        "\"Likely Miner\" when several agree.")
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

    def request_deep(self) -> None:
        # Deep (memory) scanning runs on its OWN thread so the live monitor loop
        # keeps sampling CPU at its normal cadence and the table never freezes.
        if self.deep_running:
            self._set_status("Deep scan already running…")
            return
        self.deep_running = True
        self._set_status("Deep memory scan started (busy processes), in background…")
        threading.Thread(target=self._deep_thread, daemon=True).start()
        if not self.monitoring:
            self.start_monitor()

    def _deep_thread(self) -> None:
        try:
            # Read the snapshot the scan thread computed; don't walk the engine's
            # live dicts from this thread.
            pids = list(self.engine._deep_targets)
            if not pids:
                self.q.put(("deepdone", 0, 0))
                return
            errors = 0
            for pid in pids:
                r = self.engine.deep_probe(pid)
                if r.error and "OpenProcess" in (r.error or ""):
                    errors += 1
            self.q.put(("deepdone", len(pids), errors))
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
            # Sleep in small slices so pause is responsive.
            waited = 0.0
            while waited < self.scan_interval and not self.stop_flag.is_set():
                time.sleep(0.1)
                waited += 0.1

    # -- probe --------------------------------------------------------------
    def run_probe(self) -> None:
        self._set_status("Running evasion probe (launching Task Manager decoy)…")
        threading.Thread(target=self._probe_thread, daemon=True).start()

    def _probe_thread(self) -> None:
        try:
            drops, msg = probe_mod.run_probe()
            self.q.put(("probe", drops, msg))
        except Exception as e:  # noqa: BLE001
            self.q.put(("probe", {}, f"probe failed: {type(e).__name__}: {e}"))

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
                    _, n, errors = item
                    note = f"Deep memory scan complete: {n} process(es) scanned"
                    if errors:
                        note += f", {errors} inaccessible (run as admin for full coverage)"
                    self._set_status(note)
                    self._add_event(note)
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
            if not self.hidden_banner.winfo_ismapped():
                self.hidden_banner.pack(fill="x", padx=16, pady=(0, 6))
        elif self.hidden_banner.winfo_ismapped():
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
