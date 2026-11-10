"""System-tray presence for the background watcher (Windows, no dependencies).

The service already raises notifications, but with no window and no tray icon
there is nothing to tell you it is running, and no way to ask it for anything.
This puts an icon in the notification area with a small menu — open the log,
scan autostart now, pause, quit — and lets the watcher show balloon alerts
through the same icon.

Implemented on `Shell_NotifyIcon` through ctypes rather than pystray, so the
install stays dependency-free. It needs its own window to receive the icon's
messages, and that window needs a real message loop: a window whose thread
does not pump blocks every process that enumerates windows, which is a lesson
the evasion probe already learned the hard way.

A no-op on anything other than Windows, and on Windows it degrades to a no-op
rather than failing if the shell refuses the icon.
"""

from __future__ import annotations

import ctypes
import sys
import threading

# ctypes.wintypes cannot even be imported on Linux, and ctypes.WINFUNCTYPE does
# not exist there, so every Windows-only construct is built lazily. service.py
# imports this module unconditionally; a module-level WINFUNCTYPE took the
# whole service down on Linux.
if sys.platform == "win32":
    from ctypes import wintypes
else:                                       # pragma: no cover - import guard
    wintypes = None
from dataclasses import dataclass, field
from typing import Callable

IS_WINDOWS = sys.platform == "win32"

WM_DESTROY = 0x0002
WM_COMMAND = 0x0111
WM_RBUTTONUP = 0x0205
WM_LBUTTONDBLCLK = 0x0203
WM_TRAY = 0x0400 + 1          # our own message id for icon events
NIM_ADD, NIM_MODIFY, NIM_DELETE = 0, 1, 2
NIF_MESSAGE, NIF_ICON, NIF_TIP, NIF_INFO = 0x01, 0x02, 0x04, 0x10
IDI_APPLICATION = 32512
IMAGE_ICON = 1
LR_SHARED = 0x8000
TPM_RIGHTBUTTON = 0x0002
MF_STRING, MF_SEPARATOR = 0x0000, 0x0800
CW_USEDEFAULT = -2147483648
WS_OVERLAPPED = 0x00000000


@dataclass
class MenuItem:
    label: str
    action: Callable[[], None] | None = None   # None makes a separator


@dataclass
class TrayIcon:
    """A tray icon with a right-click menu, driven on its own thread."""

    tooltip: str = "MinerSentry"
    items: list[MenuItem] = field(default_factory=list)
    _thread: threading.Thread | None = None
    _hwnd: int = 0
    _ready: threading.Event = field(default_factory=threading.Event)
    _stop: threading.Event = field(default_factory=threading.Event)
    _error: str = ""

    # -- lifecycle ---------------------------------------------------------
    def start(self, timeout: float = 5.0) -> bool:
        """Show the icon. Returns False (with `.error`) if it could not be shown."""
        if not IS_WINDOWS:
            self._error = "the tray is Windows-only"
            return False
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self._ready.wait(timeout)
        return bool(self._hwnd) and not self._error

    @property
    def error(self) -> str:
        return self._error

    def stop(self) -> None:
        self._stop.set()
        if self._hwnd:
            try:
                ctypes.windll.user32.PostMessageW(self._hwnd, WM_DESTROY, 0, 0)
            except Exception:  # noqa: BLE001
                pass
        if self._thread:
            self._thread.join(timeout=3)

    def notify(self, title: str, body: str) -> bool:
        """Show a balloon on the icon. False if there is no icon to show it on."""
        if not self._hwnd:
            return False
        data = self._nid()
        data.uFlags = NIF_INFO
        data.szInfoTitle = title[:63]
        data.szInfo = body[:255]
        try:
            return bool(ctypes.windll.shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(data)))
        except Exception:  # noqa: BLE001
            return False

    # -- internals ---------------------------------------------------------
    def _nid(self):
        class NOTIFYICONDATA(ctypes.Structure):
            _fields_ = [("cbSize", wintypes.DWORD), ("hWnd", wintypes.HWND),
                        ("uID", wintypes.UINT), ("uFlags", wintypes.UINT),
                        ("uCallbackMessage", wintypes.UINT), ("hIcon", wintypes.HICON),
                        ("szTip", wintypes.WCHAR * 128), ("dwState", wintypes.DWORD),
                        ("dwStateMask", wintypes.DWORD), ("szInfo", wintypes.WCHAR * 256),
                        ("uVersion", wintypes.UINT), ("szInfoTitle", wintypes.WCHAR * 64),
                        ("dwInfoFlags", wintypes.DWORD)]
        d = NOTIFYICONDATA()
        d.cbSize = ctypes.sizeof(NOTIFYICONDATA)
        d.hWnd = self._hwnd
        d.uID = 1
        return d

    def _run(self) -> None:
        try:
            user32 = ctypes.windll.user32
            self._hwnd = _message_window(user32, self._on_message)
            if not self._hwnd:
                self._error = "could not create the tray's message window"
                self._ready.set()
                return
            nid = self._nid()
            nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
            nid.uCallbackMessage = WM_TRAY
            nid.hIcon = user32.LoadImageW(None, wintypes.LPCWSTR(IDI_APPLICATION),
                                          IMAGE_ICON, 0, 0, LR_SHARED)
            nid.szTip = self.tooltip[:127]
            if not ctypes.windll.shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(nid)):
                self._error = "the shell refused the tray icon"
                self._ready.set()
                return
            self._ready.set()
            _pump(user32, self._stop)
        except Exception as e:  # noqa: BLE001 - a tray must never take the app down
            self._error = f"{type(e).__name__}: {e}"
            self._ready.set()
        finally:
            try:
                ctypes.windll.shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(self._nid()))
            except Exception:  # noqa: BLE001
                pass
            self._hwnd = 0

    def _on_message(self, hwnd, msg, wparam, lparam):
        if msg == WM_TRAY and lparam in (WM_RBUTTONUP, WM_LBUTTONDBLCLK):
            if lparam == WM_LBUTTONDBLCLK:
                self._invoke(0)
            else:
                self._show_menu(hwnd)
            return 0
        if msg == WM_COMMAND:
            self._invoke((wparam & 0xFFFF) - 1)
            return 0
        if msg == WM_DESTROY:
            self._stop.set()
            return 0
        return None          # let the default handler deal with everything else

    def _invoke(self, index: int) -> None:
        actionable = [i for i in self.items if i.action]
        if 0 <= index < len(self.items):
            item = self.items[index]
            if item.action:
                threading.Thread(target=_safely, args=(item.action,), daemon=True).start()
                return
        if index == 0 and actionable:      # double-click runs the first real item
            threading.Thread(target=_safely, args=(actionable[0].action,), daemon=True).start()

    def _show_menu(self, hwnd) -> None:
        user32 = ctypes.windll.user32
        menu = user32.CreatePopupMenu()
        if not menu:
            return
        try:
            for i, item in enumerate(self.items):
                if item.action is None:
                    user32.AppendMenuW(menu, MF_SEPARATOR, 0, None)
                else:
                    user32.AppendMenuW(menu, MF_STRING, i + 1, item.label)
            pt = wintypes.POINT()
            user32.GetCursorPos(ctypes.byref(pt))
            user32.SetForegroundWindow(hwnd)
            user32.TrackPopupMenu(menu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, None)
            user32.PostMessageW(hwnd, 0, 0, 0)     # dismiss cleanly
        finally:
            user32.DestroyMenu(menu)


def _safely(fn) -> None:
    try:
        fn()
    except Exception:  # noqa: BLE001 - a menu action must not kill the tray
        pass


_KEEP: list = []          # window procs must outlive the window
_LRESULT = ctypes.c_longlong if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_long


def _wndproc_type():
    """The WNDPROC signature, built on demand (Windows only)."""
    return ctypes.WINFUNCTYPE(_LRESULT, wintypes.HWND, wintypes.UINT,
                              wintypes.WPARAM, wintypes.LPARAM)


def _configure(user32) -> None:
    """Pin the signatures of every call used here (see _message_window)."""
    user32.DefWindowProcW.restype = _LRESULT
    user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT,
                                      wintypes.WPARAM, wintypes.LPARAM]
    user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT,
                                    wintypes.WPARAM, wintypes.LPARAM]
    user32.LoadImageW.restype = wintypes.HANDLE
    user32.LoadImageW.argtypes = [wintypes.HINSTANCE, wintypes.LPCWSTR, wintypes.UINT,
                                  ctypes.c_int, ctypes.c_int, wintypes.UINT]
    user32.CreatePopupMenu.restype = wintypes.HMENU
    user32.AppendMenuW.argtypes = [wintypes.HMENU, wintypes.UINT,
                                   ctypes.c_void_p, wintypes.LPCWSTR]
    user32.TrackPopupMenu.argtypes = [wintypes.HMENU, wintypes.UINT, ctypes.c_int,
                                      ctypes.c_int, ctypes.c_int, wintypes.HWND,
                                      ctypes.c_void_p]
    user32.DestroyMenu.argtypes = [wintypes.HMENU]
    user32.SetForegroundWindow.argtypes = [wintypes.HWND]


def _message_window(user32, handler) -> int:
    """A hidden window to receive tray messages."""
    class WNDCLASS(ctypes.Structure):
        _fields_ = [("style", wintypes.UINT), ("lpfnWndProc", _wndproc_type()),
                    ("cbClsExtra", ctypes.c_int), ("cbWndExtra", ctypes.c_int),
                    ("hInstance", wintypes.HINSTANCE), ("hIcon", wintypes.HICON),
                    ("hCursor", wintypes.HANDLE), ("hbrBackground", wintypes.HBRUSH),
                    ("lpszMenuName", wintypes.LPCWSTR), ("lpszClassName", wintypes.LPCWSTR)]

    def proc(hwnd, msg, wparam, lparam):
        result = handler(hwnd, msg, wparam, lparam)
        if result is None:
            return user32.DefWindowProcW(hwnd, msg, wparam, lparam)
        return result

    # Explicit signatures throughout: without them ctypes guesses c_int, and a
    # 64-bit handle or LPARAM overflows ("int too long to convert"). The window
    # proc is called by Windows, so a wrong signature there surfaces only as an
    # ignored exception on every message.
    _configure(user32)
    kernel32 = ctypes.windll.kernel32
    kernel32.GetModuleHandleW.restype = wintypes.HMODULE
    kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
    user32.CreateWindowExW.restype = wintypes.HWND
    user32.CreateWindowExW.argtypes = [
        wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
        ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
        wintypes.HWND, wintypes.HMENU, wintypes.HINSTANCE, wintypes.LPVOID]

    wndproc = _wndproc_type()(proc)
    cls = WNDCLASS()
    cls.lpfnWndProc = wndproc
    cls.lpszClassName = f"MinerSentryTray{id(wndproc)}"
    cls.hInstance = kernel32.GetModuleHandleW(None)
    if not user32.RegisterClassW(ctypes.byref(cls)):
        return 0
    hwnd = user32.CreateWindowExW(0, cls.lpszClassName, "MinerSentry", WS_OVERLAPPED,
                                  CW_USEDEFAULT, CW_USEDEFAULT, 0, 0,
                                  None, None, cls.hInstance, None)
    _KEEP.append((wndproc, cls))
    return hwnd or 0


def _pump(user32, stop: threading.Event) -> None:
    """Message loop. Mandatory: an unpumped window blocks other processes."""
    msg = wintypes.MSG()
    while not stop.is_set():
        while user32.PeekMessageW(ctypes.byref(msg), None, 0, 0, 1):
            if msg.message == WM_DESTROY:
                stop.set()
                break
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))
        stop.wait(0.05)
