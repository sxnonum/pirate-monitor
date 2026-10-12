"""Process monitor: every process start/exit, with parent, command line, image hash and tree tracking.

New processes are found by fast polling. On Windows (as Administrator, with pywin32 installed) WMI
process-start tracing is used as well, so processes that live only a few milliseconds are not missed.
"""

from __future__ import annotations

import os
import shlex
import subprocess
import threading
import time
from typing import Dict, List, Optional

import psutil

from ..core import Event
from ..util import IS_WINDOWS, HashCache
from .base import Monitor

WBEM_E_TIMED_OUT = 0x80043001
WBEM_E_ACCESS_DENIED = 0x80041003


class ProcInfo:
    __slots__ = ("pid", "ppid", "name", "exe", "ctime")

    def __init__(self, pid, ppid, name, exe, ctime):
        self.pid = pid
        self.ppid = ppid
        self.name = name
        self.exe = exe
        self.ctime = ctime


def _safe(fn):
    try:
        return fn()
    except (psutil.AccessDenied, psutil.ZombieProcess, OSError):
        return None


def _join_cmdline(parts: Optional[List[str]]) -> str:
    if not parts:
        return ""
    if IS_WINDOWS:
        return subprocess.list2cmdline(parts)
    return " ".join(shlex.quote(p) for p in parts)


def _filetime_to_unix(value) -> Optional[float]:
    try:
        return (int(value) - 116444736000000000) / 10_000_000
    except (TypeError, ValueError):
        return None


class ProcessMonitor(Monitor):
    name = "process"

    def __init__(self, bus, state, interval: float = 0.25, hash_max_bytes: int = 50 * 1024 * 1024,
                 use_wmi: bool = True, track_pids=()):
        super().__init__(bus, state)
        self.interval = interval
        self.use_wmi = use_wmi and IS_WINDOWS
        self.track_pids = list(track_pids)
        self._known: Dict[int, ProcInfo] = {}
        self._lock = threading.RLock()
        self._hashes = HashCache(hash_max_bytes)
        self.wmi_active = False

    # -- lifecycle --------------------------------------------------------------------------
    def start(self) -> None:
        for proc in psutil.process_iter(["pid", "ppid", "name", "exe", "create_time"]):
            info = proc.info
            pid = info["pid"]
            pinfo = ProcInfo(pid, info.get("ppid"), info.get("name") or "?", info.get("exe"),
                             info.get("create_time") or 0.0)
            self._known[pid] = pinfo
            if pid in self.track_pids or self.state.matches_track_name(pinfo.name):
                self._track_existing(pinfo)
        for pid in self.track_pids:
            if pid not in self._known:
                self.bus.system(f"[process] --track-pid {pid}: no such process", "warning")
        self.bus.system(f"[process] baseline: {len(self._known)} running processes")
        self._spawn(self._poll_loop, "poll")
        if self.use_wmi:
            self._spawn(self._wmi_loop, "wmi")
        self.ready.set()

    def _track_existing(self, info: ProcInfo) -> None:
        self.state.track(info.pid, info.ctime)
        self.bus.emit(Event("process", "tracking", info.exe or info.name,
                            {"pid": info.pid, "name": info.name, "note": "already running; now tracked"},
                            tracked=True))

    def launch(self, argv: List[str], new_console: bool = True) -> subprocess.Popen:
        """Start the sample and mark it as the root of the tracked tree before anything sees it."""
        kwargs = {}
        if IS_WINDOWS and new_console:
            kwargs["creationflags"] = subprocess.CREATE_NEW_CONSOLE
        elif not IS_WINDOWS:
            kwargs["start_new_session"] = True
        with self._lock:
            popen = subprocess.Popen(argv, **kwargs)
            try:
                ctime = psutil.Process(popen.pid).create_time()
            except psutil.Error:
                ctime = time.time()
            self.state.track(popen.pid, ctime)
        return popen

    # -- discovery --------------------------------------------------------------------------
    def _poll_loop(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                current = set(psutil.pids())
            except Exception:
                continue
            with self._lock:
                known = set(self._known)
            for pid in sorted(current - known):
                self._on_new(pid)
            for pid in known - current:
                self._on_exit(pid)

    def _on_new(self, pid: int, hint: Optional[dict] = None) -> None:
        try:
            proc = psutil.Process(pid)
            with proc.oneshot():
                try:
                    ctime = proc.create_time()
                except psutil.AccessDenied:
                    ctime = (hint or {}).get("ctime") or time.time()
                name = _safe(proc.name) or (hint or {}).get("name") or "?"
                ppid = _safe(proc.ppid)
                exe = _safe(proc.exe)
                cmdline = _join_cmdline(_safe(proc.cmdline))
                user = _safe(proc.username)
        except psutil.NoSuchProcess:
            if hint:
                self._emit_short_lived(pid, hint)
            return
        if ppid is None and hint:
            ppid = hint.get("ppid")
        sha256 = self._hashes.get(exe) if exe else None

        with self._lock:
            existing = self._known.get(pid)
            if existing is not None and abs(existing.ctime - ctime) < 1.0:
                return  # already reported (poller and WMI both saw it)
            tracked, dropped_image, dropped_ref = self._classify(pid, ppid, name, exe, cmdline, ctime)
            self._known[pid] = ProcInfo(pid, ppid, name, exe, ctime)
            parent = self._known.get(ppid) if ppid else None
        if existing is not None:
            self._emit_exit(existing)  # pid was reused before we noticed the old process exit

        details = {
            "pid": pid,
            "name": name,
            "exe": exe,
            "cmdline": cmdline,
            "ppid": ppid,
            "parent": parent.name if parent is not None and parent.ctime <= ctime + 1 else None,
            "parent_exe": parent.exe if parent is not None and parent.ctime <= ctime + 1 else None,
            "user": user,
            "sha256": sha256,
            "create_time": ctime,
        }
        if dropped_image:
            details["dropped_image"] = True
        if dropped_ref:
            details["dropped_reference"] = dropped_ref
        event = Event("process", "started", exe or name, details, tracked=tracked)
        if self.state.started_at - 5 <= ctime <= event.timestamp:
            event.timestamp = ctime  # order the report by when the process really started
        self.bus.emit(event)

    def _classify(self, pid, ppid, name, exe, cmdline, ctime):
        """Decide whether a new process belongs to the tracked tree. Caller holds the lock."""
        tracked = self.state.is_tracked(pid, ctime)  # e.g. launched by launch()
        parent_ct = self.state.tracked_ctime(ppid)
        if parent_ct is not None and parent_ct <= ctime + 1.0:
            parent = self._known.get(ppid)
            if parent is None or abs(parent.ctime - parent_ct) < 1.0:
                tracked = True
        if self.state.matches_track_name(name):
            tracked = True
        dropped_image = bool(exe) and self.state.is_dropped(exe)
        dropped_ref = None if dropped_image else self.state.dropped_in_text(cmdline)
        if dropped_image or dropped_ref:
            tracked = True
        if tracked:
            self.state.track(pid, ctime)
        return tracked, dropped_image, dropped_ref

    def _emit_short_lived(self, pid: int, hint: dict) -> None:
        ppid = hint.get("ppid")
        ctime = hint.get("ctime") or time.time()
        with self._lock:
            parent = self._known.get(ppid) if ppid else None
            parent_ct = self.state.tracked_ctime(ppid)
            tracked = parent_ct is not None and (parent is None or abs(parent.ctime - parent_ct) < 1.0)
            tracked = tracked or self.state.matches_track_name(hint.get("name"))
            if tracked:
                self.state.track(pid, ctime)
        details = {
            "pid": pid,
            "name": hint.get("name"),
            "ppid": ppid,
            "parent": parent.name if parent is not None else None,
            "short_lived": True,
            "create_time": ctime,
        }
        self.bus.emit(Event("process", "started", hint.get("name") or f"pid {pid}", details, tracked=tracked))

    def _on_exit(self, pid: int) -> None:
        with self._lock:
            info = self._known.pop(pid, None)
        if info is not None:
            self._emit_exit(info)

    def _emit_exit(self, info: ProcInfo) -> None:
        tracked = self.state.is_tracked(info.pid, info.ctime)
        details = {"pid": info.pid, "name": info.name}
        if info.ctime:
            details["runtime_seconds"] = round(max(time.time() - info.ctime, 0.0), 1)
        self.bus.emit(Event("process", "exited", info.exe or info.name, details, tracked=tracked))

    # -- tracked tree helpers ---------------------------------------------------------------
    def tracked_alive(self) -> List[ProcInfo]:
        with self._lock:
            return [i for i in self._known.values() if self.state.is_tracked(i.pid, i.ctime)]

    def kill_tracked(self) -> int:
        killed = 0
        for info in self.tracked_alive():
            if info.pid == os.getpid():
                continue
            try:
                proc = psutil.Process(info.pid)
                if abs(proc.create_time() - info.ctime) < 1.0:
                    proc.kill()
                    killed += 1
            except psutil.Error:
                pass
        return killed

    # -- WMI (Windows) ----------------------------------------------------------------------
    def _wmi_loop(self) -> None:
        try:
            import pythoncom
            import pywintypes
            import win32com.client
        except ImportError:
            self.bus.system("[process] pywin32 not installed: very short-lived processes may be missed "
                            "(pip install pywin32)", "notice")
            return
        pythoncom.CoInitialize()
        try:
            try:
                wmi = win32com.client.GetObject(r"winmgmts:{impersonationLevel=impersonate}!\\.\root\cimv2")
                watcher = wmi.ExecNotificationQuery("SELECT * FROM Win32_ProcessStartTrace")
            except pywintypes.com_error as exc:
                self.bus.system(f"[process] WMI process tracing unavailable ({_com_code(exc)}); "
                                "run as Administrator to catch short-lived processes", "notice")
                return
            failures = 0
            announced = False
            while not self._stop.is_set():
                try:
                    event = watcher.NextEvent(500)
                except pywintypes.com_error as exc:
                    code = _com_code(exc)
                    if code == WBEM_E_TIMED_OUT:
                        if not announced:
                            announced = True
                            self.wmi_active = True
                            self.bus.system("[process] WMI process-start tracing active (catches short-lived processes)")
                        failures = 0
                        continue
                    failures += 1
                    if code == WBEM_E_ACCESS_DENIED or failures > 5:
                        self.wmi_active = False
                        self.bus.system(f"[process] WMI process tracing stopped (0x{code or 0:08x}); "
                                        "run as Administrator to catch short-lived processes", "notice")
                        return
                    time.sleep(0.5)
                    continue
                failures = 0
                if not announced:
                    announced = True
                    self.wmi_active = True
                    self.bus.system("[process] WMI process-start tracing active (catches short-lived processes)")
                try:
                    hint = {
                        "name": str(event.ProcessName),
                        "ppid": int(event.ParentProcessID),
                        "ctime": _filetime_to_unix(event.TIME_CREATED),
                    }
                    pid = int(event.ProcessID)
                except Exception:
                    continue
                self._on_new(pid, hint)
        finally:
            pythoncom.CoUninitialize()


def _com_code(exc) -> Optional[int]:
    """Extract the WMI error code (scode) from a pywintypes.com_error."""
    args = getattr(exc, "args", ())
    if len(args) > 2 and args[2] and len(args[2]) > 5 and isinstance(args[2][5], int):
        return args[2][5] & 0xFFFFFFFF
    if args and isinstance(args[0], int):
        return args[0] & 0xFFFFFFFF
    return None
