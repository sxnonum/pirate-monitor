"""Windows-only registry access: a winreg backend and a RegNotifyChangeKeyValue notifier.

All RegNotifyChangeKeyValue calls are made from the registry monitor's single worker thread
(registrations are tied to the thread that makes them and that thread lives for the whole
session). Small helper threads only wait on the notification events, at most 63 per thread
because of the WaitForMultipleObjects limit, and hand signalled unit ids to the worker.
"""

from __future__ import annotations

import ctypes
import queue
import threading
import time
import winreg
from ctypes import wintypes
from typing import Dict, List, Optional

from .model import split_hive_path

HIVES = {
    "HKLM": winreg.HKEY_LOCAL_MACHINE,
    "HKCU": winreg.HKEY_CURRENT_USER,
    "HKU": winreg.HKEY_USERS,
    "HKCR": winreg.HKEY_CLASSES_ROOT,
    "HKCC": winreg.HKEY_CURRENT_CONFIG,
}

READ_ACCESS = winreg.KEY_READ | winreg.KEY_WOW64_64KEY
NOTIFY_ACCESS = winreg.KEY_NOTIFY | winreg.KEY_WOW64_64KEY


def open_key(path: str, access: int = READ_ACCESS):
    hive, sub = split_hive_path(path)
    if hive not in HIVES:
        raise OSError(f"unknown hive {hive}")
    return winreg.OpenKeyEx(HIVES[hive], sub, 0, access)


class WinregBackend:
    """Backend for model.take_snapshot() that reads the live registry (64-bit view)."""

    def open(self, path: str):
        return open_key(path, READ_ACCESS)

    def open_child(self, handle, name: str):
        return winreg.OpenKeyEx(handle, name, 0, READ_ACCESS)

    def close(self, handle) -> None:
        try:
            handle.Close()
        except OSError:
            pass

    def last_write(self, handle) -> int:
        return winreg.QueryInfoKey(handle)[2]

    def subkeys(self, handle) -> List[str]:
        names = []
        index = 0
        while True:
            try:
                names.append(winreg.EnumKey(handle, index))
            except OSError:
                break  # ERROR_NO_MORE_ITEMS, or the key vanished mid-enumeration
            index += 1
        return names

    def values(self, handle) -> list:
        out = []
        index = 0
        while True:
            try:
                out.append(winreg.EnumValue(handle, index))
            except OSError:
                break
            index += 1
        return out


# --- Win32 API --------------------------------------------------------------------------------
_advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

_RegNotifyChangeKeyValue = _advapi32.RegNotifyChangeKeyValue
_RegNotifyChangeKeyValue.argtypes = [wintypes.HKEY, wintypes.BOOL, wintypes.DWORD, wintypes.HANDLE, wintypes.BOOL]
_RegNotifyChangeKeyValue.restype = wintypes.LONG

_CreateEventW = _kernel32.CreateEventW
_CreateEventW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
_CreateEventW.restype = wintypes.HANDLE

_SetEvent = _kernel32.SetEvent
_SetEvent.argtypes = [wintypes.HANDLE]
_SetEvent.restype = wintypes.BOOL

_CloseHandle = _kernel32.CloseHandle
_CloseHandle.argtypes = [wintypes.HANDLE]
_CloseHandle.restype = wintypes.BOOL

_WaitForSingleObject = _kernel32.WaitForSingleObject
_WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
_WaitForSingleObject.restype = wintypes.DWORD

_WaitForMultipleObjects = _kernel32.WaitForMultipleObjects
_WaitForMultipleObjects.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE), wintypes.BOOL, wintypes.DWORD]
_WaitForMultipleObjects.restype = wintypes.DWORD

REG_NOTIFY_CHANGE_NAME = 0x1  # subkey added / deleted
REG_NOTIFY_CHANGE_LAST_SET = 0x4  # value added / changed / deleted
NOTIFY_FILTER = REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET
WAIT_OBJECT_0 = 0x0
WAIT_TIMEOUT = 0x102
WAIT_FAILED = 0xFFFFFFFF
MAX_PER_GROUP = 63  # MAXIMUM_WAIT_OBJECTS (64) minus our wake-up event


def _new_event() -> Optional[int]:
    return _CreateEventW(None, False, False, None)  # auto-reset, initially unsignalled


def _register(hkey, recursive: bool, event: int) -> int:
    return _RegNotifyChangeKeyValue(hkey.handle, bool(recursive), NOTIFY_FILTER, event, True)


class _WaitGroup(threading.Thread):
    def __init__(self, signals: "queue.Queue[tuple]"):
        super().__init__(name="pm-reg-wait", daemon=True)
        self._signals = signals
        self._mutex = threading.Lock()
        self._wake = _new_event()
        self._entries: Dict[int, int] = {}
        self._to_add: List[tuple] = []
        self._to_remove: List[int] = []
        self._stopping = False
        self.count = 0  # reserved slots, maintained by the notifier thread

    def add(self, uid: int, event: int) -> None:
        with self._mutex:
            self._to_add.append((uid, event))
        _SetEvent(self._wake)

    def remove(self, uid: int) -> None:
        with self._mutex:
            self._to_remove.append(uid)
        _SetEvent(self._wake)

    def stop(self) -> None:
        with self._mutex:
            self._stopping = True
        _SetEvent(self._wake)

    def run(self) -> None:
        while True:
            with self._mutex:
                for uid, event in self._to_add:
                    self._entries[uid] = event
                self._to_add.clear()
                for uid in self._to_remove:
                    event = self._entries.pop(uid, None)
                    if event:
                        _CloseHandle(event)
                self._to_remove.clear()
                if self._stopping:
                    break
                ids = list(self._entries)
                handles = [self._wake] + [self._entries[i] for i in ids]
            array = (wintypes.HANDLE * len(handles))(*handles)
            rc = _WaitForMultipleObjects(len(handles), array, False, 1000)
            if rc == WAIT_TIMEOUT:
                continue
            if rc == WAIT_FAILED:
                time.sleep(0.5)
                continue
            index = rc - WAIT_OBJECT_0
            if 1 <= index < len(handles):
                self._signals.put((ids[index - 1], time.monotonic()))
        for event in self._entries.values():
            _CloseHandle(event)
        self._entries.clear()
        _CloseHandle(self._wake)


class Win32Notifier:
    """Event-driven change notification for registry units."""

    def __init__(self, debounce: float = 0.15):
        self._signals: "queue.Queue[tuple]" = queue.Queue()
        self._groups: List[_WaitGroup] = []
        self._entries: Dict[int, list] = {}  # uid -> [hkey, event, group]
        self._debounce = debounce
        self.signalled_at: Dict[int, float] = {}  # uid -> monotonic time of the latest signal
        self.signal_count = 0

    def _group_with_space(self) -> _WaitGroup:
        for group in self._groups:
            if group.count < MAX_PER_GROUP:
                return group
        group = _WaitGroup(self._signals)
        group.start()
        self._groups.append(group)
        return group

    def attach(self, unit) -> bool:
        try:
            hkey = open_key(unit.path, NOTIFY_ACCESS)
        except OSError:
            return False
        event = _new_event()
        if not event:
            hkey.Close()
            return False
        if _register(hkey, unit.recursive, event) != 0:
            _CloseHandle(event)
            hkey.Close()
            return False
        group = self._group_with_space()
        group.count += 1
        group.add(unit.uid, event)
        self._entries[unit.uid] = [hkey, event, group]
        return True

    def rearm(self, unit) -> bool:
        entry = self._entries.get(unit.uid)
        if entry is None:
            return self.attach(unit)
        if _register(entry[0], unit.recursive, entry[1]) == 0:
            return True
        # The key was deleted (and maybe re-created): open it again by name.
        try:
            hkey = open_key(unit.path, NOTIFY_ACCESS)
        except OSError:
            return False
        try:
            entry[0].Close()
        except OSError:
            pass
        entry[0] = hkey
        return _register(hkey, unit.recursive, entry[1]) == 0

    def detach(self, unit) -> None:
        entry = self._entries.pop(unit.uid, None)
        if entry is None:
            return
        hkey, _event, group = entry
        group.count -= 1
        group.remove(unit.uid)  # the group thread closes the event handle
        try:
            hkey.Close()
        except OSError:
            pass

    def wait(self, timeout: float) -> List[int]:
        try:
            first = self._signals.get(timeout=timeout)
        except queue.Empty:
            return []
        time.sleep(self._debounce)  # let a burst of writes finish before re-scanning
        items = [first]
        while True:
            try:
                items.append(self._signals.get_nowait())
            except queue.Empty:
                break
        self.signal_count += len(items)
        ids = []
        for uid, when in items:
            self.signalled_at.setdefault(uid, when)
            ids.append(uid)
        return list(dict.fromkeys(ids))

    def describe(self, unit) -> dict:
        entry = self._entries.get(unit.uid)
        info = {"attached": entry is not None}
        if entry is not None:
            info["event_signalled_now"] = _WaitForSingleObject(entry[1], 0) == WAIT_OBJECT_0
            info["group_size"] = entry[2].count
        info["groups"] = len(self._groups)
        info["queued_signals"] = self._signals.qsize()
        return info

    def close(self) -> None:
        for entry in self._entries.values():
            try:
                entry[0].Close()
            except OSError:
                pass
        self._entries.clear()
        for group in self._groups:
            group.stop()
        for group in self._groups:
            group.join(timeout=2)
