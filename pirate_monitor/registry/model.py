"""Registry snapshot / diff engine.

Nothing here touches the real registry: it talks to a *backend* object, so the logic can be
unit-tested on any OS with an in-memory fake. ``win32.py`` provides the real winreg backend.

Watched trees are split into *units*. Each unit is one key watched either with its whole subtree
(recursive) or on its own (non-recursive: its values and the names of its direct children). Big
trees are split until each recursive unit holds at most ``split_threshold`` keys, so a change
notification only forces a re-scan of a small part of the registry.
"""

from __future__ import annotations

import hashlib
import itertools
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

REG_TYPES = {
    0: "REG_NONE",
    1: "REG_SZ",
    2: "REG_EXPAND_SZ",
    3: "REG_BINARY",
    4: "REG_DWORD",
    5: "REG_DWORD_BIG_ENDIAN",
    6: "REG_LINK",
    7: "REG_MULTI_SZ",
    8: "REG_RESOURCE_LIST",
    9: "REG_FULL_RESOURCE_DESCRIPTOR",
    10: "REG_RESOURCE_REQUIREMENTS_LIST",
    11: "REG_QWORD",
}

HIVE_ALIASES = {
    "HKEY_LOCAL_MACHINE": "HKLM",
    "HKLM": "HKLM",
    "HKEY_CURRENT_USER": "HKCU",
    "HKCU": "HKCU",
    "HKEY_USERS": "HKU",
    "HKU": "HKU",
    "HKEY_CLASSES_ROOT": "HKCR",
    "HKCR": "HKCR",
    "HKEY_CURRENT_CONFIG": "HKCC",
    "HKCC": "HKCC",
}

MAX_INLINE_BINARY = 256
MAX_DEPTH = 48


def canonical_key_path(path: str) -> str:
    """Normalise user input such as 'Computer\\HKEY_CURRENT_USER\\Software\\' to 'HKCU\\Software'."""
    p = path.strip().strip('"').replace("/", "\\").strip("\\")
    if p.lower().startswith("computer\\"):
        p = p[len("computer\\"):]
    hive, _, rest = p.partition("\\")
    hive = hive.rstrip(":").upper()
    if hive not in HIVE_ALIASES:
        raise ValueError(f"unknown registry hive in {path!r} (use HKLM, HKCU, HKU, HKCR or HKCC)")
    rest = "\\".join(part for part in rest.split("\\") if part)
    return HIVE_ALIASES[hive] + ("\\" + rest if rest else "")


def split_hive_path(path: str) -> Tuple[str, str]:
    hive, _, rest = path.partition("\\")
    return hive, rest


def dedupe_key_roots(paths: Iterable[str]) -> List[str]:
    """Canonicalise and drop roots nested in another root, keeping the original order."""
    ordered = list(dict.fromkeys(canonical_key_path(p) for p in paths))
    kept: Set[str] = set()
    for p in sorted(ordered, key=len):
        low = p.lower()
        if any(low == k or low.startswith(k + "\\") for k in kept):
            continue
        kept.add(low)
    result: List[str] = []
    for p in ordered:
        if p.lower() in kept and p.lower() not in {r.lower() for r in result}:
            result.append(p)
    return result


def filetime_to_unix(ft: int) -> float:
    return (ft - 116444736000000000) / 10_000_000


def _parent(key: str) -> Optional[str]:
    idx = key.rfind("\\")
    return key[:idx] if idx > 0 else None


def _store_value(data: Any) -> Any:
    """Keep small data verbatim; replace big blobs by a fingerprint to save memory."""
    if isinstance(data, bytearray):
        data = bytes(data)
    if isinstance(data, bytes) and len(data) > MAX_INLINE_BINARY:
        return ("<binary>", len(data), hashlib.sha1(data).hexdigest())
    return data


def format_value(vtype: Optional[int], data: Any, limit: int = 300) -> str:
    if data is None:
        return "(empty)"
    if isinstance(data, tuple) and len(data) == 3 and data[0] == "<binary>":
        return f"<{data[1]:,} bytes, sha1 {data[2][:12]}>"
    if isinstance(data, bool):
        data = int(data)
    if isinstance(data, int):
        return f"{data} (0x{data & 0xFFFFFFFFFFFFFFFF:x})"
    if isinstance(data, bytes):
        shown = data[:48].hex(" ")
        return f"hex[{len(data)}]: {shown}{' ...' if len(data) > 48 else ''}"
    if isinstance(data, (list, tuple)):
        text = " | ".join(str(x) for x in data)
    else:
        text = str(data)
    return text if len(text) <= limit else text[: limit - 3] + "..."


class KeyState:
    __slots__ = ("path", "last_write", "values", "children", "read_time")

    def __init__(self, path, last_write, values, children=None, read_time=0.0):
        self.path = path  # display path, e.g. HKCU\Software\Foo
        self.last_write = last_write  # FILETIME of the key's last modification
        self.values = values  # lower name -> (name, type, data)
        self.children = children  # lower name -> name (only for non-recursive units)
        self.read_time = read_time  # time.time() when the values were read


Snapshot = Dict[str, KeyState]  # lower-case full path -> state


@dataclass
class WalkStats:
    keys: int = 0
    values: int = 0
    denied: int = 0


def take_snapshot(
    backend,
    path: str,
    recursive: bool = True,
    previous: Optional[Snapshot] = None,
    stats: Optional[WalkStats] = None,
    skip: Optional[Set[str]] = None,
) -> Optional[Snapshot]:
    """Read ``path`` (and its subtree if recursive). Returns None if the key cannot be opened."""
    try:
        handle = backend.open(path)
    except OSError:
        return None
    snap: Snapshot = {}
    try:
        _walk(backend, handle, path, 0, recursive, previous, snap, stats or WalkStats(), skip or set())
    finally:
        backend.close(handle)
    return snap


def _walk(backend, handle, path, depth, recursive, previous, snap, stats, skip) -> None:
    try:
        last_write = backend.last_write(handle)
    except OSError:
        last_write = 0
    names = backend.subkeys(handle)
    lower = path.lower()
    prev = previous.get(lower) if previous else None
    # A key's last-write time changes whenever one of its values changes. If it has not changed
    # since a read that happened well after that time, the cached values are still exact.
    if (
        prev is not None
        and last_write
        and prev.last_write == last_write
        and prev.read_time - filetime_to_unix(last_write) > 2.0
    ):
        values, read_time = prev.values, prev.read_time
    else:
        read_time = time.time()
        values = {}
        for name, data, vtype in backend.values(handle):
            values[name.lower()] = (name, vtype, _store_value(data))
    children = None if recursive else {n.lower(): n for n in names}
    snap[lower] = KeyState(path, last_write, values, children, read_time)
    stats.keys += 1
    stats.values += len(values)
    if not recursive or depth >= MAX_DEPTH:
        return
    for name in names:
        child_path = path + "\\" + name
        if child_path.lower() in skip:
            continue
        try:
            child = backend.open_child(handle, name)
        except OSError:
            stats.denied += 1
            continue
        try:
            _walk(backend, child, child_path, depth + 1, recursive, previous, snap, stats, skip)
        finally:
            backend.close(child)


@dataclass
class RegChange:
    action: str  # key_created | key_deleted | value_created | value_modified | value_deleted
    key: str
    value: Optional[str] = None
    vtype: Optional[int] = None
    old: Any = None
    new: Any = None
    extra: Dict[str, Any] = field(default_factory=dict)


def diff_values(path: str, old: Dict, new: Dict) -> List[RegChange]:
    if old is new:
        return []
    out = []
    for lname, (name, vtype, data) in new.items():
        prev = old.get(lname)
        if prev is None:
            out.append(RegChange("value_created", path, name, vtype, None, data))
        elif prev[1] != vtype or prev[2] != data:
            extra = {"old_type": prev[1]} if prev[1] != vtype else {}
            out.append(RegChange("value_modified", path, name, vtype, prev[2], data, extra))
    for lname, (name, vtype, data) in old.items():
        if lname not in new:
            out.append(RegChange("value_deleted", path, name, vtype, data, None))
    return out


def _deleted_summary(states: List[KeyState], top: KeyState) -> Dict[str, Any]:
    return {
        "subkeys_removed": max(len(states) - 1, 0),
        "values_removed": sum(len(s.values) for s in states),
        "removed_values": [(n, t, d) for n, t, d in list(top.values.values())[:25]],
    }


def diff_snapshots(old: Snapshot, new: Snapshot) -> List[RegChange]:
    changes: List[RegChange] = []
    for key in sorted(k for k in new if k not in old):  # sorted: parents before children
        state = new[key]
        changes.append(RegChange("key_created", state.path))
        for name, vtype, data in state.values.values():
            changes.append(RegChange("value_created", state.path, name, vtype, None, data))

    deleted = {k for k in old if k not in new}
    groups: Dict[str, List[KeyState]] = defaultdict(list)
    for key in deleted:
        top = key
        parent = _parent(key)
        while parent is not None and parent in deleted:
            top, parent = parent, _parent(parent)
        groups[top].append(old[key])
    for top in sorted(groups):
        changes.append(RegChange("key_deleted", old[top].path, extra=_deleted_summary(groups[top], old[top])))

    for key, state in new.items():
        prev = old.get(key)
        if prev is not None:
            changes.extend(diff_values(state.path, prev.values, state.values))
    return changes


class Unit:
    __slots__ = ("uid", "path", "key", "recursive", "snapshot", "dead")

    def __init__(self, uid: int, path: str, recursive: bool, snapshot: Snapshot):
        self.uid = uid
        self.path = path
        self.key = path.lower()
        self.recursive = recursive
        self.snapshot = snapshot
        self.dead = False  # key vanished; the parent unit will report and clean up

    def __repr__(self) -> str:
        return f"Unit({self.uid}, {self.path!r}, recursive={self.recursive})"


class RegistryTracker:
    """Owns the units and turns re-scans into a list of RegChange records."""

    def __init__(self, backend, split_threshold: int = 1500, skip: Iterable[str] = ()):
        self.backend = backend
        self.split_threshold = max(1, split_threshold)
        self.skip: Set[str] = {s.lower() for s in skip}
        self.units: Dict[str, Unit] = {}
        self.by_id: Dict[int, Unit] = {}
        self.stats = WalkStats()
        self._ids = itertools.count(1)

    # -- unit bookkeeping -------------------------------------------------------------------
    def _new_unit(self, path: str, recursive: bool, snapshot: Snapshot) -> Unit:
        unit = Unit(next(self._ids), path, recursive, snapshot)
        self.units[unit.key] = unit
        self.by_id[unit.uid] = unit
        return unit

    def drop(self, unit: Unit) -> None:
        if self.units.get(unit.key) is unit:
            del self.units[unit.key]
        self.by_id.pop(unit.uid, None)

    def units_under(self, key: str) -> List[Unit]:
        prefix = key + "\\"
        return [u for k, u in self.units.items() if k == key or k.startswith(prefix)]

    def new_unit(self, path: str) -> Optional[Unit]:
        """Create an (empty) recursive unit for a key that just appeared."""
        key = path.lower()
        if key in self.skip or key in self.units:
            return None
        return self._new_unit(path, True, {})

    def prime(self, unit: Unit) -> Tuple[bool, List[RegChange]]:
        """Snapshot a brand-new unit and report everything already inside it."""
        snap = take_snapshot(self.backend, unit.path, True, skip=self.skip)
        if snap is None:
            return False, []
        unit.snapshot = snap
        changes = diff_snapshots({}, snap)
        # The key itself was already reported by the parent unit.
        return True, [c for c in changes if not (c.action == "key_created" and c.key.lower() == unit.key)]

    # -- baseline ---------------------------------------------------------------------------
    def add_root(self, path: str) -> List[Unit]:
        full = take_snapshot(self.backend, path, True, stats=self.stats, skip=self.skip)
        if full is None:
            return []
        return self._partition(path.lower(), full)

    def _list_children(self, path: str) -> Dict[str, str]:
        try:
            handle = self.backend.open(path)
        except OSError:
            return {}
        try:
            return {n.lower(): n for n in self.backend.subkeys(handle)}
        finally:
            self.backend.close(handle)

    def _partition(self, root_key: str, full: Snapshot) -> List[Unit]:
        children_of: Dict[str, List[str]] = defaultdict(list)
        sizes: Dict[str, int] = defaultdict(int)
        for key in full:
            if key != root_key:
                parent = _parent(key)
                if parent is not None:
                    children_of[parent].append(key)
            node: Optional[str] = key
            while node is not None:
                sizes[node] += 1
                if node == root_key:
                    break
                node = _parent(node)

        units: List[Unit] = []
        recursive_roots: Dict[str, Unit] = {}
        stack = [root_key]
        while stack:
            key = stack.pop()
            state = full[key]
            if sizes[key] <= self.split_threshold or not children_of.get(key):
                unit = self._new_unit(state.path, True, {})
                recursive_roots[key] = unit
            else:
                # Use the real child list (it also contains unreadable/skipped children) so that
                # later re-scans do not mistake them for newly created keys.
                state.children = self._list_children(state.path)
                unit = self._new_unit(state.path, False, {key: state})
                stack.extend(children_of[key])
            units.append(unit)

        for key, state in full.items():
            node: Optional[str] = key
            while node is not None and node not in recursive_roots:
                node = None if node == root_key else _parent(node)
            if node is not None:
                recursive_roots[node].snapshot[key] = state
        return units

    # -- change processing ------------------------------------------------------------------
    def rescan(self, unit: Unit) -> Tuple[List[RegChange], List[str], List[Unit]]:
        """Re-read a unit. Returns (changes, new child keys to watch, units to stop watching)."""
        new = take_snapshot(self.backend, unit.path, unit.recursive, previous=unit.snapshot, skip=self.skip)
        if new is None:
            return self._vanished(unit)
        if unit.recursive:
            changes = diff_snapshots(unit.snapshot, new)
            unit.snapshot = new
            return changes, [], []

        old_root = unit.snapshot.get(unit.key)
        new_root = new[unit.key]
        changes = diff_values(new_root.path, old_root.values if old_root else {}, new_root.values)
        old_children = (old_root.children if old_root else None) or {}
        new_children = new_root.children or {}
        added: List[str] = []
        removed: List[Unit] = []

        for lname, name in new_children.items():
            child_path = unit.path + "\\" + name
            child_key = child_path.lower()
            if lname not in old_children:
                changes.append(RegChange("key_created", child_path))
                added.append(child_path)
                continue
            child_unit = self.units.get(child_key)
            if child_unit is not None and child_unit.dead:
                # Deleted and re-created between two scans: report both, start over.
                gone = self.units_under(child_key)
                changes.append(RegChange("key_deleted", child_path, extra=self._removed_stats(child_key, gone)))
                changes.append(RegChange("key_created", child_path))
                removed.extend(gone)
                added.append(child_path)

        for lname, name in old_children.items():
            if lname in new_children:
                continue
            child_path = unit.path + "\\" + name
            gone = self.units_under(child_path.lower())
            changes.append(RegChange("key_deleted", child_path, extra=self._removed_stats(child_path.lower(), gone)))
            removed.extend(gone)

        unit.snapshot = new
        return changes, added, removed

    def _removed_stats(self, key: str, gone: List[Unit]) -> Dict[str, Any]:
        states = [s for u in gone for s in u.snapshot.values()]
        top = next((s for s in states if s.path.lower() == key), None)
        if top is None:
            return {}
        return _deleted_summary(states, top)

    def _vanished(self, unit: Unit) -> Tuple[List[RegChange], List[str], List[Unit]]:
        parent_key = _parent(unit.key)
        parent = self.units.get(parent_key) if parent_key else None
        if parent is not None and not parent.recursive and not parent.dead:
            unit.dead = True
            return [], [], []
        gone = self.units_under(unit.key)
        return [RegChange("key_deleted", unit.path, extra=self._removed_stats(unit.key, gone))], [], gone
