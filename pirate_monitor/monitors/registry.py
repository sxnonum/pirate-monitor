"""Live registry monitor (Windows): baseline snapshot + change notifications + exact diffs."""

from __future__ import annotations

import time
from typing import Iterable, List, Optional

from ..core import Event
from ..registry.model import REG_TYPES, RegChange, RegistryTracker, canonical_key_path, format_value
from ..util import is_admin
from .base import Monitor


class PollingNotifier:
    """Fallback when change notifications are unavailable: every unit is re-scanned periodically."""

    def attach(self, unit) -> bool:
        return False

    def rearm(self, unit) -> bool:
        return False

    def detach(self, unit) -> None:
        pass

    signalled_at: dict = {}
    signal_count = 0

    def wait(self, timeout: float) -> List[int]:
        time.sleep(timeout)
        return []

    def describe(self, unit) -> dict:
        return {"attached": False}

    def close(self) -> None:
        pass


def change_to_event(change: RegChange) -> Event:
    details = {"key": change.key}
    if change.value is not None:
        details["value"] = change.value or "(Default)"
        details["type"] = REG_TYPES.get(change.vtype, str(change.vtype))
        if change.action in ("value_modified", "value_deleted"):
            old_type = change.extra.get("old_type", change.vtype)
            details["old"] = format_value(old_type, change.old)
        if change.action in ("value_created", "value_modified"):
            details["new"] = format_value(change.vtype, change.new)
    if change.action == "key_deleted" and change.extra:
        details["subkeys_removed"] = change.extra.get("subkeys_removed", 0)
        details["values_removed"] = change.extra.get("values_removed", 0)
        removed = change.extra.get("removed_values") or []
        if removed:
            details["removed_values"] = {
                (name or "(Default)"): format_value(vtype, data, limit=200) for name, vtype, data in removed
            }
    return Event("registry", change.action, change.key, details)


class RegistryMonitor(Monitor):
    name = "registry"

    def __init__(
        self,
        bus,
        state,
        roots: Iterable[str],
        skip: Iterable[str] = (),
        poll_interval: Optional[float] = None,
        split_threshold: int = 1500,
        backend_factory=None,
        notifier_factory=None,
    ):
        super().__init__(bus, state)
        self.roots = [canonical_key_path(r) for r in roots]
        self.skip = [canonical_key_path(s) for s in skip]
        self.poll_interval = poll_interval
        self.split_threshold = split_threshold
        self._backend_factory = backend_factory
        self._notifier_factory = notifier_factory
        self.tracker: Optional[RegistryTracker] = None
        self.notifier = None
        self._polling: set = set()
        self.mode = "notifications"
        self.rescans = 0
        self.rescan_seconds = 0.0
        self.slowest = (0.0, "")
        self.max_lag = 0.0

    def start(self) -> None:
        self._spawn(self._run, "worker")

    def _make_backend_and_notifier(self):
        if self._backend_factory is not None:
            backend = self._backend_factory()
        else:
            from ..registry.win32 import WinregBackend

            backend = WinregBackend()
        if self._notifier_factory is not None:
            notifier = self._notifier_factory()
        elif self.poll_interval:
            notifier = PollingNotifier()
        else:
            try:
                from ..registry.win32 import Win32Notifier

                notifier = Win32Notifier()
            except Exception as exc:
                self.bus.system(f"[registry] change notifications unavailable ({exc!r}); polling instead", "warning")
                notifier = PollingNotifier()
        if isinstance(notifier, PollingNotifier):
            self.mode = "polling"
            self.poll_interval = self.poll_interval or 5.0
        return backend, notifier

    def _run(self) -> None:
        backend, self.notifier = self._make_backend_and_notifier()
        self.tracker = RegistryTracker(backend, self.split_threshold, self.skip)
        try:
            self._baseline()
            self.ready.set()
            self._loop()
        finally:
            self.notifier.close()
            if self.ready.is_set() and self.tracker.units:
                self.bus.system(self.stats_line())

    def stats_line(self) -> str:
        dead = sum(1 for u in self.tracker.units.values() if u.dead)
        return (
            f"[registry] {self.notifier.signal_count:,} change notifications, {self.rescans:,} re-scans "
            f"({self.rescan_seconds:.1f}s, slowest {self.slowest[0]:.2f}s {self.slowest[1]}), "
            f"max delay {self.max_lag:.1f}s, {len(self.tracker.units):,} units "
            f"({len(self._polling)} polled, {dead} dead)"
        )

    def unit_covering(self, path: str):
        key = canonical_key_path(path).lower()
        best = None
        for ukey, unit in self.tracker.units.items():
            if key == ukey or key.startswith(ukey + "\\"):
                if best is None or len(ukey) > len(best.key):
                    best = unit
        return best

    def diagnose(self, path: str) -> dict:
        """Debug helper: what is watching ``path`` right now."""
        unit = self.unit_covering(path)
        if unit is None:
            return {"unit": None}
        info = {
            "unit": unit.path,
            "uid": unit.uid,
            "recursive": unit.recursive,
            "dead": unit.dead,
            "polled": unit.uid in self._polling,
            "keys": len(unit.snapshot),
        }
        state = unit.snapshot.get(canonical_key_path(path).lower())
        if state is not None:
            info["cached_last_write"] = state.last_write
            info["cached_read_time"] = round(state.read_time, 3)
            info["cached_values"] = sorted(v[0] for v in state.values.values())
        info.update(self.notifier.describe(unit))
        info["stats"] = self.stats_line()
        return info

    def _baseline(self) -> None:
        started = time.monotonic()
        self.bus.system(f"[registry] taking baseline of {len(self.roots)} key trees (may take a few seconds)...")
        unit_count = 0
        for root in self.roots:
            if self._stop.is_set():
                return
            units = self.tracker.add_root(root)
            if not units:
                self.bus.system(f"[registry] cannot read {root} (missing or access denied) - not watched", "notice")
                continue
            for unit in units:
                self._attach(unit)
            unit_count += len(units)
        stats = self.tracker.stats
        how = "live notifications" if self.mode == "notifications" else f"polling every {self.poll_interval:g}s"
        msg = (
            f"[registry] baseline ready: {stats.keys:,} keys / {stats.values:,} values in "
            f"{time.monotonic() - started:.1f}s, {unit_count} watch units, {how}"
        )
        if stats.denied:
            hint = "" if is_admin() else " - run as Administrator to see them"
            msg += f" ({stats.denied:,} protected keys not readable{hint})"
        if self._polling and self.mode == "notifications":
            msg += f"; {len(self._polling)} units polled"
        self.bus.system(msg)

    def _loop(self) -> None:
        interval = self.poll_interval or 5.0
        last_poll = time.monotonic()
        while not self._stop.is_set():
            ids = self.notifier.wait(0.5)
            due: List[int] = []
            now = time.monotonic()
            if self._polling and now - last_poll >= interval:
                due = list(self._polling)
                last_poll = now
            for uid in dict.fromkeys(ids + due):
                signalled = self.notifier.signalled_at.pop(uid, None)
                unit = self.tracker.by_id.get(uid)
                if unit is None or unit.dead:
                    continue
                started = time.monotonic()
                if signalled is not None:
                    self.max_lag = max(self.max_lag, started - signalled)
                self._process(unit, polled=uid in self._polling)
                took = time.monotonic() - started
                self.rescans += 1
                self.rescan_seconds += took
                if took > self.slowest[0]:
                    self.slowest = (took, unit.path)

    def _attach(self, unit) -> None:
        if not self.notifier.attach(unit):
            self._polling.add(unit.uid)

    def _detach(self, unit) -> None:
        self.notifier.detach(unit)
        self._polling.discard(unit.uid)
        self.tracker.drop(unit)

    def _process(self, unit, polled: bool) -> None:
        if not polled and not self.notifier.rearm(unit):
            self._polling.add(unit.uid)
        changes, added, removed = self.tracker.rescan(unit)
        for gone in removed:
            self._detach(gone)
        self._emit(changes)
        for path in added:
            child = self.tracker.new_unit(path)
            if child is None:
                continue
            self._attach(child)
            ok, initial = self.tracker.prime(child)
            if not ok:
                self._detach(child)
                continue
            self._emit(initial)

    def _emit(self, changes: List[RegChange]) -> None:
        for change in changes:
            self.bus.emit(change_to_event(change))
