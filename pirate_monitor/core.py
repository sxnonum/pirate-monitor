"""Event model, the dispatcher thread that feeds sinks, and state shared by monitors."""

from __future__ import annotations

import datetime as _dt
import itertools
import os
import queue
import sys
import threading
import time
import traceback
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

SEVERITIES = ("info", "notice", "warning", "alert")
_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}


def severity_rank(level: str) -> int:
    return _RANK.get(level, 0)


_event_ids = itertools.count(1)


@dataclass
class Event:
    category: str  # file | registry | process | network | system
    action: str
    target: str
    details: Dict[str, Any] = field(default_factory=dict)
    severity: str = "info"
    reasons: List[str] = field(default_factory=list)
    tracked: bool = False  # belongs to the tracked (sample's) process tree
    noise: bool = False  # routine background activity: logged, hidden from the console
    timestamp: float = field(default_factory=time.time)
    id: int = field(default_factory=lambda: next(_event_ids))

    def flag(self, level: str, reason: Optional[str] = None) -> None:
        if severity_rank(level) > severity_rank(self.severity):
            self.severity = level
        if reason and reason not in self.reasons:
            self.reasons.append(reason)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "time": _dt.datetime.fromtimestamp(self.timestamp).isoformat(timespec="milliseconds"),
            "category": self.category,
            "action": self.action,
            "target": self.target,
            "severity": self.severity,
            "reasons": self.reasons,
            "tracked": self.tracked,
            "noise": self.noise,
            "details": self.details,
        }


class EventBus:
    """Monitors call emit() from any thread; one dispatcher thread grades and fans out events."""

    def __init__(self, rules=None):
        self._queue: "queue.Queue[Optional[Event]]" = queue.Queue()
        self._sinks: list = []
        self._rules = rules
        self._thread = threading.Thread(target=self._run, name="pm-dispatch", daemon=True)
        self._reported_errors: set = set()

    def add_sink(self, sink) -> None:
        self._sinks.append(sink)

    def start(self) -> None:
        self._thread.start()

    def emit(self, event: Event) -> None:
        self._queue.put(event)

    def system(self, message: str, level: str = "info", **details: Any) -> None:
        self.emit(Event("system", "message", message, details, severity=level))

    def _run(self) -> None:
        while True:
            event = self._queue.get()
            if event is None:
                break
            if self._rules is not None and event.category != "system":
                try:
                    self._rules.apply(event)
                except Exception:
                    self._report_error("rules")
            for sink in self._sinks:
                try:
                    sink.handle(event)
                except Exception:
                    self._report_error(type(sink).__name__)

    def _report_error(self, where: str) -> None:
        if where in self._reported_errors:
            return
        self._reported_errors.add(where)
        sys.stderr.write(f"[pirate-monitor] internal error in {where}:\n{traceback.format_exc()}\n")

    def stop(self, timeout: float = 30.0) -> None:
        self._queue.put(None)
        self._thread.join(timeout)
        for sink in self._sinks:
            try:
                sink.close()
            except Exception:
                self._report_error(type(sink).__name__ + ".close")


class SessionState:
    """Facts that one monitor learns and another needs (dropped files, tracked processes)."""

    def __init__(self, track_names=()):
        self._lock = threading.Lock()
        self._dropped: Dict[str, str] = {}
        self._tracked: Dict[int, float] = {}
        names = set()
        for n in track_names:
            n = n.strip().lower()
            if n:
                names.add(n)
                names.add(os.path.splitext(n)[0])
        self.track_names = frozenset(names)
        self.started_at = time.time()

    # Files written during the session that can execute code.
    def add_dropped(self, path: str) -> None:
        key = os.path.normcase(os.path.abspath(path))
        with self._lock:
            self._dropped[key] = path

    def is_dropped(self, path: Optional[str]) -> bool:
        if not path:
            return False
        key = os.path.normcase(os.path.abspath(path))
        with self._lock:
            return key in self._dropped

    def dropped_in_text(self, text: Optional[str]) -> Optional[str]:
        """Return a dropped file mentioned in a command line, if any."""
        if not text:
            return None
        hay = os.path.normcase(text)
        with self._lock:
            items = list(self._dropped.items())
        for key, original in items:
            if key in hay:
                return original
        return None

    def dropped_count(self) -> int:
        with self._lock:
            return len(self._dropped)

    # Processes belonging to the sample's tree, keyed by pid with create time to survive pid reuse.
    def track(self, pid: int, create_time: float) -> None:
        with self._lock:
            self._tracked[pid] = create_time

    def tracked_ctime(self, pid: Optional[int]) -> Optional[float]:
        if pid is None:
            return None
        with self._lock:
            return self._tracked.get(pid)

    def is_tracked(self, pid: Optional[int], create_time: Optional[float]) -> bool:
        ctime = self.tracked_ctime(pid)
        if ctime is None:
            return False
        return create_time is None or abs(ctime - create_time) < 1.0

    def tracked_count(self) -> int:
        with self._lock:
            return len(self._tracked)

    def matches_track_name(self, name: Optional[str]) -> bool:
        if not name or not self.track_names:
            return False
        name = name.lower()
        return name in self.track_names or os.path.splitext(name)[0] in self.track_names
