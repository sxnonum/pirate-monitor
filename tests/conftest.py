import threading
import time

import pytest

from pirate_monitor.core import EventBus, SessionState
from pirate_monitor.rules import Rules


class ListSink:
    def __init__(self):
        self.events = []
        self._lock = threading.Lock()

    def handle(self, ev):
        with self._lock:
            self.events.append(ev)

    def close(self):
        pass

    def snapshot(self):
        with self._lock:
            return list(self.events)

    def find(self, category=None, action=None, target_contains=None, **details):
        out = []
        for ev in self.snapshot():
            if category and ev.category != category:
                continue
            if action and ev.action != action:
                continue
            if target_contains and target_contains.lower() not in ev.target.lower():
                continue
            if any(ev.details.get(k) != v for k, v in details.items()):
                continue
            out.append(ev)
        return out


def wait_for(predicate, timeout=10.0, interval=0.05):
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(interval)
    return predicate()


@pytest.fixture
def session():
    """A started EventBus with rules and a list sink; stopped after the test."""
    state = SessionState()
    bus = EventBus(Rules(state))
    sink = ListSink()
    bus.add_sink(sink)
    bus.start()
    yield bus, state, sink
    bus.stop()
