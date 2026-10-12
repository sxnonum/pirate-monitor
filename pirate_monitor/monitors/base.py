from __future__ import annotations

import threading
import time
import traceback

from ..core import EventBus, SessionState


class Monitor:
    name = "monitor"

    def __init__(self, bus: EventBus, state: SessionState):
        self.bus = bus
        self.state = state
        self.ready = threading.Event()  # set once the baseline is taken and changes are being watched
        self._stop = threading.Event()
        self.failed = None
        self._threads: list = []

    def start(self) -> None:
        raise NotImplementedError

    def stop(self) -> None:
        self._stop.set()

    def join(self, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        for thread in self._threads:
            thread.join(max(0.0, deadline - time.monotonic()))

    def _spawn(self, target, name: str) -> threading.Thread:
        def run():
            try:
                target()
            except Exception as exc:
                self.failed = exc
                self.bus.system(
                    f"[{self.name}] monitor stopped because of an error: {exc!r}",
                    level="warning",
                    traceback=traceback.format_exc(),
                )
            finally:
                self.ready.set()

        thread = threading.Thread(target=run, name=f"pm-{self.name}-{name}", daemon=True)
        thread.start()
        self._threads.append(thread)
        return thread
