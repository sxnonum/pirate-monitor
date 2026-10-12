"""File-system monitor: created / modified / deleted / renamed files, plus analysis of dropped executables."""

from __future__ import annotations

import fnmatch
import os
import queue
import re
import stat
import time
from typing import Dict, Iterable, List, Optional

from ..core import Event
from ..util import (
    DOCUMENT_EXTS,
    PE_EXTS,
    RISKY_EXTS,
    HashCache,
    classify_file,
    file_ext,
    read_magic,
)
from .base import Monitor

_INTERESTING = ("created", "modified", "deleted", "moved")


def _compile_globs(globs: Iterable[str]) -> Optional["re.Pattern[str]"]:
    parts = [fnmatch.translate(os.path.normcase(g)) for g in globs if g]
    if not parts:
        return None
    return re.compile("|".join(f"(?:{p})" for p in parts))


class FileSystemMonitor(Monitor):
    name = "files"

    def __init__(
        self,
        bus,
        state,
        paths: Iterable[str],
        exclude_globs: Iterable[str] = (),
        noise_globs: Iterable[str] = (),
        exclude_prefixes: Iterable[str] = (),
        hash_max_bytes: int = 50 * 1024 * 1024,
        quiet_seconds: float = 2.0,
        coalesce_seconds: float = 3.0,
    ):
        super().__init__(bus, state)
        self.paths = list(paths)
        self._exclude_re = _compile_globs(exclude_globs)
        self._noise_re = _compile_globs(noise_globs)
        self._prefixes = [os.path.normcase(os.path.abspath(p)) for p in exclude_prefixes]
        self._hashes = HashCache(hash_max_bytes)
        self.quiet_seconds = quiet_seconds
        self.coalesce_seconds = coalesce_seconds
        self._raw: "queue.Queue[tuple]" = queue.Queue()
        self._pending: Dict[str, float] = {}  # files waiting to settle before inspection
        self._last_emit: Dict[str, float] = {}
        self._observer = None
        self.watched: List[str] = []
        self.suppressed = 0

    # -- setup ------------------------------------------------------------------------------
    def start(self) -> None:
        from watchdog.events import FileSystemEventHandler
        from watchdog.observers import Observer

        raw = self._raw

        class _Handler(FileSystemEventHandler):
            def on_any_event(self, event):
                if event.event_type not in _INTERESTING:
                    return
                dest = getattr(event, "dest_path", None) or None
                raw.put((time.time(), event.event_type, os.fsdecode(event.src_path),
                         os.fsdecode(dest) if dest else None, event.is_directory))

        self._observer = Observer()
        handler = _Handler()
        for path in self.paths:
            if not os.path.isdir(path):
                self.bus.system(f"[files] not a folder, skipped: {path}", "notice")
                continue
            try:
                self._observer.schedule(handler, path, recursive=True)
                self.watched.append(path)
            except Exception as exc:
                self.bus.system(f"[files] cannot watch {path}: {exc}", "warning")
        try:
            self._observer.start()
        except Exception as exc:
            # inotify watch limits and similar problems surface here on Linux.
            self.bus.system(f"[files] file watching failed to start: {exc}", "warning")
            self.ready.set()
            return
        self._spawn(self._worker, "worker")
        self.bus.system(f"[files] watching {len(self.watched)} location(s): " + ", ".join(self.watched))
        self.ready.set()

    def stop(self) -> None:
        super().stop()
        if self._observer is not None:
            try:
                self._observer.stop()
                self._observer.join(timeout=5)
            except Exception:
                pass

    # -- filtering --------------------------------------------------------------------------
    def _excluded(self, path: Optional[str]) -> bool:
        if not path:
            return True
        norm = os.path.normcase(path)
        for prefix in self._prefixes:
            if norm == prefix or norm.startswith(prefix + os.sep):
                return True
        return bool(self._exclude_re and self._exclude_re.match(norm))

    def _is_noise(self, path: str) -> bool:
        return bool(self._noise_re and self._noise_re.match(os.path.normcase(path)))

    # -- processing -------------------------------------------------------------------------
    def _worker(self) -> None:
        while not self._stop.is_set():
            try:
                item = self._raw.get(timeout=0.25)
            except queue.Empty:
                item = None
            if item is not None:
                self._handle(item)
                for _ in range(5000):
                    try:
                        self._handle(self._raw.get_nowait())
                    except queue.Empty:
                        break
            self._inspect_settled()
            self._prune()

    def _emit(self, action: str, path: str, details: dict) -> None:
        self.bus.emit(Event("file", action, path, details, noise=self._is_noise(path)))

    def _handle(self, item: tuple) -> None:
        ts, kind, src, dest, is_dir = item
        if kind == "moved":
            src_out, dest_out = self._excluded(src), self._excluded(dest)
            if src_out and dest_out:
                return
            if src_out:
                kind, src, dest = "created", dest, None
            elif dest_out:
                kind, dest = "deleted", None
        elif self._excluded(src):
            return

        if is_dir:
            if kind == "modified":
                return
            details = {"from": src} if kind == "moved" else {}
            self._emit("folder_" + kind, dest if kind == "moved" else src, details)
            return

        if kind == "created":
            self._last_emit[src] = ts
            self._pending[src] = ts
            details = self._stat_details(src)
            if file_ext(src) in RISKY_EXTS:
                self.state.add_dropped(src)
            self._emit("created", src, details)
        elif kind == "modified":
            self._pending[src] = ts
            if ts - self._last_emit.get(src, 0.0) < self.coalesce_seconds:
                self.suppressed += 1
                return
            self._last_emit[src] = ts
            self._emit("modified", src, self._stat_details(src))
        elif kind == "deleted":
            self._pending.pop(src, None)
            self._last_emit.pop(src, None)
            details = {"dropped_this_session": True} if self.state.is_dropped(src) else {}
            self._emit("deleted", src, details)
        elif kind == "moved":
            self._pending.pop(src, None)
            self._pending[dest] = ts
            self._last_emit[dest] = ts
            if file_ext(dest) in RISKY_EXTS or self.state.is_dropped(src):
                self.state.add_dropped(dest)
            details = {"from": src}
            details.update(self._stat_details(dest))
            self._emit("moved", dest, details)

    @staticmethod
    def _stat_details(path: str) -> dict:
        try:
            return {"size": os.stat(path).st_size}
        except OSError:
            return {}

    def _inspect_settled(self) -> None:
        """Once a file has stopped changing, check whether it can run code and hash it."""
        if not self._pending:
            return
        now = time.time()
        settled = [p for p, t in self._pending.items() if now - t >= self.quiet_seconds]
        for path in settled:
            del self._pending[path]
            if self._is_noise(path) and file_ext(path) not in RISKY_EXTS:
                continue
            self._inspect(path)

    def _inspect(self, path: str) -> None:
        try:
            st = os.stat(path)
        except OSError:
            return
        if not stat.S_ISREG(st.st_mode) or st.st_size == 0:
            return
        magic = read_magic(path)
        kind = classify_file(path, magic)
        if kind is None:
            return
        self.state.add_dropped(path)
        digest = self._hashes.get(path)
        details = {
            "kind": kind,
            "size": st.st_size,
            "sha256": digest or ("(file too large to hash)" if st.st_size > self._hashes.max_bytes else "(unreadable)"),
        }
        ext = file_ext(path)
        if kind == "PE executable" and ext not in PE_EXTS:
            details["disguised_as"] = ext or "(no extension)"
        elif kind in ("ELF executable", "Mach-O executable") and ext in DOCUMENT_EXTS:
            details["disguised_as"] = ext
        self._emit("executable", path, details)

    def _prune(self) -> None:
        if len(self._last_emit) < 20000:
            return
        cutoff = time.time() - 60
        self._last_emit = {p: t for p, t in self._last_emit.items() if t >= cutoff}
