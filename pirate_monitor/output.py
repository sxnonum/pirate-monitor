"""Live console output and the JSON-lines event log."""

from __future__ import annotations

import json
import sys
import time
from typing import List

from .core import Event, severity_rank
from .util import human_size, shorten

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
SEV_STYLE = {
    "info": ("INFO ", "\033[37m"),
    "notice": ("NOTE ", "\033[36m"),
    "warning": ("WARN ", "\033[33;1m"),
    "alert": ("ALERT", "\033[41;97;1m"),
}
REASON_STYLE = {"info": "\033[37m", "notice": "\033[36m", "warning": "\033[33m", "alert": "\033[91;1m"}
CAT_STYLE = {
    "file": ("FILE", "\033[34;1m"),
    "registry": ("REG ", "\033[35;1m"),
    "process": ("PROC", "\033[32;1m"),
    "network": ("NET ", "\033[96;1m"),
    "system": ("----", "\033[37;1m"),
}
INDENT = " " * 21


def describe(ev: Event) -> List[str]:
    """Human readable detail lines for an event (without the header line)."""
    d = ev.details
    lines: List[str] = []
    if ev.category == "registry":
        name = d.get("value")
        if ev.action == "value_created":
            lines.append(f'"{name}" = {d.get("new")}   [{d.get("type")}]')
        elif ev.action == "value_modified":
            lines.append(f'"{name}": {d.get("old")}  ->  {d.get("new")}   [{d.get("type")}]')
        elif ev.action == "value_deleted":
            lines.append(f'"{name}" removed (was {d.get("old")})')
        elif ev.action == "key_deleted" and (d.get("subkeys_removed") or d.get("values_removed")):
            lines.append(f"{d.get('subkeys_removed', 0)} subkeys and {d.get('values_removed', 0)} values removed with it")
    elif ev.category == "file":
        if ev.action in ("moved", "folder_moved"):
            lines.append(f"renamed/moved from {d.get('from')}")
        if ev.action == "executable":
            text = f"{d.get('kind')}, {human_size(d.get('size'))}, sha256 {d.get('sha256')}"
            if d.get("disguised_as"):
                text += f"  (named {d['disguised_as']})"
            lines.append(text)
        elif ev.action in ("created", "modified") and d.get("size") is not None:
            lines.append(human_size(d.get("size")))
    elif ev.category == "process":
        if ev.action == "started":
            parent = d.get("parent") or "?"
            line = f"pid {d.get('pid')}  parent {parent} ({d.get('ppid')})"
            if d.get("user"):
                line += f"  user {d['user']}"
            if d.get("sha256"):
                line += f"  sha256 {d['sha256'][:16]}..."
            lines.append(line)
            if d.get("cmdline"):
                lines.append("cmd: " + shorten(d["cmdline"], 500))
        elif ev.action == "exited":
            runtime = d.get("runtime_seconds")
            lines.append(f"pid {d.get('pid')}" + (f"  ran {runtime}s" if runtime is not None else ""))
        elif ev.action == "tracking":
            lines.append(f"pid {d.get('pid')}  {d.get('note', '')}")
    elif ev.category == "network":
        who = f"{d.get('process')} (pid {d.get('pid')})"
        if ev.action == "connection":
            status = f" [{d['status']}]" if d.get("status") else ""
            lines.append(f"{who}  {d.get('direction', '')} from {d.get('local')}{status}")
        else:
            lines.append(who)
    return lines


class ConsoleSink:
    def __init__(self, min_severity="info", show_noise=False, only_tracked=False, color=True,
                 quiet=False, stream=None):
        self.min_rank = severity_rank(min_severity)
        self.show_noise = show_noise
        self.only_tracked = only_tracked
        self.color = color
        self.quiet = quiet
        self.stream = stream or sys.stdout

    def _c(self, style: str, text: str) -> str:
        return f"{style}{text}{RESET}" if self.color else text

    def handle(self, ev: Event) -> None:
        if ev.category == "system":
            self._write(self._system_line(ev))
            return
        if self.quiet:
            return
        if ev.noise and not self.show_noise:
            return
        if severity_rank(ev.severity) < self.min_rank:
            return
        if self.only_tracked and ev.category in ("process", "network") and not ev.tracked:
            return
        self._write(self.format(ev))

    def _system_line(self, ev: Event) -> str:
        ts = time.strftime("%H:%M:%S", time.localtime(ev.timestamp))
        style = {"warning": "\033[33;1m", "notice": "\033[36;1m"}.get(ev.severity, BOLD)
        return f"{self._c(DIM, ts)}  {self._c(style, ev.target)}"

    def format(self, ev: Event) -> str:
        ts = time.strftime("%H:%M:%S", time.localtime(ev.timestamp)) + f".{int(ev.timestamp * 1000) % 1000:03d}"
        sev_label, sev_style = SEV_STYLE.get(ev.severity, SEV_STYLE["info"])
        cat_label, cat_style = CAT_STYLE.get(ev.category, (ev.category[:4].upper(), ""))
        mark = self._c("\033[95;1m", "*") if ev.tracked else " "
        head = (
            f"{self._c(DIM, ts)} {self._c(sev_style, sev_label)} {mark}{self._c(cat_style, cat_label)} "
            f"{ev.action:<15} {ev.target}"
        )
        lines = [head]
        for line in describe(ev):
            lines.append(INDENT + self._c(DIM, line))
        reason_style = REASON_STYLE.get(ev.severity, "")
        for reason in ev.reasons:
            lines.append(INDENT + self._c(reason_style, "! " + reason))
        return "\n".join(lines)

    def _write(self, text: str) -> None:
        try:
            self.stream.write(text + "\n")
            self.stream.flush()
        except (UnicodeEncodeError, ValueError):
            pass

    def close(self) -> None:
        pass


class JsonlSink:
    """Every event (noise included) as one JSON object per line - easy to grep or load later."""

    def __init__(self, path: str):
        self.path = path
        self._fh = open(path, "a", encoding="utf-8")

    def handle(self, ev: Event) -> None:
        self._fh.write(json.dumps(ev.to_dict(), ensure_ascii=False, default=str) + "\n")
        self._fh.flush()

    def close(self) -> None:
        self._fh.close()
