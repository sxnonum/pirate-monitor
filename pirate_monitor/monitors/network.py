"""Network monitor: new TCP connections, listening ports and UDP sockets, with the owning process."""

from __future__ import annotations

import socket
from typing import Dict, Optional, Tuple

import psutil

from ..core import Event
from .base import Monitor


def _fmt_addr(addr) -> str:
    if not addr:
        return ""
    ip, port = addr[0], addr[1]
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def _is_loopback(ip: str) -> bool:
    return ip.startswith("127.") or ip in ("::1", "localhost") or ip.startswith("::ffff:127.")


class NetworkMonitor(Monitor):
    name = "network"

    def __init__(self, bus, state, interval: float = 1.0):
        super().__init__(bus, state)
        self.interval = interval
        self._prev: Dict[tuple, object] = {}
        self._procs: Dict[int, Tuple[str, Optional[str], Optional[float]]] = {}

    def start(self) -> None:
        try:
            self._prev = self._snapshot()
        except psutil.AccessDenied:
            self.bus.system("[network] access denied listing sockets - run as Administrator/root", "warning")
            self.ready.set()
            return
        self.bus.system(f"[network] baseline: {len(self._prev)} open sockets")
        self._spawn(self._loop, "poll")
        self.ready.set()

    def _snapshot(self) -> Dict[tuple, object]:
        result = {}
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == psutil.CONN_TIME_WAIT:
                continue
            proto = "tcp" if conn.type == socket.SOCK_STREAM else "udp"
            local = _fmt_addr(conn.laddr)
            remote = _fmt_addr(conn.raddr)
            if proto == "tcp" and conn.status == psutil.CONN_LISTEN:
                kind = "listening"
            elif remote:
                kind = "connection"
            elif proto == "udp":
                kind = "udp_socket"
            else:
                continue
            result[(conn.pid, proto, local, remote, kind)] = conn
        return result

    def _loop(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                current = self._snapshot()
            except Exception:
                continue
            listening_ports = {conn.laddr[1] for key, conn in current.items() if key[4] == "listening" and conn.laddr}
            for key in current.keys() - self._prev.keys():
                self._emit(key, current[key], listening_ports)
            self._prev = current
            live = {key[0] for key in current}
            for pid in list(self._procs):
                if pid not in live:
                    del self._procs[pid]

    def _process(self, pid: Optional[int]) -> Tuple[str, Optional[str], Optional[float]]:
        if not pid:
            return ("?", None, None)
        cached = self._procs.get(pid)
        if cached is not None:
            return cached
        try:
            proc = psutil.Process(pid)
            with proc.oneshot():
                name = proc.name()
                try:
                    exe = proc.exe()
                except (psutil.AccessDenied, OSError):
                    exe = None
                ctime = proc.create_time()
            info = (name, exe, ctime)
        except psutil.Error:
            info = ("?", None, None)
        self._procs[pid] = info
        return info

    def _emit(self, key: tuple, conn, listening_ports: set) -> None:
        pid, proto, local, remote, kind = key
        name, exe, ctime = self._process(pid)
        details = {
            "pid": pid,
            "process": name,
            "exe": exe,
            "proto": proto,
            "local": local,
            "status": conn.status if conn.status != psutil.CONN_NONE else None,
        }
        if conn.laddr:
            details["local_port"] = conn.laddr[1]
        if remote:
            details["remote"] = remote
            details["remote_ip"] = conn.raddr[0]
            details["remote_port"] = conn.raddr[1]
            details["loopback"] = _is_loopback(conn.raddr[0])
            if proto == "tcp":
                details["direction"] = "inbound" if conn.laddr and conn.laddr[1] in listening_ports else "outbound"
            target = f"{proto.upper()} {remote}"
        else:
            details["loopback"] = bool(conn.laddr) and _is_loopback(conn.laddr[0])
            target = f"{proto.upper()} {local}"
        tracked = self.state.is_tracked(pid, ctime) if pid else False
        self.bus.emit(Event("network", kind, target, details, tracked=tracked))
