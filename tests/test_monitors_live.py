"""Exercise the real file, process and network monitors on whatever OS the tests run on."""

import os
import socket
import subprocess
import sys

import pytest

from pirate_monitor.monitors.filesystem import FileSystemMonitor
from pirate_monitor.monitors.network import NetworkMonitor
from pirate_monitor.monitors.processes import ProcessMonitor

from conftest import wait_for

IS_WINDOWS = sys.platform == "win32"


@pytest.fixture
def watched(tmp_path):
    folder = tmp_path / "watched"
    folder.mkdir()
    (tmp_path / "logs").mkdir()
    return tmp_path


def test_file_monitor_reports_and_inspects_dropped_files(session, watched):
    bus, state, sink = session
    folder = watched / "watched"
    monitor = FileSystemMonitor(bus, state, [str(folder)], exclude_globs=["*.ignored"],
                                noise_globs=[os.path.join("*", "cache", "*")], quiet_seconds=0.5)
    monitor.start()
    assert monitor.ready.wait(10) and monitor.watched

    try:
        exe = folder / "holiday.jpg"
        exe.write_bytes(b"MZ\x90\x00" + b"\x00" * 200)
        script = folder / "run.bat"
        script.write_text("@echo off\n")
        (folder / "skip.ignored").write_text("x")
        (folder / "cache").mkdir()
        (folder / "cache" / "blob.dat").write_text("x")
        doc = folder / "notes.txt"
        doc.write_text("hello")
        doc.rename(folder / "notes.txt.locked")

        found = wait_for(lambda: sink.find("file", "executable", target_contains="holiday.jpg"))
        assert found, [e.to_dict() for e in sink.snapshot()]
        ev = found[0]
        assert ev.details["kind"] == "PE executable"
        assert ev.details["disguised_as"] == ".jpg"
        assert len(ev.details["sha256"]) == 64
        assert ev.severity == "alert"
        assert state.is_dropped(str(exe))

        assert wait_for(lambda: sink.find("file", "created", target_contains="run.bat"))
        assert state.is_dropped(str(script))
        moved = wait_for(lambda: sink.find("file", "moved", target_contains="notes.txt.locked"))
        assert moved and moved[0].details["from"].endswith("notes.txt")
        noise = wait_for(lambda: [e for e in sink.find("file", target_contains="blob.dat") if e.noise])
        assert noise

        os.remove(exe)
        deleted = wait_for(lambda: sink.find("file", "deleted", target_contains="holiday.jpg"))
        assert deleted and deleted[0].details.get("dropped_this_session")
        assert not sink.find("file", target_contains="skip.ignored")
    finally:
        monitor.stop()


def test_file_monitor_skips_excluded_prefix(session, watched):
    bus, state, sink = session
    logs = watched / "logs"
    monitor = FileSystemMonitor(bus, state, [str(watched)], exclude_prefixes=[str(logs)], quiet_seconds=0.3)
    monitor.start()
    assert monitor.ready.wait(10)
    try:
        (logs / "events.jsonl").write_text("{}\n")
        (watched / "watched" / "marker.txt").write_text("x")
        assert wait_for(lambda: sink.find("file", "created", target_contains="marker.txt"))
        assert not sink.find("file", target_contains="events.jsonl")
    finally:
        monitor.stop()


CHILD_SCRIPT = (
    "import subprocess, sys, time;"
    "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(1.5)']);"
    "time.sleep(2)"
)


def test_process_monitor_tracks_launched_tree(session):
    bus, state, sink = session
    monitor = ProcessMonitor(bus, state, interval=0.1, use_wmi=True)
    monitor.start()
    assert monitor.ready.wait(10)
    try:
        popen = monitor.launch([sys.executable, "-c", CHILD_SCRIPT], new_console=False)
        root = wait_for(lambda: sink.find("process", "started", pid=popen.pid))
        assert root and root[0].tracked
        assert "time.sleep(2)" in root[0].details["cmdline"]

        child = wait_for(lambda: sink.find("process", "started", ppid=popen.pid))
        assert child, [e.to_dict() for e in sink.find("process")]
        assert child[0].tracked
        assert any("tracked" in r for r in child[0].reasons)

        popen.wait(10)
        exited = wait_for(lambda: sink.find("process", "exited", pid=popen.pid))
        assert exited and exited[0].tracked and not exited[0].noise
        assert wait_for(lambda: not monitor.tracked_alive(), timeout=10)
    finally:
        monitor.stop()


def test_process_running_dropped_file_is_tracked_and_alerted(session, tmp_path):
    bus, state, sink = session
    script = tmp_path / "dropper_payload.py"
    script.write_text("import time; time.sleep(1)\n")
    state.add_dropped(str(script))
    monitor = ProcessMonitor(bus, state, interval=0.1, use_wmi=False)
    monitor.start()
    assert monitor.ready.wait(10)
    try:
        proc = subprocess.Popen([sys.executable, str(script)])
        found = wait_for(lambda: sink.find("process", "started", pid=proc.pid))
        assert found
        ev = found[0]
        assert ev.tracked
        assert ev.details.get("dropped_reference")
        assert ev.severity == "alert"
        proc.wait(10)
    finally:
        monitor.stop()


def test_network_monitor_sees_new_listener_and_connection(session):
    bus, state, sink = session
    monitor = NetworkMonitor(bus, state, interval=0.2)
    monitor.start()
    assert monitor.ready.wait(10)
    server = socket.socket()
    try:
        server.bind(("0.0.0.0", 0))
        server.listen()
        port = server.getsockname()[1]
        client = socket.create_connection(("127.0.0.1", port))
        conn, _ = server.accept()

        listening = wait_for(lambda: sink.find("network", "listening", local_port=port))
        assert listening, [e.to_dict() for e in sink.find("network")]
        assert listening[0].details["pid"] == os.getpid()
        assert listening[0].severity == "warning"
        outbound = wait_for(lambda: sink.find("network", "connection", remote_port=port))
        assert outbound and outbound[0].details["direction"] == "outbound"
        inbound = wait_for(lambda: sink.find("network", "connection", local_port=port))
        assert inbound and inbound[0].details["direction"] == "inbound"
        client.close()
        conn.close()
    finally:
        server.close()
        monitor.stop()


@pytest.mark.skipif(not IS_WINDOWS, reason="WMI tracing is Windows only")
def test_wmi_catches_short_lived_processes(session):
    bus, state, sink = session
    monitor = ProcessMonitor(bus, state, interval=30.0, use_wmi=True)  # polling too slow to see it
    monitor.start()
    assert monitor.ready.wait(10)
    try:
        assert wait_for(lambda: monitor.wmi_active, timeout=30), [e.target for e in sink.find("system")]
        proc = subprocess.Popen(["cmd.exe", "/c", "exit 0"])
        proc.wait(10)
        found = wait_for(lambda: sink.find("process", "started", pid=proc.pid), timeout=15)
        assert found
    finally:
        monitor.stop()
