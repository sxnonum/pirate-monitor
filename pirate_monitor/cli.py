"""Command line entry point: builds the monitors, runs the session, writes the report."""

from __future__ import annotations

import argparse
import datetime as _dt
import getpass
import os
import platform
import subprocess
import sys
import time
from typing import List, Optional

from . import __version__
from .core import SEVERITIES, EventBus, SessionState
from .output import ConsoleSink, JsonlSink
from .registry.model import canonical_key_path, dedupe_key_roots
from .report import ReportCollector
from .rules import Rules
from .util import IS_WINDOWS, all_drive_roots, dedupe_paths, enable_ansi_colors, is_admin

BANNER = r"""
  ___ _         _         __  __          _ _
 | _ (_)_ _ __ | |_ ___  |  \/  |___ _ _ (_) |_ ___ _ _
 |  _/ | '_/ _`|  _/ -_) | |\/| / _ \ ' \| |  _/ _ \ '_|
 |_| |_|_| \__,_|\__\___| |_|  |_\___/_||_|_|\__\___/_|
"""

EXAMPLES = """\
examples:
  pirate-monitor
      watch everything (files, registry, processes, network) until Ctrl+C
  pirate-monitor --run C:\\samples\\setup.exe
      take baselines, launch the sample, follow its whole process tree, Ctrl+C to stop
  pirate-monitor --duration 300 --stop-when-done --kill-tracked --run sample.exe
      run the sample for at most 5 minutes, then kill whatever it left running
  pirate-monitor --track evil.exe --min-severity warning
      only show suspicious activity; treat any process named evil.exe as the sample
  pirate-monitor --watch D:\\ --reg-key "HKLM\\SOFTWARE\\Classes" --registry-full

Run from an Administrator terminal for full coverage. Analyse real malware only inside a
virtual machine you can roll back.
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pirate-monitor",
        description="Live monitor of everything that changes on this computer: files, registry, "
        "processes and network connections. Produces a live feed, a JSON log and an HTML report.",
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    g = p.add_argument_group("session")
    g.add_argument("--run", nargs=argparse.REMAINDER, metavar="PROGRAM",
                   help="launch PROGRAM (with any arguments) once monitoring is live and follow its process "
                        "tree. Must be the LAST option.")
    g.add_argument("--track", action="append", default=[], metavar="NAME",
                   help="treat processes with this image name (e.g. sample.exe) as the sample; repeatable")
    g.add_argument("--track-pid", action="append", default=[], type=int, metavar="PID",
                   help="treat this already running process as the sample; repeatable")
    g.add_argument("--duration", type=float, metavar="SECONDS", help="stop automatically after this many seconds")
    g.add_argument("--stop-when-done", action="store_true",
                   help="stop once every tracked process has exited (after a 15 second grace period)")
    g.add_argument("--kill-tracked", action="store_true", help="kill the tracked processes when the session ends")
    g.add_argument("-o", "--output", metavar="DIR",
                   help="session folder for events.jsonl and report.html (default: ./pirate-monitor-logs/<time>)")

    g = p.add_argument_group("what to watch")
    g.add_argument("--watch", action="append", default=[], metavar="PATH", help="extra folder to watch; repeatable")
    g.add_argument("--only-watch", action="store_true", help="watch only the --watch folders, not the defaults")
    g.add_argument("--all-drives", action="store_true", help="watch every local drive completely (Windows)")
    g.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                   help=r"ignore matching paths, e.g. '*\Steam\*'; repeatable")
    g.add_argument("--no-default-excludes", action="store_true", help="do not ignore or hide any path by default")
    g.add_argument("--reg-key", action="append", default=[], metavar="KEY",
                   help=r"extra registry tree to watch, e.g. 'HKLM\SOFTWARE\Classes'; repeatable")
    g.add_argument("--registry-full", action="store_true",
                   help="watch all of HKCU, HKLM\\SOFTWARE and HKLM\\SYSTEM (slower baseline, more memory)")
    g.add_argument("--registry-poll", type=float, metavar="SECONDS",
                   help="re-scan the registry on a timer instead of using change notifications")
    for name in ("files", "registry", "processes", "network"):
        g.add_argument(f"--no-{name}", action="store_true", help=f"disable the {name} monitor")

    g = p.add_argument_group("display")
    g.add_argument("--min-severity", choices=SEVERITIES, default="info",
                   help="only print events at or above this level (everything is still logged)")
    g.add_argument("--show-noise", action="store_true", help="also print routine background activity")
    g.add_argument("--only-tracked", action="store_true",
                   help="print process / network events only for the tracked process tree")
    g.add_argument("--quiet", action="store_true", help="print only status messages and the final summary")
    g.add_argument("--no-color", action="store_true", help="disable coloured output")

    g = p.add_argument_group("tuning")
    g.add_argument("--process-interval", type=float, default=0.25, metavar="SECONDS",
                   help="process polling interval (default 0.25)")
    g.add_argument("--network-interval", type=float, default=1.0, metavar="SECONDS",
                   help="network polling interval (default 1.0)")
    g.add_argument("--hash-max-mb", type=float, default=50.0, metavar="MB",
                   help="largest file to SHA-256 hash (default 50)")
    g.add_argument("--no-wmi", action="store_true", help="do not use WMI process tracing on Windows")
    p.add_argument("--version", action="version", version=f"pirate-monitor {__version__}")
    return p


def _check_dependencies() -> Optional[str]:
    missing = []
    for module in ("psutil", "watchdog"):
        try:
            __import__(module)
        except ImportError:
            missing.append(module)
    if missing:
        return (
            f"Missing Python packages: {', '.join(missing)}\n"
            f"Install them with:  {os.path.basename(sys.executable)} -m pip install -r requirements.txt"
        )
    return None


def _session_dir(requested: Optional[str]) -> str:
    stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    path = requested or os.path.join(os.getcwd(), "pirate-monitor-logs", stamp)
    path = os.path.abspath(path)
    os.makedirs(path, exist_ok=True)
    return path


def _build_monitors(args, bus: EventBus, state: SessionState, out_dir: str) -> list:
    from .defaults import (
        REGISTRY_FULL_ROOTS,
        REGISTRY_ROOTS,
        REGISTRY_SKIP,
        default_excludes,
        default_noise,
        default_watch_paths,
    )

    monitors = []
    hash_max = int(args.hash_max_mb * 1024 * 1024)
    if not args.no_processes:
        from .monitors.processes import ProcessMonitor

        monitors.append(ProcessMonitor(bus, state, interval=args.process_interval, hash_max_bytes=hash_max,
                                       use_wmi=not args.no_wmi, track_pids=args.track_pid))
    if not args.no_network:
        from .monitors.network import NetworkMonitor

        monitors.append(NetworkMonitor(bus, state, interval=args.network_interval))
    if not args.no_files:
        from .monitors.filesystem import FileSystemMonitor

        paths: List[str] = [] if args.only_watch else default_watch_paths()
        if args.all_drives:
            if IS_WINDOWS:
                paths += all_drive_roots()
            else:
                bus.system("--all-drives is only supported on Windows; use --watch instead", "warning")
        paths = dedupe_paths(paths + args.watch)
        excludes = ([] if args.no_default_excludes else default_excludes()) + args.exclude
        noise = [] if args.no_default_excludes else default_noise()
        monitors.append(FileSystemMonitor(bus, state, paths, excludes, noise, exclude_prefixes=[out_dir],
                                          hash_max_bytes=hash_max))
    if not args.no_registry:
        if IS_WINDOWS:
            from .monitors.registry import RegistryMonitor

            roots = list(REGISTRY_ROOTS) + (list(REGISTRY_FULL_ROOTS) if args.registry_full else []) + args.reg_key
            skip = [] if args.registry_full else REGISTRY_SKIP
            monitors.append(RegistryMonitor(bus, state, dedupe_key_roots(roots), skip=skip,
                                            poll_interval=args.registry_poll))
        elif args.reg_key or args.registry_full:
            bus.system("Registry monitoring is only available on Windows", "warning")
    return monitors


def _launch(argv: List[str], proc_monitor) -> subprocess.Popen:
    program = argv[0]
    if IS_WINDOWS and os.path.splitext(program)[1].lower() not in (".exe", ".com", ".bat", ".cmd", ""):
        # Documents and scripts (.js, .vbs, .hta, .lnk ...) open through their file association.
        argv = ["cmd.exe", "/c", program] + argv[1:]
    if proc_monitor is not None:
        return proc_monitor.launch(argv)
    kwargs = {"creationflags": subprocess.CREATE_NEW_CONSOLE} if IS_WINDOWS else {"start_new_session": True}
    return subprocess.Popen(argv, **kwargs)


def _fmt_duration(seconds: float) -> str:
    seconds = int(seconds)
    return f"{seconds // 3600:02d}:{seconds % 3600 // 60:02d}:{seconds % 60:02d}"


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.run is not None and not args.run:
        parser.error("--run needs a program to start")
    try:
        args.reg_key = [canonical_key_path(k) for k in args.reg_key]
    except ValueError as exc:
        parser.error(str(exc))
    problem = _check_dependencies()
    if problem:
        print(problem, file=sys.stderr)
        return 2

    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except Exception:
            pass
    color = not args.no_color and enable_ansi_colors()
    out_dir = _session_dir(args.output)
    admin = is_admin()
    if args.run:
        sample = os.path.abspath(args.run[0])
        if os.path.isfile(sample):
            args.run[0] = sample

    state = SessionState(track_names=args.track)
    bus = EventBus(Rules(state))
    console = ConsoleSink(min_severity=args.min_severity, show_noise=args.show_noise,
                          only_tracked=args.only_tracked, color=color, quiet=args.quiet)
    events_path = os.path.join(out_dir, "events.jsonl")
    report_path = os.path.join(out_dir, "report.html")
    collector = ReportCollector()
    bus.add_sink(console)
    bus.add_sink(JsonlSink(events_path))
    bus.add_sink(collector)

    print(BANNER if not args.quiet else "")
    print(f"  pirate-monitor {__version__}  |  {platform.platform()}  |  user {getpass.getuser()}")
    print(f"  Session folder: {out_dir}")
    if admin:
        print("  Privileges: Administrator/root - full coverage")
    else:
        print("  Privileges: NOT elevated - other users' processes, protected registry keys, scheduled task files")
        print("  and WMI process tracing are partly invisible. Re-run from an Administrator terminal for full coverage.")
    print()

    bus.start()
    monitors = _build_monitors(args, bus, state, out_dir)
    proc_monitor = next((m for m in monitors if m.name == "process"), None)
    started = time.time()
    popen: Optional[subprocess.Popen] = None
    stop_reason = "stopped with Ctrl+C"
    try:
        for monitor in monitors:
            monitor.start()
        last_note = time.time()
        while not all(m.ready.is_set() for m in monitors):
            time.sleep(0.2)
            if time.time() - last_note > 15:
                last_note = time.time()
                waiting = ", ".join(m.name for m in monitors if not m.ready.is_set())
                bus.system(f"still building baselines ({waiting})...")
        active = [m.name for m in monitors if not m.failed]
        bus.system(f"ALL MONITORS LIVE ({', '.join(active) or 'none'}) - "
                   + ("launching the sample now." if args.run else "you can run the sample now.")
                   + " Press Ctrl+C to stop and write the report.", "notice")

        if args.run:
            try:
                popen = _launch(args.run, proc_monitor)
                bus.system(f"launched {' '.join(args.run)} (pid {popen.pid}) - its process tree is marked with *", "notice")
            except OSError as exc:
                bus.system(f"could not launch {args.run[0]}: {exc}", "warning")

        deadline = started + args.duration if args.duration else None
        idle_since: Optional[float] = None
        launched_exit_reported = False
        while True:
            time.sleep(0.5)
            now = time.time()
            if popen is not None and not launched_exit_reported and popen.poll() is not None:
                launched_exit_reported = True
                bus.system(f"launched program exited with code {popen.returncode}")
            if deadline and now >= deadline:
                stop_reason = f"duration of {args.duration:g}s reached"
                break
            if args.stop_when_done and (popen is not None or state.tracked_count()):
                if proc_monitor is not None:
                    alive = len(proc_monitor.tracked_alive())
                else:
                    alive = 1 if popen is not None and popen.poll() is None else 0
                if alive:
                    idle_since = None
                elif idle_since is None:
                    idle_since = now
                elif now - idle_since >= 15:
                    stop_reason = "all tracked processes exited"
                    break
    except KeyboardInterrupt:
        pass
    finally:
        bus.system(f"stopping: {stop_reason}")
        if args.kill_tracked:
            killed = proc_monitor.kill_tracked() if proc_monitor is not None else 0
            if popen is not None and popen.poll() is None:
                popen.kill()
                killed += 1
            bus.system(f"killed {killed} tracked process(es)")
        for monitor in monitors:
            monitor.stop()
        time.sleep(0.6)  # let monitor threads flush their last events
        bus.stop()

    ended = time.time()
    meta = {
        "Session": os.path.basename(out_dir),
        "Computer": platform.node(),
        "User": getpass.getuser(),
        "OS": platform.platform(),
        "Elevated": "yes" if admin else "no",
        "Started": _dt.datetime.fromtimestamp(started).strftime("%Y-%m-%d %H:%M:%S"),
        "Ended": _dt.datetime.fromtimestamp(ended).strftime("%Y-%m-%d %H:%M:%S"),
        "Duration": _fmt_duration(ended - started),
        "Monitors": ", ".join(m.name for m in monitors),
        "Launched": " ".join(args.run) if args.run else "-",
        "Tracked names": ", ".join(args.track) or "-",
        "Stopped because": stop_reason,
        "Event log": events_path,
    }
    try:
        collector.write_html(report_path, meta)
    except OSError as exc:
        print(f"Could not write report: {exc}", file=sys.stderr)
    _print_summary(collector, ended - started, report_path, events_path, console)
    return 0


def _print_summary(col: ReportCollector, duration: float, report_path: str, events_path: str,
                   console: ConsoleSink) -> None:
    sev = col.severity_counts
    cats = col.category_counts
    print()
    print("=" * 78)
    print(f" Session summary  ({_fmt_duration(duration)})")
    print("=" * 78)
    print(f" Alerts {sev.get('alert', 0)}   Warnings {sev.get('warning', 0)}   Notices {sev.get('notice', 0)}   "
          f"Info {sev.get('info', 0)}   (+{col.noise_total:,} background noise events)")
    print(f" Processes {cats.get('process', 0)}   Network {cats.get('network', 0)}   "
          f"File changes {cats.get('file', 0)}   Registry changes {cats.get('registry', 0)}")
    findings = col.findings("warning")
    findings.sort(key=lambda e: (-SEVERITIES.index(e.severity), e.timestamp))
    if findings:
        print()
        print(" Top findings:")
        for ev in findings[:25]:
            print(console.format(ev))
        if len(findings) > 25:
            print(f" ... and {len(findings) - 25} more in the report")
    print()
    print(f" HTML report : {report_path}")
    print(f" Event log   : {events_path}")
    print()
