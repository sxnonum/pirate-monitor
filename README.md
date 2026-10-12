# Pirate Monitor

Pirate Monitor shows you, live, everything that changes on your computer while a program runs. It's built for
the question *"what did this download actually do to my PC?"*

It takes a baseline of the system, optionally launches the suspicious program for you, and then reports
every change as it happens:

| Monitor | What you see |
|---|---|
| **Registry** (Windows) | Every key created/deleted and every value created/changed/deleted, with the **old and new data**. Uses Windows change notifications, so changes appear the moment they're made. |
| **Files** | Files and folders created, modified, deleted and renamed. Anything that can run code (EXE/DLL/scripts, including executables disguised as `.jpg`/`.pdf`) is typed and **SHA-256 hashed**, with a VirusTotal link in the report. |
| **Processes** | Every process start and exit, with parent, command line, user and image hash. The sample's whole **process tree is tracked** and marked with `*`. On Windows, WMI tracing (as Administrator) also catches processes that live only a few milliseconds. |
| **Network** | New outbound/inbound TCP connections, new listening ports and UDP sockets, with the owning process. |

Every event is graded **INFO / NOTE / WARN / ALERT** by built-in heuristics that explain *why* something
was flagged. These cover autorun keys, services, scheduled tasks, the Startup folder, IFEO/Winlogon hijacks,
COM hijacks, Defender/UAC/firewall tampering, encoded PowerShell, shadow-copy deletion, masquerading
`svchost.exe`, mass renames to `.locked` (ransomware), ransom notes, executables run from Temp, and more.
It also links things together. If a file is dropped and then executed, or written into a Run key, or makes
network connections, all of those events are flagged.

When you stop (Ctrl+C, `--duration`, or automatically when the sample exits) you get:

* `events.jsonl`: every single event, one JSON object per line
* `report.html`: a self-contained report with findings, the sample's process tree, dropped executables,
  and searchable tables for processes, network, files and registry

```
14:02:11.532 ALERT  *REG  value_created   HKCU\Software\Microsoft\Windows\CurrentVersion\Run
                     "Updater" = C:\Users\bob\AppData\Roaming\upd.exe   [REG_SZ]
                     ! Autorun key: program starts at every logon
                     ! Registry value points at a file dropped during this session (upd.exe)
14:02:11.610 WARN   *NET  connection      TCP 185.220.101.4:443
                     upd.exe (pid 4312)  outbound from 10.0.2.15:49733 [ESTABLISHED]
                     ! Network activity by a file dropped during this session
```

> **Safety first.** Only run real malware inside a **virtual machine with a snapshot** that you
> roll back afterwards, ideally with networking disabled or isolated. Pirate Monitor *observes*; it does not
> stop or undo anything, and malware can detect or kill monitoring tools.

## Install (Windows)

1. Install [Python 3.9+](https://www.python.org/downloads/) and tick **"Add python.exe to PATH"**.
2. Download this repository (Code → Download ZIP) and extract it.
3. Double-click **`start-monitor.bat`**. It asks for Administrator rights, installs the requirements
   (`psutil`, `watchdog`, `pywin32`) and starts monitoring.

Or from an **Administrator** terminal:

```powershell
py -m pip install -r requirements.txt
py -m pirate_monitor                      # monitor until Ctrl+C
```

(`pip install .` also installs a `pirate-monitor` command.) It also runs on Linux and macOS, without the
registry monitor.

## Usage

```powershell
# Watch everything; run the suspicious program yourself once it says ALL MONITORS LIVE
py -m pirate_monitor

# Let it launch the sample after the baselines are ready, follow its process tree,
# stop 15 s after the last tracked process exits (or after 10 minutes), then kill leftovers
py -m pirate_monitor --stop-when-done --duration 600 --kill-tracked --run C:\samples\setup.exe

# Only show suspicious things live (everything is still logged and in the report)
py -m pirate_monitor --min-severity warning --track setup.exe

# Wider coverage: every drive, the whole registry
py -m pirate_monitor --all-drives --registry-full
```

`--run` must be the last option. Everything after it is the program and its arguments. Scripts and
documents (`.js`, `.vbs`, `.hta`, `.lnk`, ...) open through their normal file association.

| Option | Meaning |
|---|---|
| `--run PROGRAM ...` | launch the sample when monitoring is live and track its process tree |
| `--track NAME` / `--track-pid PID` | treat processes with this name / this running process as the sample |
| `--duration S`, `--stop-when-done`, `--kill-tracked` | when and how to end the session |
| `--min-severity LEVEL`, `--only-tracked`, `--show-noise`, `--quiet` | what the live console prints |
| `--watch PATH`, `--only-watch`, `--all-drives`, `--exclude GLOB` | which folders are watched |
| `--reg-key KEY`, `--registry-full`, `--registry-poll S` | which registry trees are watched, and how |
| `--no-files`, `--no-registry`, `--no-processes`, `--no-network` | turn monitors off |
| `-o DIR` | where to write `events.jsonl` and `report.html` (default `pirate-monitor-logs\<time>`) |

Run `py -m pirate_monitor --help` for everything.

### What is watched by default (Windows)

* **Folders:** your user profile (Desktop, Downloads, AppData, Startup...), `C:\Users\Public`, `C:\ProgramData`,
  `C:\Windows` (System32, Temp, Tasks, `drivers\etc\hosts`...), `C:\Program Files`, `C:\Program Files (x86)`.
* **Registry:** all of `HKCU\Software`, `HKCU\Environment`, and the machine-wide places malware uses:
  `HKLM\...\Windows\CurrentVersion` and `Windows NT\CurrentVersion` (incl. WOW6432Node), Policies,
  Windows Defender, Active Setup, Command Processor, NetSh, `exefile`/`ms-settings` handlers,
  `HKLM\SYSTEM\CurrentControlSet\Services` and `...\Control`.

Routine background churn (browser caches, Explorer bookkeeping, Windows Update, Defender signatures...)
is marked as **noise**. It's hidden from the live console but still logged, and the report counts it per location.
Use `--show-noise` to see it live, or `--no-default-excludes` to turn the filters off.

## How it works

* **Registry:** a baseline snapshot of each watched tree is split into watch units of at most ~1,500 keys.
  Each unit is armed with `RegNotifyChangeKeyValue`. When Windows signals a unit, only that unit is
  re-read and diffed against its snapshot, which gives the exact keys/values and old→new data. Unchanged keys
  are skipped using their last-write timestamps.
* **Files:** `watchdog` (ReadDirectoryChangesW on Windows, inotify on Linux). Files are inspected after they
  stop changing: magic bytes, type, SHA-256.
* **Processes:** `psutil` polling every 0.25 s, plus WMI `Win32_ProcessStartTrace` on Windows. A new process
  joins the tracked tree when its parent is tracked, its name matches `--track`, or it runs/references
  a file dropped during the session.
* **Network:** `psutil.net_connections` polling every second.

## Limitations (read these)

* File and registry changes **can't be attributed to a specific process** with these Windows APIs. They're
  system-wide and shown with timestamps, so line them up with the tracked processes. For per-process
  attribution, use Sysinternals Process Monitor or Sysmon (ETW) alongside this tool.
* Without Administrator rights (or without `pywin32`), processes shorter than the 0.25 s polling interval can
  be missed, and some protected registry keys, other users' processes and the scheduled-tasks folder are invisible.
* Network connections that open and close within one second can be missed, and DNS lookups aren't shown.
* Activity that never touches disk/registry/process list (in-memory injection into another process,
  kernel rootkits, encrypted C2 content) isn't visible.
* Under extreme load (thousands of file changes per second) Windows can drop file notifications.

## Development

```bash
pip install -r requirements.txt pytest
python -m pytest -v
```

The registry engine is OS-independent and is tested against an in-memory fake registry. CI
(`.github/workflows/tests.yml`) also runs the real-registry, WMI and end-to-end tests on Windows.
