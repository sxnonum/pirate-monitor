"""Default watch locations, exclusions, noise filters and registry keys per platform."""

from __future__ import annotations

import os
from typing import List

from .util import IS_MAC, IS_WINDOWS, dedupe_paths


def default_watch_paths() -> List[str]:
    env = os.environ
    home = os.path.expanduser("~")
    if IS_WINDOWS:
        candidates = [
            env.get("USERPROFILE") or home,  # Desktop, Downloads, AppData, Startup folder...
            env.get("PUBLIC"),
            env.get("ProgramData"),  # all-users Startup folder, common drop location
            env.get("SystemRoot") or r"C:\Windows",  # System32, Temp, Tasks, drivers\etc\hosts
            env.get("ProgramFiles"),
            env.get("ProgramFiles(x86)"),
        ]
    elif IS_MAC:
        candidates = [
            home,
            "/tmp",
            "/private/tmp",
            "/Library/LaunchAgents",
            "/Library/LaunchDaemons",
            "/Library/StartupItems",
            "/Applications",
            "/etc",
            "/usr/local/bin",
        ]
    else:
        sudo_user = env.get("SUDO_USER")
        candidates = [
            home,
            os.path.expanduser("~" + sudo_user) if sudo_user else None,
            "/tmp",
            "/var/tmp",
            "/dev/shm",
            "/etc",
            "/var/spool/cron",
            "/usr/local/bin",
            "/usr/local/sbin",
            "/usr/bin",
            "/usr/sbin",
            "/opt",
        ]
    return dedupe_paths(c for c in candidates if c and os.path.isdir(c))


# Dropped entirely: churn that never carries signal (registry hive journals, page files...).
_WINDOWS_EXCLUDES = [
    "*.etl",
    r"*\ntuser.dat*",
    r"*\ntuser.ini",
    r"*\usrclass.dat*",
    "*.regtrans-ms",
    "*.blf",
    r"*\windows\system32\config\*",
    r"*\windows\system32\winevt\logs\*",
    r"*\windows\system32\sru\*",
    r"*\pagefile.sys",
    r"*\swapfile.sys",
    r"*\hiberfil.sys",
    r"*\system volume information\*",
    r"*\$extend\*",
]

# Logged and counted, but hidden from the live console unless --show-noise.
_WINDOWS_NOISE = [
    r"*\appdata\local\google\chrome\user data\*",
    r"*\appdata\local\microsoft\edge\user data\*",
    r"*\appdata\local\bravesoftware\*",
    r"*\appdata\roaming\mozilla\firefox\profiles\*",
    r"*\appdata\local\mozilla\firefox\profiles\*",
    r"*\appdata\roaming\opera software\*",
    r"*\appdata\local\microsoft\windows\webcache\*",
    r"*\appdata\local\microsoft\windows\explorer\*",
    r"*\appdata\local\microsoft\windows\notifications\*",
    r"*\appdata\local\microsoft\windows\caches\*",
    r"*\appdata\local\microsoft\windows\inetcache\*",
    r"*\appdata\local\microsoft\windows\history\*",
    r"*\appdata\local\microsoft\windows\actioncenter*",
    r"*\appdata\local\microsoft\onedrive\*",
    r"*\appdata\local\packages\*",
    r"*\appdata\local\connecteddevicesplatform\*",
    r"*\appdata\local\d3dscache\*",
    r"*\appdata\roaming\microsoft\windows\recent\*",
    r"*\appdata\local\crashdumps\*",
    r"*\cache\*",
    r"*\code cache\*",
    r"*\gpucache\*",
    r"*\service worker\*",
    r"*\indexeddb\*",
    r"*\local storage\*",
    r"*\session storage\*",
    r"*\blob_storage\*",
    r"*\crashpad\*",
    r"*\__pycache__\*",
    r"*\.git\*",
    r"*\windows\prefetch\*",
    r"*\windows\servicing\*",
    r"*\windows\softwaredistribution\*",
    r"*\windows\logs\*",
    r"*\windows\inf\*.log",
    r"*\windows\appcompat\*",
    r"*\windows\system32\logfiles\*",
    r"*\windows\system32\wdi\*",
    r"*\windows\system32\sleepstudy\*",
    r"*\windows\system32\catroot2\*",
    r"*\windows\serviceprofiles\*",
    r"*\deliveryoptimization\*",
    r"*\programdata\microsoft\windows defender\*",
    r"*\programdata\microsoft\diagnosis\*",
    r"*\programdata\microsoft\windows\wer\*",
    r"*\programdata\microsoft\windows\apprepository\*",
    r"*\programdata\microsoft\network\downloader\*",
    r"*\programdata\microsoft\search\*",
    r"*\programdata\microsoft\edgeupdate\*",
    r"*\programdata\packages\*",
]

_POSIX_EXCLUDES = ["/proc/*", "/sys/*"]

_POSIX_NOISE = [
    "*/.cache/*",
    "*/.mozilla/*",
    "*/.config/google-chrome/*",
    "*/.config/chromium/*",
    "*/.config/BraveSoftware/*",
    "*/.config/Code/*",
    "*/.vscode-server/*",
    "*/.local/share/recently-used.xbel*",
    "*/.xsession-errors*",
    "*/__pycache__/*",
    "*/.git/*",
    "*/Library/Caches/*",
    "*/Library/Application Support/Google/Chrome/*",
]


def default_excludes() -> List[str]:
    return list(_WINDOWS_EXCLUDES if IS_WINDOWS else _POSIX_EXCLUDES)


def default_noise() -> List[str]:
    return list(_WINDOWS_NOISE if IS_WINDOWS else _POSIX_NOISE)


# Registry trees watched by default: everything per-user plus the machine-wide places
# malware uses for persistence, defence evasion and configuration.
REGISTRY_ROOTS = [
    r"HKCU\Software",
    r"HKCU\Environment",
    r"HKCU\Control Panel\Desktop",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion",
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
    r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion",
    r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion",
    r"HKLM\SOFTWARE\Policies",
    r"HKLM\SOFTWARE\Microsoft\Windows Defender",
    r"HKLM\SOFTWARE\Microsoft\Active Setup",
    r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Active Setup",
    r"HKLM\SOFTWARE\Microsoft\Command Processor",
    r"HKLM\SOFTWARE\Microsoft\NetSh",
    r"HKLM\SOFTWARE\Classes\exefile",
    r"HKLM\SOFTWARE\Classes\ms-settings",
    r"HKLM\SYSTEM\CurrentControlSet\Services",
    r"HKLM\SYSTEM\CurrentControlSet\Control",
]

# --registry-full: whole machine and user hives.
REGISTRY_FULL_ROOTS = [
    r"HKCU",
    r"HKLM\SOFTWARE",
    r"HKLM\SYSTEM\CurrentControlSet",
]

# Very large, very busy subtrees that malware practically never needs. Skipped unless --registry-full.
REGISTRY_SKIP = [
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SideBySide",
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib",
    r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Perflib",
]
