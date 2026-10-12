"""Heuristics that grade each event (info / notice / warning / alert) and explain why.

The rules are deliberately simple pattern checks: they point you at the interesting lines,
they do not decide whether something is malware.
"""

from __future__ import annotations

import os
import re
from collections import defaultdict, deque
from typing import Deque, Dict, List, Tuple

from .core import Event, SessionState, severity_rank
from .util import DOCUMENT_EXTS, RISKY_EXTS, file_ext


def _rx(pattern: str) -> "re.Pattern[str]":
    return re.compile(pattern, re.IGNORECASE)


def _slash(path: str) -> str:
    return path.replace("\\", "/").lower()


# Folders any program can write to and where droppers like to stage payloads.
STRONG_USER_WRITABLE = _rx(
    r"/appdata/local/temp/|/windows/temp/|/downloads/|/users/public/|/\$recycle\.bin/|"
    r"^/tmp/|^/var/tmp/|^/dev/shm/|^/private/tmp/|^/private/var/folders/"
)
WEAK_USER_WRITABLE = _rx(r"/appdata/roaming/|/programdata/(?!microsoft/|package cache/)")

# --------------------------------------------------------------------------------------------
# Files
# --------------------------------------------------------------------------------------------
_TASK_FILES = _rx(r"/windows/system32/tasks/|/windows/tasks/")

FILE_RULES: List[Tuple["re.Pattern[str]", str, str]] = [
    (_rx(r"/start menu/programs/startup/"), "alert", "Startup folder: runs automatically at logon"),
    (_TASK_FILES, "alert", "Scheduled task definition"),
    (_rx(r"/drivers/etc/hosts$"), "alert", "hosts file changed: can redirect websites"),
    (_rx(r"powershell/.*profile\.ps1$"), "alert", "PowerShell profile: runs every time PowerShell starts"),
    (_rx(r"/windows/(system32|syswow64)/(drivers/)?[^/]+\.(sys|dll|exe|scr|cpl|ocx)$"), "alert",
     "Binary written into a Windows system folder"),
    (_rx(r"/windows/system32/grouppolicy/"), "warning", "Group Policy files"),
    (_rx(r"/microsoft/(word/startup|excel/xlstart|addins)/"), "alert", "Office startup / add-in folder"),
    (_rx(r"^/etc/cron|^/var/spool/cron/|^/etc/anacrontab$"), "alert", "cron job (scheduled execution)"),
    (_rx(r"^/etc/systemd/|^/(usr/)?lib/systemd/system/|/\.config/systemd/user/"), "alert", "systemd unit (service persistence)"),
    (_rx(r"/\.config/autostart/|^/etc/xdg/autostart/"), "alert", "Desktop autostart entry"),
    (_rx(r"/\.(bashrc|bash_profile|bash_login|profile|zshrc|zprofile|zshenv)$|^/etc/profile(\.d/|$)|^/etc/(bash\.)?bashrc$"),
     "alert", "Shell startup file"),
    (_rx(r"^/etc/ld\.so\.preload$"), "alert", "ld.so.preload (library injection into every program)"),
    (_rx(r"/\.ssh/authorized_keys2?$"), "alert", "SSH authorized_keys (remote access backdoor)"),
    (_rx(r"^/etc/(passwd|shadow|group|sudoers)$|^/etc/sudoers\.d/"), "alert", "User account / sudo configuration"),
    (_rx(r"^/etc/rc\.local$|^/etc/init\.d/"), "alert", "Init script"),
    (_rx(r"/library/launch(agents|daemons)/"), "alert", "launchd job (macOS persistence)"),
]

# Files Windows itself creates and deletes routinely, which would otherwise look like script drops.
BENIGN_FILES = _rx(r"/__psscriptpolicytest_[^/]+\.(ps1|psm1)$")

RANSOM_NOTE_NAME = _rx(r"(read.?me|how.?to|decrypt|restore|recover|ransom|instruction|!!!).*\.(txt|html?|hta|rtf|url)$")

# --------------------------------------------------------------------------------------------
# Registry (matched against the lower-case key path)
# --------------------------------------------------------------------------------------------
REG_KEY_RULES: List[Tuple["re.Pattern[str]", str, str]] = [
    (_rx(r"\\currentversion\\(run|runonce|runonceex|runservices|runservicesonce)(\\|$)"), "alert",
     "Autorun key: program starts at every logon"),
    (_rx(r"\\policies\\explorer\\run(\\|$)"), "alert", "Policy autorun key"),
    (_rx(r"\\windows nt\\currentversion\\winlogon(\\|$)"), "warning", "Winlogon settings"),
    (_rx(r"\\image file execution options\\"), "warning", "Image File Execution Options"),
    (_rx(r"\\silentprocessexit\\"), "alert", "SilentProcessExit monitor (persistence)"),
    (_rx(r"\\windows nt\\currentversion\\windows$"), "warning", "AppInit_DLLs / Load / Run key"),
    (_rx(r"\\schedule\\taskcache\\"), "notice", "Scheduled task registry data"),
    (_rx(r"\\currentcontrolset\\services\\"), "notice", "Service configuration"),
    (_rx(r"\\control\\session manager(\\|$)"), "notice", "Session Manager"),
    (_rx(r"\\control\\lsa(\\|$)"), "warning", "LSA configuration"),
    (_rx(r"\\control\\securityproviders(\\|$)"), "warning", "Security providers"),
    (_rx(r"\\control\\print\\monitors\\"), "alert", "Print monitor DLL (persistence)"),
    (_rx(r"\\control\\safeboot\\"), "alert", "Safe Boot configuration"),
    (_rx(r"\\control\\terminal server(\\|$)"), "warning", "Remote Desktop configuration"),
    (_rx(r"\\microsoft\\netsh$"), "alert", "Netsh helper DLL (persistence)"),
    (_rx(r"\\active setup\\installed components\\"), "warning", "Active Setup (runs at logon)"),
    (_rx(r"\\classes\\clsid\\[^\\]+\\(inprocserver32|localserver32|treatas|scriptleturl)$"), "warning",
     "COM server registration (possible COM hijack)"),
    (_rx(r"\\shell\\(open|runas)\\command$"), "warning", "File / protocol open command"),
    (_rx(r"\\(ms-settings|exefile|mscfile|folder|lnkfile)\\shell\\open\\command$"), "alert",
     "Handler hijack used for UAC bypass"),
    (_rx(r"\\policies\\microsoft\\windows defender"), "alert", "Windows Defender policy"),
    (_rx(r"\\microsoft\\windows defender\\(exclusions|real-time protection|spynet|features)"), "alert",
     "Windows Defender settings / exclusions"),
    (_rx(r"\\currentversion\\policies\\system$"), "warning", "System policies"),
    (_rx(r"\\currentversion\\policies\\"), "notice", "Policies"),
    (_rx(r"^(hkcu|hku\\[^\\]+)\\environment$|\\session manager\\environment$"), "notice", "Environment variables"),
    (_rx(r"\\explorer\\(user )?shell folders$"), "warning", "Shell folder locations"),
    (_rx(r"\\sharedaccess\\parameters\\firewallpolicy\\"), "warning", "Firewall configuration"),
    (_rx(r"\\command processor$"), "warning", "cmd.exe settings"),
    (_rx(r"\\explorer\\browser helper objects\\"), "alert", "Browser Helper Object"),
    (_rx(r"\\shellserviceobjectdelayload$|\\shellserviceobjects\\"), "alert", "Shell service object (autostart)"),
    (_rx(r"\\winsock2\\"), "alert", "Winsock provider change"),
    (_rx(r"\\control panel\\desktop$"), "notice", "Desktop settings"),
    (_rx(r"\\currentversion\\uninstall\\"), "notice", "Installed programs list"),
    (_rx(r"\\currentversion\\app paths\\"), "notice", "App Paths"),
    (_rx(r"\\internet settings$"), "notice", "Internet / proxy settings"),
    (_rx(r"\\capabilityaccessmanager\\consentstore\\(webcam|microphone|location)\\"), "notice",
     "Camera / microphone / location usage record"),
]

# (key regex or None for any key, value-name regex, severity, reason)
REG_VALUE_RULES = [
    (_rx(r"\\winlogon$"), _rx(r"^(shell|userinit|taskman|appsetup|vmapplet)$"), "alert", "Winlogon Shell/Userinit hijack"),
    (_rx(r"\\image file execution options\\"), _rx(r"^(debugger|globalflag)$"), "alert", "IFEO debugger hijack"),
    (_rx(r"\\windows nt\\currentversion\\windows$"), _rx(r"^(appinit_dlls|loadappinit_dlls|load|run)$"), "alert",
     "AppInit_DLLs / Load / Run persistence"),
    (_rx(r"\\session manager$"), _rx(r"^(bootexecute|setupexecute|execute|s0initialcommand|pendingfilerenameoperations)$"),
     "alert", "Boot-time execution / file replacement"),
    (_rx(r"\\session manager\\(appcertdlls|knowndlls)$"), _rx(r".*"), "alert", "AppCertDlls / KnownDLLs"),
    (None, _rx(r"^(cor_profiler|cor_enable_profiling|cor_profiler_path|coreclr_profiler.*)$"), "alert",
     ".NET profiler hijack"),
    (None, _rx(r"^userinitmprlogonscript$"), "alert", "Logon script"),
    (_rx(r"\\policies\\system$"), _rx(r"^(enablelua|consentpromptbehavioradmin|promptonsecuredesktop|localaccounttokenfilterpolicy)$"),
     "alert", "UAC setting changed"),
    (None, _rx(r"^(disabletaskmgr|disableregistrytools|disablecmd|nofolderoptions|norun|disablelockworkstation|disablechangepassword)$"),
     "alert", "Disables a Windows tool (typical malware lockdown)"),
    (None, _rx(r"^(disableantispyware|disableantivirus|disablerealtimemonitoring|disablebehaviormonitoring|"
               r"disableioavprotection|disableonaccessprotection|disablescanonrealtimeenable|tamperprotection)$"),
     "alert", "Disables Windows Defender protection"),
    (_rx(r"\\services\\[^\\]+$"), _rx(r"^(imagepath|start|type|failurecommand)$"), "warning", "Service binary / start mode"),
    (_rx(r"\\services\\[^\\]+\\parameters$"), _rx(r"^servicedll$"), "alert", "Service DLL"),
    (_rx(r"\\command processor$"), _rx(r"^autorun$"), "alert", "cmd.exe AutoRun command"),
    (_rx(r"\\explorer\\advanced$"), _rx(r"^(hidden|hidefileext|showsuperhidden)$"), "warning", "Hides files / extensions"),
    (_rx(r"\\internet settings$"), _rx(r"^(proxyserver|proxyenable|autoconfigurl|proxyoverride)$"), "alert",
     "Proxy configuration (traffic interception)"),
    (_rx(r"\\parameters\\interfaces\\[^\\]+$|\\tcpip6?\\parameters$"), _rx(r"^nameserver$"), "alert", "DNS server changed"),
    (_rx(r"\\terminal server$"), _rx(r"^fdenytsconnections$"), "alert", "Remote Desktop enabled / disabled"),
    (_rx(r"\\control panel\\desktop$"), _rx(r"^wallpaper$"), "warning", "Wallpaper changed"),
    (_rx(r"\\lsa$"), _rx(r"^(security packages|authentication packages|notification packages|runasppl|disablerestrictedadmin|lmcompatibilitylevel)$"),
     "alert", "LSA package / credential setting"),
    (_rx(r"\\wdigest$"), _rx(r"^uselogoncredential$"), "alert", "WDigest clear-text credentials"),
    (_rx(r"\\capabilityaccessmanager\\consentstore\\(webcam|microphone|location)\\"), _rx(r"^lastusedtimestart$"),
     "warning", "Camera / microphone / location was used"),
    (None, _rx(r"^(vbawarnings|accessvbom|blockcontentexecutionfrominternet)$"), "alert", "Office macro security changed"),
]

# Structural events that matter regardless of values.
REG_CREATE_RULES = [
    (_rx(r"\\currentcontrolset\\services\\[^\\]+$"), "alert", "New Windows service registered"),
    (_rx(r"\\schedule\\taskcache\\tasks\\[^\\]+$"), "alert", "New scheduled task registered"),
    (_rx(r"^(hkcu|hku\\[^\\]+)\\software\\classes\\clsid\\[^\\]+$"), "warning",
     "COM class registered for the current user (COM hijack technique)"),
    (_rx(r"\\image file execution options\\[^\\]+$"), "warning", "New Image File Execution Options entry"),
]

# Busy keys Windows and apps write constantly; hidden from the console unless something flags them.
REG_NOISE = [
    _rx(r"\\currentversion\\explorer\\(userassist|featureusage|sessioninfo|recentdocs|comdlg32|startpage2|taskband|"
        r"bitbucket|mountpoints2|cidsizemru|streams|streammru|wordwheelquery|search|cloudstore)(\\|$)"),
    _rx(r"\\shell\\(bags|bagmru)(\\|$)"),
    _rx(r"\\local settings\\software\\microsoft\\windows\\shell\\"),
    _rx(r"\\currentversion\\(cloudstore|search|notifications|pushnotifications|diagnostics|holographic|"
        r"deliveryoptimization|webcheck|storagesense|gamedvr|wina|lock screen|authentication\\logonui)(\\|$)"),
    _rx(r"\\services\\bam\\state\\"),
    _rx(r"\\services\\(w32time|wsearch|sppsvc|bits|wuauserv|usosvc|diagtrack|nlasvc|dhcp|iphlpsvc)(\\|$)"),
    _rx(r"\\softwareprotectionplatform(\\|$)"),
    _rx(r"\\windows nt\\currentversion\\(networklist|notifications|perflib|winsat|update|"
        r"appcompatflags\\compatibility assistant)(\\|$)"),
    _rx(r"\\microsoft\\windows defender\\(signature updates|scan|diagnostics|mpengine|reporting|nis)"),
    _rx(r"\\microsoft\\(windows search|input|inputpersonalization|speech_onecore|feeds|tabletip|ctf|clipboard|ime)(\\|$)"),
    _rx(r"\\microsoft\\office\\.*\\(file mru|place mru|user mru|resiliency|recent|identity|licensing|experiment)"),
    _rx(r"\\microsoft\\(edge|edgeupdate|onedrive|tracing|wbem|sqmclient)(\\|$)"),
    _rx(r"\\google\\update(\\|$)"),
    _rx(r"\\microsoft\\cryptography\\rng(\\|$)"),
    _rx(r"\\microsoft\\windows\\windows error reporting(\\|$)"),
    _rx(r"\\control\\(deviceclasses|wmi\\autologger|diagnostics|bluetooth|usbflags)(\\|$)"),
]

# --------------------------------------------------------------------------------------------
# Processes
# --------------------------------------------------------------------------------------------
CMDLINE_RULES = [
    (_rx(r"\b(powershell|pwsh)(\.exe)?\b.*\s-(e|ec|en|enc|enco|encod|encode|encoded|encodedcommand)\s+[a-z0-9+/=]{16,}"),
     "alert", "PowerShell with an encoded (hidden) command"),
    (_rx(r"\b(powershell|pwsh)(\.exe)?\b.*\s-(w|win|window|windowstyle)\s+(h|hidden)\b"), "alert", "Hidden PowerShell window"),
    (_rx(r"downloadstring|downloadfile|downloaddata|invoke-webrequest|\biwr\b|start-bitstransfer|net\.webclient|"
         r"invoke-restmethod|\birm\b"), "alert", "Downloads content from the internet"),
    (_rx(r"\biex\b|invoke-expression"), "alert", "Executes dynamically built code (IEX)"),
    (_rx(r"frombase64string"), "warning", "Decodes a base64 payload"),
    (_rx(r"-(ep|exec|executionpolicy)\s+(bypass|unrestricted)"), "warning", "Bypasses PowerShell execution policy"),
    (_rx(r"(add|set)-mppreference"), "alert", "Changes Windows Defender settings"),
    (_rx(r"vssadmin(\.exe)?\s.*delete\s+shadows|shadowcopy\s+delete|win32_shadowcopy|wbadmin(\.exe)?\s.*delete|"
         r"bcdedit(\.exe)?\s.*(recoveryenabled\s+no|bootstatuspolicy)"),
     "alert", "Deletes backups / shadow copies (ransomware behaviour)"),
    (_rx(r"wevtutil(\.exe)?\s+(cl|clear-log)\b|clear-eventlog|remove-eventlog"), "alert", "Clears Windows event logs"),
    (_rx(r"schtasks(\.exe)?\s.*/create"), "alert", "Creates a scheduled task"),
    (_rx(r"\bsc(\.exe)?\s+(\\\\\S+\s+)?(create|config)\b|new-service"), "alert", "Creates / modifies a service"),
    (_rx(r"\breg(\.exe)?\s+save\s.*\b(hklm\\)?(sam|security|system)\b"), "alert", "Dumps registry hives (credential theft)"),
    (_rx(r"\breg(\.exe)?\s+(add|delete|import|load|restore)\b"), "warning", "Edits the registry from the command line"),
    (_rx(r"\bnet1?(\.exe)?\s+(user|localgroup)\s.*/add"), "alert", "Adds a user account / group membership"),
    (_rx(r"\bnetsh(\.exe)?\s.*(advfirewall|firewall|portproxy|wlan\s+export|winsock)"), "alert", "Changes firewall / network configuration"),
    (_rx(r"certutil(\.exe)?\s.*(-urlcache|-decode|-decodehex|-encode|-verifyctl)"), "alert", "certutil used to download / decode files"),
    (_rx(r"bitsadmin(\.exe)?\s.*/(transfer|addfile|create)"), "alert", "BITS download job"),
    (_rx(r"\bmshta(\.exe)?\b"), "alert", "mshta runs an HTML application / script"),
    (_rx(r"regsvr32(\.exe)?\s.*(/i:|scrobj|https?:)"), "alert", "regsvr32 script execution"),
    (_rx(r"rundll32(\.exe)?\s.*(javascript:|vbscript:|\\appdata\\|\\temp\\|\\users\\public\\|,#\d)"), "alert", "Suspicious rundll32 usage"),
    (_rx(r"\b(wscript|cscript)(\.exe)?\b"), "warning", "Windows Script Host runs a script"),
    (_rx(r"\battrib(\.exe)?\s.*\+[hs]\b"), "warning", "Hides files (attrib +h / +s)"),
    (_rx(r"\b(icacls|takeown|cacls)(\.exe)?\b"), "warning", "Changes file permissions / ownership"),
    (_rx(r"\b(taskkill|stop-process|sc(\.exe)?\s+stop|net\s+stop)\b.*(msmpeng|windefend|defender|avast|avg|kaspersky|mcafee|norton|"
         r"eset|malwarebytes|mbam|sophos|procmon|procexp|wireshark|taskmgr|sysmon)"),
     "alert", "Stops security / analysis tools"),
    (_rx(r"\b(whoami|systeminfo|nltest|quser|qwinsta|tasklist|ipconfig\s+/all|net1?\s+(view|group|localgroup|user|share|session|config)|"
         r"arp\s+-a|route\s+print|netstat\s+-)"), "notice", "System / network discovery command"),
    (_rx(r"\b(curl|wget)(\.exe)?\s.*https?://"), "warning", "Downloads from the internet"),
    (_rx(r"\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z|da)?sh\b"), "alert", "Pipes a download straight into a shell"),
    (_rx(r"\bchmod\s+(\+x|[0-7]*[1357]\b)"), "notice", "Makes a file executable"),
    (_rx(r"\bcrontab\b"), "warning", "Edits cron jobs"),
    (_rx(r"\bbase64\s+(-d|--decode)"), "warning", "Decodes a base64 payload"),
    (_rx(r"\bwmic(\.exe)?\s.*process\s+call\s+create"), "alert", "Starts a process through WMI"),
    (_rx(r"\b(cmstp|installutil|regasm|regsvcs|msbuild|odbcconf|forfiles|pcalua|msxsl)(\.exe)?\b"), "warning",
     "Living-off-the-land binary (can run arbitrary code)"),
    (_rx(r"\bmsiexec(\.exe)?\s.*https?://"), "alert", "Installs an MSI straight from the internet"),
    (_rx(r"\bcipher(\.exe)?\s+/w"), "alert", "Wipes free disk space (anti-forensics)"),
    (_rx(r"\bfsutil(\.exe)?\s+usn\s+deletejournal"), "alert", "Deletes the USN journal (anti-forensics)"),
    (_rx(r"mimikatz|sekurlsa|lsadump|procdump.*lsass|comsvcs(\.dll)?.*minidump"), "alert", "Credential dumping"),
]

# Windows binaries that only ever run from the Windows folder; a copy elsewhere is masquerading.
SYSTEM_PROCESS_NAMES = frozenset(
    "svchost.exe lsass.exe csrss.exe winlogon.exe services.exe smss.exe wininit.exe spoolsv.exe taskhostw.exe "
    "dllhost.exe conhost.exe explorer.exe lsaiso.exe sihost.exe ctfmon.exe dwm.exe runtimebroker.exe "
    "searchindexer.exe rundll32.exe regsvr32.exe wmiprvse.exe taskmgr.exe userinit.exe".split()
)
_SYSTEM_DIR = _rx(r"^[a-z]:/windows/(system32/|syswow64/|winsxs/|[^/]+$)")

# Routine Windows background processes (hidden from the console unless flagged or tracked).
NOISY_PROCESS_NAMES = frozenset(
    "conhost.exe backgroundtaskhost.exe runtimebroker.exe svchost.exe wmiprvse.exe searchprotocolhost.exe "
    "searchfilterhost.exe smartscreen.exe compattelrunner.exe taskhostw.exe dllhost.exe audiodg.exe "
    "wuauclt.exe msmpeng.exe mpcmdrun.exe nissrv.exe sppsvc.exe trustedinstaller.exe tiworker.exe "
    "musnotification.exe sihclient.exe usocoreworker.exe consent.exe wermgr.exe werfault.exe "
    "systemsettingsbroker.exe applicationframehost.exe textinputhost.exe shellexperiencehost.exe "
    "startmenuexperiencehost.exe searchhost.exe widgets.exe".split()
)

# --------------------------------------------------------------------------------------------
# Network
# --------------------------------------------------------------------------------------------
SUSPICIOUS_PORTS = {
    23: "Telnet",
    1080: "SOCKS proxies",
    1337: "hacker tools",
    3389: "Remote Desktop",
    4444: "Metasploit / reverse shells",
    4445: "reverse shells",
    5555: "Android debug / RATs",
    5900: "VNC remote control",
    6666: "IRC botnets",
    6667: "IRC botnets",
    6697: "IRC botnets",
    9001: "Tor",
    9050: "Tor",
    9150: "Tor",
    31337: "hacker tools",
}


class Rules:
    def __init__(self, state: SessionState):
        self.state = state
        self._renames: Dict[str, Deque[float]] = defaultdict(deque)
        self._rename_alerted: Dict[str, float] = {}
        self._changes: Deque[float] = deque()
        self._burst_alerted = 0.0
        self._notes: Dict[str, Dict[str, float]] = defaultdict(dict)

    def apply(self, event: Event) -> None:
        handler = {
            "file": self._file,
            "registry": self._registry,
            "process": self._process,
            "network": self._network,
        }.get(event.category)
        if handler is not None:
            handler(event)
        if event.tracked:
            event.flag("notice")
        if severity_rank(event.severity) >= severity_rank("warning") or event.tracked:
            event.noise = False

    # ------------------------------------------------------------------------------------------
    def _file(self, ev: Event) -> None:
        path = ev.target
        p = _slash(path)
        if BENIGN_FILES.search(p):
            ev.noise = True
            return
        removed = ev.action in ("deleted", "folder_deleted")
        for rx, level, reason in FILE_RULES:
            if rx.search(p):
                if removed:
                    ev.flag("notice", "Removed: " + reason)
                elif ev.action == "modified" and rx is _TASK_FILES:
                    ev.flag("notice", "Existing scheduled task updated")  # Windows does this routinely
                else:
                    ev.flag(level, reason)

        ext = file_ext(path)
        if ev.action in ("created", "moved") and ext in RISKY_EXTS:
            if STRONG_USER_WRITABLE.search(p):
                ev.flag("warning", "Executable / script dropped in a temp, download or public folder")
            elif WEAK_USER_WRITABLE.search(p):
                ev.flag("warning", "Executable / script dropped in AppData / ProgramData")
            else:
                ev.flag("notice", "Executable / script file written")

        if ev.action == "executable":
            if ext not in RISKY_EXTS:
                # Found by its content rather than its name, so the "created" event was not flagged.
                if STRONG_USER_WRITABLE.search(p):
                    ev.flag("warning", "Executable dropped in a temp, download or public folder")
                elif WEAK_USER_WRITABLE.search(p):
                    ev.flag("warning", "Executable dropped in AppData / ProgramData")
                else:
                    ev.flag("notice", "Executable file written")
            disguised = ev.details.get("disguised_as")
            if disguised in DOCUMENT_EXTS:
                ev.flag("alert", f"Executable code disguised as a {disguised} file")
            elif disguised:
                ev.flag("warning", f"Executable code inside a file named {disguised}")

        if ev.action == "deleted" and ev.details.get("dropped_this_session"):
            ev.flag("notice", "A file dropped during this session was deleted (cleanup / self-delete?)")

        if ev.noise or removed:
            return
        now = ev.timestamp
        self._check_burst(ev, now)
        if ev.action == "moved":
            self._check_mass_rename(ev, now)
        if ev.action == "created":
            self._check_ransom_note(ev, now)

    def _check_burst(self, ev: Event, now: float) -> None:
        if ev.action not in ("created", "modified", "moved"):
            return
        self._changes.append(now)
        while self._changes and now - self._changes[0] > 10:
            self._changes.popleft()
        if len(self._changes) >= 150 and now - self._burst_alerted > 30:
            self._burst_alerted = now
            ev.flag("warning", f"Mass file changes: {len(self._changes)} files touched in 10 seconds")

    def _check_mass_rename(self, ev: Event, now: float) -> None:
        src = os.path.basename(ev.details.get("from") or "").lower()
        dst = os.path.basename(ev.target).lower()
        new_ext = file_ext(dst)
        if not src or not new_ext or new_ext == file_ext(src) or not dst.startswith(src):
            return  # only "photo.jpg" -> "photo.jpg.locked" style renames
        window = self._renames[new_ext]
        window.append(now)
        while window and now - window[0] > 30:
            window.popleft()
        if len(window) >= 10 and now - self._rename_alerted.get(new_ext, 0.0) > 30:
            self._rename_alerted[new_ext] = now
            ev.flag("alert", f"{len(window)} files renamed to *{new_ext} in 30 seconds: possible ransomware encryption")

    def _check_ransom_note(self, ev: Event, now: float) -> None:
        name = os.path.basename(ev.target).lower()
        if not RANSOM_NOTE_NAME.search(name):
            return
        folders = self._notes[name]
        folders[os.path.dirname(ev.target).lower()] = now
        for folder in [f for f, t in folders.items() if now - t > 120]:
            del folders[folder]
        if len(folders) >= 5:
            ev.flag("alert", f"'{name}' written into {len(folders)} folders within 2 minutes: possible ransom note")
        if len(self._notes) > 5000:
            self._notes.clear()

    # ------------------------------------------------------------------------------------------
    def _registry(self, ev: Event) -> None:
        key = ev.target.lower()
        value = (ev.details.get("value") or "").lower()
        if value == "(default)":
            value = ""
        for rx, level, reason in REG_KEY_RULES:
            if rx.search(key):
                ev.flag(level, reason)
        if ev.action.startswith("value_"):
            for key_rx, value_rx, level, reason in REG_VALUE_RULES:
                if (key_rx is None or key_rx.search(key)) and value_rx.search(value):
                    ev.flag(level, reason)
        if ev.action == "key_created":
            for rx, level, reason in REG_CREATE_RULES:
                if rx.search(key):
                    ev.flag(level, reason)
        data = " ".join(str(ev.details.get(k, "")) for k in ("new", "old"))
        dropped = self.state.dropped_in_text(data)
        if dropped:
            ev.flag("alert", f"Registry value points at a file dropped during this session ({os.path.basename(dropped)})")
        if severity_rank(ev.severity) < severity_rank("warning"):
            if any(rx.search(key) for rx in REG_NOISE):
                ev.noise = True
            elif "\\schedule\\taskcache\\" in key and ev.action == "value_modified":
                ev.noise = True  # task run bookkeeping (DynamicInfo)

    # ------------------------------------------------------------------------------------------
    def _process(self, ev: Event) -> None:
        d = ev.details
        if ev.action == "exited":
            if not ev.tracked:
                ev.noise = True
            return
        if ev.action != "started":
            return
        exe = d.get("exe") or ""
        p = _slash(exe)
        name = (d.get("name") or "").lower()
        cmdline = d.get("cmdline") or ""
        if d.get("dropped_image"):
            ev.flag("alert", "Runs a file that was dropped during this session")
        if d.get("dropped_reference"):
            ev.flag("alert", f"Command line uses a file dropped during this session ({os.path.basename(d['dropped_reference'])})")
        if p:
            if STRONG_USER_WRITABLE.search(p):
                ev.flag("warning", "Runs from a temp, download or public folder")
            elif WEAK_USER_WRITABLE.search(p):
                ev.flag("notice", "Runs from AppData / ProgramData")
            if name in SYSTEM_PROCESS_NAMES and ":/" in p and not _SYSTEM_DIR.search(p):
                ev.flag("alert", f"Masquerading: '{name}' running from outside the Windows folder")
        for rx, level, reason in CMDLINE_RULES:
            if rx.search(cmdline):
                ev.flag(level, reason)
        if d.get("short_lived"):
            ev.flag("notice", "Exited almost immediately (caught by WMI tracing)")
        if ev.tracked:
            ev.flag("notice", "Part of the tracked process tree")
        elif name in NOISY_PROCESS_NAMES and severity_rank(ev.severity) < severity_rank("warning"):
            ev.noise = True

    # ------------------------------------------------------------------------------------------
    def _network(self, ev: Event) -> None:
        d = ev.details
        exe = d.get("exe") or ""
        loopback = bool(d.get("loopback"))
        if ev.action == "listening":
            if loopback:
                ev.flag("notice", "New listening port (local machine only)")
            else:
                ev.flag("warning", "New listening port: accepts connections from the network")
        port = d.get("remote_port")
        if ev.action == "connection" and port in SUSPICIOUS_PORTS and not loopback:
            ev.flag("warning", f"Remote port {port} is typical for {SUSPICIOUS_PORTS[port]}")
        if exe and self.state.is_dropped(exe):
            ev.flag("alert", "Network activity by a file dropped during this session")
        elif exe and STRONG_USER_WRITABLE.search(_slash(exe)):
            ev.flag("warning", "Network activity by a program in a temp / download folder")
        if ev.tracked:
            ev.flag("warning", "Network activity by the tracked process tree")
        if severity_rank(ev.severity) < severity_rank("warning") and (loopback or ev.action == "udp_socket"):
            ev.noise = True
