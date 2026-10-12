"""Small platform helpers: privilege checks, console colours, hashing, file typing."""

from __future__ import annotations

import ctypes
import hashlib
import os
import sys
import threading
from typing import Dict, Iterable, List, Optional, Tuple

IS_WINDOWS = sys.platform == "win32"
IS_MAC = sys.platform == "darwin"

# Extensions of files that carry native code (PE images on Windows, shared objects elsewhere).
PE_EXTS = frozenset(
    ".exe .dll .sys .scr .com .pif .cpl .ocx .drv .efi .mui .ax .acm .tsp .node .pyd "
    ".winmd .ime .xll .msstyles .tlb .fon".split()
)
EXECUTABLE_EXTS = PE_EXTS | frozenset(
    ".msi .msp .msix .appx .jar .elf .run .appimage .so .dylib .bin".split()
)
# Files that run code when opened / double-clicked, or that configure something to run.
SCRIPT_EXTS = frozenset(
    ".bat .cmd .ps1 .psm1 .psd1 .vbs .vbe .js .jse .wsf .wsh .hta .sct .reg .inf .scf .url .lnk "
    ".application .appref-ms .settingcontent-ms .py .pyw .sh .bash .zsh .command .pl .rb "
    ".desktop .plist .service .timer".split()
)
RISKY_EXTS = EXECUTABLE_EXTS | SCRIPT_EXTS
# Extensions an attacker uses to make an executable look harmless.
DOCUMENT_EXTS = frozenset(
    ".pdf .doc .docx .xls .xlsx .ppt .pptx .txt .rtf .csv .jpg .jpeg .png .gif .bmp .ico .svg "
    ".mp3 .mp4 .avi .mkv .mov .wav .zip .rar .7z .htm .html".split()
)

_MACHO_MAGICS = (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe")


def file_ext(path: str) -> str:
    return os.path.splitext(path)[1].lower()


def norm_path(path: str) -> str:
    """Normalise a path for comparisons (case-insensitive on Windows)."""
    return os.path.normcase(os.path.abspath(path))


def read_magic(path: str, size: int = 4) -> Optional[bytes]:
    try:
        with open(path, "rb") as fh:
            return fh.read(size)
    except OSError:
        return None


def classify_file(path: str, magic: Optional[bytes]) -> Optional[str]:
    """Return a human label if the file can run code, otherwise None."""
    magic = magic or b""
    if magic.startswith(b"MZ"):
        return "PE executable"
    if magic.startswith(b"\x7fELF"):
        return "ELF executable"
    if magic[:4] in _MACHO_MAGICS:
        return "Mach-O executable"
    ext = file_ext(path)
    if ext in SCRIPT_EXTS or magic.startswith(b"#!"):
        return "script / launcher"
    if ext in EXECUTABLE_EXTS:
        return "installer / package"
    return None


def sha256_file(path: str, max_bytes: int) -> Optional[str]:
    digest = hashlib.sha256()
    total = 0
    try:
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(1 << 20)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    return None
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


class HashCache:
    """SHA-256 of files, cached by (path, size, mtime) so repeated launches are cheap."""

    def __init__(self, max_bytes: int):
        self.max_bytes = max_bytes
        self._cache: Dict[Tuple[str, int, int], Optional[str]] = {}
        self._lock = threading.Lock()

    def get(self, path: Optional[str]) -> Optional[str]:
        if not path:
            return None
        try:
            st = os.stat(path)
        except OSError:
            return None
        if st.st_size > self.max_bytes:
            return None
        key = (norm_path(path), st.st_size, st.st_mtime_ns)
        with self._lock:
            if key in self._cache:
                return self._cache[key]
        digest = sha256_file(path, self.max_bytes)
        with self._lock:
            if len(self._cache) > 10000:
                self._cache.clear()
            self._cache[key] = digest
        return digest


def is_admin() -> bool:
    if IS_WINDOWS:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def enable_ansi_colors(stream=None) -> bool:
    """Turn on ANSI escape handling. Returns False if colours should not be used."""
    stream = stream or sys.stdout
    try:
        if not stream.isatty():
            return False
    except Exception:
        return False
    if not IS_WINDOWS:
        return True
    try:
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32
        kernel32.GetStdHandle.restype = wintypes.HANDLE
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = wintypes.DWORD()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        enable_vt = 0x0004  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        if mode.value & enable_vt:
            return True
        return bool(kernel32.SetConsoleMode(handle, mode.value | enable_vt))
    except Exception:
        return False


def dedupe_paths(paths: Iterable[str]) -> List[str]:
    """Resolve paths and drop any that are nested inside another one in the list."""
    resolved = []
    for p in paths:
        if not p:
            continue
        try:
            resolved.append(os.path.realpath(p))
        except OSError:
            continue
    kept: List[str] = []
    kept_keys: List[str] = []
    for p in sorted(set(resolved), key=len):
        key = os.path.normcase(p)
        if not key.endswith(os.sep):
            key += os.sep
        if any(key.startswith(k) for k in kept_keys):
            continue
        kept.append(p)
        kept_keys.append(key)
    return kept


def all_drive_roots() -> List[str]:
    import psutil

    roots = []
    for part in psutil.disk_partitions(all=False):
        opts = (part.opts or "").lower()
        if "cdrom" in opts or not part.fstype:
            continue
        roots.append(part.mountpoint)
    return roots


def human_size(num: Optional[int]) -> str:
    if num is None:
        return "?"
    value = float(num)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:,.0f} {unit}" if unit == "B" else f"{value:,.1f} {unit}"
        value /= 1024
    return f"{num} B"


def shorten(text: str, limit: int) -> str:
    text = str(text)
    return text if len(text) <= limit else text[: limit - 3] + "..."
