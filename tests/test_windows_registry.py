"""Real-registry integration tests (Windows only): winreg backend + RegNotifyChangeKeyValue."""

import subprocess
import sys
import uuid

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows registry only")

from conftest import wait_for  # noqa: E402


@pytest.fixture
def test_key():
    import winreg

    path = r"Software\PirateMonitorTest-" + uuid.uuid4().hex[:8]
    winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, path).Close()
    yield path
    _delete_tree(winreg.HKEY_CURRENT_USER, path)


def _delete_tree(root, path):
    import winreg

    try:
        with winreg.OpenKey(root, path, 0, winreg.KEY_ALL_ACCESS) as key:
            while True:
                try:
                    child = winreg.EnumKey(key, 0)
                except OSError:
                    break
                _delete_tree(root, path + "\\" + child)
        winreg.DeleteKey(root, path)
    except FileNotFoundError:
        pass


def test_winreg_backend_snapshot(test_key):
    import winreg

    from pirate_monitor.registry.model import take_snapshot
    from pirate_monitor.registry.win32 import WinregBackend

    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, test_key + r"\Sub") as key:
        winreg.SetValueEx(key, "str", 0, winreg.REG_SZ, "hello")
        winreg.SetValueEx(key, "num", 0, winreg.REG_DWORD, 7)
        winreg.SetValueEx(key, "multi", 0, winreg.REG_MULTI_SZ, ["a", "b"])
    snap = take_snapshot(WinregBackend(), "HKCU\\" + test_key)
    sub = snap[("HKCU\\" + test_key + r"\Sub").lower()]
    assert sub.values["str"][2] == "hello"
    assert sub.values["num"][1:] == (winreg.REG_DWORD, 7)
    assert sub.values["multi"][2] == ["a", "b"]
    assert sub.last_write > 0


@pytest.mark.parametrize("split_threshold", [1500, 1])
def test_live_notifications_report_exact_changes(session, test_key, split_threshold):
    import winreg

    from pirate_monitor.monitors.registry import RegistryMonitor

    bus, state, sink = session
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, test_key + r"\Existing\Deep") as key:
        winreg.SetValueEx(key, "keep", 0, winreg.REG_SZ, "1")
    root = "HKCU\\" + test_key
    monitor = RegistryMonitor(bus, state, [root], split_threshold=split_threshold)
    monitor.start()
    assert monitor.ready.wait(30)
    assert monitor.failed is None
    assert monitor.mode == "notifications"

    try:
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, test_key + r"\Existing\Deep") as key:
            winreg.SetValueEx(key, "keep", 0, winreg.REG_SZ, "2")
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, test_key + r"\NewKey\Inner") as key:
            winreg.SetValueEx(key, "payload", 0, winreg.REG_SZ, r"C:\evil.exe")
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, test_key, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "top", 0, winreg.REG_DWORD, 1)

        modified = wait_for(lambda: sink.find("registry", "value_modified", value="keep"))
        assert modified, [e.to_dict() for e in sink.snapshot()]
        assert modified[0].details["old"] == "1" and modified[0].details["new"] == "2"
        assert wait_for(lambda: sink.find("registry", "key_created", target_contains="NewKey"))
        payload = wait_for(lambda: sink.find("registry", "value_created", value="payload"))
        assert payload and payload[0].details["new"] == r"C:\evil.exe"
        assert wait_for(lambda: sink.find("registry", "value_created", value="top"))

        # A second change to the same key must also arrive (notifications are re-armed).
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, test_key + r"\NewKey\Inner") as key:
            winreg.SetValueEx(key, "payload", 0, winreg.REG_SZ, r"C:\evil2.exe")
        assert wait_for(lambda: sink.find("registry", "value_modified", value="payload"))

        _delete_tree(winreg.HKEY_CURRENT_USER, test_key + r"\NewKey")
        deleted = wait_for(lambda: sink.find("registry", "key_deleted", target_contains="NewKey"))
        assert deleted
        top_level = [e for e in deleted if e.target.endswith("NewKey")]
        assert len(top_level) == 1

        # Re-created key keeps being watched.
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, test_key + r"\NewKey") as key:
            winreg.SetValueEx(key, "again", 0, winreg.REG_SZ, "x")
        assert wait_for(lambda: sink.find("registry", "value_created", value="again"))
    finally:
        monitor.stop()


def test_default_roots_catch_every_run_key_write(session):
    """Full default configuration (thousands of watch units) must not miss autorun writes."""
    import time
    import winreg

    from pirate_monitor.defaults import REGISTRY_ROOTS, REGISTRY_SKIP
    from pirate_monitor.monitors.registry import RegistryMonitor
    from pirate_monitor.registry.model import dedupe_key_roots

    bus, state, sink = session
    run_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, run_path).Close()  # missing in fresh profiles
    monitor = RegistryMonitor(bus, state, dedupe_key_roots(REGISTRY_ROOTS), skip=REGISTRY_SKIP)
    monitor.start()
    assert monitor.ready.wait(180)
    assert monitor.failed is None
    names = []

    def write(i, name):
        if i % 3 == 0:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, run_path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, name, 0, winreg.REG_SZ, r"C:\diag.exe")
            return "winreg"
        if i % 3 == 1:
            subprocess.run(["powershell.exe", "-NoProfile", "-Command",
                            f"New-ItemProperty -Path 'HKCU:\\{run_path}' -Name {name} -Value 'C:\\diag.exe' -Force"],
                           check=True, capture_output=True)
            return "powershell"
        subprocess.run(["reg.exe", "add", "HKCU\\" + run_path, "/v", name, "/d", r"C:\diag.exe", "/f"],
                       check=True, capture_output=True)
        return "reg.exe"

    try:
        for i in range(3):
            name = f"PMDiag{uuid.uuid4().hex[:6]}"
            names.append(name)
            written = time.monotonic()
            how = write(i, name)
            seen = wait_for(lambda: sink.find("registry", "value_created", value=name), timeout=15)
            diag = monitor.diagnose("HKCU\\" + run_path)
            print(f"write {i} via {how}: seen={bool(seen)} after {time.monotonic() - written:.2f}s  {diag}")
            if not seen:
                from pirate_monitor.registry.model import take_snapshot
                from pirate_monitor.registry.win32 import WinregBackend

                fresh = take_snapshot(WinregBackend(), "HKCU\\" + run_path, recursive=False)
                fresh_state = next(iter(fresh.values()))
                print("fresh read:", fresh_state.last_write, sorted(v[0] for v in fresh_state.values.values()))
                print("time now:", time.time())
            assert seen, f"Run key write {i} via {how} missed; watcher state: {diag}"
            time.sleep(1)
    finally:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, run_path, 0, winreg.KEY_SET_VALUE) as key:
            for name in names:
                try:
                    winreg.DeleteValue(key, name)
                except OSError:
                    pass
        monitor.stop()
        monitor.join(5)
    print(monitor.stats_line())
