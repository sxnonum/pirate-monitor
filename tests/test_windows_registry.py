"""Real-registry integration tests (Windows only): winreg backend + RegNotifyChangeKeyValue."""

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
