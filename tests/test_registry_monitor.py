"""Drives the RegistryMonitor loop (polling mode) against the in-memory registry."""

from pirate_monitor.monitors.registry import PollingNotifier, RegistryMonitor

from conftest import wait_for
from fake_registry import FakeRegistry


def test_registry_monitor_reports_persistence_changes(session, tmp_path):
    bus, state, sink = session
    reg = FakeRegistry()
    reg.set_value(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "OneDrive", r"C:\od.exe")
    for i in range(10):
        reg.set_value(rf"HKCU\Software\Vendor{i}\App", "x", i, 4)

    monitor = RegistryMonitor(
        bus, state, [r"HKCU\Software"], poll_interval=0.2, split_threshold=4,
        backend_factory=lambda: reg, notifier_factory=PollingNotifier,
    )
    monitor.start()
    assert monitor.ready.wait(10)
    assert monitor.failed is None
    assert wait_for(lambda: any("baseline ready" in e.target for e in sink.find("system")))

    dropped = str(tmp_path / "upd.exe")
    state.add_dropped(dropped)
    reg.set_value(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "Updater", f'"{dropped}" --silent')
    reg.set_value(r"HKCU\Software\EvilCorp\Settings", "id", 1234, 4)
    reg.delete_key(r"HKCU\Software\Vendor3")

    run = wait_for(lambda: sink.find("registry", "value_created", value="Updater"))
    assert run, [e.to_dict() for e in sink.snapshot()]
    ev = run[0]
    assert ev.severity == "alert"
    assert any("Autorun" in r for r in ev.reasons)
    assert any("dropped" in r for r in ev.reasons)
    assert ev.details["new"] == f'"{dropped}" --silent'

    assert wait_for(lambda: sink.find("registry", "key_created", target_contains="EvilCorp\\Settings"))
    created = wait_for(lambda: sink.find("registry", "value_created", value="id"))
    assert created and created[0].details["new"] == "1234 (0x4d2)"
    deleted = wait_for(lambda: sink.find("registry", "key_deleted", target_contains="Vendor3"))
    assert len(deleted) == 1

    monitor.stop()
