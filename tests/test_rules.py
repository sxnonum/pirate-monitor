from pirate_monitor.core import Event, SessionState
from pirate_monitor.rules import Rules


def graded(event, state=None):
    Rules(state or SessionState()).apply(event)
    return event


def test_run_key_value_is_an_alert():
    ev = graded(Event("registry", "value_created", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                      {"value": "upd", "new": r"C:\x.exe"}))
    assert ev.severity == "alert" and not ev.noise


def test_wow64_and_hklm_run_keys_match_too():
    ev = graded(Event("registry", "value_created", r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
                      {"value": "x", "new": "y"}))
    assert ev.severity == "alert"


def test_defender_and_uac_values():
    ev = graded(Event("registry", "value_created", r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender",
                      {"value": "DisableAntiSpyware", "new": "1"}))
    assert ev.severity == "alert"
    ev = graded(Event("registry", "value_modified", r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                      {"value": "EnableLUA", "old": "1", "new": "0"}))
    assert ev.severity == "alert"


def test_new_service_key_is_an_alert():
    ev = graded(Event("registry", "key_created", r"HKLM\SYSTEM\CurrentControlSet\Services\evilsvc"))
    assert ev.severity == "alert"
    assert "New Windows service registered" in ev.reasons


def test_explorer_bookkeeping_is_noise():
    ev = graded(Event("registry", "value_modified",
                      r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count",
                      {"value": "x", "old": "1", "new": "2"}))
    assert ev.noise and ev.severity == "info"


def test_startup_folder_file_is_an_alert():
    ev = graded(Event("file", "created",
                      r"C:\Users\bob\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\upd.lnk"))
    assert ev.severity == "alert"


def test_executable_dropped_in_temp():
    ev = graded(Event("file", "created", r"C:\Users\bob\AppData\Local\Temp\a1b2.exe"))
    assert ev.severity == "warning"
    ev = graded(Event("file", "created", "/tmp/payload.sh"))
    assert ev.severity == "warning"


def test_disguised_executable():
    ev = graded(Event("file", "executable", r"C:\Users\bob\Downloads\invoice.pdf", {"disguised_as": ".pdf"}))
    assert ev.severity == "alert"


def test_mass_rename_triggers_ransomware_alert():
    rules = Rules(SessionState())
    events = []
    for i in range(12):
        ev = Event("file", "moved", f"/home/u/docs/f{i}.docx.locked", {"from": f"/home/u/docs/f{i}.docx"})
        rules.apply(ev)
        events.append(ev)
    assert events[9].severity == "alert"
    assert "ransomware" in events[9].reasons[-1]


def test_benign_office_save_rename_is_not_ransomware():
    rules = Rules(SessionState())
    for i in range(20):
        ev = Event("file", "moved", f"/home/u/docs/report{i}.docx", {"from": f"/home/u/docs/~WRL{i}.tmp"})
        rules.apply(ev)
        assert ev.severity != "alert"


def test_ransom_note_in_many_folders():
    rules = Rules(SessionState())
    last = None
    for i in range(5):
        last = Event("file", "created", f"/data/folder{i}/HOW_TO_DECRYPT.txt")
        rules.apply(last)
    assert last.severity == "alert"


def test_encoded_powershell_and_shadow_copy_deletion():
    ev = graded(Event("process", "started", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                      {"name": "powershell.exe", "exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                       "cmdline": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA"}))
    assert ev.severity == "alert"
    assert any("encoded" in r for r in ev.reasons)
    ev = graded(Event("process", "started", r"C:\Windows\System32\vssadmin.exe",
                      {"name": "vssadmin.exe", "exe": r"C:\Windows\System32\vssadmin.exe",
                       "cmdline": "vssadmin.exe delete shadows /all /quiet"}))
    assert ev.severity == "alert"


def test_execution_policy_flag_is_not_mistaken_for_encoded_command():
    ev = graded(Event("process", "started", "powershell.exe",
                      {"name": "powershell.exe", "cmdline": "powershell.exe -ExecutionPolicy RemoteSigned -File x.ps1"}))
    assert not any("encoded" in r for r in ev.reasons)


def test_masquerading_system_process():
    ev = graded(Event("process", "started", r"C:\Users\bob\AppData\Roaming\svchost.exe",
                      {"name": "svchost.exe", "exe": r"C:\Users\bob\AppData\Roaming\svchost.exe", "cmdline": ""}))
    assert ev.severity == "alert"
    ok = graded(Event("process", "started", r"C:\Windows\System32\svchost.exe",
                      {"name": "svchost.exe", "exe": r"C:\Windows\System32\svchost.exe", "cmdline": "svchost.exe -k netsvcs"}))
    assert ok.severity == "info" and ok.noise
    explorer = graded(Event("process", "started", r"C:\Windows\explorer.exe",
                            {"name": "explorer.exe", "exe": r"C:\Windows\explorer.exe", "cmdline": ""}))
    assert explorer.severity == "info"


def test_dropped_file_execution_and_network():
    state = SessionState()
    state.add_dropped("/tmp/x/payload")
    ev = graded(Event("process", "started", "/tmp/x/payload",
                      {"name": "payload", "exe": "/tmp/x/payload", "dropped_image": True}, tracked=True), state)
    assert ev.severity == "alert"
    net = graded(Event("network", "connection", "TCP 1.2.3.4:4444",
                       {"exe": "/tmp/x/payload", "remote_port": 4444, "loopback": False}), state)
    assert net.severity == "alert"
    assert any("4444" in r for r in net.reasons)


def test_tracked_events_are_never_hidden():
    ev = graded(Event("process", "exited", "x.exe", {"name": "x.exe"}, tracked=True))
    assert not ev.noise and ev.severity == "notice"
    ev = graded(Event("process", "exited", "y.exe", {"name": "y.exe"}))
    assert ev.noise


def test_loopback_and_udp_noise():
    ev = graded(Event("network", "connection", "TCP 127.0.0.1:5000", {"loopback": True, "remote_port": 5000}))
    assert ev.noise
    ev = graded(Event("network", "listening", "TCP 0.0.0.0:8080", {"loopback": False}))
    assert ev.severity == "warning" and not ev.noise


def test_extensionless_binary_found_by_content_is_flagged_by_location():
    ev = graded(Event("file", "executable", "/tmp/stage/svc-update", {"kind": "ELF executable"}))
    assert ev.severity == "warning"
    ev = graded(Event("file", "executable", r"C:\Users\bob\AppData\Local\Temp\x.exe", {"kind": "PE executable"}))
    assert ev.severity == "info"  # already flagged on its "created" event
