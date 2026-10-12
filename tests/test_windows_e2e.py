"""Full session on real Windows: default registry roots, files, processes, network and WMI."""

import json
import sys
import uuid

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows only")

RUN_KEY = r"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"


def test_sample_persistence_is_caught_end_to_end(tmp_path, capsys):
    import winreg

    from pirate_monitor.cli import main

    name = "PMTest" + uuid.uuid4().hex[:6]
    watched = tmp_path / "watched"
    watched.mkdir()
    dropped = watched / "stage2.bat"
    script = (
        f"Set-Content -Path '{dropped}' -Value 'echo hi'; "
        f"New-ItemProperty -Path '{RUN_KEY}' -Name {name} -Value '{dropped}' -Force | Out-Null; "
        "cmd.exe /c whoami | Out-Null; "
        "Start-Sleep -Seconds 3"
    )
    out = tmp_path / "out"
    try:
        code = main([
            "--watch", str(watched), "--no-color", "--stop-when-done", "--duration", "300", "-o", str(out),
            "--run", "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script,
        ])
    finally:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run",
                                0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, name)
        except OSError:
            pass
    assert code == 0
    events = [json.loads(line) for line in (out / "events.jsonl").read_text(encoding="utf-8").splitlines()]

    def find(category, action, pred=lambda e: True):
        return [e for e in events if e["category"] == category and e["action"] == action and pred(e)]

    for e in find("system", "message"):
        print(e["time"], e["target"])

    run = find("registry", "value_created", lambda e: e["details"].get("value") == name)
    assert run, "Run key write not seen"
    assert run[0]["severity"] == "alert"
    assert any("dropped" in r for r in run[0]["reasons"]), run[0]

    assert find("file", "created", lambda e: e["target"].lower().endswith("stage2.bat"))
    ps = find("process", "started", lambda e: (e["details"].get("name") or "").lower() == "powershell.exe")
    assert ps and ps[0]["tracked"]
    whoami = find("process", "started", lambda e: (e["details"].get("name") or "").lower() == "whoami.exe")
    assert whoami and whoami[0]["tracked"], "short-lived child should be caught (WMI) and tracked"
    assert any("baseline ready" in e["target"] for e in find("system", "message"))
    assert (out / "report.html").exists()
