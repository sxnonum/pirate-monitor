import json
import sys

import pytest

from pirate_monitor.cli import build_parser, main


def test_run_collects_remaining_arguments():
    args = build_parser().parse_args(["--duration", "5", "--run", "sample.exe", "--flag", "x"])
    assert args.run == ["sample.exe", "--flag", "x"]
    assert args.duration == 5


def test_bad_registry_key_is_rejected(capsys):
    with pytest.raises(SystemExit):
        main(["--reg-key", "HKXX\\Nope"])


def test_full_session_with_run_writes_report(tmp_path, capsys):
    watched = tmp_path / "watched"
    watched.mkdir()
    out = tmp_path / "out"
    payload = (
        "import pathlib, sys, time;"
        f"pathlib.Path({str(watched)!r}, 'dropped.bat').write_text('@echo off');"
        "time.sleep(1)"
    )
    code = main([
        "--only-watch", "--watch", str(watched), "--no-registry", "--no-color", "--no-wmi",
        "--stop-when-done", "--duration", "40", "-o", str(out),
        "--run", sys.executable, "-c", payload,
    ])
    assert code == 0
    report = (out / "report.html").read_text(encoding="utf-8")
    assert "Pirate Monitor report" in report
    assert "dropped.bat" in report
    events = [json.loads(line) for line in (out / "events.jsonl").read_text(encoding="utf-8").splitlines()]
    started = [e for e in events if e["category"] == "process" and e["action"] == "started" and e["tracked"]]
    assert started, "launched program should be tracked"
    assert any(e["category"] == "file" and e["target"].endswith("dropped.bat") for e in events)
    assert any(e["category"] == "system" and "all tracked processes exited" in e["target"] for e in events)
    printed = capsys.readouterr().out
    assert "Session summary" in printed
