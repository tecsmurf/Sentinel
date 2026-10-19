"""The headless CLI end to end, against a temporary data directory."""

import json
import logging
import sys
from pathlib import Path

import pytest

from sentinel.config import AppConfig, TextLogSource, save_config
from sentinel.logging_config import LOGGER_NAME
from sentinel.main import EXIT_OK, EXIT_SETUP, main


@pytest.fixture(autouse=True)
def restore_logging():
    logger = logging.getLogger(LOGGER_NAME)
    saved = (list(logger.handlers), logger.level, logger.propagate)
    hooks = (sys.excepthook,)
    yield
    for handler in list(logger.handlers):
        if handler not in saved[0]:
            handler.close()
    logger.handlers[:] = saved[0]
    logger.setLevel(saved[1])
    logger.propagate = saved[2]
    sys.excepthook = hooks[0]


@pytest.fixture
def data_dir(tmp_path):
    root = tmp_path / "data"
    temp = tmp_path / "Temp"
    temp.mkdir()
    (temp / "cache.tmp").write_bytes(b"x" * 2048)
    log = tmp_path / "app.log"
    log.write_text("".join("ERROR Payment gateway timeout\n" for _ in range(6)), encoding="utf-8")
    config = AppConfig()
    config.event_logs.enabled = False  # keep the test independent of the machine's event logs
    config.temp_scan.include_user_temp = False
    config.temp_scan.include_windows_temp = False
    config.temp_scan.extra_roots = [str(temp)]
    config.text_logs = [TextLogSource(path=str(log), id="app", name="Billing")]
    save_config(config, root / "config.json")
    return root


def run(capsys, *args):
    code = main(["--data-dir", str(args[0]), *args[1:]])
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_no_command_prints_help(capsys, data_dir):
    code, out, _ = run(capsys, data_dir)
    assert code == EXIT_OK
    assert "status" in out and "report" in out


def test_status_on_a_fresh_database(capsys, data_dir):
    code, out, _ = run(capsys, data_dir, "status", "--json")
    assert code == EXIT_OK
    data = json.loads(out)
    assert data["observations"] == 0
    assert data["last_temp_scan"] is None


def test_collect_analyze_findings_and_events(capsys, data_dir):
    code, out, _ = run(capsys, data_dir, "collect", "--json")
    assert code == EXIT_OK
    data = json.loads(out)
    assert data["observations_added"] == 6
    assert data["findings_created"] == 1

    code, out, _ = run(capsys, data_dir, "findings", "--json")
    (finding,) = json.loads(out)
    assert finding["rule_id"] == "repeated_error"
    assert finding["evidence"] == 6

    code, out, _ = run(capsys, data_dir, "findings")
    assert "Repeated error from Billing" in out

    code, out, _ = run(capsys, data_dir, "analyze")
    assert code == EXIT_OK
    assert "0 new" in out

    code, out, _ = run(capsys, data_dir, "events", "--search", "gateway", "--limit", "3")
    assert out.count("Payment gateway timeout") == 3


def test_scan_reports_roots_and_growth(capsys, data_dir, tmp_path):
    code, out, _ = run(capsys, data_dir, "scan", "--json")
    assert code == EXIT_OK
    first = json.loads(out)
    assert first["status"] == "completed"
    assert first["roots"][0]["bytes"] == 2048
    (tmp_path / "Temp" / "new.bin").write_bytes(b"x" * 1024)
    code, out, _ = run(capsys, data_dir, "scan")
    assert code == EXIT_OK
    assert "1.0 KB since" in out


def test_report_writes_a_file(capsys, data_dir, tmp_path):
    run(capsys, data_dir, "collect")
    target = tmp_path / "out" / "report.md"
    code, out, _ = run(capsys, data_dir, "report", "--format", "md", "--out", str(target))
    assert code == EXIT_OK
    assert out.strip() == str(target)
    assert "# Sentinel Local diagnostic report" in target.read_text(encoding="utf-8")

    code, out, _ = run(capsys, data_dir, "report", "--format", "json", "--no-redact")
    path = out.strip()
    assert path.endswith(".json")
    report = json.loads(Path(path).read_text(encoding="utf-8"))
    assert report["report"]["redacted"] is False


def test_config_warnings_are_shown(capsys, data_dir):
    (data_dir / "config.json").write_text('{"ui": {"theme": "neon"}}', encoding="utf-8")
    code, _, err = run(capsys, data_dir, "status")
    assert code == EXIT_OK
    assert "config warning" in err and "neon" in err


def test_unusable_database_exits_with_setup_error(capsys, data_dir):
    (data_dir / "sentinel.db").write_bytes(b"definitely not sqlite" * 100)
    code, _, err = run(capsys, data_dir, "status")
    assert code == EXIT_SETUP
    assert "rename it" in err


def test_version(capsys):
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])
    assert exit_info.value.code == 0
    assert "Sentinel Local" in capsys.readouterr().out
