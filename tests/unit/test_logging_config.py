import json
import logging
import logging.handlers
import sys
import threading

import pytest

from sentinel.logging_config import (
    LOG_FILE_NAME,
    LOGGER_NAME,
    configure_logging,
    install_exception_hooks,
)


@pytest.fixture(autouse=True)
def restore_logger():
    logger = logging.getLogger(LOGGER_NAME)
    saved = (list(logger.handlers), logger.level, logger.propagate)
    saved_hooks = (sys.excepthook, threading.excepthook)
    yield
    for handler in list(logger.handlers):
        if handler not in saved[0]:
            handler.close()
    logger.handlers[:] = saved[0]
    logger.setLevel(saved[1])
    logger.propagate = saved[2]
    sys.excepthook, threading.excepthook = saved_hooks


def read_lines(log_dir):
    for handler in logging.getLogger(LOGGER_NAME).handlers:
        handler.flush()
    text = (log_dir / LOG_FILE_NAME).read_text(encoding="utf-8")
    return [json.loads(line) for line in text.splitlines()]


def test_writes_json_lines_with_extra_fields(tmp_path):
    logger = configure_logging(tmp_path, console=False)
    logging.getLogger("sentinel.test").info(
        "collected %d events", 3, extra={"source_id": "winevt:Application"}
    )
    (record,) = read_lines(tmp_path)
    assert record["msg"] == "collected 3 events"
    assert record["level"] == "INFO"
    assert record["logger"] == "sentinel.test"
    assert record["source_id"] == "winevt:Application"
    assert record["ts"].endswith("+00:00")
    assert logger.propagate is False


def test_exception_info_is_captured(tmp_path):
    configure_logging(tmp_path, console=False)
    try:
        raise ValueError("boom")
    except ValueError:
        logging.getLogger("sentinel.test").exception("failed")
    (record,) = read_lines(tmp_path)
    assert "ValueError: boom" in record["exc"]


def test_reconfiguring_does_not_duplicate_handlers(tmp_path):
    configure_logging(tmp_path, console=True)
    logger = configure_logging(tmp_path, console=True)
    assert len(logger.handlers) == 2


def test_level_filters_records(tmp_path):
    configure_logging(tmp_path, level="WARNING", console=False)
    log = logging.getLogger("sentinel.test")
    log.info("hidden")
    log.warning("shown")
    assert [r["msg"] for r in read_lines(tmp_path)] == ["shown"]


def test_no_console_handler_without_stderr(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "stderr", None)
    logger = configure_logging(tmp_path, console=True)
    # Only the rotating file handler remains (it subclasses StreamHandler, hence the exact check).
    assert [type(h) for h in logger.handlers] == [logging.handlers.RotatingFileHandler]


def test_thread_exceptions_are_logged(tmp_path):
    logger = configure_logging(tmp_path, console=False)
    install_exception_hooks(logger)

    def crash():
        raise RuntimeError("worker failed")

    worker = threading.Thread(target=crash, name="collector-x")
    worker.start()
    worker.join()
    (record,) = read_lines(tmp_path)
    assert record["msg"] == "uncaught exception in worker thread"
    assert record["worker"] == "collector-x"
    assert "RuntimeError: worker failed" in record["exc"]
