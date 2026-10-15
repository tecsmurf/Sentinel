"""Structured application logging.

Sentinel Local's own diagnostics are written as JSON lines to a size-rotated file in the
data directory, so they can be filtered and parsed reliably. Monitored log *content* is
never written to this log; only metadata such as source identifiers and counts.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import sys
import threading
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType

LOGGER_NAME = "sentinel"
LOG_FILE_NAME = "sentinel.log"
DEFAULT_MAX_BYTES = 5 * 1024 * 1024
DEFAULT_BACKUP_COUNT = 5

_HANDLER_MARKER = "_sentinel_handler"
_STANDARD_ATTRS = frozenset(
    vars(logging.LogRecord("", logging.INFO, "", 0, "", (), None)).keys()
) | {"message", "asctime", "taskName"}


class JsonLinesFormatter(logging.Formatter):
    """One JSON object per line: timestamp (UTC), level, logger, message, extra fields."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="microseconds"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "thread": record.threadName,
        }
        for key, value in record.__dict__.items():
            if key not in _STANDARD_ATTRS and not key.startswith("_"):
                payload[key] = value
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        if record.stack_info:
            payload["stack"] = self.formatStack(record.stack_info)
        return json.dumps(payload, default=str, ensure_ascii=False)


def _mark(handler: logging.Handler) -> logging.Handler:
    setattr(handler, _HANDLER_MARKER, True)
    return handler


def configure_logging(
    log_dir: Path | None,
    *,
    level: str | int = "INFO",
    console: bool = True,
    max_bytes: int = DEFAULT_MAX_BYTES,
    backup_count: int = DEFAULT_BACKUP_COUNT,
) -> logging.Logger:
    """Configure the ``sentinel`` logger. Safe to call repeatedly (handlers are replaced)."""
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(level)
    logger.propagate = False

    for handler in list(logger.handlers):
        if getattr(handler, _HANDLER_MARKER, False):
            logger.removeHandler(handler)
            handler.close()

    if log_dir is not None:
        log_dir.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            log_dir / LOG_FILE_NAME,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
            delay=True,
        )
        file_handler.setFormatter(JsonLinesFormatter())
        logger.addHandler(_mark(file_handler))

    # Windowed executables (pythonw, PyInstaller --windowed) have no stderr.
    if console and sys.stderr is not None:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
        )
        logger.addHandler(_mark(console_handler))

    return logger


def install_exception_hooks(logger: logging.Logger | None = None) -> None:
    """Route uncaught exceptions (main thread and worker threads) to the application log."""
    target = logger or logging.getLogger(LOGGER_NAME)
    previous_hook = sys.excepthook

    def handle_exception(
        exc_type: type[BaseException], exc: BaseException, tb: TracebackType | None
    ) -> None:
        if issubclass(exc_type, KeyboardInterrupt):
            previous_hook(exc_type, exc, tb)
            return
        target.critical("uncaught exception", exc_info=(exc_type, exc, tb))

    def handle_thread_exception(args: threading.ExceptHookArgs) -> None:
        if args.exc_type is SystemExit:
            return
        thread_name = args.thread.name if args.thread else "unknown"
        target.error(
            "uncaught exception in worker thread",
            exc_info=(args.exc_type, args.exc_value, args.exc_traceback),
            extra={"worker": thread_name},
        )

    sys.excepthook = handle_exception
    threading.excepthook = handle_thread_exception
