"""Incremental, checkpointed reading of configured application log files.

Reading is driven entirely by per-file checkpoints (DECISIONS.md D-006): a call to
:meth:`TextLogCollector.poll` is idempotent and cheap when nothing changed, so it can be
triggered by filesystem notifications and by periodic reconciliation alike.

Behaviour:

* Only complete lines are consumed; a trailing partial line (an in-progress write) is
  held back until its newline arrives, or until the file has been idle for
  ``multiline_flush_seconds``.
* With a multi-line start pattern, continuation lines are grouped into the preceding
  record; the last record is held back until the next record starts or the file idles.
* Rotation (a new file at the same path), truncation, and in-place rewrites are detected
  from the file identity, size, and a hash of the first bytes. Each starts a new
  *generation*, so offsets never collide in deduplication keys.
* A newly added file is read from at most ``initial_backfill_bytes`` before its end.
* Lines and pending records are capped below half the read window, so the reader always
  makes progress; over-long lines are truncated and their remainder skipped.
* Encodings: BOM detection (UTF-8, UTF-16 LE/BE), otherwise the configured encoding or
  UTF-8. Undecodable bytes are replaced and reported, never fatal.
* On Windows files are opened with ``FILE_SHARE_DELETE`` so that Sentinel never blocks the
  writing application from rotating or deleting its own log.

Problems are returned as :class:`HealthNote` values, which the monitoring service records
as monitoring-health observations.
"""

from __future__ import annotations

import fnmatch
import hashlib
import logging
import os
import re
import sys
from collections.abc import Callable, Iterable, Mapping
from dataclasses import asdict, dataclass, field
from datetime import datetime, tzinfo
from pathlib import Path
from typing import Any, BinaryIO

from sentinel.analysis.normalize import fingerprint, prepare_message
from sentinel.analysis.parser import RecordParser
from sentinel.collectors.base import HealthNote
from sentinel.config import MonitoringSettings, TextLogSource
from sentinel.models import Observation, Severity, SourceType, utc_now
from sentinel.paths import PathError, canonical_key, expand_path

logger = logging.getLogger(__name__)

__all__ = ["FileState", "HealthNote", "TailResult", "TailSettings", "TextLogCollector"]

HEAD_BYTES = 1024
MAX_FILES_PER_SOURCE = 200
MAX_DIRECTORY_ENTRIES = 50_000
MAX_LINES_PER_RECORD = 500
_BOMS = ((b"\xef\xbb\xbf", "utf-8"), (b"\xff\xfe", "utf-16-le"), (b"\xfe\xff", "utf-16-be"))
_LOG_SUFFIXES = frozenset({".log", ".txt", ".json", ".jsonl", ".ndjson", ".out", ".err"})
_ERROR_SHARING_VIOLATION = 32


@dataclass(frozen=True, slots=True)
class TailSettings:
    max_message_chars: int = 8192
    max_line_bytes: int = 65_536
    max_read_bytes: int = 4 * 1024 * 1024
    multiline_flush_seconds: float = 5.0
    initial_backfill_bytes: int = 1024 * 1024

    @classmethod
    def from_monitoring(cls, settings: MonitoringSettings) -> TailSettings:
        return cls(
            max_message_chars=settings.max_message_chars,
            max_line_bytes=settings.max_line_bytes,
            max_read_bytes=settings.max_read_bytes_per_cycle,
            multiline_flush_seconds=settings.multiline_flush_seconds,
            initial_backfill_bytes=settings.initial_backfill_bytes,
        )

    @property
    def line_limit(self) -> int:
        """Byte cap for one line or pending record; always fits twice in a read window."""
        limit = max(256, min(self.max_line_bytes, self.max_read_bytes // 2))
        return limit - limit % 2  # keep UTF-16 code units whole


@dataclass(slots=True)
class FileState:
    """Checkpoint for one file; persisted as JSON in the ``checkpoints`` table."""

    path: str
    file_id: str | None = None
    generation: int = 0
    offset: int = 0
    head_hash: str | None = None
    head_len: int = 0
    encoding: str | None = None
    status: str = "new"  # new | ok | missing | denied | error
    last_size: int = 0
    pending_size: int | None = None
    pending_since: float | None = None
    discarding: bool = False
    align_to_newline: bool = False

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> FileState:
        known = set(cls.__dataclass_fields__)
        return cls(**{key: value for key, value in data.items() if key in known})

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class TailResult:
    source_id: str
    path: str
    checkpoint_key: str
    state: FileState | None
    observations: list[Observation] = field(default_factory=list)
    notes: list[HealthNote] = field(default_factory=list)
    bytes_read: int = 0
    more: bool = False
    file_size: int | None = None


@dataclass(slots=True)
class _Line:
    start: int
    end: int
    text: str
    truncated: bool


@dataclass(slots=True)
class _CompiledSource:
    source: TextLogSource
    parser: RecordParser
    multiline_start: re.Pattern[str] | None


def checkpoint_key(source_id: str, path: str) -> str:
    return f"{source_id}|{canonical_key(path)}"


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _file_id(info: os.stat_result) -> str | None:
    return f"{info.st_dev}:{info.st_ino}" if info.st_ino else None


def open_shared(path: str) -> BinaryIO:
    """Open a file for reading without preventing the writer from renaming or deleting it."""
    if sys.platform != "win32":
        return open(path, "rb")

    import msvcrt

    import pywintypes
    import win32con
    import win32file

    share = win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE
    try:
        handle = win32file.CreateFile(
            path,
            win32con.GENERIC_READ,
            share,
            None,
            win32con.OPEN_EXISTING,
            win32con.FILE_ATTRIBUTE_NORMAL | win32con.FILE_FLAG_SEQUENTIAL_SCAN,
            None,
        )
    except pywintypes.error as exc:
        if exc.winerror in (2, 3):
            raise FileNotFoundError(exc.winerror, exc.strerror, path) from None
        if exc.winerror == 5:
            raise PermissionError(exc.winerror, exc.strerror, path) from None
        raise OSError(exc.winerror, exc.strerror, path) from None
    fd = msvcrt.open_osfhandle(handle.Detach(), os.O_RDONLY | os.O_BINARY)
    return os.fdopen(fd, "rb")


def _normalise_encoding(name: str) -> str:
    lowered = name.lower().replace("_", "-")
    return "utf-16-le" if lowered in ("utf-16", "utf16") else lowered


def _detect_encoding(start: bytes, configured: str) -> tuple[str, int]:
    for bom, encoding in _BOMS:
        if start.startswith(bom):
            return encoding, len(bom)
    if configured and configured != "auto":
        return _normalise_encoding(configured), 0
    return "utf-8", 0


def _newline_for(encoding: str) -> tuple[bytes, int]:
    if encoding.startswith("utf-16-le"):
        return b"\n\x00", 2
    if encoding.startswith("utf-16-be"):
        return b"\x00\n", 2
    return b"\n", 1


def _find_newline(data: bytes, newline: bytes, unit: int, start: int) -> int:
    index = data.find(newline, start)
    while unit == 2 and index >= 0 and index % 2:
        index = data.find(newline, index + 1)
    return index


def _decode(raw: bytes, encoding: str) -> tuple[str, int]:
    try:
        return raw.decode(encoding), 0
    except UnicodeDecodeError:
        return raw.decode(encoding, errors="replace"), 1


def discover_files(source: TextLogSource) -> tuple[list[str], list[HealthNote]]:
    """Resolve a source to the files it covers (newest first, bounded)."""
    try:
        path = expand_path(source.path)
    except PathError as exc:
        return [], [HealthNote("config_error", Severity.WARNING, f"invalid log path: {exc}")]
    if path.is_file():
        return [str(path)], []
    if path.is_dir():
        return _match_directory(source, path)
    if path.suffix.lower() in _LOG_SUFFIXES:
        return [str(path)], []  # a file that may appear later; reported as missing
    return [], [HealthNote("missing", Severity.WARNING, "log directory does not exist", str(path))]


def _match_directory(source: TextLogSource, root: Path) -> tuple[list[str], list[HealthNote]]:
    pattern = source.pattern.lower()
    matches: list[tuple[float, str]] = []
    notes: list[HealthNote] = []
    stack = [str(root)]
    seen = 0
    while stack and seen < MAX_DIRECTORY_ENTRIES:
        directory = stack.pop()
        try:
            with os.scandir(directory) as iterator:
                for entry in iterator:
                    seen += 1
                    if seen > MAX_DIRECTORY_ENTRIES:
                        notes.append(
                            HealthNote(
                                "too_many_entries",
                                Severity.WARNING,
                                f"stopped listing after {MAX_DIRECTORY_ENTRIES} entries",
                                str(root),
                            )
                        )
                        break
                    try:
                        if entry.is_symlink() or getattr(entry, "is_junction", lambda: False)():
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            if source.recursive:
                                stack.append(entry.path)
                            continue
                        if fnmatch.fnmatch(entry.name.lower(), pattern):
                            matches.append((entry.stat(follow_symlinks=False).st_mtime, entry.path))
                    except OSError:
                        continue
        except PermissionError:
            notes.append(
                HealthNote("access_denied", Severity.WARNING, "cannot list directory", directory)
            )
        except OSError as exc:
            notes.append(HealthNote("read_error", Severity.WARNING, str(exc.strerror), directory))
    matches.sort(reverse=True)
    if len(matches) > MAX_FILES_PER_SOURCE:
        notes.append(
            HealthNote(
                "too_many_files",
                Severity.WARNING,
                f"{len(matches)} files match; only the {MAX_FILES_PER_SOURCE} most recently "
                "modified are monitored",
                str(root),
            )
        )
    return [path for _, path in matches[:MAX_FILES_PER_SOURCE]], notes


class TextLogCollector:
    """Polls configured text-log sources. Not thread-safe; owned by one worker thread."""

    def __init__(
        self,
        sources: Iterable[TextLogSource],
        settings: TailSettings | None = None,
        *,
        clock: Callable[[], datetime] = utc_now,
        local_tz: tzinfo | None = None,
    ) -> None:
        self.settings = settings or TailSettings()
        self.clock = clock
        self.local_tz = local_tz  # None: the machine's local time zone
        self._sources: dict[str, _CompiledSource] = {}
        self.update_sources(sources)

    def update_sources(self, sources: Iterable[TextLogSource]) -> None:
        compiled: dict[str, _CompiledSource] = {}
        for source in sources:
            if not source.enabled:
                continue
            parser = RecordParser(
                source.format,
                source.line_pattern,
                source.timestamp_format,
                local_tz=self.local_tz,
                clock=self.clock,
            )
            start = re.compile(source.multiline_start) if source.multiline_start else None
            compiled[source.id] = _CompiledSource(source, parser, start)
        self._sources = compiled

    @property
    def sources(self) -> list[TextLogSource]:
        return [compiled.source for compiled in self._sources.values()]

    def poll(
        self, checkpoints: Mapping[str, Mapping[str, Any]], source_ids: Iterable[str] | None = None
    ) -> list[TailResult]:
        """Read new data from the given sources (all enabled sources by default)."""
        results: list[TailResult] = []
        for source_id in list(source_ids) if source_ids is not None else list(self._sources):
            compiled = self._sources.get(source_id)
            if compiled is None:
                continue
            files, notes = discover_files(compiled.source)
            if notes:
                results.append(TailResult(source_id, compiled.source.path, "", None, notes=notes))
            for path in files:
                key = checkpoint_key(source_id, path)
                try:
                    results.append(self.tail_file(compiled, path, key, checkpoints.get(key)))
                except Exception as exc:  # one broken file must not stop the others
                    logger.exception(
                        "unexpected error tailing log file", extra={"source": source_id}
                    )
                    note = HealthNote(
                        "read_error",
                        Severity.WARNING,
                        f"unexpected error while reading ({type(exc).__name__})",
                        path,
                    )
                    results.append(TailResult(source_id, path, key, None, notes=[note]))
        return results

    # ------------------------------------------------------------------------------

    def tail_file(
        self,
        compiled: _CompiledSource,
        path: str,
        key: str,
        state_data: Mapping[str, Any] | None,
    ) -> TailResult:
        state = FileState.from_dict(state_data) if state_data else FileState(path=path)
        result = TailResult(compiled.source.id, path, key, state)
        try:
            info = os.stat(path)
        except FileNotFoundError:
            self._set_status(result, "missing", "log file not found")
            return result
        except PermissionError:
            self._set_status(result, "denied", "access to the log file was denied")
            return result
        except OSError as exc:
            self._set_status(result, "error", f"cannot read file information: {exc.strerror}")
            return result

        result.file_size = info.st_size
        file_id = _file_id(info)
        if state.status == "new":
            state.file_id = file_id
            backfill = self.settings.initial_backfill_bytes
            if info.st_size > backfill:
                state.offset = info.st_size - backfill
                state.align_to_newline = True
                result.notes.append(
                    HealthNote(
                        "backfill_limited",
                        Severity.INFO,
                        f"existing file of {info.st_size} bytes: reading started {backfill} "
                        "bytes before the end; older content was not imported",
                        path,
                    )
                )
        else:
            if state.status != "ok":
                result.notes.append(
                    HealthNote("recovered", Severity.INFO, "log file is readable again", path)
                )
            if state.file_id and file_id and state.file_id != file_id:
                self._new_generation(result, "rotated", file_id)
            elif info.st_size < state.offset:
                self._new_generation(result, "truncated", file_id)
        state.status = "ok"

        unchanged = (
            info.st_size == state.offset == state.last_size
            and state.pending_size is None
            and state.head_hash is not None
            and not state.align_to_newline
        )
        if unchanged:
            return result

        try:
            with open_shared(path) as handle:
                self._verify_head(result, handle, info.st_size)
                self._read(compiled, result, handle, info.st_size)
        except FileNotFoundError:
            self._set_status(result, "missing", "log file disappeared while reading")
        except PermissionError:
            self._set_status(result, "denied", "access to the log file was denied")
        except OSError as exc:
            if exc.errno == _ERROR_SHARING_VIOLATION or getattr(exc, "winerror", None) == 32:
                result.notes.append(
                    HealthNote(
                        "file_locked",
                        Severity.INFO,
                        "file is locked by another program; will retry",
                        path,
                    )
                )
            else:
                self._set_status(result, "error", f"read failed: {exc.strerror}")
        state.last_size = info.st_size
        return result

    def _set_status(self, result: TailResult, status: str, message: str) -> None:
        state = result.state
        if state is None:
            return
        if state.status != status:
            kind = {"missing": "missing", "denied": "access_denied"}.get(status, "read_error")
            result.notes.append(HealthNote(kind, Severity.WARNING, message, result.path))
        state.status = status

    def _new_generation(self, result: TailResult, reason: str, file_id: str | None) -> None:
        state = result.state
        if state is None:
            return
        unread = max(state.last_size - state.offset, 0)
        message = {
            "rotated": "log file was rotated (a new file now uses this path)",
            "truncated": "log file was truncated",
            "replaced": "log file content was rewritten from the beginning",
        }[reason]
        severity = Severity.INFO
        if unread:
            message += f"; {unread} previously written bytes were not read before this happened"
            severity = Severity.WARNING
        result.notes.append(HealthNote(reason, severity, message, result.path))
        state.generation += 1
        state.offset = 0
        state.file_id = file_id
        state.head_hash = None
        state.head_len = 0
        state.encoding = None
        state.pending_size = None
        state.pending_since = None
        state.discarding = False
        state.align_to_newline = False

    def _verify_head(self, result: TailResult, handle: BinaryIO, size: int) -> None:
        state = result.state
        if state is None or state.head_hash is None or state.head_len == 0:
            return
        if size < state.head_len:
            return  # covered by truncation detection
        handle.seek(0)
        if _digest(handle.read(state.head_len)) != state.head_hash:
            self._new_generation(result, "replaced", state.file_id)

    def _read(
        self, compiled: _CompiledSource, result: TailResult, handle: BinaryIO, size: int
    ) -> None:
        state = result.state
        if state is None:
            return
        settings = self.settings
        now = self.clock()
        now_ts = now.timestamp()

        if state.encoding is None:
            handle.seek(0)
            encoding, bom_length = _detect_encoding(handle.read(4), compiled.source.encoding)
            state.encoding = encoding
            state.offset = max(state.offset, bom_length)
            if _newline_for(encoding)[1] == 2 and (state.offset - bom_length) % 2:
                state.offset -= 1
        encoding = state.encoding
        newline, unit = _newline_for(encoding)
        limit = settings.line_limit

        handle.seek(state.offset)
        data = handle.read(settings.max_read_bytes)
        result.bytes_read = len(data)
        reached_end = state.offset + len(data) >= size
        pos = 0

        if state.align_to_newline:  # started mid-file: drop the partial first line
            index = _find_newline(data, newline, unit, 0)
            if index < 0:
                pos = len(data) if not reached_end else 0
            else:
                pos = index + len(newline)
                state.align_to_newline = False
        if state.discarding:  # skipping the rest of an over-long line
            index = _find_newline(data, newline, unit, pos)
            if index < 0:
                pos = len(data)
            else:
                pos = index + len(newline)
                state.discarding = False

        lines: list[_Line] = []
        decode_errors = 0
        too_long = 0
        while not state.align_to_newline:
            index = _find_newline(data, newline, unit, pos)
            if index < 0:
                break
            raw = data[pos:index]
            truncated = len(raw) > limit
            if truncated:
                raw = raw[:limit]
                too_long += 1
            text, bad = _decode(raw, encoding)
            decode_errors += bad
            start = state.offset + pos
            pos = index + len(newline)
            lines.append(_Line(start, state.offset + pos, text.rstrip("\r"), truncated))

        tail = b"" if state.align_to_newline else data[pos:]
        if len(tail) >= limit:  # over-long line with no newline in sight
            text, bad = _decode(tail[:limit], encoding)
            decode_errors += bad
            too_long += 1
            lines.append(_Line(state.offset + pos, state.offset + len(data), text, True))
            pos = len(data)
            tail = b""
            state.discarding = True
        tail_start = state.offset + pos

        records = self._group(lines, compiled.multiline_start, limit)
        pending = records.pop() if compiled.multiline_start is not None and records else None

        consumed = tail_start
        if pending is not None or tail:
            idle_long_enough = (
                state.pending_size == size
                and state.pending_since is not None
                and now_ts - state.pending_since >= settings.multiline_flush_seconds
            )
            if idle_long_enough and reached_end:
                if tail:
                    text, bad = _decode(tail, encoding)
                    decode_errors += bad
                    tail_line = _Line(tail_start, tail_start + len(tail), text.rstrip("\r"), False)
                    pending = [*pending, tail_line] if pending else [tail_line]
                records.append(pending)
                consumed = state.offset + len(data)
                state.pending_size = None
                state.pending_since = None
            else:
                if pending is not None:
                    consumed = pending[0].start
                if state.pending_size != size:
                    state.pending_size = size
                    state.pending_since = now_ts
        else:
            state.pending_size = None
            state.pending_since = None

        path_tag = _digest(canonical_key(result.path).encode())[:10]
        parse_errors = 0
        for record in records:
            observation = self._observation(compiled, result.path, path_tag, state, record, now)
            if "parse_error" in observation.metadata:
                parse_errors += 1
            result.observations.append(observation)

        state.offset = consumed
        result.more = state.offset < size and len(data) == settings.max_read_bytes

        if state.head_len < min(HEAD_BYTES, size):  # head already verified; extend it
            handle.seek(0)
            head = handle.read(min(HEAD_BYTES, size))
            state.head_hash = _digest(head)
            state.head_len = len(head)

        if decode_errors:
            result.notes.append(
                HealthNote(
                    "decode_errors",
                    Severity.WARNING,
                    f"{decode_errors} line(s) contained bytes invalid in {encoding}; "
                    "they were replaced",
                    result.path,
                    decode_errors,
                )
            )
        if too_long:
            result.notes.append(
                HealthNote(
                    "line_too_long",
                    Severity.WARNING,
                    f"{too_long} line(s) exceeded {limit} bytes and were truncated",
                    result.path,
                    too_long,
                )
            )
        if parse_errors:
            result.notes.append(
                HealthNote(
                    "parse_errors",
                    Severity.WARNING,
                    f"{parse_errors} record(s) could not be fully parsed",
                    result.path,
                    parse_errors,
                )
            )

    @staticmethod
    def _group(
        lines: list[_Line], start_pattern: re.Pattern[str] | None, limit: int
    ) -> list[list[_Line]]:
        if start_pattern is None:
            return [[line] for line in lines]
        records: list[list[_Line]] = []
        current: list[_Line] | None = None
        current_bytes = 0
        for line in lines:
            starts_record = start_pattern.match(line.text) is not None
            full = current is not None and (
                len(current) >= MAX_LINES_PER_RECORD or current_bytes >= limit
            )
            if current is None or starts_record or full:
                if current is not None:
                    records.append(current)
                current = [line]
                current_bytes = line.end - line.start
            else:
                current.append(line)
                current_bytes += line.end - line.start
        if current is not None:
            records.append(current)
        return records

    def _observation(
        self,
        compiled: _CompiledSource,
        path: str,
        path_tag: str,
        state: FileState,
        record: list[_Line],
        now: datetime,
    ) -> Observation:
        source = compiled.source
        start = record[0].start
        text = "\n".join(line.text for line in record)
        parsed = compiled.parser.parse(text)
        message, message_truncated = prepare_message(
            parsed.message, self.settings.max_message_chars
        )
        metadata: dict[str, Any] = {
            "path": path,
            "offset": start,
            "generation": state.generation,
            "lines": len(record),
        }
        if parsed.fields:
            metadata["fields"] = parsed.fields
        if parsed.timestamp is None:
            metadata["timestamp_inferred"] = True
        if parsed.severity is None:
            metadata["severity_defaulted"] = True
        if parsed.severity_inferred:
            metadata["severity_inferred"] = True
        if parsed.parse_error:
            metadata["parse_error"] = parsed.parse_error
        if message_truncated or any(line.truncated for line in record):
            metadata["truncated"] = True
        content_tag = _digest(text.encode("utf-8", "replace"))[:10]
        return Observation(
            source_id=source.id,
            source_type=SourceType.TEXT_LOG,
            event_timestamp=parsed.timestamp or now,
            severity=parsed.severity or Severity.INFO,
            message=message,
            dedup_key=f"{source.id}:{path_tag}:{state.generation}:{start}:{content_tag}",
            fingerprint=fingerprint("text_log", source.id, message=parsed.message),
            collected_at=now,
            event_type="log_record",
            provider=source.name or Path(path).name,
            record_id=str(start),
            metadata=metadata,
        )
