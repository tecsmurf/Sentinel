"""Parse one log record (plain text or a JSON line) into timestamp, severity, and message.

Log content is untrusted input. The parser only inspects bounded prefixes with simple,
linear regular expressions, never evaluates content, and never raises on bad input: a
record that cannot be understood is returned with ``parse_error`` set.

Supported timestamp formats (searched near the start of the record):

* ISO 8601 / RFC 3339 — ``2026-10-15T12:00:01.123Z``, ``2026-10-15 12:00:01,123``
* Slash dates — ``10/15/2026 1:02:03 PM`` (month/day unless the first number exceeds 12)
* Common Log Format — ``[15/Oct/2026:12:00:01 +0000]``
* Syslog — ``Oct 15 12:00:01`` (year inferred)
* Time only — ``12:00:01.123`` at the start of the line (date inferred)

Timestamps without a zone are interpreted in the machine's local time zone.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta, timezone, tzinfo
from typing import Any

from sentinel.models import Severity, utc_now

TIMESTAMP_SEARCH_CHARS = 64
LEVEL_SCAN_CHARS = 160
MAX_PATTERN_INPUT = 4096
MAX_FIELDS = 20
MAX_FIELD_CHARS = 256
_MIN_PLAUSIBLE = datetime(1990, 1, 1, tzinfo=UTC)
_FUTURE_TOLERANCE = timedelta(days=2)

_MONTHS = {
    name: index
    for index, name in enumerate(
        ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"),
        start=1,
    )
}

_ISO = re.compile(
    r"(?P<y>\d{4})-(?P<mo>\d{2})-(?P<d>\d{2})[T ](?P<h>\d{2}):(?P<mi>\d{2}):(?P<s>\d{2})"
    r"(?:[.,](?P<frac>\d{1,9}))?\s?(?P<tz>Z|[+-]\d{2}:?\d{2})?"
)
_SLASH = re.compile(
    r"(?P<a>\d{1,2})/(?P<b>\d{1,2})/(?P<y>\d{4})[ ,T]+(?P<h>\d{1,2}):(?P<mi>\d{2}):(?P<s>\d{2})"
    r"(?:[.,](?P<frac>\d{1,9}))?(?:\s?(?P<ampm>[AaPp][Mm]))?"
)
_CLF = re.compile(
    r"\[(?P<d>\d{2})/(?P<mon>[A-Za-z]{3})/(?P<y>\d{4}):(?P<h>\d{2}):(?P<mi>\d{2}):(?P<s>\d{2})"
    r" (?P<tz>[+-]\d{4})\]"
)
_SYSLOG = re.compile(
    r"^\W{0,2}(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(?P<d>\d{1,2})"
    r" (?P<h>\d{2}):(?P<mi>\d{2}):(?P<s>\d{2})"
)
_TIME_ONLY = re.compile(
    r"^\W{0,2}(?P<h>\d{2}):(?P<mi>\d{2}):(?P<s>\d{2})(?:[.,](?P<frac>\d{1,9}))?"
)

_LOGFMT_LEVEL = re.compile(
    r"\b(?:level|lvl|severity|loglevel)\s*[=:]\s*\"?(?P<v>[A-Za-z]{3,11})", re.IGNORECASE
)
_BRACKETED = re.compile(r"[\[(<]\s*(?P<v>[A-Za-z]{3,11})\s*[\])>]")
_BARE = re.compile(
    r"(?<![\w-])(?P<v>TRACE|DEBUG|INFO|INFORMATION|NOTICE|WARN|WARNING|ERROR|ERR|FATAL"
    r"|CRITICAL|CRIT|SEVERE|ALERT|EMERG)(?![\w-])"
)
_EXCEPTION_HINT = re.compile(
    r"\b(?:exception|traceback|unhandled|fatal error|stack trace)\b", re.IGNORECASE
)
_LEADING_SEPARATORS = re.compile(r"^[\s\-:|>\]]+")

_JSON_TIME_KEYS = ("timestamp", "@timestamp", "time", "ts", "datetime", "date", "t")
_JSON_LEVEL_KEYS = ("level", "severity", "lvl", "loglevel", "levelname", "log.level")
_JSON_MESSAGE_KEYS = ("message", "msg", "text", "@message", "log")


@dataclass(slots=True)
class ParsedRecord:
    message: str
    timestamp: datetime | None = None
    severity: Severity | None = None
    severity_inferred: bool = False
    fields: dict[str, Any] = field(default_factory=dict)
    parse_error: str | None = None


def _fraction_to_micros(frac: str | None) -> int:
    if not frac:
        return 0
    return int((frac + "000000")[:6])


def _parse_offset(text: str | None) -> tzinfo | None:
    if not text:
        return None
    if text == "Z":
        return UTC
    sign = 1 if text[0] == "+" else -1
    digits = text[1:].replace(":", "")
    hours, minutes = int(digits[:2]), int(digits[2:4])
    return timezone(sign * timedelta(hours=hours, minutes=minutes))


class RecordParser:
    """Stateless parser configured per log source."""

    def __init__(
        self,
        fmt: str = "auto",
        line_pattern: str | None = None,
        timestamp_format: str | None = None,
        *,
        local_tz: tzinfo | None = None,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self.fmt = fmt
        self.pattern = re.compile(line_pattern) if line_pattern else None
        self.timestamp_format = timestamp_format
        self.local_tz = local_tz
        self.clock = clock

    # ------------------------------------------------------------------ public API

    def parse(self, text: str) -> ParsedRecord:
        """Parse one record. Never raises: unexpected failures yield ``parse_error``."""
        try:
            return self._parse(text)
        except (ValueError, OverflowError, RecursionError, TypeError) as exc:
            return ParsedRecord(
                message=text.strip(),
                parse_error=f"record could not be parsed ({type(exc).__name__})",
            )

    def _parse(self, text: str) -> ParsedRecord:
        stripped = text.strip()
        if self.fmt == "json" or (self.fmt == "auto" and stripped.startswith("{")):
            record = self._parse_json(stripped)
            if record is not None:
                return record
            if self.fmt == "json":
                fallback = self._parse_text(text)
                fallback.parse_error = "line is not a valid JSON object"
                return fallback
        if self.pattern is not None:
            return self._parse_with_pattern(text)
        return self._parse_text(text)

    # ------------------------------------------------------------------ helpers

    def _localize(self, naive: datetime) -> datetime:
        if self.local_tz is not None:
            return naive.replace(tzinfo=self.local_tz).astimezone(UTC)
        return naive.astimezone().astimezone(UTC)  # naive datetimes are treated as local

    def _finish_timestamp(self, moment: datetime, record: ParsedRecord, raw: str) -> None:
        if moment < _MIN_PLAUSIBLE or moment > self.clock() + _FUTURE_TOLERANCE:
            record.fields["rejected_timestamp"] = raw[:64]
            return
        record.timestamp = moment

    def _match_timestamp(self, text: str) -> tuple[datetime, tuple[int, int]] | None:
        """Find a supported timestamp near the start of ``text``; returns (UTC time, span)."""
        head = text[:TIMESTAMP_SEARCH_CHARS]
        try:
            if m := _ISO.search(head):
                naive = datetime(
                    int(m["y"]), int(m["mo"]), int(m["d"]), int(m["h"]), int(m["mi"]),
                    int(m["s"]), _fraction_to_micros(m["frac"]),
                )  # fmt: skip
                offset = _parse_offset(m["tz"])
                moment = naive.replace(tzinfo=offset).astimezone(UTC) if offset else None
                return (moment or self._localize(naive)), m.span()
            if m := _CLF.search(head):
                naive = datetime(
                    int(m["y"]), _MONTHS[m["mon"].lower()], int(m["d"]),
                    int(m["h"]), int(m["mi"]), int(m["s"]),
                )  # fmt: skip
                offset = _parse_offset(m["tz"][:3] + ":" + m["tz"][3:])
                return naive.replace(tzinfo=offset).astimezone(UTC), m.span()
            if m := _SLASH.search(head):
                first, second = int(m["a"]), int(m["b"])
                month, day = (second, first) if first > 12 else (first, second)
                hour = int(m["h"])
                if m["ampm"]:
                    hour = hour % 12 + (12 if m["ampm"].lower() == "pm" else 0)
                naive = datetime(
                    int(m["y"]), month, day, hour, int(m["mi"]), int(m["s"]),
                    _fraction_to_micros(m["frac"]),
                )  # fmt: skip
                return self._localize(naive), m.span()
            reference = self.clock()
            local_reference = (
                reference.astimezone(self.local_tz) if self.local_tz else (reference.astimezone())
            )
            if m := _SYSLOG.match(head):
                naive = datetime(
                    local_reference.year, _MONTHS[m["mon"].lower()], int(m["d"]),
                    int(m["h"]), int(m["mi"]), int(m["s"]),
                )  # fmt: skip
                moment = self._localize(naive)
                if moment > reference + _FUTURE_TOLERANCE:
                    moment = self._localize(naive.replace(year=naive.year - 1))
                return moment, m.span()
            if m := _TIME_ONLY.match(head):
                naive = datetime(
                    local_reference.year, local_reference.month, local_reference.day,
                    int(m["h"]), int(m["mi"]), int(m["s"]), _fraction_to_micros(m["frac"]),
                )  # fmt: skip
                moment = self._localize(naive)
                if moment > reference + timedelta(hours=1):
                    moment -= timedelta(days=1)
                return moment, m.span()
        except (ValueError, OverflowError):
            return None  # e.g. month 13, day 32
        return None

    @staticmethod
    def _find_level(text: str) -> tuple[Severity, tuple[int, int]] | None:
        head = text[:LEVEL_SCAN_CHARS]
        if m := _LOGFMT_LEVEL.search(head):
            severity = Severity.from_name(m["v"])
            if severity is not None:
                return severity, m.span()
        for m in _BRACKETED.finditer(head):
            severity = Severity.from_name(m["v"])
            if severity is not None:
                return severity, m.span()
        if m := _BARE.search(head):
            severity = Severity.from_name(m["v"])
            if severity is not None:
                return severity, m.span()
        return None

    def _parse_text(self, text: str) -> ParsedRecord:
        record = ParsedRecord(message=text.strip())
        remainder = text
        found = self._match_timestamp(text)
        if found is not None:
            moment, (start, end) = found
            self._finish_timestamp(moment, record, text[start:end])
            if start <= 2:  # timestamp is the record prefix; drop it from the message
                remainder = text[end:]
        remainder = _LEADING_SEPARATORS.sub("", remainder)

        level = self._find_level(remainder)
        if level is not None:
            record.severity, (start, end) = level
            if start == 0:
                remainder = _LEADING_SEPARATORS.sub("", remainder[end:])
        elif _EXCEPTION_HINT.search(remainder[:LEVEL_SCAN_CHARS]):
            record.severity = Severity.ERROR
            record.severity_inferred = True
        record.message = remainder.strip() or text.strip()
        return record

    def _parse_with_pattern(self, text: str) -> ParsedRecord:
        if self.pattern is None:
            return self._parse_text(text)
        match = self.pattern.search(text[:MAX_PATTERN_INPUT])
        if match is None:
            record = self._parse_text(text)
            record.fields["pattern_mismatch"] = True
            return record
        groups = match.groupdict()
        record = ParsedRecord(message=(groups.get("message") or text).strip())
        raw_ts = groups.get("timestamp")
        if raw_ts:
            moment = self._parse_explicit_timestamp(raw_ts)
            if moment is None:
                record.parse_error = "timestamp did not match the configured format"
            else:
                self._finish_timestamp(moment, record, raw_ts)
        raw_level = groups.get("level")
        if raw_level:
            record.severity = Severity.from_name(raw_level)
        return record

    def _parse_explicit_timestamp(self, raw: str) -> datetime | None:
        if self.timestamp_format:
            try:
                parsed = datetime.strptime(raw.strip(), self.timestamp_format)
            except ValueError:
                return None
            return parsed.astimezone(UTC) if parsed.tzinfo else self._localize(parsed)
        found = self._match_timestamp(raw)
        return None if found is None else found[0]

    def _parse_json(self, text: str) -> ParsedRecord | None:
        try:
            data = json.loads(text)
        except (ValueError, RecursionError):
            return None
        if not isinstance(data, dict):
            return None

        def lookup(keys: tuple[str, ...]) -> tuple[str | None, Any]:
            for key in keys:
                if key in data:
                    return key, data[key]
                if "." in key:  # nested, e.g. {"log": {"level": "error"}}
                    outer, inner = key.split(".", 1)
                    nested = data.get(outer)
                    if isinstance(nested, dict) and inner in nested:
                        return key, nested[inner]
            return None, None

        message_key, message = lookup(_JSON_MESSAGE_KEYS)
        if not isinstance(message, str):
            message_key = None
            message = json.dumps(data, ensure_ascii=False, default=str)[: MAX_FIELD_CHARS * 4]
        record = ParsedRecord(message=message.strip())

        time_key, raw_time = lookup(_JSON_TIME_KEYS)
        moment = self._json_time(raw_time)
        if moment is not None:
            self._finish_timestamp(moment, record, str(raw_time))
        level_key, raw_level = lookup(_JSON_LEVEL_KEYS)
        if isinstance(raw_level, str):
            record.severity = Severity.from_name(raw_level)
        elif raw_level is not None:
            record.fields["raw_level"] = raw_level  # numeric scales differ between libraries

        used = {message_key, time_key, level_key}
        for key, value in data.items():
            if len(record.fields) >= MAX_FIELDS:
                break
            if key in used or not isinstance(value, str | int | float | bool):
                continue
            if isinstance(value, str):
                value = value[:MAX_FIELD_CHARS]
            record.fields[str(key)[:64]] = value
        return record

    def _json_time(self, value: Any) -> datetime | None:
        if isinstance(value, bool) or value is None:
            return None
        if isinstance(value, int | float):
            # Epoch value: infer the unit from its magnitude (seconds up to year ~5138).
            try:
                number = float(value)  # huge JSON integers overflow here
            except OverflowError:
                return None
            if not math.isfinite(number):  # json.loads accepts NaN and Infinity
                return None
            if number >= 1e17:
                seconds = number / 1e9  # nanoseconds
            elif number >= 1e14:
                seconds = number / 1e6  # microseconds
            elif number >= 1e11:
                seconds = number / 1e3  # milliseconds
            else:
                seconds = number
            try:
                return datetime.fromtimestamp(seconds, UTC)
            except (OverflowError, OSError, ValueError):
                return None
        if isinstance(value, str):
            found = self._match_timestamp(value)
            return None if found is None else found[0]
        return None
