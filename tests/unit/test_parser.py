import json
from datetime import UTC, datetime, timedelta, timezone

import pytest

from sentinel.analysis.parser import RecordParser
from sentinel.models import Severity
from tests.support import BASE_TIME  # 2026-10-15 12:00 UTC


def parser(**kwargs) -> RecordParser:
    kwargs.setdefault("local_tz", UTC)
    kwargs.setdefault("clock", lambda: BASE_TIME)
    return RecordParser(**kwargs)


def at(hour, minute=0, second=0, micro=0, day=15, month=10, year=2026):
    return datetime(year, month, day, hour, minute, second, micro, tzinfo=UTC)


class TestTextTimestamps:
    def test_iso_with_zone_and_fraction(self):
        record = parser().parse("2026-10-15T11:59:01.123Z ERROR Disk full")
        assert record.timestamp == at(11, 59, 1, 123000)
        assert record.severity is Severity.ERROR
        assert record.message == "Disk full"

    def test_iso_with_offset(self):
        record = parser().parse("2026-10-15 17:30:00+05:30 [WARN] slow response")
        assert record.timestamp == at(12, 0)
        assert record.severity is Severity.WARNING
        assert record.message == "slow response"

    def test_naive_iso_uses_local_zone(self):
        ist = timezone(timedelta(hours=5, minutes=30))
        record = parser(local_tz=ist).parse("2026-10-15 17:30:00,250 info started")
        assert record.timestamp == at(12, 0, 0, 250000)

    def test_python_logging_layout(self):
        record = parser().parse("2026-10-15 10:00:00,250 - app.db - ERROR - Connection lost")
        assert record.severity is Severity.ERROR
        assert record.message == "app.db - ERROR - Connection lost"

    def test_us_slash_date_with_pm(self):
        record = parser().parse("10/15/2026 1:02:03 PM ERROR service stopped")
        assert record.timestamp == at(13, 2, 3)
        assert record.severity is Severity.ERROR

    def test_day_first_slash_date_when_unambiguous(self):
        assert parser().parse("25/09/2026 08:00:00 x").timestamp == at(8, day=25, month=9)

    def test_common_log_format(self):
        line = '127.0.0.1 - - [15/Oct/2026:11:00:00 +0100] "GET / HTTP/1.1" 500 12'
        record = parser().parse(line)
        assert record.timestamp == at(10, 0)
        assert record.message == line  # the timestamp is not a prefix, so the line is kept

    def test_syslog_with_bracketed_level(self):
        record = parser().parse("Oct 15 11:00:00 host app[12]: <error> failed to bind")
        assert record.timestamp == at(11, 0)
        assert record.severity is Severity.ERROR

    def test_syslog_year_rolls_back_at_new_year(self):
        new_year = datetime(2026, 1, 1, 0, 30, tzinfo=UTC)
        record = parser(clock=lambda: new_year).parse("Dec 31 23:59:00 host x")
        assert record.timestamp == at(23, 59, day=31, month=12, year=2025)

    def test_time_only_uses_today(self):
        record = parser().parse("11:30:00.5 [INFO] started")
        assert record.timestamp == at(11, 30, 0, 500000)
        assert record.message == "started"

    def test_time_only_in_the_future_means_yesterday(self):
        assert parser().parse("23:00:00 x").timestamp == at(23, day=14)

    def test_implausible_timestamp_is_rejected(self):
        record = parser().parse("2099-01-01 00:00:00 ERROR from the future")
        assert record.timestamp is None
        assert record.fields["rejected_timestamp"].startswith("2099-01-01")
        assert record.severity is Severity.ERROR

    def test_invalid_calendar_date_does_not_raise(self):
        assert parser().parse("2026-13-40 10:00:00 ERROR x").timestamp is None


class TestTextSeverity:
    def test_logfmt_level(self):
        record = parser().parse('ts=2026-10-15T11:00:00Z level=warn msg="retrying"')
        assert record.severity is Severity.WARNING

    def test_non_level_brackets_are_skipped(self):
        assert parser().parse("[main] [ERROR] boom").severity is Severity.ERROR

    def test_exception_text_infers_error(self):
        record = parser().parse("Unhandled exception in worker thread")
        assert record.severity is Severity.ERROR
        assert record.severity_inferred

    def test_lowercase_prose_does_not_set_severity(self):
        record = parser().parse("no error was found during the check")
        assert record.severity is None
        assert not record.severity_inferred

    def test_very_long_line_is_handled(self):
        record = parser().parse("2026-10-15 11:00:00 ERROR " + "x" * 200_000)
        assert record.severity is Severity.ERROR
        assert record.timestamp == at(11, 0)


class TestJson:
    def test_common_fields(self):
        line = json.dumps(
            {
                "ts": "2026-10-15T11:00:00Z",
                "level": "warn",
                "msg": "retrying",
                "attempt": 3,
                "nested": {"a": 1},
            }
        )
        record = parser().parse(line)
        assert record.timestamp == at(11, 0)
        assert record.severity is Severity.WARNING
        assert record.message == "retrying"
        assert record.fields == {"attempt": 3}

    @pytest.mark.parametrize("scale", [1, 1_000, 1_000_000, 1_000_000_000])
    def test_epoch_numbers_in_any_unit(self, scale):
        value = int(BASE_TIME.timestamp()) * scale
        record = parser().parse(json.dumps({"time": value, "message": "x"}))
        assert record.timestamp == BASE_TIME

    def test_nested_ecs_level(self):
        line = json.dumps(
            {"@timestamp": "2026-10-15T11:00:00Z", "log": {"level": "error"}, "message": "x"}
        )
        assert parser().parse(line).severity is Severity.ERROR

    def test_numeric_level_is_kept_but_not_guessed(self):
        record = parser().parse(json.dumps({"level": 50, "msg": "x"}))
        assert record.severity is None
        assert record.fields["raw_level"] == 50

    def test_missing_message_uses_compact_json(self):
        record = parser().parse(json.dumps({"event": "login", "user": "x"}))
        assert record.message.startswith('{"event": "login"')

    def test_invalid_json_in_json_mode_is_flagged(self):
        record = parser(fmt="json").parse("{not json} ERROR x")
        assert record.parse_error == "line is not a valid JSON object"
        assert record.severity is Severity.ERROR

    @pytest.mark.parametrize(
        "raw_time",
        ["10" + "0" * 400, "1e400", "NaN", "Infinity", "-Infinity", "-1e30"],
    )
    def test_hostile_epoch_values_do_not_raise(self, raw_time):
        # Regression: float() of a huge JSON integer raised OverflowError outside the guard.
        record = parser().parse(f'{{"time": {raw_time}, "msg": "x", "level": "error"}}')
        assert record.timestamp is None
        assert record.message == "x"
        assert record.severity is Severity.ERROR

    def test_deeply_nested_json_does_not_raise(self):
        record = parser().parse("[" * 100_000 + "]" * 100_000)
        assert record.parse_error is None or "could not be parsed" in record.parse_error

    def test_brace_line_in_auto_mode_falls_back_silently(self):
        record = parser().parse("{not json} ERROR x")
        assert record.parse_error is None
        assert record.severity is Severity.ERROR


class TestCustomPattern:
    PATTERN = r"^(?P<timestamp>\S+ \S+) \| (?P<level>\w+) \| (?P<message>.*)$"

    def test_named_groups_and_strptime_format(self):
        p = parser(line_pattern=self.PATTERN, timestamp_format="%Y/%m/%d %H:%M:%S")
        record = p.parse("2026/10/15 11:00:00 | Warning | low disk space")
        assert record.timestamp == at(11, 0)
        assert record.severity is Severity.WARNING
        assert record.message == "low disk space"

    def test_mismatch_falls_back_to_heuristics(self):
        record = parser(line_pattern=self.PATTERN).parse("2026-10-15 11:00:00 ERROR other")
        assert record.fields["pattern_mismatch"] is True
        assert record.severity is Severity.ERROR

    def test_timestamp_format_mismatch_is_reported(self):
        p = parser(line_pattern=self.PATTERN, timestamp_format="%d.%m.%Y %H:%M")
        record = p.parse("2026/10/15 11:00:00 | Info | x")
        assert record.timestamp is None
        assert record.parse_error == "timestamp did not match the configured format"
