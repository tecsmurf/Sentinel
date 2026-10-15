from datetime import UTC, datetime, timedelta, timezone

import pytest

from sentinel.models import (
    FindingSeverity,
    Severity,
    SourceType,
    from_micros,
    to_micros,
)


class TestTimestamps:
    def test_round_trip_preserves_microseconds(self):
        moment = datetime(2026, 10, 15, 12, 30, 56, 539761, tzinfo=UTC)
        assert from_micros(to_micros(moment)) == moment

    def test_other_timezones_are_converted(self):
        ist = timezone(timedelta(hours=5, minutes=30))
        local = datetime(2026, 10, 15, 18, 0, tzinfo=ist)
        assert from_micros(to_micros(local)) == datetime(2026, 10, 15, 12, 30, tzinfo=UTC)

    def test_naive_datetimes_are_rejected(self):
        with pytest.raises(ValueError, match="naive"):
            to_micros(datetime(2026, 1, 1))

    def test_epoch_is_zero_and_values_sort_chronologically(self):
        assert to_micros(datetime(1970, 1, 1, tzinfo=UTC)) == 0
        earlier = to_micros(datetime(2026, 1, 1, tzinfo=UTC))
        later = to_micros(datetime(2026, 1, 1, 0, 0, 0, 1, tzinfo=UTC))
        assert later - earlier == 1


class TestSeverity:
    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("ERROR", Severity.ERROR),
            ("err", Severity.ERROR),
            ("[WARN]", Severity.WARNING),
            ("Warning:", Severity.WARNING),
            ("fatal", Severity.CRITICAL),
            ("Information", Severity.INFO),
            ("TRACE", Severity.DEBUG),
            ("  notice ", Severity.INFO),
        ],
    )
    def test_from_name_aliases(self, text, expected):
        assert Severity.from_name(text) is expected

    @pytest.mark.parametrize("text", ["", None, "banana", "E"])
    def test_unknown_names_return_none(self, text):
        assert Severity.from_name(text) is None

    @pytest.mark.parametrize(
        ("level", "expected"),
        [
            (1, Severity.CRITICAL),
            (2, Severity.ERROR),
            (3, Severity.WARNING),
            (4, Severity.INFO),
            (5, Severity.DEBUG),
            (0, Severity.INFO),
            (None, Severity.INFO),
            (99, Severity.INFO),
        ],
    )
    def test_windows_levels(self, level, expected):
        assert Severity.from_windows_level(level) is expected

    def test_ordering_and_labels(self):
        assert Severity.ERROR > Severity.WARNING
        assert Severity.CRITICAL.label == "Critical"


def test_finding_severity_from_name():
    assert FindingSeverity.from_name(" high ") is FindingSeverity.HIGH
    assert FindingSeverity.CRITICAL > FindingSeverity.LOW
    with pytest.raises(KeyError):
        FindingSeverity.from_name("extreme")


def test_source_type_values_are_stable_strings():
    # These values are persisted; changing them requires a migration.
    assert [s.value for s in SourceType] == ["windows_event", "text_log", "sentinel"]
