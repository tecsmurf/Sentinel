"""Event Log collection against an in-memory backend (no Windows API needed)."""

import xml.etree.ElementTree as ET
from datetime import UTC, datetime, timedelta

import pytest

from sentinel.collectors.windows_events import (
    MAX_EVENT_XML_CHARS,
    ChannelInfo,
    EventLogAccessError,
    EventQuery,
    RawEvent,
    WindowsEventCollector,
    normalize_event,
    parse_system_time,
)
from sentinel.config import EventLogSettings
from sentinel.models import Severity, SourceType
from tests.support import BASE_TIME, event_xml


class FakeBackend:
    """Interprets EventQuery structurally, like the real XPath query would."""

    def __init__(self, now=BASE_TIME):
        self.now = now
        self.channels: dict[str, list[tuple[int, datetime, int, RawEvent]]] = {}
        self.errors: dict[str, str] = {}
        self.queries: list[EventQuery] = []

    def add(self, channel, record_id, *, provider="App", event_id=1, level=2, when=None, **kw):
        when = when or self.now - timedelta(minutes=1)
        message = kw.pop("message", None)
        xml = event_xml(
            provider=provider, event_id=event_id, record_id=record_id, when=when, level=level,
            channel=channel, **kw,
        )  # fmt: skip
        self.channels.setdefault(channel, []).append(
            (record_id, when, level, RawEvent(xml, message))
        )

    def _events(self, channel):
        if channel in self.errors:
            raise EventLogAccessError(self.errors[channel], f"{channel}: simulated")
        if channel not in self.channels:
            raise EventLogAccessError("not_found", f"{channel}: missing")
        return self.channels[channel]

    def query(self, query):
        self.queries.append(query)
        events = sorted(self._events(query.channel), key=lambda e: e[0], reverse=query.newest_first)
        result = []
        for record_id, when, level, raw in events:
            if query.after_record_id is not None and record_id <= query.after_record_id:
                continue
            if query.levels and level not in query.levels:
                continue
            if query.within is not None and when < self.now - query.within:
                continue
            result.append(raw)
            if len(result) >= query.max_events:
                break
        return result

    def channel_info(self, channel):
        events = self._events(channel)
        ids = [e[0] for e in events]
        return ChannelInfo(min(ids) if ids else None, len(ids))

    def notifier(self, channels):
        return None


def collector(backend, **settings):
    settings.setdefault("channels", ["Application"])
    return WindowsEventCollector(
        EventLogSettings(**settings), backend, clock=lambda: backend.now, batch_size=50
    )


def run(col, checkpoints):
    results = col.poll(checkpoints)
    for result in results:
        checkpoints[result.checkpoint_key] = result.state
    return results


def record_ids(results):
    return [int(o.record_id) for r in results for o in r.observations]


def kinds(results):
    return [n.kind for r in results for n in r.notes]


class TestQueryAndTime:
    def test_xpath_forms(self):
        assert EventQuery("System").xpath() == "*"
        assert EventQuery("System", after_record_id=42).xpath() == ("*[System[EventRecordID > 42]]")
        query = EventQuery("System", levels=(1, 2), within=timedelta(hours=1))
        assert query.xpath() == (
            "*[System[(Level=1 or Level=2) and TimeCreated[timediff(@SystemTime) <= 3600000]]]"
        )

    def test_system_time_with_100ns_precision(self):
        assert parse_system_time("2026-10-15T12:30:56.5397613Z") == datetime(
            2026, 10, 15, 12, 30, 56, 539761, tzinfo=UTC
        )

    def test_system_time_with_offset_and_without_fraction(self):
        assert parse_system_time("2026-10-15T18:00:00+05:30") == datetime(
            2026, 10, 15, 12, 30, tzinfo=UTC
        )

    @pytest.mark.parametrize("text", [None, "", "yesterday", "2026-13-01T00:00:00Z"])
    def test_invalid_system_time(self, text):
        assert parse_system_time(text) is None

    def test_channel_info_newest(self):
        assert ChannelInfo(100, 5).newest_record_id == 104
        assert ChannelInfo(None, 0).newest_record_id is None


def _event(**kwargs) -> RawEvent:
    message = kwargs.pop("message", None)
    kwargs.setdefault("when", BASE_TIME)
    kwargs.setdefault("record_id", 7)
    return RawEvent(event_xml(**kwargs), message)


class TestNormalize:
    def test_service_failure_with_named_data(self):
        raw = _event(
            provider="Service Control Manager", event_id=7023, channel="System",
            data={"param1": "vgc", "param2": "%%1"},
        )  # fmt: skip
        obs = normalize_event(raw, "System", now=BASE_TIME)
        assert obs.source_id == "winevt:System"
        assert obs.source_type is SourceType.WINDOWS_EVENT
        assert (obs.provider, obs.event_code, obs.record_id) == (
            "Service Control Manager",
            "7023",
            "7",
        )
        assert obs.severity is Severity.ERROR
        assert obs.event_timestamp == BASE_TIME
        assert obs.metadata["entity"] == "service:vgc"
        assert obs.metadata["data"] == {"param1": "vgc", "param2": "%%1"}
        assert obs.metadata["user_sid"] == "S-1-5-18"
        assert obs.metadata["message_formatted"] is False
        assert obs.message == "Service Control Manager event 7023: param1=vgc; param2=%%1"
        assert obs.dedup_key.startswith("winevt:System:7:")

    def test_formatted_message_is_preferred(self):
        raw = _event(provider="X", event_id=1, message="  The X service hung.  ")
        obs = normalize_event(raw, "Application")
        assert obs.message == "The X service hung."
        assert obs.metadata["message_formatted"] is True

    def test_application_error_with_positional_data(self):
        raw = _event(provider="Application Error", event_id=1000, data=["Chrome.exe", "1.0", "x"])
        obs = normalize_event(raw, "Application")
        assert obs.metadata["entity"] == "app:chrome.exe"
        assert obs.process_name == "Chrome.exe"

    def test_application_hang_with_named_data(self):
        raw = _event(provider="Application Hang", event_id=1002, data={"AppName": "editor.exe"})
        assert normalize_event(raw, "Application").metadata["entity"] == "app:editor.exe"

    def test_wer_app_crash_and_live_kernel_event(self):
        crash = _event(
            provider="Windows Error Reporting", event_id=1001,
            data={"EventName": "APPCRASH", "P1": "game.exe"},
        )  # fmt: skip
        assert normalize_event(crash, "Application").metadata["entity"] == "app:game.exe"
        live = _event(
            provider="Windows Error Reporting", event_id=1001,
            data={"EventName": "LiveKernelEvent", "P1": "117"},
        )  # fmt: skip
        assert normalize_event(live, "Application").metadata["entity"] == "wer:LiveKernelEvent:117"

    def test_dotnet_runtime_application_from_message(self):
        raw = _event(
            provider=".NET Runtime", event_id=1026,
            message="Application: Billing.exe\nFramework Version: v4.0\nDescription: crashed",
        )  # fmt: skip
        obs = normalize_event(raw, "Application")
        assert obs.metadata["entity"] == "app:billing.exe"
        assert obs.process_name == "Billing.exe"

    def test_user_data_payload(self):
        raw = _event(provider="Microsoft-Windows-Kernel", event_id=5, user_data={"Code": "0x7"})
        assert normalize_event(raw, "System").metadata["data"] == {"Code": "0x7"}

    @pytest.mark.parametrize(
        ("level", "severity"),
        [(1, Severity.CRITICAL), (2, Severity.ERROR), (3, Severity.WARNING), (4, Severity.INFO),
         (0, Severity.INFO), (5, Severity.DEBUG)],
    )  # fmt: skip
    def test_levels(self, level, severity):
        assert (
            normalize_event(_event(provider="X", event_id=1, level=level), "A").severity is severity
        )

    def test_same_failure_has_same_fingerprint(self):
        one = _event(provider="Service Control Manager", event_id=7031, data={"param1": "Spooler"})
        two = _event(
            provider="Service Control Manager", event_id=7031, record_id=8,
            data={"param1": "Spooler"},
        )  # fmt: skip
        other = _event(
            provider="Service Control Manager", event_id=7031, data={"param1": "W32Time"}
        )
        fp = [normalize_event(e, "System").fingerprint for e in (one, two, other)]
        assert fp[0] == fp[1] != fp[2]

    def test_long_message_is_truncated(self):
        obs = normalize_event(
            _event(provider="X", event_id=1, message="m" * 5000), "A", max_message_chars=300
        )
        assert obs.metadata["truncated"] is True
        assert len(obs.message) < 400

    def test_missing_time_uses_collection_time(self):
        xml = _event(provider="X", event_id=1).xml
        xml = xml.replace("<TimeCreated", "<Ignored").replace("<Correlation/>", "<Correlation/>")
        obs = normalize_event(RawEvent(xml), "A", now=BASE_TIME)
        assert obs.event_timestamp == BASE_TIME
        assert obs.metadata["timestamp_inferred"] is True

    def test_malformed_xml_raises_parse_error(self):
        with pytest.raises(ET.ParseError):
            normalize_event(RawEvent("<Event><System>"), "A")

    def test_document_type_declarations_are_rejected(self):
        hostile = '<!DOCTYPE x [<!ENTITY a "aaaa">]><Event>&a;</Event>'
        with pytest.raises(ValueError, match="document type"):
            normalize_event(RawEvent(hostile), "A")

    def test_oversized_xml_is_rejected(self):
        with pytest.raises(ValueError, match="size limit"):
            normalize_event(RawEvent("<Event>" + "x" * MAX_EVENT_XML_CHARS + "</Event>"), "A")

    def test_event_without_system_is_rejected(self):
        with pytest.raises(ValueError, match="System"):
            normalize_event(
                RawEvent("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'/>"),
                "A",
            )


class TestCollector:
    def test_initial_import_is_bounded_by_lookback(self):
        backend = FakeBackend()
        backend.add("Application", 1, when=BASE_TIME - timedelta(hours=30))
        backend.add("Application", 2, when=BASE_TIME - timedelta(hours=2))
        backend.add("Application", 3, when=BASE_TIME - timedelta(hours=1))
        checkpoints = {}
        results = run(collector(backend), checkpoints)
        assert record_ids(results) == [2, 3]  # chronological, within 24 hours
        assert checkpoints["winevt:Application"]["last_record_id"] == 3

    def test_initial_import_limit_is_reported(self):
        backend = FakeBackend()
        for rid in range(1, 11):
            backend.add("Application", rid)
        results = run(collector(backend, max_initial_events_per_channel=4), {})
        assert record_ids(results) == [7, 8, 9, 10]
        assert "initial_import_limited" in kinds(results)

    def test_incremental_polls_only_return_new_events(self):
        backend = FakeBackend()
        backend.add("Application", 1)
        checkpoints = {}
        col = collector(backend)
        run(col, checkpoints)
        backend.add("Application", 2)
        backend.add("Application", 3)
        assert record_ids(run(col, checkpoints)) == [2, 3]
        assert record_ids(run(col, checkpoints)) == []
        assert backend.queries[-1].after_record_id == 3

    def test_severity_filter_still_advances_checkpoint(self):
        backend = FakeBackend()
        backend.add("Application", 1, level=4)
        checkpoints = {}
        col = collector(backend, min_severity="warning")
        run(col, checkpoints)
        for rid in range(2, 6):
            backend.add("Application", rid, level=4)
        backend.add("Application", 6, level=3)
        assert record_ids(run(col, checkpoints)) == [6]
        assert checkpoints["winevt:Application"]["last_record_id"] == 6
        assert backend.queries[-1].levels == (1, 2, 3)

    def test_quiet_filtered_channel_reports_no_false_gap(self):
        backend = FakeBackend()
        for rid in range(1, 4):
            backend.add("Application", rid, level=4)
        checkpoints = {}
        col = collector(backend, min_severity="error")
        run(col, checkpoints)
        backend.channels["Application"] = [e for e in backend.channels["Application"] if e[0] > 2]
        for rid in range(4, 8):
            backend.add("Application", rid, level=4)
        assert "log_gap" not in kinds(run(col, checkpoints))

    def test_overwritten_events_are_reported_as_a_gap(self):
        backend = FakeBackend()
        backend.add("Application", 10)
        checkpoints = {"winevt:Application": {"channel": "Application", "last_record_id": 10}}
        col = collector(backend)
        backend.channels["Application"] = []
        for rid in range(16, 21):
            backend.add("Application", rid)
        results = run(col, checkpoints)
        (gap,) = [n for r in results for n in r.notes if n.kind == "log_gap"]
        assert gap.count == 5
        assert gap.severity is Severity.WARNING
        assert record_ids(results) == [16, 17, 18, 19, 20]

    def test_cleared_log_is_detected_and_reread(self):
        backend = FakeBackend()
        for rid in (1, 2, 3):
            backend.add("Application", rid)
        checkpoints = {"winevt:Application": {"channel": "Application", "last_record_id": 50}}
        results = run(collector(backend), checkpoints)
        assert "log_cleared" in kinds(results)
        assert record_ids(results) == [1, 2, 3]

    def test_access_denied_is_reported_once_then_recovers(self):
        backend = FakeBackend()
        backend.add("Security", 1)
        backend.errors["Security"] = "access_denied"
        col = collector(backend, channels=["Security"])
        checkpoints = {}
        first = run(col, checkpoints)
        assert kinds(first) == ["access_denied"]
        assert "administrator" in first[0].notes[0].message
        assert kinds(run(col, checkpoints)) == []
        del backend.errors["Security"]
        assert "recovered" in kinds(run(col, checkpoints))

    def test_missing_channel(self):
        results = run(collector(FakeBackend(), channels=["Nope/Operational"]), {})
        assert kinds(results) == ["not_found"]

    def test_excluded_providers_and_ids(self):
        backend = FakeBackend()
        backend.add("Application", 1, provider="Noisy")
        backend.add("Application", 2, provider="App", event_id=10016)
        backend.add("Application", 3, provider="App", event_id=1)
        checkpoints = {}
        col = collector(backend, exclude_providers=["noisy"], exclude_event_ids=[10016])
        assert record_ids(run(col, checkpoints)) == [3]
        assert checkpoints["winevt:Application"]["last_record_id"] == 3

    def test_malformed_event_is_skipped_and_reported(self):
        backend = FakeBackend()
        backend.add("Application", 1)
        backend.channels["Application"].append((2, BASE_TIME, 2, RawEvent("<Event><broken")))
        backend.add("Application", 3)
        results = run(collector(backend), {})
        assert record_ids(results) == [1, 3]
        assert "malformed_events" in kinds(results)

    def test_large_backlog_is_read_in_batches(self):
        backend = FakeBackend()
        backend.add("Application", 1)
        checkpoints = {}
        col = collector(backend)
        run(col, checkpoints)
        for rid in range(2, 123):
            backend.add("Application", rid)
        first = run(col, checkpoints)
        assert first[0].more
        assert len(record_ids(first)) == 50
        seen = record_ids(first)
        while True:
            results = run(col, checkpoints)
            seen += record_ids(results)
            if not results[0].more:
                break
        assert seen == list(range(2, 123))

    def test_one_failing_channel_does_not_stop_others(self):
        backend = FakeBackend()
        backend.add("Application", 1)
        backend.add("System", 1)
        original = backend.query

        def query(q):
            if q.channel == "System":
                raise RuntimeError("driver bug")
            return original(q)

        backend.query = query
        results = run(collector(backend, channels=["System", "Application"]), {})
        assert record_ids(results) == [1]
        assert "read_error" in kinds(results)

    def test_disabled_collection(self):
        assert collector(FakeBackend(), enabled=False).poll({}) == []
