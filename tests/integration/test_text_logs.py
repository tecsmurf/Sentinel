import json
import os
from datetime import UTC, timedelta

import pytest

from sentinel.collectors import text_logs
from sentinel.collectors.text_logs import (
    FileState,
    TailSettings,
    TextLogCollector,
    checkpoint_key,
    discover_files,
)
from sentinel.config import TextLogSource
from sentinel.models import Severity, SourceType
from tests.support import BASE_TIME


class Clock:
    def __init__(self):
        self.now = BASE_TIME

    def __call__(self):
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


class Harness:
    """Drives a collector and keeps checkpoints the way the monitoring service does."""

    def __init__(self, *sources, settings=None):
        self.clock = Clock()
        self.collector = TextLogCollector(
            sources, settings or TailSettings(), clock=self.clock, local_tz=UTC
        )
        self.checkpoints: dict[str, dict] = {}

    def poll(self):
        results = self.collector.poll(self.checkpoints)
        for result in results:
            if result.state is not None:
                self.checkpoints[result.checkpoint_key] = result.state.to_dict()
        return results

    def messages(self):
        return [o.message for r in self.poll() for o in r.observations]


def notes(results):
    return [n.kind for r in results for n in r.notes]


def source(path, **kwargs):
    kwargs.setdefault("id", "app")
    kwargs.setdefault("name", "app")
    return TextLogSource(path=str(path), **kwargs)


def append(path, data: bytes):
    with open(path, "ab") as handle:
        handle.write(data)


@pytest.fixture
def log(tmp_path):
    return tmp_path / "app.log"


class TestIncrementalReading:
    def test_reads_only_new_complete_lines(self, log):
        log.write_bytes(b"first\nsecond\n")
        harness = Harness(source(log))
        assert harness.messages() == ["first", "second"]
        append(log, b"third\n")
        assert harness.messages() == ["third"]
        assert harness.messages() == []

    def test_partial_line_waits_for_newline(self, log):
        log.write_bytes(b"one\npart")
        harness = Harness(source(log))
        assert harness.messages() == ["one"]
        append(log, b"ial\n")
        assert harness.messages() == ["partial"]

    def test_partial_line_is_flushed_once_the_file_is_idle(self, log):
        log.write_bytes(b"no newline at the end")
        harness = Harness(source(log))
        assert harness.messages() == []
        harness.clock.advance(1)
        assert harness.messages() == []  # not idle long enough yet
        harness.clock.advance(5)
        assert harness.messages() == ["no newline at the end"]
        assert harness.messages() == []

    def test_crlf_line_endings(self, log):
        log.write_bytes(b"windows line\r\nnext\r\n")
        assert Harness(source(log)).messages() == ["windows line", "next"]

    def test_observation_fields_and_metadata(self, log):
        log.write_bytes(b"2026-10-15 11:00:00 [ERROR] database unavailable\nplain line\n")
        harness = Harness(source(log, name="Billing"))
        first, second = [o for r in harness.poll() for o in r.observations]
        assert first.source_type is SourceType.TEXT_LOG
        assert first.severity is Severity.ERROR
        assert first.event_timestamp == BASE_TIME - timedelta(hours=1)
        assert first.provider == "Billing"
        assert first.message == "database unavailable"
        assert first.metadata["path"] == str(log)
        assert first.metadata["offset"] == 0
        assert second.event_timestamp == BASE_TIME  # no timestamp: collection time is used
        assert second.metadata["timestamp_inferred"] is True
        assert second.severity is Severity.INFO
        assert first.dedup_key != second.dedup_key

    def test_restart_resumes_from_checkpoint(self, log):
        log.write_bytes(b"a\nb\n")
        first = Harness(source(log))
        first.poll()
        append(log, b"c\n")
        restarted = Harness(source(log))
        restarted.checkpoints = dict(first.checkpoints)
        assert restarted.messages() == ["c"]

    def test_rereading_after_checkpoint_loss_produces_identical_keys(self, log):
        log.write_bytes(b"a\nb\n")
        keys_one = [o.dedup_key for r in Harness(source(log)).poll() for o in r.observations]
        keys_two = [o.dedup_key for r in Harness(source(log)).poll() for o in r.observations]
        assert keys_one == keys_two  # the database ignores the duplicates

    def test_read_window_limits_each_poll(self, log):
        log.write_bytes(b"".join(b"line %04d\n" % i for i in range(20_000)))
        harness = Harness(source(log), settings=TailSettings(max_read_bytes=64 * 1024))
        results = harness.poll()
        assert results[0].more
        assert 0 < len(results[0].observations) < 20_000
        total = len(results[0].observations)
        while True:
            results = harness.poll()
            total += len(results[0].observations)
            if not results[0].more:
                break
        assert total == 20_000


class TestRotationAndTruncation:
    def test_truncation_starts_a_new_generation(self, log):
        log.write_bytes(b"one\ntwo\nthree\n")
        harness = Harness(source(log))
        harness.poll()
        log.write_bytes(b"new\n")  # truncates in place (same file)
        results = harness.poll()
        assert [o.message for o in results[0].observations] == ["new"]
        assert "truncated" in notes(results)
        assert results[0].observations[0].metadata["generation"] == 1

    def test_rotation_to_a_new_file_is_detected(self, log):
        log.write_bytes(b"old-1\nold-2\n")
        harness = Harness(source(log))
        harness.poll()
        os.replace(log, log.with_name("app.log.1"))
        log.write_bytes(b"fresh-1\nfresh-2\nfresh-3\n")
        results = harness.poll()
        assert [o.message for o in results[0].observations] == ["fresh-1", "fresh-2", "fresh-3"]
        assert "rotated" in notes(results)

    def test_rewrite_with_longer_content_is_detected_by_head_hash(self, log):
        log.write_bytes(b"AAAA\n")
        harness = Harness(source(log))
        harness.poll()
        with open(log, "r+b") as handle:  # same file, rewritten from the start
            handle.write(b"BBBB\nCCCC\n")
        results = harness.poll()
        assert [o.message for o in results[0].observations] == ["BBBB", "CCCC"]
        assert "replaced" in notes(results)

    def test_unread_data_before_rotation_is_reported(self, log):
        log.write_bytes(b"x" * 300 + b"\n")
        harness = Harness(source(log), settings=TailSettings(max_read_bytes=64 * 1024))
        harness.poll()
        append(log, b"unread line\n")
        # Simulate a poll that saw the larger size but has not read it yet.
        state = FileState.from_dict(harness.checkpoints[checkpoint_key("app", str(log))])
        state.last_size = log.stat().st_size
        harness.checkpoints[checkpoint_key("app", str(log))] = state.to_dict()
        log.write_bytes(b"short\n")
        results = harness.poll()
        (truncated,) = [n for r in results for n in r.notes if n.kind == "truncated"]
        assert truncated.severity is Severity.WARNING
        assert "not read" in truncated.message


class TestBackfillAndLimits:
    def test_existing_large_file_is_read_from_near_its_end(self, log):
        log.write_bytes(b"".join(b"history line %05d\n" % i for i in range(2000)))
        harness = Harness(source(log), settings=TailSettings(initial_backfill_bytes=1024))
        results = harness.poll()
        messages = [o.message for o in results[0].observations]
        assert "backfill_limited" in notes(results)
        assert messages[-1] == "history line 01999"
        assert 0 < len(messages) <= 1024 // 19
        assert all(m.startswith("history line ") for m in messages)  # partial line dropped

    def test_over_long_line_is_truncated_and_remainder_skipped(self, log):
        settings = TailSettings(max_line_bytes=1024, max_read_bytes=64 * 1024)
        log.write_bytes(b"short\n" + b"Z" * 5000 + b"\nafter\n")
        results = Harness(source(log), settings=settings).poll()
        observations = results[0].observations
        assert observations[0].message == "short"
        assert observations[1].metadata["truncated"] is True
        assert observations[1].message.startswith("Z" * 100)
        assert observations[-1].message == "after"
        assert "line_too_long" in notes(results)

    def test_over_long_line_without_newline_does_not_stall(self, log):
        settings = TailSettings(max_line_bytes=1024, max_read_bytes=64 * 1024)
        log.write_bytes(b"Y" * 3000)
        harness = Harness(source(log), settings=settings)
        first = harness.poll()
        assert first[0].observations[0].metadata["truncated"] is True
        append(log, b"Y" * 500 + b"\nnext\n")
        assert harness.messages() == ["next"]


class TestEncodings:
    def test_utf8_bom(self, log):
        log.write_bytes(b"\xef\xbb\xbfh\xc3\xa9llo\n")
        assert Harness(source(log)).messages() == ["héllo"]

    def test_utf16_le_with_bom(self, log):
        log.write_bytes("﻿alpha\r\nβeta\r\n".encode("utf-16-le"))
        harness = Harness(source(log))
        assert harness.messages() == ["alpha", "βeta"]
        append(log, "gamma\r\n".encode("utf-16-le"))
        assert harness.messages() == ["gamma"]

    def test_configured_legacy_encoding(self, log):
        log.write_bytes("café €\n".encode("cp1252"))
        assert Harness(source(log, encoding="cp1252")).messages() == ["café €"]

    def test_invalid_utf8_is_replaced_and_reported(self, log):
        log.write_bytes(b"bad \xff\xfe bytes\n")
        results = Harness(source(log)).poll()
        assert results[0].observations[0].message == "bad �� bytes"
        assert "decode_errors" in notes(results)


class TestMultiline:
    START = r"^\d{4}-\d{2}-\d{2} "

    def test_continuation_lines_join_the_previous_record(self, log):
        log.write_bytes(
            b"2026-10-15 11:00:00 ERROR Unhandled exception\n"
            b"Traceback (most recent call last):\n"
            b'  File "app.py", line 3\n'
            b"2026-10-15 11:00:01 INFO recovered\n"
        )
        harness = Harness(source(log, multiline_start=self.START))
        results = harness.poll()
        (record,) = results[0].observations  # the last record is held back
        assert record.metadata["lines"] == 3
        assert "Traceback" in record.message
        assert record.severity is Severity.ERROR
        # The first poll started the idle timer for the held-back record; once the file has
        # been idle for longer than multiline_flush_seconds, the next poll emits it.
        harness.clock.advance(10)
        assert harness.messages() == ["recovered"]
        assert harness.messages() == []

    def test_continuation_arriving_later_is_joined(self, log):
        log.write_bytes(b"2026-10-15 11:00:00 ERROR failed\n")
        harness = Harness(source(log, multiline_start=self.START))
        assert harness.messages() == []
        append(log, b"  caused by: timeout\n2026-10-15 11:00:05 INFO ok\n")
        (message,) = harness.messages()
        assert message == "failed\n  caused by: timeout"


class TestSourcesAndErrors:
    def test_missing_file_is_reported_once_then_recovers(self, log):
        harness = Harness(source(log))
        assert notes(harness.poll()) == ["missing"]
        assert notes(harness.poll()) == []
        log.write_bytes(b"appeared\n")
        results = harness.poll()
        assert "recovered" in notes(results)
        assert [o.message for o in results[0].observations] == ["appeared"]

    def test_directory_source_with_pattern(self, tmp_path):
        logs = tmp_path / "logs"
        (logs / "nested").mkdir(parents=True)
        (logs / "a.log").write_bytes(b"from a\n")
        (logs / "b.txt").write_bytes(b"ignored\n")
        (logs / "nested" / "c.log").write_bytes(b"from c\n")
        flat = Harness(source(logs, pattern="*.log"))
        assert flat.messages() == ["from a"]
        deep = Harness(source(logs, pattern="*.LOG", recursive=True))
        assert sorted(deep.messages()) == ["from a", "from c"]

    def test_json_lines_source(self, log):
        lines = [
            {"ts": "2026-10-15T11:00:00Z", "level": "error", "msg": "payment failed"},
            {"ts": "2026-10-15T11:00:01Z", "level": "info", "msg": "retry ok"},
        ]
        log.write_text("\n".join(json.dumps(x) for x in lines) + "\n", encoding="utf-8")
        records = [o for r in Harness(source(log, format="json")).poll() for o in r.observations]
        assert [(o.severity, o.message) for o in records] == [
            (Severity.ERROR, "payment failed"),
            (Severity.INFO, "retry ok"),
        ]

    def test_parse_errors_are_reported(self, log):
        log.write_bytes(b"{not json}\n")
        results = Harness(source(log, format="json")).poll()
        assert results[0].observations[0].metadata["parse_error"]
        assert "parse_errors" in notes(results)

    def test_disabled_sources_are_skipped(self, log):
        log.write_bytes(b"x\n")
        assert Harness(source(log, enabled=False)).poll() == []

    def test_invalid_path_is_reported(self):
        files, problems = discover_files(TextLogSource(path="relative/path.log", id="x"))
        assert files == []
        assert problems[0].kind == "config_error"

    def test_one_broken_file_does_not_stop_others(self, tmp_path, monkeypatch):
        good = tmp_path / "good.log"
        bad = tmp_path / "bad.log"
        good.write_bytes(b"fine\n")
        bad.write_bytes(b"boom\n")
        original = TextLogCollector.tail_file

        def flaky(self, compiled, path, key, state):
            if path == str(bad):
                raise RuntimeError("simulated failure")
            return original(self, compiled, path, key, state)

        monkeypatch.setattr(TextLogCollector, "tail_file", flaky)
        harness = Harness(source(bad, id="bad"), source(good, id="good"))
        results = harness.poll()
        assert [o.message for r in results for o in r.observations] == ["fine"]
        assert "read_error" in notes(results)


def test_line_limit_always_fits_in_read_window():
    settings = TailSettings(max_line_bytes=16 * 1024 * 1024, max_read_bytes=64 * 1024)
    assert settings.line_limit == 32 * 1024
    assert TailSettings(max_line_bytes=1001).line_limit % 2 == 0


def test_module_does_not_write_files(tmp_path, monkeypatch, log):
    log.write_bytes(b"x\n")
    real_open = open

    def guarded_open(file, mode="r", *args, **kwargs):
        if any(flag in mode for flag in "wax+"):
            raise AssertionError(f"collector attempted to write {file}")
        return real_open(file, mode, *args, **kwargs)

    monkeypatch.setattr(text_logs, "open", guarded_open, raising=False)
    assert Harness(source(log)).messages() == ["x"]
