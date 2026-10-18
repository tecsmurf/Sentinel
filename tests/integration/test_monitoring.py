"""Monitoring pipeline: synchronous ingestion, threaded service, backpressure, recovery."""

import sqlite3
import time

import pytest

from sentinel.config import AppConfig, EventLogSettings, TextLogSource
from sentinel.models import SourceType
from sentinel.services.monitoring import IngestionPipeline, MonitoringService
from sentinel.storage import ObservationFilter, Repository
from tests.support import FakeBackend


def make_config(log, channels=("Application",)) -> AppConfig:
    config = AppConfig()
    config.text_logs = [TextLogSource(path=str(log), id="app", name="app")]
    config.event_logs = EventLogSettings(channels=list(channels))
    config.monitoring.batch_interval_seconds = 0.05
    config.monitoring.reconcile_interval_seconds = 0.2
    config.monitoring.enqueue_timeout_seconds = 0.05
    config.event_logs.poll_interval_seconds = 0.5
    return config


def count(database, source_type=None, **filters) -> int:
    repo = Repository.open(database.path)
    try:
        types = [source_type] if source_type else ()
        return repo.count_observations(ObservationFilter(source_types=types, **filters))
    finally:
        repo.close()


def wait_until(predicate, timeout=8.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


def append(path, text):
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(text)


@pytest.fixture
def log(tmp_path):
    path = tmp_path / "app.log"
    path.write_text("first\nsecond\n", encoding="utf-8")
    return path


@pytest.fixture
def backend():
    fake = FakeBackend()
    fake.add("Application", 1, provider="Application Error", event_id=1000)
    fake.add("Application", 2, provider="Application Error", event_id=1000)
    return fake


class TestIngestionPipeline:
    def test_run_once_persists_logs_events_and_health(self, database, log, backend):
        backend.add("Security", 1)
        backend.errors["Security"] = "access_denied"
        config = make_config(log, channels=("Application", "Security"))
        repo = Repository(database.connect())
        try:
            inserted = IngestionPipeline(config, event_backend=backend).run_once(repo)
            assert inserted == 5
            assert count(database, SourceType.TEXT_LOG) == 2
            assert count(database, SourceType.WINDOWS_EVENT) == 2
            (health,) = repo.query_observations(
                ObservationFilter(source_types=[SourceType.SENTINEL])
            )
            assert health.event_code == "access_denied"
            assert health.metadata["source"] == "winevt:Security"
            checkpoints = repo.all_checkpoints()
            assert checkpoints["winevt:Application"]["last_record_id"] == 2
            assert any(key.startswith("app|") for key in checkpoints)
            # Running again, or after a restart, imports nothing twice.
            assert IngestionPipeline(config, event_backend=backend).run_once(repo) == 0
        finally:
            repo.close()

    def test_missing_event_log_support_is_disclosed(self, database, log):
        repo = Repository(database.connect())
        try:
            IngestionPipeline(make_config(log), event_backend=None).run_once(repo)
            (note,) = repo.query_observations(ObservationFilter(source_types=[SourceType.SENTINEL]))
        finally:
            repo.close()
        assert note.event_code == "event_log_unavailable"

    def test_log_growth_metric_is_recorded(self, database, log):
        repo = Repository(database.connect())
        try:
            IngestionPipeline(make_config(log), event_backend=None).run_once(repo)
            (sample,) = repo.metric_series("log_bytes_ingested", since=_epoch())
        finally:
            repo.close()
        assert sample[0] == str(log)
        assert sample[2] == log.stat().st_size  # text mode writes CRLF on Windows


def _epoch():
    from datetime import UTC, datetime

    return datetime(2000, 1, 1, tzinfo=UTC)


class TestMonitoringService:
    def test_ingests_continuously_and_resumes_after_restart(self, database, log, backend):
        config = make_config(log)
        service = MonitoringService(database.path, config, event_backend=backend)
        service.start()
        try:
            assert wait_until(lambda: count(database, SourceType.TEXT_LOG) == 2)
            append(log, "third\n")
            backend.add("Application", 3)
            assert wait_until(lambda: count(database, SourceType.TEXT_LOG) == 3)
            assert wait_until(lambda: count(database, SourceType.WINDOWS_EVENT) == 3)
            status = service.status()
            assert status.running
            assert status.observations_written >= 6
            assert status.text_sources == 1
        finally:
            service.stop()
        assert not service.status().running

        append(log, "written while stopped\n")
        restarted = MonitoringService(database.path, config, event_backend=backend)
        restarted.start()
        try:
            assert wait_until(lambda: count(database, SourceType.TEXT_LOG) == 4)
        finally:
            restarted.stop()
        assert count(database, SourceType.WINDOWS_EVENT) == 3  # no duplicates

    def test_request_poll_wakes_the_worker(self, database, log):
        config = make_config(log, channels=())
        config.monitoring.reconcile_interval_seconds = 120
        service = MonitoringService(database.path, config, event_backend=None)
        service.start()
        try:
            assert wait_until(lambda: count(database, SourceType.TEXT_LOG) == 2)
            append(log, "urgent\n")
            service.request_poll("app")
            assert wait_until(lambda: count(database, SourceType.TEXT_LOG) == 3, timeout=3)
        finally:
            service.stop()

    def test_backpressure_rereads_instead_of_dropping(self, database, log):
        service = MonitoringService(
            database.path, make_config(log, channels=()), event_backend=None, queue_size=1
        )
        pipeline = service.pipeline
        repo = Repository(database.connect())
        try:
            pipeline.load_checkpoints(repo)
            assert service._offer(pipeline.collect_text())  # fills the queue
            append(log, "third\nfourth\n")
            assert not service._offer(pipeline.collect_text())  # queue full: rejected
            assert service.status().backpressure_events == 1
            # The writer catches up...
            queued = service._queue.get_nowait()
            IngestionPipeline.persist(repo, [queued])
            pipeline.mark_committed(queued)
            # ...and the rejected data is simply read again.
            retry = pipeline.collect_text()
            assert [o.message for o in retry.observations if o.source_id == "app"] == [
                "third",
                "fourth",
            ]
            IngestionPipeline.persist(repo, [retry])
        finally:
            repo.close()
        assert count(database, SourceType.TEXT_LOG) == 4
        notes = service._pending_notes
        assert [n.event_code for n in notes] == ["ingestion_delayed"]

    def test_failed_write_rewinds_and_loses_nothing(self, database, log, monkeypatch):
        original = Repository.insert_observations
        calls = {"n": 0}

        def flaky(self, observations):
            calls["n"] += 1
            if calls["n"] == 1:
                raise sqlite3.OperationalError("database is locked")
            return original(self, observations)

        monkeypatch.setattr(Repository, "insert_observations", flaky)
        service = MonitoringService(
            database.path, make_config(log, channels=()), event_backend=None
        )
        service.start()
        try:
            assert wait_until(lambda: count(database, SourceType.TEXT_LOG) == 2)
            assert service.status().write_failures == 1
            assert "database write failed" in service.status().last_error
        finally:
            service.stop()

    def test_stop_is_prompt_and_idempotent(self, database, log, backend):
        service = MonitoringService(database.path, make_config(log), event_backend=backend)
        service.stop()  # not started: no-op
        service.start()
        service.start()  # already running: no-op
        assert wait_until(lambda: count(database, SourceType.TEXT_LOG) == 2)
        started = time.monotonic()
        service.stop()
        assert time.monotonic() - started < 3
        service.stop()
        service.start()
        service.stop()
        assert not service.running
