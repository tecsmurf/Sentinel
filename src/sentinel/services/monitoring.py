"""Monitoring pipeline: collectors on worker threads, one batching writer (D-008).

``IngestionPipeline`` is the synchronous core: collect from text logs and event logs,
convert health notes into monitoring-health observations, and persist everything in one
transaction. ``MonitoringService`` runs that core continuously:

* a text-log worker (woken by filesystem notifications; reconciles every source on a
  fixed interval),
* an event-log worker (woken by Event Log subscriptions; polls on an interval otherwise),
* a single writer thread that drains a bounded queue and commits in batches.

Backpressure without silent loss: both collectors are pull-based and checkpointed, so
when the queue is full a worker simply does not advance its working checkpoints and the
same data is read again on the next cycle. Each such delay is recorded as a
monitoring-health warning. If a database write fails, the pipeline rewinds its working
checkpoints to the last committed state and starts a new *epoch*; batches collected in an
older epoch are discarded by both the workers and the writer, so nothing is skipped.
"""

from __future__ import annotations

import logging
import queue
import sqlite3
import threading
import time
import uuid
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from sentinel.analysis.normalize import fingerprint
from sentinel.collectors.base import HealthNote
from sentinel.collectors.file_watcher import LogWatcher
from sentinel.collectors.text_logs import TailResult, TailSettings, TextLogCollector
from sentinel.collectors.windows_events import (
    ChannelPollResult,
    EventLogBackend,
    WindowsEventCollector,
    create_backend,
)
from sentinel.config import AppConfig
from sentinel.models import Observation, Severity, SourceType, utc_now
from sentinel.storage import Repository

logger = logging.getLogger(__name__)

SENTINEL_SOURCE = "sentinel:monitoring"
SENTINEL_PROVIDER = "Sentinel Local"
HEALTH_EVENT_TYPE = "monitoring_health"
LOG_BYTES_METRIC = "log_bytes_ingested"
BACKPRESSURE_REPORT_INTERVAL = 60.0
RETRY_DELAY_SECONDS = 0.5
MORE, DONE, RETRY = "more", "done", "retry"

Metric = tuple[str, str, datetime, float]


def health_observation(source_id: str, note: HealthNote, now: datetime) -> Observation:
    """Record a collector problem as a first-class observation (visible and searchable)."""
    metadata: dict[str, Any] = {"source": source_id, "count": note.count}
    if note.path:
        metadata["path"] = note.path
    return Observation(
        source_id=SENTINEL_SOURCE,
        source_type=SourceType.SENTINEL,
        event_timestamp=now,
        collected_at=now,
        severity=note.severity,
        message=note.message,
        dedup_key=f"{SENTINEL_SOURCE}:{note.kind}:{uuid.uuid4().hex}",
        fingerprint=fingerprint("sentinel", source_id, note.kind, message=note.message),
        event_type=HEALTH_EVENT_TYPE,
        provider=SENTINEL_PROVIDER,
        event_code=note.kind,
        metadata=metadata,
    )


@dataclass(slots=True)
class CollectBatch:
    observations: list[Observation] = field(default_factory=list)
    checkpoints: dict[str, dict[str, Any]] = field(default_factory=dict)
    metrics: list[Metric] = field(default_factory=list)
    more: bool = False
    epoch: int = 0

    def __bool__(self) -> bool:
        return bool(self.observations or self.checkpoints or self.metrics)


class IngestionPipeline:
    """Synchronous collection and persistence. Safe for one text and one event worker."""

    def __init__(
        self,
        config: AppConfig,
        *,
        event_backend: EventLogBackend | Literal["auto"] | None = "auto",
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self.config = config
        self.clock = clock
        self.text = TextLogCollector(
            config.text_logs, TailSettings.from_monitoring(config.monitoring), clock=clock
        )
        backend = create_backend() if event_backend == "auto" else event_backend
        self.events: WindowsEventCollector | None = None
        self.event_log_available = backend is not None
        if backend is not None:
            self.events = WindowsEventCollector(
                config.event_logs,
                backend,
                max_message_chars=config.monitoring.max_message_chars,
                clock=clock,
            )
        self._checkpoints: dict[str, dict[str, Any]] = {}
        self._committed: dict[str, dict[str, Any]] = {}
        self._epoch = 0
        self._lock = threading.Lock()

    # -------------------------------------------------------------- checkpoints

    def load_checkpoints(self, repo: Repository) -> None:
        stored = repo.all_checkpoints()
        with self._lock:
            self._checkpoints = {k: dict(v) for k, v in stored.items()}
            self._committed = {k: dict(v) for k, v in stored.items()}

    @property
    def epoch(self) -> int:
        with self._lock:
            return self._epoch

    def _snapshot(self) -> tuple[int, dict[str, dict[str, Any]]]:
        with self._lock:
            return self._epoch, dict(self._checkpoints)

    def checkpoints(self) -> dict[str, dict[str, Any]]:
        return self._snapshot()[1]

    def advance(self, batch: CollectBatch) -> bool:
        """Adopt a batch's checkpoints as the working position, unless it is stale."""
        with self._lock:
            if batch.epoch != self._epoch:
                return False
            self._checkpoints.update(batch.checkpoints)
            return True

    def mark_committed(self, batch: CollectBatch) -> None:
        with self._lock:
            self._committed.update(batch.checkpoints)

    def rewind(self) -> None:
        """Return to the last committed positions (after a failed write); start a new epoch."""
        with self._lock:
            self._checkpoints = {k: dict(v) for k, v in self._committed.items()}
            self._epoch += 1

    # -------------------------------------------------------------- collection

    def startup_notes(self) -> list[Observation]:
        now = self.clock()
        if self.config.event_logs.enabled and not self.event_log_available:
            note = HealthNote(
                "event_log_unavailable",
                Severity.INFO,
                "Windows Event Log collection is not available on this platform",
            )
            return [health_observation("winevt", note, now)]
        return []

    def collect_text(self, source_ids: Iterable[str] | None = None) -> CollectBatch:
        epoch, checkpoints = self._snapshot()
        return self._text_batch(self.text.poll(checkpoints, source_ids), epoch)

    def _text_batch(self, results: list[TailResult], epoch: int) -> CollectBatch:
        now = self.clock()
        batch = CollectBatch(epoch=epoch)
        for result in results:
            batch.observations.extend(result.observations)
            batch.observations.extend(
                health_observation(result.source_id, note, now) for note in result.notes
            )
            if result.state is not None and result.checkpoint_key:
                batch.checkpoints[result.checkpoint_key] = result.state.to_dict()
            if result.bytes_read:
                batch.metrics.append((LOG_BYTES_METRIC, result.path, now, float(result.bytes_read)))
            batch.more = batch.more or result.more
        return batch

    def collect_events(self) -> CollectBatch:
        if self.events is None:
            return CollectBatch(epoch=self.epoch)
        epoch, checkpoints = self._snapshot()
        return self._event_batch(self.events.poll(checkpoints), epoch)

    def _event_batch(self, results: list[ChannelPollResult], epoch: int) -> CollectBatch:
        now = self.clock()
        batch = CollectBatch(epoch=epoch)
        for result in results:
            batch.observations.extend(result.observations)
            batch.observations.extend(
                health_observation(result.checkpoint_key, note, now) for note in result.notes
            )
            batch.checkpoints[result.checkpoint_key] = dict(result.state)
            batch.more = batch.more or result.more
        return batch

    # -------------------------------------------------------------- persistence

    @staticmethod
    def persist(repo: Repository, batches: Iterable[CollectBatch]) -> int:
        """Write batches in one transaction. Returns newly inserted observations."""
        observations: list[Observation] = []
        checkpoints: dict[str, dict[str, Any]] = {}
        metrics: list[Metric] = []
        for batch in batches:
            observations.extend(batch.observations)
            checkpoints.update(batch.checkpoints)
            metrics.extend(batch.metrics)
        with repo.transaction():
            inserted = repo.insert_observations(observations)
            for key, state in checkpoints.items():
                repo.set_checkpoint(key, state)
            if metrics:
                repo.add_metric_samples(metrics)
        return inserted

    def run_once(self, repo: Repository, *, max_cycles: int = 100) -> int:
        """Collect everything currently available and persist it (used by the CLI)."""
        self.load_checkpoints(repo)
        inserted = 0
        startup = self.startup_notes()
        if startup:
            inserted += self.persist(repo, [CollectBatch(observations=startup)])
        for collect in (self.collect_text, self.collect_events):
            for _ in range(max_cycles):
                batch = collect()
                if batch:
                    inserted += self.persist(repo, [batch])
                    self.advance(batch)
                    self.mark_committed(batch)
                if not batch.more:
                    break
        return inserted


@dataclass(slots=True)
class MonitorStatus:
    running: bool = False
    started_at: datetime | None = None
    observations_written: int = 0
    batches_written: int = 0
    last_write_at: datetime | None = None
    queue_depth: int = 0
    backpressure_events: int = 0
    write_failures: int = 0
    event_log_available: bool = False
    watcher_running: bool = False
    text_sources: int = 0
    event_channels: int = 0
    last_text_poll: datetime | None = None
    last_event_poll: datetime | None = None
    last_error: str = ""


_STOP = object()


class MonitoringService:
    """Continuous monitoring on background threads. ``start``/``stop`` are idempotent."""

    def __init__(
        self,
        database_path: Path,
        config: AppConfig,
        *,
        event_backend: EventLogBackend | Literal["auto"] | None = "auto",
        clock: Callable[[], datetime] = utc_now,
        queue_size: int | None = None,
    ) -> None:
        self.database_path = database_path
        self.config = config
        self.clock = clock
        self.pipeline = IngestionPipeline(config, event_backend=event_backend, clock=clock)
        maxsize = queue_size or config.monitoring.queue_max_size
        self._queue: queue.Queue[Any] = queue.Queue(maxsize=maxsize)
        self._stop = threading.Event()
        self._text_wake = threading.Event()
        self._dirty: set[str] = set()
        self._dirty_lock = threading.Lock()
        self._status = MonitorStatus(event_log_available=self.pipeline.event_log_available)
        self._status_lock = threading.Lock()
        self._threads: list[threading.Thread] = []
        self._watcher = LogWatcher(self.request_poll)
        self._pending_notes: list[Observation] = []
        self._last_backpressure_note = float("-inf")

    # -------------------------------------------------------------- lifecycle

    @property
    def running(self) -> bool:
        return any(t.is_alive() for t in self._threads)

    def start(self) -> None:
        if self.running:
            return
        self._stop.clear()
        repo = Repository.open(self.database_path)
        try:
            self.pipeline.load_checkpoints(repo)
        finally:
            repo.close()
        now = self.clock()
        notes = list(self.pipeline.startup_notes())
        notes.extend(
            health_observation("watcher", note, now)
            for note in self._watcher.watch(self.config.text_logs)
        )
        with self._status_lock:
            self._pending_notes.extend(notes)
        targets: list[tuple[str, Callable[[], None]]] = [
            ("sentinel-writer", self._writer_loop),
            ("sentinel-textlogs", self._text_loop),
        ]
        if self.pipeline.events is not None and self.pipeline.events.channels:
            targets.append(("sentinel-eventlog", self._event_loop))
        self._threads = [
            threading.Thread(target=fn, name=name, daemon=True) for name, fn in targets
        ]
        with self._status_lock:
            self._status = MonitorStatus(
                running=True,
                started_at=now,
                event_log_available=self.pipeline.event_log_available,
                watcher_running=self._watcher.running,
                text_sources=len(self.pipeline.text.sources),
                event_channels=len(self.pipeline.events.channels) if self.pipeline.events else 0,
            )
        for thread in self._threads:
            thread.start()
        logger.info("monitoring started", extra={"threads": [t.name for t in self._threads]})

    def stop(self, timeout: float = 10.0) -> None:
        if not self._threads:
            return
        self._stop.set()
        self._text_wake.set()
        self._watcher.stop()
        writer, *workers = self._threads
        for thread in workers:
            thread.join(timeout)
        # Workers are done; the writer drains everything queued before the stop marker.
        self._queue.put(_STOP)
        writer.join(timeout)
        self._threads = []
        with self._status_lock:
            self._status.running = False
            self._status.watcher_running = False
        logger.info("monitoring stopped")

    def request_poll(self, source_id: str | None = None) -> None:
        """Ask the text-log worker to poll now (one source, or all when ``None``)."""
        with self._dirty_lock:
            self._dirty.add(source_id or "*")
        self._text_wake.set()

    def status(self) -> MonitorStatus:
        with self._status_lock:
            snapshot = replace(self._status)
        snapshot.queue_depth = self._queue.qsize()
        return snapshot

    # -------------------------------------------------------------- workers

    def _offer(self, batch: CollectBatch) -> bool:
        """Queue a batch. On success the working checkpoints advance; otherwise they don't."""
        if batch.epoch != self.pipeline.epoch:
            return False  # collected before a rewind; the data will be read again
        try:
            self._queue.put(batch, timeout=self.config.monitoring.enqueue_timeout_seconds)
        except queue.Full:
            with self._status_lock:
                self._status.backpressure_events += 1
            self._report_backpressure()
            return False
        return self.pipeline.advance(batch)

    def _report_backpressure(self) -> None:
        now_mono = time.monotonic()
        if now_mono - self._last_backpressure_note < BACKPRESSURE_REPORT_INTERVAL:
            return
        self._last_backpressure_note = now_mono
        note = HealthNote(
            "ingestion_delayed",
            Severity.WARNING,
            "the database writer is falling behind; collection is paused and resumes from "
            "the last accepted position (no data is skipped)",
        )
        with self._status_lock:
            self._pending_notes.append(health_observation("pipeline", note, self.clock()))

    def _take_dirty(self) -> set[str] | None:
        with self._dirty_lock:
            dirty, self._dirty = self._dirty, set()
        if not dirty or "*" in dirty:
            return None  # poll everything
        return dirty

    def _guarded(self, name: str, action: Callable[[], str]) -> str:
        try:
            return action()
        except Exception as exc:  # keep the worker alive; report and retry next cycle
            logger.exception("monitoring worker error", extra={"worker": name})
            with self._status_lock:
                self._status.last_error = f"{name}: {type(exc).__name__}"
            return DONE

    def _text_cycle(self, source_ids: Iterable[str] | None) -> str:
        batch = self.pipeline.collect_text(source_ids)
        with self._status_lock:
            self._status.last_text_poll = self.clock()
        if batch and not self._offer(batch):
            return RETRY
        return MORE if batch.more else DONE

    def _text_loop(self) -> None:
        interval = self.config.monitoring.reconcile_interval_seconds
        source_ids: set[str] | None = None  # first cycle: reconcile everything
        while not self._stop.is_set():
            outcome = self._guarded("text", lambda ids=source_ids: self._text_cycle(ids))
            if outcome == MORE:
                continue
            if outcome == RETRY:
                self._stop.wait(RETRY_DELAY_SECONDS)
                source_ids = None  # re-read everything not yet accepted
                continue
            self._text_wake.wait(interval)
            self._text_wake.clear()
            source_ids = self._take_dirty()

    def _event_cycle(self) -> str:
        batch = self.pipeline.collect_events()
        with self._status_lock:
            self._status.last_event_poll = self.clock()
        if batch and not self._offer(batch):
            return RETRY
        return MORE if batch.more else DONE

    def _event_loop(self) -> None:
        events = self.pipeline.events
        if events is None:
            return
        interval = self.config.event_logs.poll_interval_seconds
        notifier = None
        try:
            notifier = events.backend.notifier(events.channels)
        except Exception:
            logger.exception("event notifier unavailable; polling instead")
        try:
            while not self._stop.is_set():
                outcome = self._guarded("eventlog", self._event_cycle)
                if outcome == MORE:
                    continue
                if outcome == RETRY:
                    self._stop.wait(RETRY_DELAY_SECONDS)
                    continue
                deadline = time.monotonic() + interval
                while not self._stop.is_set() and time.monotonic() < deadline:
                    step = min(1.0, max(deadline - time.monotonic(), 0.0))
                    if notifier is not None:
                        if notifier.wait(step):
                            break
                    elif self._stop.wait(step):
                        break
        finally:
            if notifier is not None:
                notifier.close()

    def _writer_loop(self) -> None:
        monitoring = self.config.monitoring
        repo = Repository.open(self.database_path)
        pending: list[CollectBatch] = []
        pending_rows = 0
        first_pending = 0.0
        try:
            while True:
                try:
                    item = self._queue.get(timeout=monitoring.batch_interval_seconds)
                except queue.Empty:
                    item = None
                stopping = item is _STOP
                if isinstance(item, CollectBatch) and item.epoch != self.pipeline.epoch:
                    item = None  # collected before a rewind; it will be read again
                if isinstance(item, CollectBatch):
                    if not pending:
                        first_pending = time.monotonic()
                    pending.append(item)
                    pending_rows += len(item.observations)
                with self._status_lock:
                    notes, self._pending_notes = self._pending_notes, []
                if notes:
                    if not pending:
                        first_pending = time.monotonic()
                    pending.append(CollectBatch(observations=notes, epoch=self.pipeline.epoch))
                due = bool(pending) and (
                    stopping
                    or pending_rows >= monitoring.batch_size
                    or time.monotonic() - first_pending >= monitoring.batch_interval_seconds
                )
                if due:
                    self._flush(repo, pending)
                    pending, pending_rows, first_pending = [], 0, 0.0
                if stopping:
                    break
        finally:
            repo.close()

    def _flush(self, repo: Repository, batches: list[CollectBatch]) -> None:
        try:
            inserted = IngestionPipeline.persist(repo, batches)
        except sqlite3.Error as exc:
            logger.exception("database write failed; collectors will re-read the data")
            self.pipeline.rewind()  # queued batches are now stale and will be discarded
            with self._status_lock:
                self._status.write_failures += 1
                self._status.last_error = f"database write failed: {type(exc).__name__}"
            return
        for batch in batches:
            self.pipeline.mark_committed(batch)
        with self._status_lock:
            self._status.observations_written += inserted
            self._status.batches_written += 1
            self._status.last_write_at = self.clock()
