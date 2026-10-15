import sqlite3
from datetime import timedelta

import pytest

from sentinel.models import (
    DirSnapshot,
    FileSample,
    RootSnapshot,
    ScanError,
    ScanRun,
    ScanStatus,
    Severity,
    SourceType,
)
from sentinel.storage import Database, DatabaseError, ObservationFilter, Repository, transaction
from sentinel.storage.database import SCHEMA_VERSION
from tests.support import BASE_TIME


class TestDatabaseLifecycle:
    def test_initialize_creates_schema_with_expected_pragmas(self, tmp_path):
        db = Database(tmp_path / "nested" / "s.db")
        assert db.initialize() == SCHEMA_VERSION
        conn = db.connect()
        try:
            assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
            assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
            assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
            assert conn.execute("PRAGMA auto_vacuum").fetchone()[0] == 2  # incremental
            tables = {
                row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
        finally:
            conn.close()
        assert {"observations", "checkpoints", "findings", "incidents", "scan_runs"} <= tables

    def test_initialize_is_idempotent(self, database):
        assert database.initialize() == SCHEMA_VERSION

    def test_newer_schema_is_refused(self, database):
        conn = database.connect()
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")
        conn.close()
        with pytest.raises(DatabaseError, match="upgrade the application"):
            database.initialize()

    def test_corrupt_file_is_reported_clearly(self, tmp_path):
        path = tmp_path / "broken.db"
        path.write_bytes(b"this is not a sqlite database" * 100)
        with pytest.raises(DatabaseError, match="not a readable Sentinel database"):
            Database(path).initialize()

    def test_transaction_rolls_back_on_error(self, repo, make_observation):
        with pytest.raises(RuntimeError), repo.transaction():
            repo.insert_observations([make_observation()])
            raise RuntimeError("abort")
        assert repo.count_observations() == 0

    def test_transaction_helper_commits(self, database, make_observation):
        conn = database.connect()
        with transaction(conn):
            Repository(conn).insert_observations([make_observation()])
        conn.close()
        reader = Repository.open(database.path)
        assert reader.count_observations() == 1
        reader.close()


class TestObservations:
    def test_duplicate_dedup_keys_are_ignored(self, repo, make_observation):
        first = make_observation(dedup_key="winevt:Application:1")
        again = make_observation(message="different text", dedup_key="winevt:Application:1")
        assert repo.insert_observations([first]) == 1
        assert repo.insert_observations([again, make_observation()]) == 1
        assert repo.count_observations() == 2

    def test_round_trip_preserves_fields(self, repo, make_observation):
        original = make_observation(
            "Faulting application name: app.exe — ünïcode ✓",
            severity=Severity.CRITICAL,
            source_type=SourceType.WINDOWS_EVENT,
            event_code="1000",
            record_id="49378",
            process_name="app.exe",
            process_id=4242,
            metadata={"channel": "Application", "data": {"AppName": "app.exe"}},
        )
        repo.insert_observations([original])
        (stored,) = repo.query_observations()
        assert stored.id is not None
        for name in (
            "source_id",
            "source_type",
            "event_timestamp",
            "severity",
            "message",
            "event_code",
            "record_id",
            "process_name",
            "process_id",
            "fingerprint",
            "metadata",
        ):
            assert getattr(stored, name) == getattr(original, name), name

    def test_filters(self, repo, make_observation):
        repo.insert_observations(
            [
                make_observation("disk warning", severity=Severity.WARNING, provider="disk"),
                make_observation("app error", severity=Severity.ERROR, provider="app"),
                make_observation(
                    "service crashed",
                    severity=Severity.CRITICAL,
                    source_id="winevt:System",
                    source_type=SourceType.WINDOWS_EVENT,
                    provider="Service Control Manager",
                    event_code="7031",
                ),
            ]
        )
        count = repo.count_observations
        assert count(ObservationFilter(min_severity=Severity.ERROR)) == 2
        assert count(ObservationFilter(source_types=[SourceType.WINDOWS_EVENT])) == 1
        assert count(ObservationFilter(source_ids=["winevt:System", "test:source"])) == 3
        assert count(ObservationFilter(provider="disk")) == 1
        assert count(ObservationFilter(event_code="7031")) == 1
        assert count(ObservationFilter(text="CRASHED")) == 1  # case-insensitive
        assert count(ObservationFilter(text="7031")) == 1  # event-code match
        assert count(ObservationFilter(since=BASE_TIME + timedelta(seconds=2))) == 2
        assert count(ObservationFilter(until=BASE_TIME + timedelta(seconds=2))) == 1

    def test_text_search_treats_wildcards_literally(self, repo, make_observation):
        repo.insert_observations(
            [make_observation("100% done"), make_observation("1000 done"), make_observation("a_b")]
        )
        assert repo.count_observations(ObservationFilter(text="100%")) == 1
        assert repo.count_observations(ObservationFilter(text="a_b")) == 1
        assert repo.count_observations(ObservationFilter(text="'; DROP TABLE x; --")) == 0

    def test_ordering_limit_offset_and_after_id(self, repo, make_observation):
        repo.insert_observations([make_observation(f"m{i}") for i in range(5)])
        newest = repo.query_observations(limit=2)
        assert [o.message for o in newest] == ["m4", "m3"]
        assert [o.message for o in repo.query_observations(limit=2, offset=2)] == ["m2", "m1"]
        oldest = repo.query_observations(limit=1, newest_first=False)
        assert oldest[0].message == "m0"
        later = repo.query_observations(ObservationFilter(after_id=newest[1].id))
        assert [o.message for o in later] == ["m4"]
        assert repo.max_observation_id() == newest[0].id

    def test_get_observations_by_id_is_chronological(self, repo, make_observation):
        repo.insert_observations([make_observation(f"m{i}") for i in range(3)])
        ids = [o.id for o in repo.query_observations()]  # newest first
        fetched = repo.get_observations([*ids, 999_999])
        assert [o.message for o in fetched] == ["m0", "m1", "m2"]

    def test_unreadable_metadata_does_not_break_queries(self, repo, make_observation):
        repo.insert_observations([make_observation()])
        repo.conn.execute("UPDATE observations SET metadata_json = '{broken'")
        assert repo.query_observations()[0].metadata == {}

    def test_volume_buckets(self, repo, make_observation):
        repo.insert_observations(
            [make_observation(at=BASE_TIME + timedelta(minutes=m)) for m in (0, 1, 2, 7, 11)]
        )
        volume = repo.observation_volume(BASE_TIME, BASE_TIME + timedelta(hours=1), 300)
        assert volume == [
            (BASE_TIME, 3),
            (BASE_TIME + timedelta(minutes=5), 1),
            (BASE_TIME + timedelta(minutes=10), 1),
        ]

    def test_severity_counts_and_source_stats(self, repo, make_observation):
        repo.insert_observations(
            [
                make_observation(severity=Severity.ERROR),
                make_observation(severity=Severity.INFO),
                make_observation(severity=Severity.INFO, source_id="other"),
            ]
        )
        counts = repo.severity_counts()
        assert counts[Severity.INFO] == 2
        assert counts[Severity.ERROR] == 1
        assert counts[Severity.CRITICAL] == 0
        stats = {s["source_id"]: s for s in repo.source_stats()}
        assert stats["test:source"]["total"] == 2
        assert stats["test:source"]["errors"] == 1
        assert stats["other"]["errors"] == 0
        assert repo.distinct_providers() == ["TestProvider"]


class TestCheckpointsAndMetrics:
    def test_checkpoint_upsert(self, repo):
        assert repo.get_checkpoint("winevt:Application") is None
        repo.set_checkpoint("winevt:Application", {"record_id": 10})
        repo.set_checkpoint("winevt:Application", {"record_id": 25})
        assert repo.get_checkpoint("winevt:Application") == {"record_id": 25}
        assert repo.all_checkpoints() == {"winevt:Application": {"record_id": 25}}

    def test_metric_series(self, repo):
        repo.add_metric_samples(
            [
                ("log_size", "a", BASE_TIME, 100),
                ("log_size", "a", BASE_TIME + timedelta(minutes=1), 250),
                ("log_size", "b", BASE_TIME, 5),
                ("other", "a", BASE_TIME, 1),
            ]
        )
        assert repo.metric_series("log_size", BASE_TIME, subject="a") == [
            ("a", BASE_TIME, 100.0),
            ("a", BASE_TIME + timedelta(minutes=1), 250.0),
        ]
        assert len(repo.metric_series("log_size", BASE_TIME)) == 3
        assert repo.metric_series("log_size", BASE_TIME + timedelta(seconds=1), subject="b") == []


def _snapshot(root_key: str, total: int, *, complete: bool = True) -> RootSnapshot:
    return RootSnapshot(
        root=root_key.upper(),
        root_key=root_key,
        complete=complete,
        total_bytes=total,
        file_count=total // 10,
        oldest_mtime=BASE_TIME - timedelta(days=30),
        newest_mtime=BASE_TIME,
        stats={"extensions": {".tmp": 3}},
        dirs=[DirSnapshot("sub-a", total // 2, 4), DirSnapshot("sub-b", total // 4, 2)],
    )


class TestScans:
    def _run(self, repo, *, minutes: int = 0) -> ScanRun:
        scan = ScanRun(scan_type="temp", started_at=BASE_TIME + timedelta(minutes=minutes))
        repo.create_scan_run(scan)
        return scan

    def test_scan_run_lifecycle(self, repo):
        scan = self._run(repo)
        assert repo.get_scan_run(scan.id).status is ScanStatus.RUNNING
        scan.status = ScanStatus.PARTIAL
        scan.finished_at = BASE_TIME + timedelta(seconds=30)
        scan.roots = ["C:/Temp"]
        scan.files_scanned = 12
        scan.errors = [ScanError(path="C:/Temp/locked", kind="access_denied")]
        scan.error_count = 1
        scan.summary = {"cancelled": False}
        repo.complete_scan_run(scan)

        stored = repo.get_scan_run(scan.id)
        assert stored.status is ScanStatus.PARTIAL
        assert stored.files_scanned == 12
        assert stored.errors == [ScanError(path="C:/Temp/locked", kind="access_denied")]
        assert stored.finished_at == BASE_TIME + timedelta(seconds=30)
        assert [s.id for s in repo.list_scan_runs("temp")] == [scan.id]

    def test_complete_requires_created_scan(self, repo):
        with pytest.raises(ValueError, match="not been created"):
            repo.complete_scan_run(ScanRun(scan_type="temp", started_at=BASE_TIME))

    def test_root_snapshots_with_dirs(self, repo):
        scan = self._run(repo)
        snapshot_id = repo.save_root_snapshot(scan.id, _snapshot("c:\\temp", 1000))
        (stored,) = repo.root_snapshots(scan.id, with_dirs=True)
        assert stored.id == snapshot_id
        assert stored.total_bytes == 1000
        assert stored.stats == {"extensions": {".tmp": 3}}
        assert [d.rel_path for d in stored.dirs] == ["sub-a", "sub-b"]
        assert repo.get_root_snapshot(snapshot_id).dirs[0].total_bytes == 500

    def test_previous_snapshot_ignores_partial_and_later_scans(self, repo):
        first = self._run(repo, minutes=0)
        repo.save_root_snapshot(first.id, _snapshot("c:\\temp", 1000))
        second = self._run(repo, minutes=10)
        repo.save_root_snapshot(second.id, _snapshot("c:\\temp", 5000, complete=False))
        third = self._run(repo, minutes=20)
        repo.save_root_snapshot(third.id, _snapshot("c:\\temp", 7000))

        baseline = repo.previous_root_snapshot("c:\\temp", third.id)
        assert baseline.scan_id == first.id
        assert repo.previous_root_snapshot("c:\\temp", first.id) is None
        assert repo.previous_root_snapshot("c:\\other", third.id) is None

        history = repo.root_history("c:\\temp")
        assert [h[1] for h in history] == [1000, 5000, 7000]
        assert [h[3] for h in history] == [True, False, True]

    def test_file_samples(self, repo):
        scan = self._run(repo)
        repo.save_file_samples(
            scan.id,
            [
                FileSample(
                    path=f"C:/Temp/f{i}.tmp",
                    size=i * 100,
                    modified_at=BASE_TIME - timedelta(days=i),
                    created_at=None,
                    extension=".tmp",
                    classification="temporary",
                    category="largest",
                    reasons=["large"],
                    root="C:/Temp",
                )
                for i in range(1, 4)
            ],
        )
        largest = repo.file_samples(scan.id, "largest")
        assert [s.size for s in largest] == [300, 200, 100]
        assert largest[0].reasons == ["large"]
        assert largest[0].created_at is None
        assert repo.file_samples(scan.id, "oldest") == []

    def test_deleting_scan_cascades(self, repo):
        scan = self._run(repo)
        repo.save_root_snapshot(scan.id, _snapshot("c:\\temp", 1000))
        repo.conn.execute("DELETE FROM scan_runs WHERE id = ?", (scan.id,))
        assert repo.conn.execute("SELECT COUNT(*) FROM root_snapshots").fetchone()[0] == 0
        assert repo.conn.execute("SELECT COUNT(*) FROM dir_snapshots").fetchone()[0] == 0


def test_concurrent_reader_sees_committed_writes(database, make_observation):
    writer = Repository(database.connect())
    reader = Repository(database.connect())
    try:
        with writer.transaction():
            writer.insert_observations([make_observation()])
            # WAL: the reader is not blocked and does not see uncommitted rows.
            assert reader.count_observations() == 0
        assert reader.count_observations() == 1
    finally:
        writer.close()
        reader.close()


def test_sqlite_version_supports_required_features():
    # RETURNING/UPSERT/WITHOUT ROWID need SQLite >= 3.35.
    assert tuple(int(p) for p in sqlite3.sqlite_version.split(".")) >= (3, 35)
