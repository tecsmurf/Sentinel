"""Repository: the only module that knows the SQL schema.

All SQL uses ``?`` placeholders for values. Where a query is assembled from optional
filter clauses, the clauses themselves are constant strings defined in this module;
user-supplied values only ever travel as bound parameters.
"""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from sentinel.config import RetentionSettings
from sentinel.models import (
    DirSnapshot,
    FileSample,
    Observation,
    RootSnapshot,
    ScanError,
    ScanRun,
    ScanStatus,
    Severity,
    SourceType,
    from_micros,
    to_micros,
    utc_now,
)
from sentinel.storage.codec import dumps as _dumps
from sentinel.storage.codec import loads as _loads
from sentinel.storage.codec import micros as _micros
from sentinel.storage.codec import moment as _moment
from sentinel.storage.database import connect, transaction
from sentinel.storage.findings import FindingsMixin
from sentinel.storage.retention import RetentionResult, apply_retention

logger = logging.getLogger(__name__)

_MAX_IDS_PER_QUERY = 500


def escape_like(text: str) -> str:
    """Escape LIKE wildcards so user search text is matched literally (with ``ESCAPE '\\'``)."""
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


@dataclass(slots=True)
class ObservationFilter:
    since: datetime | None = None
    until: datetime | None = None
    min_severity: Severity | None = None
    source_types: Sequence[SourceType] = ()
    source_ids: Sequence[str] = ()
    provider: str | None = None
    event_code: str | None = None
    fingerprint: str | None = None
    text: str | None = None
    after_id: int | None = None

    def to_sql(self) -> tuple[str, list[Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if self.since is not None:
            clauses.append("event_ts >= ?")
            params.append(to_micros(self.since))
        if self.until is not None:
            clauses.append("event_ts < ?")
            params.append(to_micros(self.until))
        if self.min_severity is not None:
            clauses.append("severity >= ?")
            params.append(int(self.min_severity))
        if self.source_types:
            clauses.append(f"source_type IN ({','.join('?' * len(self.source_types))})")
            params.extend(str(t) for t in self.source_types)
        if self.source_ids:
            clauses.append(f"source_id IN ({','.join('?' * len(self.source_ids))})")
            params.extend(self.source_ids)
        if self.provider:
            clauses.append("provider = ?")
            params.append(self.provider)
        if self.event_code:
            clauses.append("event_code = ?")
            params.append(self.event_code)
        if self.fingerprint:
            clauses.append("fingerprint = ?")
            params.append(self.fingerprint)
        if self.text:
            clauses.append(
                "(message LIKE ? ESCAPE '\\' OR provider LIKE ? ESCAPE '\\' OR event_code = ?)"
            )
            pattern = f"%{escape_like(self.text.strip())}%"
            params.extend([pattern, pattern, self.text.strip()])
        if self.after_id is not None:
            clauses.append("id > ?")
            params.append(self.after_id)
        where = " AND ".join(clauses) if clauses else "1=1"
        return where, params


_FILE_SAMPLE_SELECT = (
    "SELECT root, path, size, mtime_ts, ctime_ts, extension, classification, category, "
    "reasons_json FROM file_samples WHERE scan_id = ? AND category = ? "
)
_FILE_SAMPLES_BY_SIZE = _FILE_SAMPLE_SELECT + "ORDER BY size DESC LIMIT ?"
_FILE_SAMPLES_BY_AGE = _FILE_SAMPLE_SELECT + "ORDER BY mtime_ts ASC LIMIT ?"

_OBSERVATION_COLUMNS = (
    "id, source_id, source_type, event_ts, collected_ts, severity, event_type, provider, "
    "event_code, record_id, process_name, process_id, message, fingerprint, dedup_key, "
    "metadata_json"
)


def _row_to_observation(row: sqlite3.Row) -> Observation:
    return Observation(
        id=row["id"],
        source_id=row["source_id"],
        source_type=SourceType(row["source_type"]),
        event_timestamp=from_micros(row["event_ts"]),
        collected_at=from_micros(row["collected_ts"]),
        severity=Severity(row["severity"]),
        event_type=row["event_type"],
        provider=row["provider"],
        event_code=row["event_code"],
        record_id=row["record_id"],
        process_name=row["process_name"],
        process_id=row["process_id"],
        message=row["message"],
        fingerprint=row["fingerprint"],
        dedup_key=row["dedup_key"],
        metadata=_loads(row["metadata_json"], {}),
    )


class Repository(FindingsMixin):
    """Data access for one connection. Create one repository per thread."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    @classmethod
    def open(cls, path: Path | str) -> Repository:
        return cls(connect(path))

    def close(self) -> None:
        self.conn.close()

    def transaction(self):
        return transaction(self.conn)

    # ----------------------------------------------------------------------------------
    # Observations
    # ----------------------------------------------------------------------------------

    def insert_observations(self, observations: Iterable[Observation]) -> int:
        """Insert observations, ignoring any whose ``dedup_key`` already exists.

        Returns the number of rows actually inserted. Call inside a transaction when
        batching with other writes (for example, checkpoint updates).
        """
        rows = [
            (
                o.source_id,
                str(o.source_type),
                to_micros(o.event_timestamp),
                to_micros(o.collected_at),
                int(o.severity),
                o.event_type,
                o.provider,
                o.event_code,
                o.record_id,
                o.process_name,
                o.process_id,
                o.message,
                o.fingerprint,
                o.dedup_key,
                _dumps(o.metadata),
            )
            for o in observations
        ]
        if not rows:
            return 0
        before = self.conn.total_changes
        self.conn.executemany(
            "INSERT OR IGNORE INTO observations (source_id, source_type, event_ts, collected_ts, "
            "severity, event_type, provider, event_code, record_id, process_name, process_id, "
            "message, fingerprint, dedup_key, metadata_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
        return self.conn.total_changes - before

    def query_observations(
        self,
        flt: ObservationFilter | None = None,
        *,
        limit: int = 500,
        offset: int = 0,
        newest_first: bool = True,
    ) -> list[Observation]:
        where, params = (flt or ObservationFilter()).to_sql()
        order = "DESC" if newest_first else "ASC"
        sql = (
            f"SELECT {_OBSERVATION_COLUMNS} FROM observations WHERE {where} "  # noqa: S608 - constant clauses
            f"ORDER BY event_ts {order}, id {order} LIMIT ? OFFSET ?"
        )
        rows = self.conn.execute(sql, [*params, int(limit), int(offset)]).fetchall()
        return [_row_to_observation(row) for row in rows]

    def count_observations(self, flt: ObservationFilter | None = None) -> int:
        where, params = (flt or ObservationFilter()).to_sql()
        sql = f"SELECT COUNT(*) FROM observations WHERE {where}"  # noqa: S608 - constant clauses
        return self.conn.execute(sql, params).fetchone()[0]

    def get_observations(self, ids: Sequence[int]) -> list[Observation]:
        """Fetch observations by id, in chronological order. Missing ids are skipped."""
        result: list[Observation] = []
        unique = list(dict.fromkeys(ids))
        for start in range(0, len(unique), _MAX_IDS_PER_QUERY):
            chunk = unique[start : start + _MAX_IDS_PER_QUERY]
            placeholders = ",".join("?" * len(chunk))
            sql = f"SELECT {_OBSERVATION_COLUMNS} FROM observations WHERE id IN ({placeholders})"  # noqa: S608
            result.extend(_row_to_observation(r) for r in self.conn.execute(sql, chunk))
        result.sort(key=lambda o: (o.event_timestamp, o.id or 0))
        return result

    def max_observation_id(self) -> int:
        return self.conn.execute("SELECT COALESCE(MAX(id), 0) FROM observations").fetchone()[0]

    def observation_volume(
        self,
        since: datetime,
        until: datetime,
        bucket_seconds: int,
        source_types: Sequence[SourceType] = (),
    ) -> list[tuple[datetime, int]]:
        """Observation counts per time bucket (empty buckets are omitted)."""
        bucket = int(bucket_seconds) * 1_000_000
        flt = ObservationFilter(since=since, until=until, source_types=source_types)
        where, params = flt.to_sql()
        sql = (
            f"SELECT (event_ts / ?) * ? AS bucket, COUNT(*) FROM observations WHERE {where} "  # noqa: S608
            "GROUP BY bucket ORDER BY bucket"
        )
        rows = self.conn.execute(sql, [bucket, bucket, *params]).fetchall()
        return [(from_micros(row[0]), row[1]) for row in rows]

    def observation_volume_by_source(
        self, since: datetime, until: datetime, bucket_seconds: int
    ) -> dict[str, list[tuple[datetime, int]]]:
        """Per-source observation counts per time bucket, excluding Sentinel's own records."""
        bucket = int(bucket_seconds) * 1_000_000
        rows = self.conn.execute(
            "SELECT source_id, (event_ts / ?) * ? AS bucket, COUNT(*) FROM observations "
            "WHERE event_ts >= ? AND event_ts < ? AND source_type != ? "
            "GROUP BY source_id, bucket ORDER BY source_id, bucket",
            (bucket, bucket, to_micros(since), to_micros(until), str(SourceType.SENTINEL)),
        )
        result: dict[str, list[tuple[datetime, int]]] = {}
        for source_id, start, count in rows:
            result.setdefault(source_id, []).append((from_micros(start), count))
        return result

    def severity_counts(self, since: datetime | None = None) -> dict[Severity, int]:
        where, params = ObservationFilter(since=since).to_sql()
        sql = f"SELECT severity, COUNT(*) FROM observations WHERE {where} GROUP BY severity"  # noqa: S608
        counts = dict.fromkeys(Severity, 0)
        for severity, count in self.conn.execute(sql, params):
            try:
                counts[Severity(severity)] = count
            except ValueError:
                logger.warning("ignored unknown severity value in database")
        return counts

    def source_stats(self) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT source_id, source_type, COUNT(*) AS total, MAX(event_ts) AS last_ts, "
            "SUM(CASE WHEN severity >= ? THEN 1 ELSE 0 END) AS errors "
            "FROM observations GROUP BY source_id, source_type ORDER BY source_id",
            (int(Severity.ERROR),),
        ).fetchall()
        return [
            {
                "source_id": row["source_id"],
                "source_type": row["source_type"],
                "total": row["total"],
                "errors": row["errors"],
                "last_event": _moment(row["last_ts"]),
            }
            for row in rows
        ]

    def distinct_providers(self, limit: int = 500) -> list[str]:
        rows = self.conn.execute(
            "SELECT provider FROM observations WHERE provider != '' "
            "GROUP BY provider ORDER BY COUNT(*) DESC LIMIT ?",
            (int(limit),),
        )
        return [row[0] for row in rows]

    # ----------------------------------------------------------------------------------
    # Checkpoints and metrics
    # ----------------------------------------------------------------------------------

    def get_checkpoint(self, source_id: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT state_json FROM checkpoints WHERE source_id = ?", (source_id,)
        ).fetchone()
        return None if row is None else _loads(row[0], None)

    def set_checkpoint(self, source_id: str, state: dict[str, Any]) -> None:
        self.conn.execute(
            "INSERT INTO checkpoints (source_id, state_json, updated_ts) VALUES (?, ?, ?) "
            "ON CONFLICT(source_id) DO UPDATE SET state_json = excluded.state_json, "
            "updated_ts = excluded.updated_ts",
            (source_id, _dumps(state), to_micros(utc_now())),
        )

    def all_checkpoints(self) -> dict[str, dict[str, Any]]:
        rows = self.conn.execute("SELECT source_id, state_json FROM checkpoints")
        return {row[0]: _loads(row[1], {}) for row in rows}

    def add_metric_samples(self, samples: Iterable[tuple[str, str, datetime, float]]) -> None:
        self.conn.executemany(
            "INSERT INTO metric_samples (metric, subject, ts, value) VALUES (?, ?, ?, ?)",
            [(metric, subject, to_micros(ts), float(v)) for metric, subject, ts, v in samples],
        )

    def metric_series(
        self, metric: str, since: datetime, subject: str | None = None
    ) -> list[tuple[str, datetime, float]]:
        if subject is None:
            rows = self.conn.execute(
                "SELECT subject, ts, value FROM metric_samples WHERE metric = ? AND ts >= ? "
                "ORDER BY subject, ts",
                (metric, to_micros(since)),
            )
        else:
            rows = self.conn.execute(
                "SELECT subject, ts, value FROM metric_samples "
                "WHERE metric = ? AND subject = ? AND ts >= ? ORDER BY ts",
                (metric, subject, to_micros(since)),
            )
        return [(row[0], from_micros(row[1]), row[2]) for row in rows]

    def metric_samples_since(
        self, metric: str, since: datetime
    ) -> list[tuple[int, str, datetime, float]]:
        """(id, subject, timestamp, value) samples of one metric, oldest first."""
        rows = self.conn.execute(
            "SELECT id, subject, ts, value FROM metric_samples WHERE metric = ? AND ts >= ? "
            "ORDER BY ts, id",
            (metric, to_micros(since)),
        )
        return [(row[0], row[1], from_micros(row[2]), row[3]) for row in rows]

    # ----------------------------------------------------------------------------------
    # Scans
    # ----------------------------------------------------------------------------------

    def create_scan_run(self, scan: ScanRun) -> int:
        cursor = self.conn.execute(
            "INSERT INTO scan_runs (scan_type, started_ts, status, roots_json) VALUES (?, ?, ?, ?)",
            (scan.scan_type, to_micros(scan.started_at), str(scan.status), _dumps(scan.roots)),
        )
        scan.id = cursor.lastrowid
        return scan.id

    def complete_scan_run(self, scan: ScanRun) -> None:
        if scan.id is None:
            raise ValueError("scan run has not been created")
        self.conn.execute(
            "UPDATE scan_runs SET finished_ts = ?, status = ?, roots_json = ?, files_scanned = ?, "
            "dirs_scanned = ?, bytes_total = ?, error_count = ?, errors_json = ?, summary_json = ? "
            "WHERE id = ?",
            (
                _micros(scan.finished_at),
                str(scan.status),
                _dumps(scan.roots),
                scan.files_scanned,
                scan.dirs_scanned,
                scan.bytes_total,
                scan.error_count,
                _dumps([asdict(e) for e in scan.errors]),
                _dumps(scan.summary),
                scan.id,
            ),
        )

    def _row_to_scan(self, row: sqlite3.Row) -> ScanRun:
        return ScanRun(
            id=row["id"],
            scan_type=row["scan_type"],
            started_at=from_micros(row["started_ts"]),
            finished_at=_moment(row["finished_ts"]),
            status=ScanStatus(row["status"]),
            roots=_loads(row["roots_json"], []),
            files_scanned=row["files_scanned"],
            dirs_scanned=row["dirs_scanned"],
            bytes_total=row["bytes_total"],
            error_count=row["error_count"],
            errors=[ScanError(**e) for e in _loads(row["errors_json"], []) if isinstance(e, dict)],
            summary=_loads(row["summary_json"], {}),
        )

    def get_scan_run(self, scan_id: int) -> ScanRun | None:
        row = self.conn.execute("SELECT * FROM scan_runs WHERE id = ?", (scan_id,)).fetchone()
        return None if row is None else self._row_to_scan(row)

    def list_scan_runs(self, scan_type: str | None = None, limit: int = 50) -> list[ScanRun]:
        if scan_type is None:
            rows = self.conn.execute(
                "SELECT * FROM scan_runs ORDER BY started_ts DESC, id DESC LIMIT ?", (limit,)
            )
        else:
            rows = self.conn.execute(
                "SELECT * FROM scan_runs WHERE scan_type = ? ORDER BY started_ts DESC, id DESC "
                "LIMIT ?",
                (scan_type, limit),
            )
        return [self._row_to_scan(row) for row in rows]

    def save_root_snapshot(self, scan_id: int, snapshot: RootSnapshot) -> int:
        cursor = self.conn.execute(
            "INSERT INTO root_snapshots (scan_id, root, root_key, complete, total_bytes, "
            "file_count, dir_count, inaccessible_count, skipped_links, new_files, modified_files, "
            "oldest_mtime_ts, newest_mtime_ts, stats_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                scan_id,
                snapshot.root,
                snapshot.root_key,
                int(snapshot.complete),
                snapshot.total_bytes,
                snapshot.file_count,
                snapshot.dir_count,
                snapshot.inaccessible_count,
                snapshot.skipped_links,
                snapshot.new_files,
                snapshot.modified_files,
                _micros(snapshot.oldest_mtime),
                _micros(snapshot.newest_mtime),
                _dumps(snapshot.stats),
            ),
        )
        snapshot.id = cursor.lastrowid
        snapshot.scan_id = scan_id
        self.conn.executemany(
            "INSERT INTO dir_snapshots (snapshot_id, rel_path, total_bytes, file_count) "
            "VALUES (?, ?, ?, ?)",
            [(snapshot.id, d.rel_path, d.total_bytes, d.file_count) for d in snapshot.dirs],
        )
        return snapshot.id

    def _row_to_root_snapshot(self, row: sqlite3.Row, with_dirs: bool) -> RootSnapshot:
        snapshot = RootSnapshot(
            id=row["id"],
            scan_id=row["scan_id"],
            root=row["root"],
            root_key=row["root_key"],
            complete=bool(row["complete"]),
            total_bytes=row["total_bytes"],
            file_count=row["file_count"],
            dir_count=row["dir_count"],
            inaccessible_count=row["inaccessible_count"],
            skipped_links=row["skipped_links"],
            new_files=row["new_files"],
            modified_files=row["modified_files"],
            oldest_mtime=_moment(row["oldest_mtime_ts"]),
            newest_mtime=_moment(row["newest_mtime_ts"]),
            stats=_loads(row["stats_json"], {}),
        )
        if with_dirs:
            snapshot.dirs = self.dir_snapshots(snapshot.id)
        return snapshot

    def dir_snapshots(self, snapshot_id: int) -> list[DirSnapshot]:
        rows = self.conn.execute(
            "SELECT rel_path, total_bytes, file_count FROM dir_snapshots WHERE snapshot_id = ? "
            "ORDER BY total_bytes DESC",
            (snapshot_id,),
        )
        return [DirSnapshot(row[0], row[1], row[2]) for row in rows]

    def root_snapshots(self, scan_id: int, *, with_dirs: bool = False) -> list[RootSnapshot]:
        rows = self.conn.execute(
            "SELECT * FROM root_snapshots WHERE scan_id = ? ORDER BY id", (scan_id,)
        ).fetchall()
        return [self._row_to_root_snapshot(row, with_dirs) for row in rows]

    def get_root_snapshot(self, snapshot_id: int, *, with_dirs: bool = True) -> RootSnapshot | None:
        row = self.conn.execute(
            "SELECT * FROM root_snapshots WHERE id = ?", (snapshot_id,)
        ).fetchone()
        return None if row is None else self._row_to_root_snapshot(row, with_dirs)

    def previous_root_snapshot(
        self, root_key: str, before_scan_id: int, *, with_dirs: bool = True
    ) -> RootSnapshot | None:
        """Most recent *complete* snapshot of the same root from an earlier scan.

        Partial snapshots are not used as a baseline: comparing against an incomplete
        measurement would report growth that did not happen.
        """
        row = self.conn.execute(
            "SELECT * FROM root_snapshots WHERE root_key = ? AND scan_id < ? AND complete = 1 "
            "ORDER BY scan_id DESC LIMIT 1",
            (root_key, before_scan_id),
        ).fetchone()
        return None if row is None else self._row_to_root_snapshot(row, with_dirs)

    def root_history(self, root_key: str, limit: int = 60) -> list[tuple[datetime, int, int, bool]]:
        """(scan start, total bytes, file count, complete) for a root, oldest first."""
        rows = self.conn.execute(
            "SELECT s.started_ts, r.total_bytes, r.file_count, r.complete "
            "FROM root_snapshots r JOIN scan_runs s ON s.id = r.scan_id "
            "WHERE r.root_key = ? ORDER BY s.started_ts DESC, s.id DESC LIMIT ?",
            (root_key, limit),
        ).fetchall()
        return [(from_micros(r[0]), r[1], r[2], bool(r[3])) for r in reversed(rows)]

    def save_file_samples(self, scan_id: int, samples: Iterable[FileSample]) -> None:
        self.conn.executemany(
            "INSERT INTO file_samples (scan_id, root, path, size, mtime_ts, ctime_ts, extension, "
            "classification, category, reasons_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    scan_id,
                    s.root,
                    s.path,
                    s.size,
                    _micros(s.modified_at),
                    _micros(s.created_at),
                    s.extension,
                    s.classification,
                    s.category,
                    _dumps(s.reasons),
                )
                for s in samples
            ],
        )

    def file_samples(self, scan_id: int, category: str, limit: int = 1000) -> list[FileSample]:
        sql = _FILE_SAMPLES_BY_AGE if category == "oldest" else _FILE_SAMPLES_BY_SIZE
        rows = self.conn.execute(sql, (scan_id, category, limit))
        return [
            FileSample(
                root=row[0],
                path=row[1],
                size=row[2],
                modified_at=_moment(row[3]),
                created_at=_moment(row[4]),
                extension=row[5],
                classification=row[6],
                category=row[7],
                reasons=_loads(row[8], []),
            )
            for row in rows
        ]

    # ----------------------------------------------------------------------------------
    # Retention
    # ----------------------------------------------------------------------------------

    def apply_retention(
        self, settings: RetentionSettings, now: datetime | None = None
    ) -> RetentionResult:
        """Delete expired data (evidence of retained findings is kept) and reclaim space."""
        with self.transaction():
            result = apply_retention(self.conn, settings, now or utc_now())
        if result.total:
            self.conn.execute("PRAGMA incremental_vacuum").fetchall()
        return result
