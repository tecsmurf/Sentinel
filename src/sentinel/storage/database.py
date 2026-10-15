"""SQLite database lifecycle: connections, pragmas, transactions, versioned migrations.

Connections run in autocommit mode (``isolation_level=None``); every write happens inside
an explicit :func:`transaction`. One writer thread owns writes; other threads open their
own connections and read concurrently thanks to WAL journaling.

Schema versions are tracked with ``PRAGMA user_version``. Migrations are append-only:
never edit a released migration, add a new one.
"""

from __future__ import annotations

import contextlib
import logging
import sqlite3
from collections.abc import Iterator
from pathlib import Path

logger = logging.getLogger(__name__)


class DatabaseError(RuntimeError):
    """The database file is unusable (corrupt, foreign, or from a newer version)."""


_SCHEMA_V1 = [
    """
    CREATE TABLE observations (
        id            INTEGER PRIMARY KEY,
        source_id     TEXT    NOT NULL,
        source_type   TEXT    NOT NULL,
        event_ts      INTEGER NOT NULL,
        collected_ts  INTEGER NOT NULL,
        severity      INTEGER NOT NULL,
        event_type    TEXT    NOT NULL DEFAULT '',
        provider      TEXT    NOT NULL DEFAULT '',
        event_code    TEXT    NOT NULL DEFAULT '',
        record_id     TEXT,
        process_name  TEXT,
        process_id    INTEGER,
        message       TEXT    NOT NULL,
        fingerprint   TEXT    NOT NULL,
        dedup_key     TEXT    NOT NULL,
        metadata_json TEXT    NOT NULL DEFAULT '{}'
    )
    """,
    "CREATE UNIQUE INDEX ux_observations_dedup ON observations(dedup_key)",
    "CREATE INDEX ix_observations_ts ON observations(event_ts)",
    "CREATE INDEX ix_observations_severity_ts ON observations(severity, event_ts)",
    "CREATE INDEX ix_observations_source_ts ON observations(source_id, event_ts)",
    "CREATE INDEX ix_observations_fingerprint_ts ON observations(fingerprint, event_ts)",
    """
    CREATE TABLE checkpoints (
        source_id  TEXT PRIMARY KEY,
        state_json TEXT    NOT NULL,
        updated_ts INTEGER NOT NULL
    )
    """,
    """
    CREATE TABLE metric_samples (
        id      INTEGER PRIMARY KEY,
        metric  TEXT    NOT NULL,
        subject TEXT    NOT NULL,
        ts      INTEGER NOT NULL,
        value   REAL    NOT NULL
    )
    """,
    "CREATE INDEX ix_metric_samples ON metric_samples(metric, subject, ts)",
    """
    CREATE TABLE scan_runs (
        id            INTEGER PRIMARY KEY,
        scan_type     TEXT    NOT NULL,
        started_ts    INTEGER NOT NULL,
        finished_ts   INTEGER,
        status        TEXT    NOT NULL,
        roots_json    TEXT    NOT NULL DEFAULT '[]',
        files_scanned INTEGER NOT NULL DEFAULT 0,
        dirs_scanned  INTEGER NOT NULL DEFAULT 0,
        bytes_total   INTEGER NOT NULL DEFAULT 0,
        error_count   INTEGER NOT NULL DEFAULT 0,
        errors_json   TEXT    NOT NULL DEFAULT '[]',
        summary_json  TEXT    NOT NULL DEFAULT '{}'
    )
    """,
    "CREATE INDEX ix_scan_runs_type_started ON scan_runs(scan_type, started_ts)",
    """
    CREATE TABLE root_snapshots (
        id                 INTEGER PRIMARY KEY,
        scan_id            INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
        root               TEXT    NOT NULL,
        root_key           TEXT    NOT NULL,
        complete           INTEGER NOT NULL,
        total_bytes        INTEGER NOT NULL DEFAULT 0,
        file_count         INTEGER NOT NULL DEFAULT 0,
        dir_count          INTEGER NOT NULL DEFAULT 0,
        inaccessible_count INTEGER NOT NULL DEFAULT 0,
        skipped_links      INTEGER NOT NULL DEFAULT 0,
        new_files          INTEGER NOT NULL DEFAULT 0,
        modified_files     INTEGER NOT NULL DEFAULT 0,
        oldest_mtime_ts    INTEGER,
        newest_mtime_ts    INTEGER,
        stats_json         TEXT    NOT NULL DEFAULT '{}'
    )
    """,
    "CREATE INDEX ix_root_snapshots_scan ON root_snapshots(scan_id)",
    "CREATE INDEX ix_root_snapshots_key ON root_snapshots(root_key, scan_id)",
    """
    CREATE TABLE dir_snapshots (
        snapshot_id INTEGER NOT NULL REFERENCES root_snapshots(id) ON DELETE CASCADE,
        rel_path    TEXT    NOT NULL,
        total_bytes INTEGER NOT NULL,
        file_count  INTEGER NOT NULL,
        PRIMARY KEY (snapshot_id, rel_path)
    ) WITHOUT ROWID
    """,
    """
    CREATE TABLE file_samples (
        id             INTEGER PRIMARY KEY,
        scan_id        INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
        root           TEXT    NOT NULL,
        path           TEXT    NOT NULL,
        size           INTEGER NOT NULL,
        mtime_ts       INTEGER,
        ctime_ts       INTEGER,
        extension      TEXT    NOT NULL DEFAULT '',
        classification TEXT    NOT NULL DEFAULT '',
        category       TEXT    NOT NULL,
        reasons_json   TEXT    NOT NULL DEFAULT '[]'
    )
    """,
    "CREATE INDEX ix_file_samples_scan ON file_samples(scan_id, category)",
    """
    CREATE TABLE incidents (
        id              INTEGER PRIMARY KEY,
        title           TEXT    NOT NULL,
        severity        INTEGER NOT NULL,
        status          TEXT    NOT NULL,
        created_ts      INTEGER NOT NULL,
        updated_ts      INTEGER NOT NULL,
        window_start_ts INTEGER NOT NULL,
        window_end_ts   INTEGER NOT NULL,
        summary         TEXT    NOT NULL DEFAULT '',
        reasons_json    TEXT    NOT NULL DEFAULT '[]'
    )
    """,
    "CREATE INDEX ix_incidents_status ON incidents(status, updated_ts)",
    """
    CREATE TABLE findings (
        id              INTEGER PRIMARY KEY,
        rule_id         TEXT    NOT NULL,
        subject         TEXT    NOT NULL,
        title           TEXT    NOT NULL,
        severity        INTEGER NOT NULL,
        status          TEXT    NOT NULL,
        status_note     TEXT    NOT NULL DEFAULT '',
        detected_ts     INTEGER NOT NULL,
        updated_ts      INTEGER NOT NULL,
        window_start_ts INTEGER NOT NULL,
        window_end_ts   INTEGER NOT NULL,
        occurrences     INTEGER NOT NULL DEFAULT 1,
        explanation     TEXT    NOT NULL,
        recommendation  TEXT    NOT NULL,
        entities_json   TEXT    NOT NULL DEFAULT '[]',
        details_json    TEXT    NOT NULL DEFAULT '{}',
        incident_id     INTEGER REFERENCES incidents(id) ON DELETE SET NULL
    )
    """,
    "CREATE INDEX ix_findings_rule_subject ON findings(rule_id, subject, window_end_ts)",
    "CREATE INDEX ix_findings_status ON findings(status, updated_ts)",
    "CREATE INDEX ix_findings_incident ON findings(incident_id)",
    """
    CREATE TABLE finding_evidence (
        finding_id    INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
        evidence_type TEXT    NOT NULL,
        ref_id        INTEGER NOT NULL,
        note          TEXT    NOT NULL DEFAULT '',
        PRIMARY KEY (finding_id, evidence_type, ref_id)
    ) WITHOUT ROWID
    """,
    "CREATE INDEX ix_finding_evidence_ref ON finding_evidence(evidence_type, ref_id)",
    """
    CREATE TABLE hypotheses (
        id           INTEGER PRIMARY KEY,
        incident_id  INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
        template_id  TEXT    NOT NULL,
        statement    TEXT    NOT NULL,
        rationale    TEXT    NOT NULL,
        confidence   TEXT    NOT NULL,
        basis_json   TEXT    NOT NULL DEFAULT '[]',
        generated_by TEXT    NOT NULL,
        created_ts   INTEGER NOT NULL,
        UNIQUE (incident_id, template_id)
    )
    """,
    """
    CREATE TABLE suppressions (
        id         INTEGER PRIMARY KEY,
        rule_id    TEXT    NOT NULL,
        subject    TEXT    NOT NULL,
        reason     TEXT    NOT NULL DEFAULT '',
        created_ts INTEGER NOT NULL,
        UNIQUE (rule_id, subject)
    )
    """,
]

MIGRATIONS: list[tuple[int, str, list[str]]] = [
    (1, "initial schema", _SCHEMA_V1),
]
SCHEMA_VERSION = MIGRATIONS[-1][0]


def connect(path: Path | str) -> sqlite3.Connection:
    """Open a connection with Sentinel's per-connection settings."""
    conn = sqlite3.connect(str(path), timeout=10.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 10000")
    conn.execute("PRAGMA synchronous = NORMAL")
    conn.execute("PRAGMA temp_store = MEMORY")
    return conn


@contextlib.contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """``BEGIN IMMEDIATE`` … ``COMMIT``; rolls back if the block raises."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")


class Database:
    """Owns the database file location and its schema lifecycle."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    def connect(self) -> sqlite3.Connection:
        return connect(self.path)

    def initialize(self) -> int:
        """Create or upgrade the schema. Returns the schema version now in effect."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn: sqlite3.Connection | None = None
        try:
            # A corrupt or foreign file can fail as early as the per-connection pragmas.
            conn = connect(self.path)
            current = conn.execute("PRAGMA user_version").fetchone()[0]
        except sqlite3.DatabaseError as exc:
            if conn is not None:
                conn.close()
            raise DatabaseError(
                f"{self.path.name} is not a readable Sentinel database: {exc}"
            ) from exc
        try:
            if current > SCHEMA_VERSION:
                raise DatabaseError(
                    f"{self.path.name} uses schema version {current}, but this version of "
                    f"Sentinel Local supports up to {SCHEMA_VERSION}; upgrade the application"
                )
            if current == 0:
                # Must be set before the first table exists to take effect.
                conn.execute("PRAGMA auto_vacuum = INCREMENTAL")
            conn.execute("PRAGMA journal_mode = WAL")

            for version, description, statements in MIGRATIONS:
                if version <= current:
                    continue
                with transaction(conn):
                    for statement in statements:
                        conn.execute(statement)
                    conn.execute(f"PRAGMA user_version = {int(version)}")
                logger.info(
                    "applied database migration",
                    extra={"schema_version": version, "migration": description},
                )
            return SCHEMA_VERSION
        finally:
            conn.close()
