"""Shared domain types.

These types are deliberately separate (see DECISIONS.md D-010):

* :class:`Observation` — what a source actually reported (an event, a log record, or a
  Sentinel monitoring-health record).
* :class:`FindingDraft` / :class:`Finding` — a rule matched; always carries evidence refs.
* :class:`Incident` — findings grouped by correlation, with the reasons they were grouped.
* :class:`Hypothesis` — a possible explanation, never presented as fact.
* :class:`ScanRun`, :class:`RootSnapshot`, :class:`DirSnapshot`, :class:`FileSample` —
  temporary-directory measurements.

All datetimes are timezone-aware and in UTC. Storage converts them to integer
microseconds since the Unix epoch (:func:`to_micros` / :func:`from_micros`).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import IntEnum, StrEnum
from typing import Any

EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_ONE_MICROSECOND = timedelta(microseconds=1)


def utc_now() -> datetime:
    return datetime.now(UTC)


def to_micros(moment: datetime) -> int:
    """Convert an aware datetime to integer microseconds since the Unix epoch (UTC)."""
    if moment.tzinfo is None:
        raise ValueError("naive datetime; attach a timezone before storing")
    return (moment - EPOCH) // _ONE_MICROSECOND


def from_micros(micros: int) -> datetime:
    return EPOCH + timedelta(microseconds=micros)


class Severity(IntEnum):
    """Severity of an observation. Values match Python's logging levels."""

    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40
    CRITICAL = 50

    @property
    def label(self) -> str:
        return self.name.capitalize()

    @classmethod
    def from_name(cls, text: str | None) -> Severity | None:
        """Map a textual level (``WARN``, ``err``, ``Fatal``, ...) to a severity, if known."""
        if not text:
            return None
        return _SEVERITY_ALIASES.get(text.strip().strip("[]()<>:").casefold())

    @classmethod
    def from_windows_level(cls, level: int | None) -> Severity:
        """Windows Event Log levels: 1 Critical, 2 Error, 3 Warning, 4 Information, 5 Verbose.

        Level 0 ("LogAlways") and unknown values are treated as informational.
        """
        return _WINDOWS_LEVELS.get(level or 0, cls.INFO)


_SEVERITY_ALIASES: dict[str, Severity] = {
    **dict.fromkeys(
        ("trace", "debug", "dbg", "verbose", "fine", "finer", "finest"), Severity.DEBUG
    ),
    **dict.fromkeys(("info", "information", "informational", "inf", "notice"), Severity.INFO),
    **dict.fromkeys(("warn", "warning", "wrn"), Severity.WARNING),
    **dict.fromkeys(("error", "err", "severe", "fail", "failure"), Severity.ERROR),
    **dict.fromkeys(
        ("critical", "crit", "fatal", "alert", "emerg", "emergency", "panic"), Severity.CRITICAL
    ),
}

_WINDOWS_LEVELS: dict[int, Severity] = {
    1: Severity.CRITICAL,
    2: Severity.ERROR,
    3: Severity.WARNING,
    4: Severity.INFO,
    5: Severity.DEBUG,
}


class FindingSeverity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.capitalize()

    @classmethod
    def from_name(cls, text: str) -> FindingSeverity:
        return cls[text.strip().upper()]


class SourceType(StrEnum):
    WINDOWS_EVENT = "windows_event"
    TEXT_LOG = "text_log"
    SENTINEL = "sentinel"  # Sentinel Local's own monitoring-health records


class FindingStatus(StrEnum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    SUPPRESSED = "suppressed"
    RESOLVED = "resolved"


class IncidentStatus(StrEnum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


class ScanStatus(StrEnum):
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"  # finished, but limits or errors mean some data is missing
    CANCELLED = "cancelled"
    FAILED = "failed"


class EvidenceType(StrEnum):
    OBSERVATION = "observation"
    SCAN_RUN = "scan_run"
    ROOT_SNAPSHOT = "root_snapshot"
    METRIC = "metric"


@dataclass(slots=True)
class Observation:
    """A normalised record of something a source reported."""

    source_id: str
    source_type: SourceType
    event_timestamp: datetime
    severity: Severity
    message: str
    dedup_key: str
    fingerprint: str
    collected_at: datetime = field(default_factory=utc_now)
    event_type: str = ""
    provider: str = ""
    event_code: str = ""
    record_id: str | None = None
    process_name: str | None = None
    process_id: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    id: int | None = None


@dataclass(slots=True, frozen=True)
class EvidenceRef:
    evidence_type: EvidenceType
    ref_id: int
    note: str = ""


@dataclass(slots=True)
class FindingDraft:
    """A rule match before persistence and deduplication."""

    rule_id: str
    subject: str
    title: str
    severity: FindingSeverity
    explanation: str
    recommendation: str
    window_start: datetime
    window_end: datetime
    evidence: list[EvidenceRef] = field(default_factory=list)
    entities: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Finding:
    id: int
    rule_id: str
    subject: str
    title: str
    severity: FindingSeverity
    status: FindingStatus
    explanation: str
    recommendation: str
    detected_at: datetime
    updated_at: datetime
    window_start: datetime
    window_end: datetime
    occurrences: int = 1
    entities: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    incident_id: int | None = None
    status_note: str = ""
    evidence_count: int = 0


@dataclass(slots=True)
class Incident:
    id: int
    title: str
    severity: FindingSeverity
    status: IncidentStatus
    created_at: datetime
    updated_at: datetime
    window_start: datetime
    window_end: datetime
    summary: str = ""
    reasons: list[str] = field(default_factory=list)
    finding_ids: list[int] = field(default_factory=list)


@dataclass(slots=True)
class Hypothesis:
    """A possible explanation for an incident. Always unconfirmed."""

    incident_id: int
    template_id: str
    statement: str
    rationale: str
    confidence: str  # "low" or "medium"; never "high" — these are not conclusions
    basis: list[str] = field(default_factory=list)
    generated_by: str = "rule-template"
    created_at: datetime = field(default_factory=utc_now)
    id: int | None = None


@dataclass(slots=True)
class ScanError:
    path: str
    kind: str  # e.g. "access_denied", "not_found", "os_error", "limit"
    detail: str = ""


@dataclass(slots=True)
class FileSample:
    """A notable file captured by a scan (largest, oldest, or cleanup candidate)."""

    path: str
    size: int
    modified_at: datetime | None
    created_at: datetime | None
    extension: str
    classification: str
    category: str  # "largest", "oldest", "candidate"
    reasons: list[str] = field(default_factory=list)
    root: str = ""


@dataclass(slots=True)
class DirSnapshot:
    """Aggregate size of one first-level subdirectory of a scan root."""

    rel_path: str
    total_bytes: int
    file_count: int


@dataclass(slots=True)
class RootSnapshot:
    root: str
    root_key: str
    complete: bool
    total_bytes: int = 0
    file_count: int = 0
    dir_count: int = 0
    inaccessible_count: int = 0
    skipped_links: int = 0
    new_files: int = 0
    modified_files: int = 0
    oldest_mtime: datetime | None = None
    newest_mtime: datetime | None = None
    stats: dict[str, Any] = field(default_factory=dict)
    dirs: list[DirSnapshot] = field(default_factory=list)
    id: int | None = None
    scan_id: int | None = None


@dataclass(slots=True)
class ScanRun:
    scan_type: str
    started_at: datetime
    status: ScanStatus = ScanStatus.RUNNING
    finished_at: datetime | None = None
    roots: list[str] = field(default_factory=list)
    files_scanned: int = 0
    dirs_scanned: int = 0
    bytes_total: int = 0
    error_count: int = 0
    errors: list[ScanError] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    id: int | None = None
