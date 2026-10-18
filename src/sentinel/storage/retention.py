"""Bounded data retention (DECISIONS.md D-014).

Evidence is protected: an observation, scan, or snapshot referenced by a retained finding
is never deleted, so a finding can always show what supported it (D-010). The most recent
scan of each type and the most recent complete snapshot of each scan root are also kept,
so growth comparisons keep working after long gaps.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta

from sentinel.config import RetentionSettings
from sentinel.models import FindingStatus, IncidentStatus, to_micros

# Evidence of retained findings, the latest scan of each type, and the latest complete
# snapshot of each root are never deleted. Statements are complete literals (no assembly).
_DELETE_OLD_OBSERVATIONS = (
    "DELETE FROM observations WHERE event_ts < ? AND id NOT IN "
    "(SELECT ref_id FROM finding_evidence WHERE evidence_type = 'observation')"
)
_DELETE_EXCESS_OBSERVATIONS = (
    "DELETE FROM observations WHERE id IN (SELECT id FROM observations WHERE id NOT IN "
    "(SELECT ref_id FROM finding_evidence WHERE evidence_type = 'observation') "
    "ORDER BY event_ts, id LIMIT ?)"
)
_DELETE_OLD_SCANS = (
    "DELETE FROM scan_runs WHERE started_ts < ? AND id NOT IN ("
    "SELECT ref_id FROM finding_evidence WHERE evidence_type = 'scan_run' "
    "UNION SELECT scan_id FROM root_snapshots WHERE id IN "
    "(SELECT ref_id FROM finding_evidence WHERE evidence_type = 'root_snapshot') "
    "UNION SELECT MAX(id) FROM scan_runs GROUP BY scan_type "
    "UNION SELECT scan_id FROM root_snapshots WHERE id IN "
    "(SELECT MAX(id) FROM root_snapshots WHERE complete = 1 GROUP BY root_key))"
)


@dataclass(frozen=True, slots=True)
class RetentionResult:
    observations: int = 0
    metrics: int = 0
    scans: int = 0
    findings: int = 0
    incidents: int = 0

    @property
    def total(self) -> int:
        return self.observations + self.metrics + self.scans + self.findings + self.incidents


def apply_retention(
    conn: sqlite3.Connection, settings: RetentionSettings, now: datetime
) -> RetentionResult:
    """Delete expired data. Call inside a transaction."""

    def cutoff(days: int) -> int:
        return to_micros(now - timedelta(days=days))

    closed = (str(FindingStatus.RESOLVED), str(FindingStatus.SUPPRESSED))
    findings = conn.execute(
        "DELETE FROM findings WHERE status IN (?, ?) AND updated_ts < ?",
        (*closed, cutoff(settings.closed_finding_days)),
    ).rowcount
    incidents = conn.execute(
        "DELETE FROM incidents WHERE status = ? AND updated_ts < ? AND id NOT IN "
        "(SELECT incident_id FROM findings WHERE incident_id IS NOT NULL)",
        (str(IncidentStatus.RESOLVED), cutoff(settings.closed_finding_days)),
    ).rowcount

    observations = conn.execute(
        _DELETE_OLD_OBSERVATIONS, (cutoff(settings.observation_days),)
    ).rowcount
    total = conn.execute("SELECT COUNT(*) FROM observations").fetchone()[0]
    excess = total - settings.max_observations
    if excess > 0:
        observations += conn.execute(_DELETE_EXCESS_OBSERVATIONS, (excess,)).rowcount

    metrics = conn.execute(
        "DELETE FROM metric_samples WHERE ts < ?", (cutoff(settings.metric_days),)
    ).rowcount
    scans = conn.execute(_DELETE_OLD_SCANS, (cutoff(settings.scan_history_days),)).rowcount
    return RetentionResult(observations, metrics, scans, findings, incidents)
