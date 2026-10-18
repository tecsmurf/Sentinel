"""Persistence for findings, evidence, suppressions, incidents, and hypotheses.

Mixed into :class:`sentinel.storage.repository.Repository`; uses ``self.conn``.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable, Sequence
from datetime import datetime
from typing import Any

from sentinel.models import (
    EvidenceRef,
    EvidenceType,
    Finding,
    FindingDraft,
    FindingSeverity,
    FindingStatus,
    Hypothesis,
    Incident,
    IncidentStatus,
    from_micros,
    to_micros,
)
from sentinel.storage.codec import dumps, loads

_FINDING_SELECT = (
    "SELECT f.*, (SELECT COUNT(*) FROM finding_evidence e WHERE e.finding_id = f.id) "
    "AS evidence_count FROM findings f"
)


def _row_to_finding(row: sqlite3.Row) -> Finding:
    return Finding(
        id=row["id"],
        rule_id=row["rule_id"],
        subject=row["subject"],
        title=row["title"],
        severity=FindingSeverity(row["severity"]),
        status=FindingStatus(row["status"]),
        explanation=row["explanation"],
        recommendation=row["recommendation"],
        detected_at=from_micros(row["detected_ts"]),
        updated_at=from_micros(row["updated_ts"]),
        window_start=from_micros(row["window_start_ts"]),
        window_end=from_micros(row["window_end_ts"]),
        occurrences=row["occurrences"],
        entities=loads(row["entities_json"], []),
        details=loads(row["details_json"], {}),
        incident_id=row["incident_id"],
        status_note=row["status_note"],
        evidence_count=row["evidence_count"],
    )


def _row_to_incident(row: sqlite3.Row, finding_ids: list[int]) -> Incident:
    return Incident(
        id=row["id"],
        title=row["title"],
        severity=FindingSeverity(row["severity"]),
        status=IncidentStatus(row["status"]),
        created_at=from_micros(row["created_ts"]),
        updated_at=from_micros(row["updated_ts"]),
        window_start=from_micros(row["window_start_ts"]),
        window_end=from_micros(row["window_end_ts"]),
        summary=row["summary"],
        reasons=loads(row["reasons_json"], []),
        finding_ids=finding_ids,
    )


class FindingsMixin:
    conn: sqlite3.Connection

    # ------------------------------------------------------------------ findings

    def find_active_finding(self, rule_id: str, subject: str, since: datetime) -> Finding | None:
        """The latest unresolved finding for (rule, subject) whose window ends after ``since``."""
        row = self.conn.execute(
            f"{_FINDING_SELECT} WHERE f.rule_id = ? AND f.subject = ? AND f.status != ? "
            "AND f.window_end_ts >= ? ORDER BY f.id DESC LIMIT 1",
            (rule_id, subject, str(FindingStatus.RESOLVED), to_micros(since)),
        ).fetchone()
        return None if row is None else _row_to_finding(row)

    def insert_finding(self, draft: FindingDraft, status: FindingStatus, now: datetime) -> int:
        cursor = self.conn.execute(
            "INSERT INTO findings (rule_id, subject, title, severity, status, detected_ts, "
            "updated_ts, window_start_ts, window_end_ts, occurrences, explanation, "
            "recommendation, entities_json, details_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)",
            (
                draft.rule_id,
                draft.subject,
                draft.title,
                int(draft.severity),
                str(status),
                to_micros(now),
                to_micros(now),
                to_micros(draft.window_start),
                to_micros(draft.window_end),
                draft.explanation,
                draft.recommendation,
                dumps(sorted(set(draft.entities))),
                dumps(draft.details),
            ),
        )
        finding_id = int(cursor.lastrowid)
        self.add_evidence(finding_id, draft.evidence)
        return finding_id

    def merge_finding(self, finding_id: int, draft: FindingDraft, now: datetime) -> None:
        """Fold a repeated match into an existing finding (widen window, keep max severity)."""
        row = self.conn.execute(
            "SELECT entities_json FROM findings WHERE id = ?", (finding_id,)
        ).fetchone()
        entities = sorted(set(loads(row[0] if row else None, [])) | set(draft.entities))
        self.conn.execute(
            "UPDATE findings SET title = ?, explanation = ?, recommendation = ?, "
            "severity = MAX(severity, ?), window_start_ts = MIN(window_start_ts, ?), "
            "window_end_ts = MAX(window_end_ts, ?), updated_ts = ?, "
            "occurrences = occurrences + 1, entities_json = ?, details_json = ? WHERE id = ?",
            (
                draft.title,
                draft.explanation,
                draft.recommendation,
                int(draft.severity),
                to_micros(draft.window_start),
                to_micros(draft.window_end),
                to_micros(now),
                dumps(entities),
                dumps(draft.details),
                finding_id,
            ),
        )
        self.add_evidence(finding_id, draft.evidence)

    def add_evidence(self, finding_id: int, refs: Iterable[EvidenceRef]) -> int:
        rows = [(finding_id, str(r.evidence_type), int(r.ref_id), r.note) for r in refs]
        if not rows:
            return 0
        before = self.conn.total_changes
        self.conn.executemany(
            "INSERT OR IGNORE INTO finding_evidence (finding_id, evidence_type, ref_id, note) "
            "VALUES (?, ?, ?, ?)",
            rows,
        )
        return self.conn.total_changes - before

    def get_finding(self, finding_id: int) -> Finding | None:
        row = self.conn.execute(f"{_FINDING_SELECT} WHERE f.id = ?", (finding_id,)).fetchone()
        return None if row is None else _row_to_finding(row)

    def list_findings(
        self,
        *,
        statuses: Sequence[FindingStatus] = (),
        min_severity: FindingSeverity | None = None,
        since: datetime | None = None,
        rule_ids: Sequence[str] = (),
        incident_id: int | None = None,
        unassigned: bool = False,
        limit: int = 500,
    ) -> list[Finding]:
        clauses: list[str] = []
        params: list[Any] = []
        if statuses:
            clauses.append(f"f.status IN ({','.join('?' * len(statuses))})")
            params.extend(str(s) for s in statuses)
        if min_severity is not None:
            clauses.append("f.severity >= ?")
            params.append(int(min_severity))
        if since is not None:
            clauses.append("f.window_end_ts >= ?")
            params.append(to_micros(since))
        if rule_ids:
            clauses.append(f"f.rule_id IN ({','.join('?' * len(rule_ids))})")
            params.extend(rule_ids)
        if incident_id is not None:
            clauses.append("f.incident_id = ?")
            params.append(incident_id)
        if unassigned:
            clauses.append("f.incident_id IS NULL")
        where = " AND ".join(clauses) if clauses else "1=1"
        sql = f"{_FINDING_SELECT} WHERE {where} ORDER BY f.updated_ts DESC, f.id DESC LIMIT ?"
        rows = self.conn.execute(sql, [*params, int(limit)]).fetchall()
        return [_row_to_finding(row) for row in rows]

    def finding_evidence(self, finding_id: int, limit: int = 1000) -> list[EvidenceRef]:
        rows = self.conn.execute(
            "SELECT evidence_type, ref_id, note FROM finding_evidence WHERE finding_id = ? "
            "ORDER BY evidence_type, ref_id LIMIT ?",
            (finding_id, limit),
        )
        return [EvidenceRef(EvidenceType(r[0]), r[1], r[2]) for r in rows]

    def set_finding_status(
        self, finding_id: int, status: FindingStatus, now: datetime, note: str = ""
    ) -> None:
        self.conn.execute(
            "UPDATE findings SET status = ?, status_note = ?, updated_ts = ? WHERE id = ?",
            (str(status), note, to_micros(now), finding_id),
        )

    def open_finding_counts(self) -> dict[FindingSeverity, int]:
        counts = dict.fromkeys(FindingSeverity, 0)
        rows = self.conn.execute(
            "SELECT severity, COUNT(*) FROM findings WHERE status = ? GROUP BY severity",
            (str(FindingStatus.OPEN),),
        )
        for severity, count in rows:
            counts[FindingSeverity(severity)] = count
        return counts

    # -------------------------------------------------------------- suppressions

    def add_suppression(self, rule_id: str, subject: str, reason: str, now: datetime) -> None:
        self.conn.execute(
            "INSERT INTO suppressions (rule_id, subject, reason, created_ts) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(rule_id, subject) DO UPDATE SET reason = excluded.reason",
            (rule_id, subject, reason, to_micros(now)),
        )

    def remove_suppression(self, rule_id: str, subject: str) -> None:
        self.conn.execute(
            "DELETE FROM suppressions WHERE rule_id = ? AND subject = ?", (rule_id, subject)
        )

    def is_suppressed(self, rule_id: str, subject: str) -> bool:
        row = self.conn.execute(
            "SELECT 1 FROM suppressions WHERE rule_id = ? AND subject = ?", (rule_id, subject)
        ).fetchone()
        return row is not None

    def list_suppressions(self) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT rule_id, subject, reason, created_ts FROM suppressions ORDER BY created_ts DESC"
        )
        return [
            {"rule_id": r[0], "subject": r[1], "reason": r[2], "created_at": from_micros(r[3])}
            for r in rows
        ]

    # ----------------------------------------------------------------- incidents

    def create_incident(self, incident: Incident) -> int:
        cursor = self.conn.execute(
            "INSERT INTO incidents (title, severity, status, created_ts, updated_ts, "
            "window_start_ts, window_end_ts, summary, reasons_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                incident.title,
                int(incident.severity),
                str(incident.status),
                to_micros(incident.created_at),
                to_micros(incident.updated_at),
                to_micros(incident.window_start),
                to_micros(incident.window_end),
                incident.summary,
                dumps(incident.reasons),
            ),
        )
        incident.id = int(cursor.lastrowid)
        return incident.id

    def update_incident(self, incident: Incident) -> None:
        self.conn.execute(
            "UPDATE incidents SET title = ?, severity = ?, updated_ts = ?, window_start_ts = ?, "
            "window_end_ts = ?, summary = ?, reasons_json = ? WHERE id = ?",
            (
                incident.title,
                int(incident.severity),
                to_micros(incident.updated_at),
                to_micros(incident.window_start),
                to_micros(incident.window_end),
                incident.summary,
                dumps(incident.reasons),
                incident.id,
            ),
        )

    def _finding_ids(self, incident_id: int) -> list[int]:
        rows = self.conn.execute(
            "SELECT id FROM findings WHERE incident_id = ? ORDER BY window_start_ts, id",
            (incident_id,),
        )
        return [r[0] for r in rows]

    def get_incident(self, incident_id: int) -> Incident | None:
        row = self.conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        return None if row is None else _row_to_incident(row, self._finding_ids(incident_id))

    def list_incidents(
        self, *, statuses: Sequence[IncidentStatus] = (), limit: int = 200
    ) -> list[Incident]:
        if statuses:
            placeholders = ",".join("?" * len(statuses))
            rows = self.conn.execute(
                f"SELECT * FROM incidents WHERE status IN ({placeholders}) "  # noqa: S608
                "ORDER BY updated_ts DESC, id DESC LIMIT ?",
                [*(str(s) for s in statuses), limit],
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM incidents ORDER BY updated_ts DESC, id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [_row_to_incident(row, self._finding_ids(row["id"])) for row in rows]

    def assign_findings(self, finding_ids: Iterable[int], incident_id: int | None) -> None:
        self.conn.executemany(
            "UPDATE findings SET incident_id = ? WHERE id = ?",
            [(incident_id, fid) for fid in finding_ids],
        )

    def delete_empty_incidents(self) -> int:
        cursor = self.conn.execute(
            "DELETE FROM incidents WHERE id NOT IN "
            "(SELECT incident_id FROM findings WHERE incident_id IS NOT NULL)"
        )
        return cursor.rowcount

    def set_incident_status(self, incident_id: int, status: IncidentStatus, now: datetime) -> None:
        self.conn.execute(
            "UPDATE incidents SET status = ?, updated_ts = ? WHERE id = ?",
            (str(status), to_micros(now), incident_id),
        )

    # ---------------------------------------------------------------- hypotheses

    def upsert_hypothesis(self, hypothesis: Hypothesis) -> None:
        self.conn.execute(
            "INSERT INTO hypotheses (incident_id, template_id, statement, rationale, confidence, "
            "basis_json, generated_by, created_ts) VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(incident_id, template_id) DO UPDATE SET statement = excluded.statement, "
            "rationale = excluded.rationale, confidence = excluded.confidence, "
            "basis_json = excluded.basis_json",
            (
                hypothesis.incident_id,
                hypothesis.template_id,
                hypothesis.statement,
                hypothesis.rationale,
                hypothesis.confidence,
                dumps(hypothesis.basis),
                hypothesis.generated_by,
                to_micros(hypothesis.created_at),
            ),
        )

    def hypotheses_for(self, incident_id: int) -> list[Hypothesis]:
        rows = self.conn.execute(
            "SELECT * FROM hypotheses WHERE incident_id = ? ORDER BY id", (incident_id,)
        )
        return [
            Hypothesis(
                id=r["id"],
                incident_id=r["incident_id"],
                template_id=r["template_id"],
                statement=r["statement"],
                rationale=r["rationale"],
                confidence=r["confidence"],
                basis=loads(r["basis_json"], []),
                generated_by=r["generated_by"],
                created_at=from_micros(r["created_ts"]),
            )
            for r in rows
        ]

    def prune_hypotheses(self, incident_id: int, keep: Iterable[str]) -> None:
        keep_ids = list(keep)
        if keep_ids:
            marks = ",".join("?" * len(keep_ids))
            sql = f"DELETE FROM hypotheses WHERE incident_id = ? AND template_id NOT IN ({marks})"  # noqa: S608
            self.conn.execute(sql, [incident_id, *keep_ids])
        else:
            self.conn.execute("DELETE FROM hypotheses WHERE incident_id = ?", (incident_id,))
