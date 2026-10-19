"""Runs the detection rules over stored data and maintains findings.

Deduplication: a draft whose (rule, subject) matches an unresolved finding that ended
within the rule's window is merged into it (window widened, new evidence added, severity
never lowered) instead of creating a new finding; a draft that adds nothing new leaves the
finding untouched. Suppressed (rule, subject) pairs still produce findings, stored with
status ``suppressed`` so they remain visible but do not alert (DECISIONS.md D-010).
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from sentinel.analysis.rules import (
    RULES_BY_ID,
    AnalysisInput,
    RuleParams,
    TempComparison,
    lookback,
    resolve_rule_params,
    run_rules,
)
from sentinel.config import AppConfig
from sentinel.models import (
    Finding,
    FindingDraft,
    FindingStatus,
    ScanStatus,
    Severity,
    utc_now,
)
from sentinel.services.monitoring import LOG_BYTES_METRIC
from sentinel.services.scan_service import TEMP_SCAN
from sentinel.storage import ObservationFilter, Repository

logger = logging.getLogger(__name__)

MAX_EVIDENCE_PER_FINDING = 200
MAX_OBSERVATIONS = 50_000

CREATED, UPDATED, UNCHANGED, SUPPRESSED = "created", "updated", "unchanged", "suppressed"


@dataclass(slots=True)
class AnalysisResult:
    ran_at: datetime
    drafts: int = 0
    created: list[int] = field(default_factory=list)
    updated: list[int] = field(default_factory=list)
    suppressed: list[int] = field(default_factory=list)
    unchanged: int = 0
    warnings: list[str] = field(default_factory=list)
    new_open: list[Finding] = field(default_factory=list)


class AnalysisService:
    def __init__(
        self,
        database_path: Path,
        config: AppConfig,
        *,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self.database_path = database_path
        self.config = config
        self.clock = clock

    def run(self) -> AnalysisResult:
        now = self.clock()
        result = AnalysisResult(ran_at=now)
        params, warnings = resolve_rule_params(self.config.rules)
        result.warnings.extend(warnings)
        repo = Repository.open(self.database_path)
        try:
            inp = self.build_input(repo, now, params)
            drafts, errors = run_rules(inp, params)
            result.warnings.extend(f"rule failed: {e}" for e in errors)
            result.drafts = len(drafts)
            with repo.transaction():
                for draft in drafts:
                    window = RULES_BY_ID[draft.rule_id].dedup_window(params[draft.rule_id])
                    outcome, finding_id = self.upsert(repo, draft, now, window)
                    if outcome == CREATED:
                        result.created.append(finding_id)
                    elif outcome == UPDATED:
                        result.updated.append(finding_id)
                    elif outcome == SUPPRESSED:
                        result.suppressed.append(finding_id)
                    else:
                        result.unchanged += 1
            result.new_open = [f for i in result.created if (f := repo.get_finding(i))]
        finally:
            repo.close()
        logger.info(
            "analysis finished",
            extra={
                "drafts": result.drafts,
                "created": len(result.created),
                "updated": len(result.updated),
            },
        )
        return result

    def build_input(self, repo: Repository, now: datetime, params: RuleParams) -> AnalysisInput:
        since = now - lookback(params)
        newest = repo.query_observations(
            ObservationFilter(since=since, min_severity=Severity.WARNING),
            limit=MAX_OBSERVATIONS,
        )
        newest.reverse()

        burst = params["event_burst"]
        bucket = timedelta(minutes=burst["bucket_minutes"])
        volume = repo.observation_volume_by_source(
            now - timedelta(hours=burst["baseline_hours"]) - 2 * bucket,
            now + bucket,
            int(bucket.total_seconds()),
        )
        metrics = repo.metric_samples_since(
            LOG_BYTES_METRIC, now - timedelta(minutes=params["log_growth"]["window_minutes"])
        )

        comparisons: list[TempComparison] = []
        recent = now - timedelta(hours=params["temp_growth"]["lookback_hours"])
        for scan in repo.list_scan_runs(TEMP_SCAN, limit=10):
            usable = scan.status in (ScanStatus.COMPLETED, ScanStatus.PARTIAL)
            if not usable or scan.finished_at is None or scan.finished_at < recent:
                continue
            for item in scan.summary.get("comparisons", []):
                parsed = TempComparison.from_summary(scan.id or 0, item)
                if parsed is not None:
                    comparisons.append(parsed)

        def sample_ids(source_id: str | None, start: datetime, end: datetime, limit: int):
            flt = ObservationFilter(
                source_ids=[source_id] if source_id else (), since=start, until=end
            )
            return [o.id for o in repo.query_observations(flt, limit=limit) if o.id is not None]

        return AnalysisInput(
            now=now,
            observations=newest,
            volume_by_source=volume,
            metric_samples=metrics,
            temp_comparisons=comparisons,
            sample_ids=sample_ids,
        )

    @staticmethod
    def upsert(
        repo: Repository, draft: FindingDraft, now: datetime, window: timedelta
    ) -> tuple[str, int]:
        existing = repo.find_active_finding(
            draft.rule_id, draft.subject, draft.window_start - window
        )
        if existing is not None:
            known = {(e.evidence_type, e.ref_id) for e in repo.finding_evidence(existing.id)}
            fresh = [r for r in draft.evidence if (r.evidence_type, r.ref_id) not in known]
            if not fresh and draft.window_end <= existing.window_end:
                return UNCHANGED, existing.id
            room = max(MAX_EVIDENCE_PER_FINDING - existing.evidence_count, 0)
            draft.evidence = fresh[-room:] if room else []
            repo.merge_finding(existing.id, draft, now)
            return UPDATED, existing.id
        if repo.is_suppressed(draft.rule_id, draft.subject):
            return SUPPRESSED, repo.insert_finding(draft, FindingStatus.SUPPRESSED, now)
        return CREATED, repo.insert_finding(draft, FindingStatus.OPEN, now)
