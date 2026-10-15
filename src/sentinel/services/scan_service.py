"""On-demand temporary-directory scans: run, persist, and compare with the previous scan."""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from sentinel.config import TempScanSettings
from sentinel.models import ScanError, ScanRun, ScanStatus, utc_now
from sentinel.paths import canonical_key
from sentinel.scanner.snapshots import RootComparison, compare_snapshots
from sentinel.scanner.temp_scanner import (
    MAX_ERRORS_RECORDED,
    RootScanResult,
    ScanLimits,
    ScanProgress,
    TempScanner,
    resolve_scan_roots,
)
from sentinel.storage import Repository

logger = logging.getLogger(__name__)

TEMP_SCAN = "temp"


@dataclass(slots=True)
class TempScanOutcome:
    scan: ScanRun
    results: list[RootScanResult] = field(default_factory=list)
    comparisons: list[RootComparison] = field(default_factory=list)
    skipped_roots: list[tuple[str, str]] = field(default_factory=list)


class ScanService:
    """Runs a temp scan across all configured roots as one persisted scan run."""

    def __init__(
        self,
        database_path: Path,
        settings: TempScanSettings,
        *,
        scanner: TempScanner | None = None,
        environ: Mapping[str, str] | None = None,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self.database_path = database_path
        self.settings = settings
        self.scanner = scanner or TempScanner(ScanLimits.from_settings(settings), clock=clock)
        self.environ = environ
        self.clock = clock

    def run_temp_scan(
        self,
        *,
        cancel: threading.Event | None = None,
        progress: Callable[[ScanProgress], None] | None = None,
    ) -> TempScanOutcome:
        resolved = resolve_scan_roots(self.settings, self.environ)
        scan = ScanRun(
            scan_type=TEMP_SCAN,
            started_at=self.clock(),
            roots=[str(root) for root in resolved.roots],
        )
        outcome = TempScanOutcome(scan=scan, skipped_roots=resolved.skipped)
        repo = Repository.open(self.database_path)
        try:
            with repo.transaction():
                repo.create_scan_run(scan)
            logger.info(
                "temp scan started",
                extra={"scan_id": scan.id, "roots": len(resolved.roots)},
            )
            try:
                self._scan_roots(repo, outcome, resolved.roots, cancel, progress)
            except Exception as exc:
                scan.status = ScanStatus.FAILED
                scan.errors.append(ScanError(path="", kind="internal_error", detail=repr(exc)))
                scan.error_count += 1
                self._finish(repo, outcome)
                logger.exception("temp scan failed", extra={"scan_id": scan.id})
                raise
            cancelled = any(r.cancelled for r in outcome.results) or (
                cancel is not None
                and cancel.is_set()
                and len(outcome.results) < len(resolved.roots)
            )
            incomplete = any(not r.snapshot.complete or r.error_count for r in outcome.results)
            if cancelled:
                scan.status = ScanStatus.CANCELLED
            elif incomplete:
                scan.status = ScanStatus.PARTIAL
            else:
                scan.status = ScanStatus.COMPLETED
            self._finish(repo, outcome)
            logger.info(
                "temp scan finished",
                extra={"scan_id": scan.id, "status": str(scan.status), "files": scan.files_scanned},
            )
            return outcome
        finally:
            repo.close()

    def _scan_roots(
        self,
        repo: Repository,
        outcome: TempScanOutcome,
        roots: list[Path],
        cancel: threading.Event | None,
        progress: Callable[[ScanProgress], None] | None,
    ) -> None:
        scan = outcome.scan
        if scan.id is None:
            raise RuntimeError("scan run must be persisted before roots are scanned")
        for root in roots:
            if cancel is not None and cancel.is_set():
                break
            baseline = repo.previous_root_snapshot(canonical_key(root), scan.id)
            baseline_scan = repo.get_scan_run(baseline.scan_id) if baseline else None
            since = baseline_scan.started_at if baseline_scan else None

            result = self.scanner.scan_root(root, cancel=cancel, progress=progress, since=since)
            with repo.transaction():
                repo.save_root_snapshot(scan.id, result.snapshot)
                repo.save_file_samples(scan.id, result.samples)
            outcome.results.append(result)

            if baseline is not None and baseline_scan is not None and result.snapshot.complete:
                outcome.comparisons.append(
                    compare_snapshots(
                        baseline, result.snapshot, baseline_scan.started_at, scan.started_at
                    )
                )

    def _finish(self, repo: Repository, outcome: TempScanOutcome) -> None:
        scan = outcome.scan
        scan.finished_at = self.clock()
        scan.files_scanned = sum(r.snapshot.file_count for r in outcome.results)
        scan.dirs_scanned = sum(r.snapshot.dir_count for r in outcome.results)
        scan.bytes_total = sum(r.snapshot.total_bytes for r in outcome.results)
        scan.error_count += sum(r.error_count for r in outcome.results)
        for result in outcome.results:
            room = MAX_ERRORS_RECORDED - len(scan.errors)
            if room <= 0:
                break
            scan.errors.extend(result.errors[:room])
        scan.summary = {
            "skipped_roots": [{"path": p, "reason": r} for p, r in outcome.skipped_roots],
            "comparisons": [c.to_dict() for c in outcome.comparisons],
            "cancelled": scan.status is ScanStatus.CANCELLED,
        }
        with repo.transaction():
            repo.complete_scan_run(scan)
