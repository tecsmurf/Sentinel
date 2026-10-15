"""Comparison of successive snapshots of the same scan root."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sentinel.models import RootSnapshot
from sentinel.scanner.temp_scanner import MAX_DIRS_RECORDED

DEFAULT_MAX_DIR_CHANGES = 20


@dataclass(frozen=True, slots=True)
class DirChange:
    rel_path: str
    bytes_before: int
    bytes_after: int
    delta_bytes: int
    status: str  # "grew", "shrank", "new", "removed"


@dataclass(frozen=True, slots=True)
class RootComparison:
    root: str
    root_key: str
    baseline_scan_id: int
    baseline_snapshot_id: int
    current_snapshot_id: int | None
    baseline_at: datetime
    current_at: datetime
    bytes_before: int
    bytes_after: int
    files_before: int
    files_after: int
    dir_changes: list[DirChange] = field(default_factory=list)
    caveats: list[str] = field(default_factory=list)

    @property
    def delta_bytes(self) -> int:
        return self.bytes_after - self.bytes_before

    @property
    def delta_files(self) -> int:
        return self.files_after - self.files_before

    @property
    def delta_ratio(self) -> float | None:
        """Relative change, or ``None`` when the baseline was empty."""
        return None if self.bytes_before == 0 else self.delta_bytes / self.bytes_before

    @property
    def elapsed(self) -> timedelta:
        return self.current_at - self.baseline_at

    @property
    def bytes_per_hour(self) -> float | None:
        hours = self.elapsed.total_seconds() / 3600
        return None if hours <= 0 else self.delta_bytes / hours

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["baseline_at"] = self.baseline_at.isoformat()
        data["current_at"] = self.current_at.isoformat()
        data["delta_bytes"] = self.delta_bytes
        data["delta_files"] = self.delta_files
        return data


def compare_snapshots(
    baseline: RootSnapshot,
    current: RootSnapshot,
    baseline_at: datetime,
    current_at: datetime,
    *,
    max_dir_changes: int = DEFAULT_MAX_DIR_CHANGES,
) -> RootComparison:
    """Describe how a root changed between two snapshots, largest changes first."""
    if baseline.scan_id is None or baseline.id is None:
        raise ValueError("baseline snapshot must be persisted")

    before = {d.rel_path: d.total_bytes for d in baseline.dirs}
    after = {d.rel_path: d.total_bytes for d in current.dirs}
    changes: list[DirChange] = []
    for name in before.keys() | after.keys():
        old, new = before.get(name), after.get(name)
        delta = (new or 0) - (old or 0)
        if old is None:
            status = "new"
        elif new is None:
            status = "removed"
        elif delta > 0:
            status = "grew"
        elif delta < 0:
            status = "shrank"
        else:
            continue
        changes.append(DirChange(name, old or 0, new or 0, delta, status))
    changes.sort(key=lambda c: (abs(c.delta_bytes), c.rel_path), reverse=True)

    caveats: list[str] = []
    if MAX_DIRS_RECORDED in (len(baseline.dirs), len(current.dirs)):
        caveats.append(
            f"Subfolder lists are limited to the {MAX_DIRS_RECORDED} largest entries; "
            "a subfolder reported as new or removed may only have crossed that limit."
        )
    if baseline.inaccessible_count != current.inaccessible_count:
        caveats.append(
            f"{current.inaccessible_count} item(s) were inaccessible in this scan versus "
            f"{baseline.inaccessible_count} in the baseline; part of the difference may "
            "come from access changes rather than real growth."
        )
    if not current.complete:
        caveats.append("The current scan is incomplete; totals may be underestimated.")

    return RootComparison(
        root=current.root,
        root_key=current.root_key,
        baseline_scan_id=baseline.scan_id,
        baseline_snapshot_id=baseline.id,
        current_snapshot_id=current.id,
        baseline_at=baseline_at,
        current_at=current_at,
        bytes_before=baseline.total_bytes,
        bytes_after=current.total_bytes,
        files_before=baseline.file_count,
        files_after=current.file_count,
        dir_changes=changes[:max_dir_changes],
        caveats=caveats,
    )
