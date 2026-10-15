"""Iterative, cancellable, read-only inventory of temporary directories.

Safety properties (DECISIONS.md D-011, D-014):

* Read-only: only directory listings and file metadata are used; no file is opened.
* No link traversal: symbolic links, junctions, and any other reparse-point directory
  are counted and skipped, never followed. On Windows these are the only ways to form a
  directory cycle or to escape a root, so traversal stays inside the root and terminates.
* Bounded: an explicit stack (no recursion), maximum depth, maximum entries, bounded
  sample lists, and a bounded error list (the total error count is always kept).
* Cancellable: the cancel event is checked for every directory entry.
"""

from __future__ import annotations

import heapq
import itertools
import os
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from sentinel.config import TempScanSettings
from sentinel.models import DirSnapshot, FileSample, RootSnapshot, ScanError, utc_now
from sentinel.paths import PathError, canonical_key, dedupe_roots, expand_path
from sentinel.scanner.classification import (
    CandidatePolicy,
    assess_candidate,
    classify,
    file_extension,
)

FILE_ATTRIBUTE_REPARSE_POINT = 0x400
MAX_ERRORS_RECORDED = 200
MAX_EXTENSIONS_TRACKED = 300
MAX_EXTENSIONS_REPORTED = 50
MAX_DIRS_RECORDED = 500
PROGRESS_INTERVAL_SECONDS = 0.2
ROOT_FILES_KEY = "(files directly in folder)"
OTHER_KEY = "(other)"

_GB = 1024**3
SIZE_BUCKETS: list[tuple[int | None, str]] = [
    (1024, "< 1 KB"),
    (1024**2, "1 KB - 1 MB"),
    (10 * 1024**2, "1 - 10 MB"),
    (100 * 1024**2, "10 - 100 MB"),
    (_GB, "100 MB - 1 GB"),
    (None, "≥ 1 GB"),
]
AGE_BUCKETS: list[tuple[int | None, str]] = [
    (1, "< 1 day"),
    (7, "1 - 7 days"),
    (30, "7 - 30 days"),
    (90, "30 - 90 days"),
    (365, "90 - 365 days"),
    (None, "≥ 1 year"),
]

ScandirFunc = Callable[[str], AbstractContextManager[Iterator[os.DirEntry]]]


@dataclass(frozen=True, slots=True)
class ScanLimits:
    max_depth: int = 32
    max_entries: int = 500_000
    top_files_kept: int = 100
    max_candidates: int = 500
    candidate_min_age_days: int = 7

    @classmethod
    def from_settings(cls, settings: TempScanSettings) -> ScanLimits:
        return cls(
            max_depth=settings.max_depth,
            max_entries=settings.max_entries,
            top_files_kept=settings.top_files_kept,
            max_candidates=settings.max_candidates,
            candidate_min_age_days=settings.candidate_min_age_days,
        )


@dataclass(frozen=True, slots=True)
class ScanProgress:
    root: str
    files: int
    dirs: int
    bytes: int
    current: str


@dataclass(slots=True)
class RootScanResult:
    snapshot: RootSnapshot
    samples: list[FileSample]
    errors: list[ScanError]
    error_count: int
    cancelled: bool
    limit_reached: str | None


@dataclass(slots=True)
class ResolvedRoots:
    roots: list[Path] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)


def _env_get(env: Mapping[str, str], name: str) -> str | None:
    if name in env:
        return env[name]
    upper = name.upper()
    return next((value for key, value in env.items() if key.upper() == upper), None)


def resolve_scan_roots(
    settings: TempScanSettings, environ: Mapping[str, str] | None = None
) -> ResolvedRoots:
    """Expand, validate, and deduplicate the configured scan roots.

    Every root that will *not* be scanned is reported with a reason, so the UI can
    disclose the exact scan scope.
    """
    env = os.environ if environ is None else environ
    raw: list[str] = []
    if settings.include_user_temp:
        user_temps = [_env_get(env, "TEMP"), _env_get(env, "TMP")]
        local_app_data = _env_get(env, "LOCALAPPDATA")
        if local_app_data:
            user_temps.append(str(Path(local_app_data) / "Temp"))
        found = [value for value in user_temps if value]
        raw.extend(found or [tempfile.gettempdir()])
    if settings.include_windows_temp and sys.platform == "win32":
        system_root = _env_get(env, "SystemRoot") or r"C:\Windows"
        raw.append(str(Path(system_root) / "Temp"))
    raw.extend(settings.extra_roots)

    existing: list[Path] = []
    skipped: list[tuple[str, str]] = []
    for item in raw:
        try:
            path = expand_path(item, env)
        except PathError as exc:
            skipped.append((item, str(exc)))
            continue
        if not os.path.exists(path):
            skipped.append((str(path), "does not exist or is not accessible"))
        elif not os.path.isdir(path):
            skipped.append((str(path), "is not a directory"))
        else:
            existing.append(path)

    selection = dedupe_roots(existing)
    skipped.extend((str(path), reason) for path, reason in selection.skipped)
    return ResolvedRoots(roots=selection.roots, skipped=skipped)


def _timestamp(value: float | None) -> datetime | None:
    if value is None:
        return None
    try:
        return datetime.fromtimestamp(value, UTC)
    except (OverflowError, OSError, ValueError):
        return None  # corrupt or out-of-range filesystem timestamp


def _bucket(labels: list[tuple[int | None, str]], value: float) -> str:
    for limit, label in labels:
        if limit is None or value < limit:
            return label
    return labels[-1][1]


class _Accumulator:
    """Running statistics for one root."""

    def __init__(self, limits: ScanLimits, now: datetime, since: datetime | None) -> None:
        self.limits = limits
        self.now = now
        self.since = since
        self.policy = CandidatePolicy(min_age_days=limits.candidate_min_age_days)
        self.total_bytes = 0
        self.files = 0
        self.dirs = 0
        self.inaccessible = 0
        self.skipped_links = 0
        self.vanished = 0
        self.new_files = 0
        self.modified_files = 0
        self.oldest: datetime | None = None
        self.newest: datetime | None = None
        self.extensions: dict[str, list[int]] = {}
        self.classes: dict[str, list[int]] = {}
        self.size_buckets = {label: [0, 0] for _, label in SIZE_BUCKETS}
        self.age_buckets = {label: [0, 0] for _, label in AGE_BUCKETS}
        self.top_dirs: dict[str, list[int]] = {}
        self.candidate_count = 0
        self.candidate_bytes = 0
        self._seq = itertools.count()
        self._largest: list[tuple] = []
        self._oldest: list[tuple] = []
        self._candidates: list[tuple] = []

    @staticmethod
    def _add(table: dict[str, list[int]], key: str, size: int) -> None:
        entry = table.setdefault(key, [0, 0])
        entry[0] += 1
        entry[1] += size

    def _keep_top(self, heap: list[tuple], key: float, item: tuple, capacity: int) -> None:
        entry = (key, next(self._seq), item)
        if len(heap) < capacity:
            heapq.heappush(heap, entry)
        elif key > heap[0][0]:
            heapq.heapreplace(heap, entry)

    def add_dir(self, top: str) -> None:
        self.dirs += 1
        self.top_dirs.setdefault(top, [0, 0])

    def add_file(self, path: str, name: str, top: str, st: os.stat_result) -> None:
        size = st.st_size
        modified = _timestamp(st.st_mtime)
        created = _timestamp(getattr(st, "st_birthtime", None))
        ext = file_extension(name)
        kind = classify(name, ext)

        self.files += 1
        self.total_bytes += size
        self._add(self.top_dirs, top, size)
        ext_key = ext or "(none)"
        if ext_key not in self.extensions and len(self.extensions) >= MAX_EXTENSIONS_TRACKED:
            ext_key = OTHER_KEY
        self._add(self.extensions, ext_key, size)
        self._add(self.classes, kind, size)
        self.size_buckets[_bucket(SIZE_BUCKETS, size)][0] += 1
        self.size_buckets[_bucket(SIZE_BUCKETS, size)][1] += size

        item = (path, size, modified, created, ext, kind)
        self._keep_top(self._largest, size, item, self.limits.top_files_kept)
        if modified is None:
            return

        age_days = (self.now - modified).total_seconds() / 86_400
        bucket = self.age_buckets[_bucket(AGE_BUCKETS, max(age_days, 0))]
        bucket[0] += 1
        bucket[1] += size
        self.oldest = modified if self.oldest is None else min(self.oldest, modified)
        self.newest = modified if self.newest is None else max(self.newest, modified)
        # Oldest files: keep the N smallest timestamps using a heap keyed on -timestamp.
        self._keep_top(self._oldest, -modified.timestamp(), item, self.limits.top_files_kept)

        if self.since is not None:
            if created is not None and created >= self.since:
                self.new_files += 1
            elif modified >= self.since:
                self.modified_files += 1

        reasons = assess_candidate(kind, ext, modified, created, self.now, self.policy)
        if reasons is not None:
            self.candidate_count += 1
            self.candidate_bytes += size
            self._keep_top(self._candidates, size, (*item, reasons), self.limits.max_candidates)

    def samples(self, root: str) -> list[FileSample]:
        def build(item: tuple, category: str, reasons: list[str] | None = None) -> FileSample:
            path, size, modified, created, ext, kind = item[:6]
            return FileSample(
                path=path,
                size=size,
                modified_at=modified,
                created_at=created,
                extension=ext,
                classification=kind,
                category=category,
                reasons=reasons or [],
                root=root,
            )

        largest = [build(i, "largest") for _, _, i in sorted(self._largest, reverse=True)]
        oldest = [build(i, "oldest") for _, _, i in sorted(self._oldest, reverse=True)]
        candidates = [
            build(i, "candidate", i[6]) for _, _, i in sorted(self._candidates, reverse=True)
        ]
        return largest + oldest + candidates

    @staticmethod
    def _table(table: dict[str, list[int]], key_name: str, limit: int) -> list[dict]:
        rows = sorted(table.items(), key=lambda kv: kv[1][1], reverse=True)
        result = [{key_name: k, "count": v[0], "bytes": v[1]} for k, v in rows[:limit]]
        rest = rows[limit:]
        if rest:
            result.append(
                {
                    key_name: OTHER_KEY,
                    "count": sum(v[0] for _, v in rest),
                    "bytes": sum(v[1] for _, v in rest),
                }
            )
        return result

    def stats(self, cancelled: bool, limit: str | None) -> dict:
        return {
            "extensions": self._table(self.extensions, "extension", MAX_EXTENSIONS_REPORTED),
            "classifications": self._table(self.classes, "classification", 100),
            "size_buckets": [
                {"label": label, "count": v[0], "bytes": v[1]}
                for label, v in self.size_buckets.items()
            ],
            "age_buckets": [
                {"label": label, "count": v[0], "bytes": v[1]}
                for label, v in self.age_buckets.items()
            ],
            "candidates": {"count": self.candidate_count, "bytes": self.candidate_bytes},
            "vanished": self.vanished,
            "cancelled": cancelled,
            "limit_reached": limit,
            "baseline_since": self.since.isoformat() if self.since else None,
        }

    def dir_snapshots(self) -> list[DirSnapshot]:
        rows = sorted(self.top_dirs.items(), key=lambda kv: kv[1][1], reverse=True)
        return [DirSnapshot(name, v[1], v[0]) for name, v in rows[:MAX_DIRS_RECORDED]]


class TempScanner:
    """Scans one root at a time. Stateless between roots; safe to reuse."""

    def __init__(
        self,
        limits: ScanLimits | None = None,
        *,
        clock: Callable[[], datetime] = utc_now,
        scandir: ScandirFunc = os.scandir,
    ) -> None:
        self.limits = limits or ScanLimits()
        self._clock = clock
        self._scandir = scandir

    def scan_root(
        self,
        root: Path,
        *,
        cancel: threading.Event | None = None,
        progress: Callable[[ScanProgress], None] | None = None,
        since: datetime | None = None,
    ) -> RootScanResult:
        """Inventory ``root``. ``since`` (previous scan time) enables new/modified counts."""
        root_text = str(root)
        acc = _Accumulator(self.limits, self._clock(), since)
        errors: list[ScanError] = []
        error_count = 0
        limit: str | None = None
        cancelled = False
        entries = 0
        last_report = 0.0

        def record(path: str, kind: str, detail: str = "") -> None:
            nonlocal error_count
            error_count += 1
            if len(errors) < MAX_ERRORS_RECORDED:
                errors.append(ScanError(path=path, kind=kind, detail=detail))

        def report(current: str) -> None:
            nonlocal last_report
            if progress is None:
                return
            now = time.monotonic()
            if now - last_report >= PROGRESS_INTERVAL_SECONDS:
                last_report = now
                progress(ScanProgress(root_text, acc.files, acc.dirs, acc.total_bytes, current))

        # Stack items: (directory path, depth, first-level child name used for aggregation)
        stack: list[tuple[str, int, str]] = [(root_text, 0, ROOT_FILES_KEY)]
        while stack and not cancelled and limit != "max_entries":
            directory, depth, top = stack.pop()
            try:
                with self._scandir(directory) as iterator:
                    for entry in iterator:
                        if cancel is not None and cancel.is_set():
                            cancelled = True
                            break
                        entries += 1
                        if entries > self.limits.max_entries:
                            limit = "max_entries"
                            detail = f"stopped after {self.limits.max_entries} entries"
                            record(directory, "limit", detail)
                            break
                        try:
                            if entry.is_symlink() or _is_junction(entry):
                                acc.skipped_links += 1
                                continue
                            st = entry.stat(follow_symlinks=False)
                            if entry.is_dir(follow_symlinks=False):
                                if _is_reparse_point(st):
                                    acc.skipped_links += 1
                                    continue
                                # First-level directories become the aggregation key.
                                child_top = entry.name if depth == 0 else top
                                acc.add_dir(child_top)
                                # Directories up to max_depth levels below the root are listed.
                                if depth + 1 > self.limits.max_depth:
                                    if limit is None:
                                        limit = "max_depth"
                                    record(entry.path, "limit", "maximum depth reached")
                                    continue
                                stack.append((entry.path, depth + 1, child_top))
                                continue
                            acc.add_file(entry.path, entry.name, top, st)
                        except FileNotFoundError:
                            acc.vanished += 1  # deleted while scanning; not an error
                        except PermissionError as exc:
                            acc.inaccessible += 1
                            record(entry.path, "access_denied", exc.strerror or "")
                        except OSError as exc:
                            record(entry.path, "os_error", exc.strerror or str(exc))
                        report(directory)
            except FileNotFoundError:
                if depth == 0:
                    record(directory, "not_found", "scan root does not exist")
                else:
                    acc.vanished += 1
            except PermissionError as exc:
                acc.inaccessible += 1
                record(directory, "access_denied", exc.strerror or "")
            except OSError as exc:
                record(directory, "os_error", exc.strerror or str(exc))

        root_unreadable = any(e.path == root_text and e.kind != "limit" for e in errors)
        complete = not cancelled and limit is None and not root_unreadable
        snapshot = RootSnapshot(
            root=root_text,
            root_key=canonical_key(root),
            complete=complete,
            total_bytes=acc.total_bytes,
            file_count=acc.files,
            dir_count=acc.dirs,
            inaccessible_count=acc.inaccessible,
            skipped_links=acc.skipped_links,
            new_files=acc.new_files,
            modified_files=acc.modified_files,
            oldest_mtime=acc.oldest,
            newest_mtime=acc.newest,
            stats=acc.stats(cancelled, limit),
            dirs=acc.dir_snapshots(),
        )
        if progress is not None:
            progress(ScanProgress(root_text, acc.files, acc.dirs, acc.total_bytes, root_text))
        return RootScanResult(
            snapshot=snapshot,
            samples=acc.samples(root_text),
            errors=errors,
            error_count=error_count,
            cancelled=cancelled,
            limit_reached=limit,
        )


def _is_junction(entry: os.DirEntry) -> bool:
    is_junction = getattr(entry, "is_junction", None)  # Python 3.12+
    return bool(is_junction and is_junction())


def _is_reparse_point(st: os.stat_result) -> bool:
    return bool(getattr(st, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT)
