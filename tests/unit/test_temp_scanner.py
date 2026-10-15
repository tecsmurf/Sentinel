import builtins
import os
import threading
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from sentinel.config import TempScanSettings
from sentinel.paths import canonical_key
from sentinel.scanner import temp_scanner
from sentinel.scanner.temp_scanner import (
    ROOT_FILES_KEY,
    ScanLimits,
    TempScanner,
    resolve_scan_roots,
)

# Files created by the tests have a real creation time of "now". The scanner clock runs 400
# days ahead so that modification times set with os.utime decide each file's age.
FAKE_NOW = datetime.now(UTC) + timedelta(days=400)


def make_file(path: Path, size: int = 0, *, age_days: float = 0) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"x" * size)
    stamp = (FAKE_NOW - timedelta(days=age_days)).timestamp()
    os.utime(path, (stamp, stamp))
    return path


def scanner(**limits) -> TempScanner:
    return TempScanner(ScanLimits(**limits), clock=lambda: FAKE_NOW)


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "Temp"
    make_file(root / "a.tmp", 100, age_days=30)
    make_file(root / "sub1" / "b.log", 2000, age_days=2)
    make_file(root / "sub1" / "deep" / "c.dmp", 5000, age_days=60)
    make_file(root / "sub2" / "d.exe", 300, age_days=90)
    (root / "empty").mkdir()
    return root


class TestInventory:
    def test_totals_and_directory_aggregates(self, tree):
        result = scanner().scan_root(tree)
        snap = result.snapshot
        assert snap.complete
        assert not result.cancelled
        assert result.errors == []
        assert snap.root_key == canonical_key(tree)
        assert (snap.file_count, snap.total_bytes, snap.dir_count) == (4, 7400, 4)
        dirs = {d.rel_path: (d.total_bytes, d.file_count) for d in snap.dirs}
        assert dirs == {
            "sub1": (7000, 2),
            "sub2": (300, 1),
            ROOT_FILES_KEY: (100, 1),
            "empty": (0, 0),
        }

    def test_extension_classification_and_bucket_stats(self, tree):
        stats = scanner().scan_root(tree).snapshot.stats
        exts = {row["extension"]: (row["count"], row["bytes"]) for row in stats["extensions"]}
        assert exts == {".dmp": (1, 5000), ".log": (1, 2000), ".exe": (1, 300), ".tmp": (1, 100)}
        classes = {row["classification"]: row["count"] for row in stats["classifications"]}
        assert classes == {"crash_dump": 1, "log": 1, "executable": 1, "temporary": 1}
        sizes = {row["label"]: row["count"] for row in stats["size_buckets"]}
        assert sizes["< 1 KB"] == 2
        assert sizes["1 KB - 1 MB"] == 2
        ages = {row["label"]: row["count"] for row in stats["age_buckets"]}
        assert ages == {
            "< 1 day": 0,
            "1 - 7 days": 1,
            "7 - 30 days": 0,
            "30 - 90 days": 2,
            "90 - 365 days": 1,
            "≥ 1 year": 0,
        }

    def test_largest_and_oldest_samples_are_bounded_and_sorted(self, tree):
        samples = scanner(top_files_kept=2).scan_root(tree).samples
        largest = [s for s in samples if s.category == "largest"]
        oldest = [s for s in samples if s.category == "oldest"]
        assert [Path(s.path).name for s in largest] == ["c.dmp", "b.log"]
        assert [Path(s.path).name for s in oldest] == ["d.exe", "c.dmp"]
        assert all(s.root == str(tree) for s in samples)

    def test_oldest_and_newest_modification_times(self, tree):
        snap = scanner().scan_root(tree).snapshot
        assert (FAKE_NOW - snap.oldest_mtime).days == 90
        assert (FAKE_NOW - snap.newest_mtime).days == 2

    def test_cleanup_candidates_explain_selection(self, tree):
        result = scanner().scan_root(tree)
        candidates = {Path(s.path).name: s for s in result.samples if s.category == "candidate"}
        # .tmp (30 days) and .dmp (60 days, with caution); .log is too recent; .exe never.
        assert set(candidates) == {"a.tmp", "c.dmp"}
        assert candidates["a.tmp"].reasons[0] == "not modified for 30 days"
        assert candidates["c.dmp"].reasons[-1].startswith("caution:")
        assert result.snapshot.stats["candidates"] == {"count": 2, "bytes": 5100}

    def test_modified_since_previous_scan(self, tree):
        since = FAKE_NOW - timedelta(days=10)
        snap = scanner().scan_root(tree, since=since).snapshot
        # Only b.log (2 days old) changed after `since`; creation times are 400 days earlier.
        assert (snap.new_files, snap.modified_files) == (0, 1)

    def test_scanner_never_opens_files(self, tree, monkeypatch):
        def forbidden(*args, **kwargs):
            raise AssertionError("the scanner must not open files")

        monkeypatch.setattr(builtins, "open", forbidden)
        monkeypatch.setattr(os, "open", forbidden)
        assert scanner().scan_root(tree).snapshot.file_count == 4

    def test_progress_reports_final_totals(self, tree):
        updates = []
        scanner().scan_root(tree, progress=updates.append)
        assert updates
        assert (updates[-1].files, updates[-1].bytes) == (4, 7400)


class TestLimitsAndCancellation:
    def test_max_entries_stops_and_marks_incomplete(self, tree):
        result = scanner(max_entries=2).scan_root(tree)
        assert result.limit_reached == "max_entries"
        assert not result.snapshot.complete
        assert result.snapshot.stats["limit_reached"] == "max_entries"

    def test_max_depth_limits_traversal(self, tmp_path):
        root = tmp_path / "Temp"
        make_file(root / "l1" / "one.tmp", 1)
        make_file(root / "l1" / "l2" / "two.tmp", 1)
        make_file(root / "l1" / "l2" / "l3" / "three.tmp", 1)
        result = scanner(max_depth=2).scan_root(root)
        assert result.snapshot.file_count == 2
        assert result.limit_reached == "max_depth"
        assert not result.snapshot.complete
        assert result.errors[0].kind == "limit"

    def test_preset_cancel_returns_immediately(self, tree):
        cancel = threading.Event()
        cancel.set()
        result = scanner().scan_root(tree, cancel=cancel)
        assert result.cancelled
        assert not result.snapshot.complete
        assert result.snapshot.file_count == 0

    def test_cancel_during_scan(self, tree):
        class CancelAfter(threading.Event):
            def __init__(self, checks):
                super().__init__()
                self.remaining = checks

            def is_set(self):
                self.remaining -= 1
                return self.remaining < 0

        result = scanner().scan_root(tree, cancel=CancelAfter(3))
        assert result.cancelled
        assert 0 < result.snapshot.file_count + result.snapshot.dir_count < 8


class _FlakyEntry:
    """Wraps a real DirEntry and makes stat() raise a chosen error."""

    def __init__(self, entry, error):
        self._entry = entry
        self._error = error
        self.name = entry.name
        self.path = entry.path

    def is_symlink(self):
        return self._entry.is_symlink()

    def is_junction(self):
        return False

    def is_dir(self, *, follow_symlinks=True):
        return self._entry.is_dir(follow_symlinks=follow_symlinks)

    def stat(self, *, follow_symlinks=True):
        if self._error is not None:
            raise self._error
        return self._entry.stat(follow_symlinks=follow_symlinks)


def fake_scandir(deny: set[str] = frozenset(), entry_errors: dict | None = None):
    entry_errors = entry_errors or {}

    @contextmanager
    def scandir(path):
        if Path(path).name in deny:
            raise PermissionError(13, "Access is denied", path)
        with os.scandir(path) as iterator:
            yield [_FlakyEntry(e, entry_errors.get(e.name)) for e in iterator]

    return scandir


class TestErrorHandling:
    def test_inaccessible_directory_is_reported_and_scan_continues(self, tree):
        result = TempScanner(clock=lambda: FAKE_NOW, scandir=fake_scandir(deny={"sub1"})).scan_root(
            tree
        )
        assert result.snapshot.inaccessible_count == 1
        assert result.errors[0].kind == "access_denied"
        assert result.errors[0].path.endswith("sub1")
        assert result.snapshot.file_count == 2  # a.tmp and sub2/d.exe
        assert result.snapshot.complete  # traversal finished; gaps are reported separately

    def test_inaccessible_root_is_incomplete(self, tree):
        result = TempScanner(scandir=fake_scandir(deny={tree.name})).scan_root(tree)
        assert not result.snapshot.complete
        assert result.errors[0].kind == "access_denied"

    def test_missing_root(self, tmp_path):
        result = TempScanner().scan_root(tmp_path / "missing")
        assert not result.snapshot.complete
        assert result.errors[0].kind == "not_found"

    def test_file_deleted_during_scan_is_counted_as_vanished(self, tree):
        errors = {"a.tmp": FileNotFoundError(2, "gone")}
        result = TempScanner(scandir=fake_scandir(entry_errors=errors)).scan_root(tree)
        assert result.snapshot.stats["vanished"] == 1
        assert result.errors == []
        assert result.snapshot.file_count == 3

    def test_other_os_errors_are_recorded(self, tree):
        errors = {"a.tmp": OSError(5, "I/O error")}
        result = TempScanner(scandir=fake_scandir(entry_errors=errors)).scan_root(tree)
        assert result.errors[0].kind == "os_error"
        assert result.snapshot.file_count == 3

    def test_error_list_is_bounded_but_count_is_complete(self, tmp_path, monkeypatch):
        monkeypatch.setattr(temp_scanner, "MAX_ERRORS_RECORDED", 5)
        root = tmp_path / "Temp"
        names = [f"f{i}.tmp" for i in range(12)]
        for name in names:
            make_file(root / name)
        errors = {name: PermissionError(13, "denied") for name in names}
        result = TempScanner(scandir=fake_scandir(entry_errors=errors)).scan_root(root)
        assert len(result.errors) == 5
        assert result.error_count == 12
        assert result.snapshot.inaccessible_count == 12


def test_symbolic_links_are_not_followed(tmp_path):
    outside = tmp_path / "outside"
    make_file(outside / "secret.bin", 999)
    root = tmp_path / "Temp"
    make_file(root / "real.tmp", 1)
    try:
        os.symlink(outside, root / "link", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("creating symbolic links is not permitted here")
    snap = TempScanner().scan_root(root).snapshot
    assert snap.file_count == 1
    assert snap.skipped_links == 1


class TestResolveScanRoots:
    def test_duplicate_temp_variables_collapse(self, tmp_path):
        temp = tmp_path / "Temp"
        temp.mkdir()
        env = {"TEMP": str(temp), "TMP": str(temp), "LOCALAPPDATA": str(tmp_path)}
        settings = TempScanSettings(include_windows_temp=False)
        resolved = resolve_scan_roots(settings, env)
        assert [canonical_key(p) for p in resolved.roots] == [canonical_key(temp)]
        assert len(resolved.skipped) == 2
        assert all("same location" in reason for _, reason in resolved.skipped)

    def test_extra_roots_are_validated(self, tmp_path):
        good = tmp_path / "cache"
        good.mkdir()
        not_dir = tmp_path / "file.txt"
        not_dir.write_text("x")
        settings = TempScanSettings(
            include_user_temp=False,
            include_windows_temp=False,
            extra_roots=[str(good), str(tmp_path / "missing"), str(not_dir), "%NOPE%", "rel"],
        )
        resolved = resolve_scan_roots(settings, {})
        assert resolved.roots == [good.resolve()]
        reasons = [reason for _, reason in resolved.skipped]
        assert reasons[0] == "does not exist or is not accessible"
        assert reasons[1] == "is not a directory"
        assert "NOPE" in reasons[2]
        assert "absolute" in reasons[3]

    def test_nested_extra_root_is_skipped(self, tmp_path):
        temp = tmp_path / "Temp"
        (temp / "nested").mkdir(parents=True)
        settings = TempScanSettings(include_windows_temp=False, extra_roots=[str(temp / "nested")])
        resolved = resolve_scan_roots(settings, {"TEMP": str(temp)})
        assert len(resolved.roots) == 1
        assert "already covered" in resolved.skipped[0][1]

    def test_nothing_enabled(self):
        settings = TempScanSettings(include_user_temp=False, include_windows_temp=False)
        assert resolve_scan_roots(settings, {}).roots == []
