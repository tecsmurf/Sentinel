import threading

import pytest

from sentinel.config import TempScanSettings
from sentinel.models import ScanStatus
from sentinel.scanner.temp_scanner import ScanLimits, TempScanner
from sentinel.services.scan_service import ScanService
from sentinel.storage import Repository
from tests.support import fake_scandir


@pytest.fixture
def temp_root(tmp_path):
    root = tmp_path / "Temp"
    (root / "cache").mkdir(parents=True)
    (root / "cache" / "a.tmp").write_bytes(b"x" * 1000)
    (root / "b.log").write_bytes(b"x" * 200)
    return root


def make_service(database, *roots, scanner=None):
    settings = TempScanSettings(
        include_user_temp=False,
        include_windows_temp=False,
        extra_roots=[str(r) for r in roots],
    )
    return ScanService(database.path, settings, scanner=scanner, environ={})


def stored_scan(database, scan_id):
    repo = Repository.open(database.path)
    try:
        return repo.get_scan_run(scan_id), repo.root_snapshots(scan_id, with_dirs=True)
    finally:
        repo.close()


def test_first_scan_is_persisted_without_comparison(database, temp_root):
    outcome = make_service(database, temp_root).run_temp_scan()
    assert outcome.scan.status is ScanStatus.COMPLETED
    assert outcome.comparisons == []

    scan, snapshots = stored_scan(database, outcome.scan.id)
    assert scan.status is ScanStatus.COMPLETED
    assert scan.finished_at is not None
    assert (scan.files_scanned, scan.bytes_total) == (2, 1200)
    assert snapshots[0].complete
    assert {d.rel_path for d in snapshots[0].dirs} >= {"cache"}
    assert scan.summary["comparisons"] == []


def test_second_scan_reports_growth_against_previous(database, temp_root):
    service = make_service(database, temp_root)
    first = service.run_temp_scan()
    (temp_root / "downloads").mkdir()
    (temp_root / "downloads" / "big.part").write_bytes(b"x" * 5000)

    second = service.run_temp_scan()
    (comparison,) = second.comparisons
    assert comparison.baseline_scan_id == first.scan.id
    assert comparison.delta_bytes == 5000
    assert comparison.delta_files == 1
    assert comparison.dir_changes[0].rel_path == "downloads"
    assert comparison.dir_changes[0].status == "new"

    snapshot = second.results[0].snapshot
    assert snapshot.new_files + snapshot.modified_files == 1

    scan, _ = stored_scan(database, second.scan.id)
    assert scan.summary["comparisons"][0]["delta_bytes"] == 5000


def test_inaccessible_entries_make_the_scan_partial(database, temp_root):
    scanner = TempScanner(scandir=fake_scandir(deny={"cache"}))
    outcome = make_service(database, temp_root, scanner=scanner).run_temp_scan()
    assert outcome.scan.status is ScanStatus.PARTIAL
    scan, _ = stored_scan(database, outcome.scan.id)
    assert scan.error_count == 1
    assert scan.errors[0].kind == "access_denied"


def test_cancelled_scan_is_not_used_as_a_baseline(database, temp_root):
    service = make_service(database, temp_root)
    first = service.run_temp_scan()

    cancel = threading.Event()
    cancel.set()
    cancelled = service.run_temp_scan(cancel=cancel)
    assert cancelled.scan.status is ScanStatus.CANCELLED
    assert stored_scan(database, cancelled.scan.id)[0].summary["cancelled"] is True

    third = service.run_temp_scan()
    assert third.comparisons[0].baseline_scan_id == first.scan.id


def test_limit_reached_marks_partial_and_skips_comparison(database, temp_root):
    service = make_service(database, temp_root)
    service.run_temp_scan()
    limited = make_service(database, temp_root, scanner=TempScanner(ScanLimits(max_entries=1)))
    outcome = limited.run_temp_scan()
    assert outcome.scan.status is ScanStatus.PARTIAL
    assert outcome.comparisons == []  # incomplete measurements are never compared


def test_skipped_roots_are_disclosed(database, temp_root, tmp_path):
    outcome = make_service(database, temp_root, tmp_path / "missing").run_temp_scan()
    assert outcome.scan.status is ScanStatus.COMPLETED
    scan, _ = stored_scan(database, outcome.scan.id)
    skipped = scan.summary["skipped_roots"]
    assert skipped == [
        {"path": str(tmp_path / "missing"), "reason": "does not exist or is not accessible"}
    ]


def test_multiple_roots_share_one_scan_run(database, temp_root, tmp_path):
    other = tmp_path / "Other"
    other.mkdir()
    (other / "x.tmp").write_bytes(b"x" * 7)
    outcome = make_service(database, temp_root, other).run_temp_scan()
    _, snapshots = stored_scan(database, outcome.scan.id)
    assert len(snapshots) == 2
    assert outcome.scan.bytes_total == 1207


def test_internal_failure_is_recorded_and_raised(database, temp_root):
    class ExplodingScanner(TempScanner):
        def scan_root(self, *args, **kwargs):
            raise RuntimeError("disk on fire")

    service = make_service(database, temp_root, scanner=ExplodingScanner())
    with pytest.raises(RuntimeError, match="disk on fire"):
        service.run_temp_scan()
    repo = Repository.open(database.path)
    try:
        (scan,) = repo.list_scan_runs("temp")
    finally:
        repo.close()
    assert scan.status is ScanStatus.FAILED
    assert scan.errors[0].kind == "internal_error"
