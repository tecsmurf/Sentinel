from datetime import timedelta

import pytest

from sentinel.models import DirSnapshot, RootSnapshot
from sentinel.scanner.snapshots import compare_snapshots
from tests.support import BASE_TIME


def snap(total, dirs, *, files=10, inaccessible=0, complete=True, snapshot_id=1, scan_id=1):
    return RootSnapshot(
        root="C:\\Temp",
        root_key="c:\\temp",
        complete=complete,
        total_bytes=total,
        file_count=files,
        inaccessible_count=inaccessible,
        dirs=[DirSnapshot(name, size, 1) for name, size in dirs.items()],
        id=snapshot_id,
        scan_id=scan_id,
    )


def compare(baseline, current, hours=2):
    return compare_snapshots(baseline, current, BASE_TIME, BASE_TIME + timedelta(hours=hours))


def test_totals_rates_and_ratio():
    result = compare(
        snap(1000, {}, files=10), snap(3000, {}, files=14, snapshot_id=2, scan_id=2), hours=4
    )
    assert (result.delta_bytes, result.delta_files) == (2000, 4)
    assert result.delta_ratio == 2.0
    assert result.bytes_per_hour == 500
    assert result.baseline_snapshot_id == 1
    assert result.current_snapshot_id == 2


def test_empty_baseline_has_no_ratio():
    assert compare(snap(0, {}), snap(10, {})).delta_ratio is None


def test_zero_elapsed_has_no_rate():
    assert compare(snap(0, {}), snap(10, {}), hours=0).bytes_per_hour is None


def test_dir_changes_are_classified_and_sorted_by_magnitude():
    before = {"grows": 100, "shrinks": 500, "same": 7, "removed": 50}
    after = {"grows": 1100, "shrinks": 200, "same": 7, "brand-new": 20}
    result = compare(snap(657, before), snap(1327, after))
    summary = [(c.rel_path, c.status, c.delta_bytes) for c in result.dir_changes]
    assert summary == [
        ("grows", "grew", 1000),
        ("shrinks", "shrank", -300),
        ("removed", "removed", -50),
        ("brand-new", "new", 20),
    ]


def test_dir_changes_are_bounded():
    before = {f"d{i}": 0 for i in range(50)}
    after = {f"d{i}": i + 1 for i in range(50)}
    result = compare_snapshots(
        snap(0, before), snap(1, after), BASE_TIME, BASE_TIME, max_dir_changes=5
    )
    assert [c.rel_path for c in result.dir_changes] == ["d49", "d48", "d47", "d46", "d45"]


def test_caveats_for_access_changes_and_incomplete_scans():
    result = compare(snap(10, {}, inaccessible=0), snap(20, {}, inaccessible=3, complete=False))
    assert any("inaccessible" in c for c in result.caveats)
    assert any("incomplete" in c for c in result.caveats)


def test_baseline_must_be_persisted():
    baseline = snap(0, {})
    baseline.id = None
    with pytest.raises(ValueError, match="persisted"):
        compare(baseline, snap(0, {}))


def test_to_dict_is_json_friendly():
    data = compare(snap(1, {"a": 1}), snap(5, {"a": 5})).to_dict()
    assert data["delta_bytes"] == 4
    assert data["baseline_at"] == BASE_TIME.isoformat()
    assert data["dir_changes"][0]["status"] == "grew"
