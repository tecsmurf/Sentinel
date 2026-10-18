from datetime import timedelta

from sentinel.config import RetentionSettings
from sentinel.models import (
    DirSnapshot,
    EvidenceRef,
    EvidenceType,
    FindingDraft,
    FindingSeverity,
    FindingStatus,
    RootSnapshot,
    ScanRun,
    ScanStatus,
)
from tests.support import BASE_TIME

NOW = BASE_TIME + timedelta(days=100)


def settings(**kw) -> RetentionSettings:
    defaults = {
        "observation_days": 30,
        "max_observations": 10_000,
        "scan_history_days": 30,
        "metric_days": 30,
        "closed_finding_days": 30,
    }
    return RetentionSettings(**{**defaults, **kw})


def evidence_finding(repo, observation_id, status=FindingStatus.OPEN, updated=BASE_TIME):
    draft = FindingDraft(
        rule_id="repeated_error",
        subject=f"fp:{observation_id}",
        title="t",
        severity=FindingSeverity.MEDIUM,
        explanation="e",
        recommendation="r",
        window_start=BASE_TIME,
        window_end=BASE_TIME,
        evidence=[EvidenceRef(EvidenceType.OBSERVATION, observation_id)],
    )
    return repo.insert_finding(draft, status, updated)


def ids(repo):
    return sorted(o.id for o in repo.query_observations(limit=100_000))


def test_old_observations_are_deleted_but_evidence_is_kept(repo, make_observation):
    with repo.transaction():
        repo.insert_observations(
            [make_observation(f"o{i}", at=BASE_TIME + timedelta(days=i * 20)) for i in range(5)]
        )
    first, second, *_ = ids(repo)
    with repo.transaction():
        evidence_finding(repo, second)
    result = repo.apply_retention(settings(), NOW)
    # Observations at day 0 and 20 are older than 30 days (NOW is day 100) -> day 0 deleted,
    # day 20 kept as evidence; day 40 and 60 also expire; day 80 is within the window.
    remaining = ids(repo)
    assert first not in remaining
    assert second in remaining
    assert result.observations == 3
    assert len(remaining) == 2


def test_row_cap_removes_oldest_unprotected_rows(repo, make_observation):
    with repo.transaction():
        repo.insert_observations(
            [make_observation(f"o{i}", at=NOW - timedelta(minutes=100 - i)) for i in range(20)]
        )
    oldest = ids(repo)[0]
    with repo.transaction():
        evidence_finding(repo, oldest)
    result = repo.apply_retention(settings(max_observations=10_000), NOW)
    assert result.observations == 0
    # Lower the cap below the row count (bypassing config validation for the test).
    capped = RetentionSettings.__new__(RetentionSettings)
    capped.__dict__.update(settings().__dict__)
    object.__setattr__(capped, "max_observations", 5)
    result = repo.apply_retention(capped, NOW)
    remaining = ids(repo)
    assert len(remaining) == 5
    assert oldest in remaining  # protected even though it is the oldest
    assert result.observations == 15


def test_metrics_expire(repo):
    with repo.transaction():
        repo.add_metric_samples(
            [("log_bytes_ingested", "a", NOW - timedelta(days=40), 1.0),
             ("log_bytes_ingested", "a", NOW - timedelta(days=1), 2.0)]
        )  # fmt: skip
    assert repo.apply_retention(settings(), NOW).metrics == 1
    assert [v for _, _, v in repo.metric_series("log_bytes_ingested", BASE_TIME)] == [2.0]


def _scan(repo, days_ago, *, root="c:\\temp", complete=True, scan_type="temp"):
    with repo.transaction():
        scan = ScanRun(scan_type=scan_type, started_at=NOW - timedelta(days=days_ago))
        repo.create_scan_run(scan)
        scan.status = ScanStatus.COMPLETED
        repo.complete_scan_run(scan)
        repo.save_root_snapshot(
            scan.id,
            RootSnapshot(
                root=root, root_key=root, complete=complete, dirs=[DirSnapshot("a", 1, 1)]
            ),
        )
    return scan.id


def test_old_scans_expire_but_baselines_are_kept(repo):
    # Every scan is older than the 30-day window.
    oldest = _scan(repo, 90)
    baseline = _scan(repo, 60)  # latest complete snapshot of c:\temp
    other_root = _scan(repo, 70, root="c:\\other")  # latest complete snapshot of c:\other
    latest = _scan(repo, 50, complete=False)  # most recent temp scan (highest id)
    result = repo.apply_retention(settings(), NOW)
    remaining = {s.id for s in repo.list_scan_runs()}
    assert remaining == {baseline, other_root, latest}
    assert oldest not in remaining
    assert result.scans == 1


def test_superseded_incomplete_scans_expire(repo):
    _scan(repo, 60)
    incomplete = _scan(repo, 50, complete=False)
    _scan(repo, 40)  # newer complete scan of the same root
    repo.apply_retention(settings(), NOW)
    assert incomplete not in {s.id for s in repo.list_scan_runs()}


def test_closed_findings_expire_and_cascade_their_evidence(repo, make_observation):
    with repo.transaction():
        repo.insert_observations([make_observation(at=BASE_TIME)])
    observation_id = ids(repo)[0]
    with repo.transaction():
        resolved = evidence_finding(repo, observation_id, FindingStatus.RESOLVED, BASE_TIME)
        open_old = evidence_finding(repo, observation_id, FindingStatus.OPEN, BASE_TIME)
    result = repo.apply_retention(settings(), NOW)
    assert result.findings == 1
    assert repo.get_finding(resolved) is None
    assert repo.get_finding(open_old) is not None  # open findings are never expired
    assert observation_id in ids(repo)  # still evidence of the open finding


def test_nothing_to_delete_is_a_cheap_no_op(repo):
    assert repo.apply_retention(settings(), NOW).total == 0
