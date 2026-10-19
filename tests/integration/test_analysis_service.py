from datetime import timedelta

import pytest

from sentinel.config import AppConfig, TempScanSettings
from sentinel.models import EvidenceType, FindingStatus, Severity, SourceType
from sentinel.services.analysis_service import AnalysisService
from sentinel.services.scan_service import ScanService
from sentinel.storage import Repository
from tests.support import BASE_TIME

NOW = BASE_TIME


def service(database, rules=None):
    config = AppConfig()
    config.rules = rules or {}
    return AnalysisService(database.path, config, clock=lambda: NOW)


def add_errors(repo, make_observation, count, *, start_minutes=10, message="Disk quota exceeded"):
    with repo.transaction():
        repo.insert_observations(
            [
                make_observation(message, at=NOW - timedelta(minutes=start_minutes - i * 0.5))
                for i in range(count)
            ]
        )


def findings(database, **filters):
    repo = Repository.open(database.path)
    try:
        return repo.list_findings(**filters)
    finally:
        repo.close()


class TestFindingLifecycle:
    def test_create_then_unchanged_then_merge(self, database, repo, make_observation):
        add_errors(repo, make_observation, 5)
        first = service(database).run()
        assert len(first.created) == 1
        assert [f.rule_id for f in first.new_open] == ["repeated_error"]
        (finding,) = findings(database)
        assert finding.status is FindingStatus.OPEN
        assert finding.evidence_count == 5

        second = service(database).run()
        assert second.created == [] and second.updated == []
        assert second.unchanged == 1

        add_errors(repo, make_observation, 3, start_minutes=2)
        third = service(database).run()
        assert third.updated == [finding.id]
        merged = findings(database)[0]
        assert merged.occurrences == 2
        assert merged.evidence_count == 8
        assert len(findings(database)) == 1

    def test_suppressed_subject_is_stored_but_not_alerted(self, database, repo, make_observation):
        add_errors(repo, make_observation, 5)
        result = service(database).run()
        (finding,) = findings(database)
        with repo.transaction():
            repo.add_suppression(finding.rule_id, finding.subject, "known issue", NOW)
            repo.set_finding_status(finding.id, FindingStatus.RESOLVED, NOW)
        add_errors(repo, make_observation, 5, start_minutes=4)
        again = service(database).run()
        assert again.created == [] and len(again.suppressed) == 1
        assert again.new_open == []
        statuses = sorted(f.status for f in findings(database))
        assert statuses == [FindingStatus.RESOLVED, FindingStatus.SUPPRESSED]
        assert result.created

    def test_acknowledged_finding_keeps_its_status_when_updated(
        self, database, repo, make_observation
    ):
        add_errors(repo, make_observation, 5)
        service(database).run()
        (finding,) = findings(database)
        with repo.transaction():
            repo.set_finding_status(finding.id, FindingStatus.ACKNOWLEDGED, NOW, "looking into it")
        add_errors(repo, make_observation, 2, start_minutes=1)
        assert service(database).run().updated == [finding.id]
        assert findings(database)[0].status is FindingStatus.ACKNOWLEDGED

    def test_invalid_rule_configuration_is_reported(self, database):
        result = service(database, rules={"repeated_error": {"threshold": "lots"}}).run()
        assert any("expected a number" in w for w in result.warnings)


def test_log_growth_from_metrics(database, repo):
    with repo.transaction():
        repo.add_metric_samples(
            [("log_bytes_ingested", "C:\\logs\\app.log", NOW - timedelta(minutes=m), 2 * 1024**2)
             for m in (5, 15, 25)]
        )  # fmt: skip
    result = service(database, rules={"log_growth": {"threshold_mb_per_hour": 1}}).run()
    (finding,) = findings(database, rule_ids=["log_growth"])
    assert finding.id in result.created
    evidence = repo.finding_evidence(finding.id)
    assert {e.evidence_type for e in evidence} == {EvidenceType.METRIC}


def test_temp_growth_from_real_scans(database, tmp_path):
    root = tmp_path / "Temp"
    root.mkdir()
    (root / "small.tmp").write_bytes(b"x" * 1024)
    scans = ScanService(
        database.path,
        TempScanSettings(
            include_user_temp=False, include_windows_temp=False, extra_roots=[str(root)]
        ),
        environ={},
    )
    scans.run_temp_scan()
    (root / "cache").mkdir()
    (root / "cache" / "big.bin").write_bytes(b"x" * 3 * 1024 * 1024)
    scans.run_temp_scan()

    analysis = AnalysisService(
        database.path,
        _config(rules={"temp_growth": {"min_growth_mb": 2}}),
    )
    analysis.run()
    (finding,) = findings(database, rule_ids=["temp_growth"])
    assert "cache (+3.0 MB)" in finding.explanation
    repo = Repository.open(database.path)
    try:
        kinds = {e.evidence_type for e in repo.finding_evidence(finding.id)}
    finally:
        repo.close()
    assert kinds == {EvidenceType.SCAN_RUN, EvidenceType.ROOT_SNAPSHOT}


def _config(rules):
    config = AppConfig()
    config.rules = rules
    return config


def test_event_burst_against_stored_baseline(database, repo, make_observation):
    baseline = [
        make_observation(
            "routine",
            severity=Severity.INFO,
            source_id="winevt:System",
            source_type=SourceType.WINDOWS_EVENT,
            at=NOW - timedelta(minutes=5 * bucket + 2),
        )
        for bucket in range(2, 40)
        for _ in range(3)
    ]
    burst = [
        make_observation(
            "storm",
            severity=Severity.INFO,
            source_id="winevt:System",
            source_type=SourceType.WINDOWS_EVENT,
            at=NOW - timedelta(seconds=30 + i),
        )
        for i in range(150)
    ]
    with repo.transaction():
        repo.insert_observations(baseline + burst)
    service(database).run()
    (finding,) = findings(database, rule_ids=["event_burst"])
    assert finding.details["count"] == 150
    assert finding.evidence_count == 50


@pytest.mark.parametrize("disabled", ["repeated_error"])
def test_disabled_rules_produce_nothing(database, repo, make_observation, disabled):
    add_errors(repo, make_observation, 10)
    service(database, rules={disabled: {"enabled": False}}).run()
    assert findings(database, rule_ids=[disabled]) == []
