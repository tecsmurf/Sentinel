"""End-to-end: observations -> findings -> incidents -> hypotheses."""

from datetime import timedelta

from sentinel.config import AppConfig
from sentinel.models import FindingStatus, IncidentStatus, Severity, SourceType
from sentinel.services.analysis_service import AnalysisService
from sentinel.storage import Repository
from tests.support import BASE_TIME

NOW = BASE_TIME


def analysis(database):
    return AnalysisService(database.path, AppConfig(), clock=lambda: NOW)


def crash(make_observation, minutes_ago):
    return make_observation(
        "Faulting application name: Game.exe",
        severity=Severity.ERROR,
        source_id="winevt:Application",
        source_type=SourceType.WINDOWS_EVENT,
        provider="Application Error",
        event_code="1000",
        at=NOW - timedelta(minutes=minutes_ago),
        process_name="Game.exe",
        metadata={"entity": "app:game.exe"},
    )


def game_error(make_observation, minutes_ago):
    return make_observation(
        "GPU device removed (reason 0x887a0006)",
        source_id="textlog-game",
        at=NOW - timedelta(minutes=minutes_ago),
        metadata={"entity": "app:game.exe"},
    )


def seed(repo, make_observation):
    with repo.transaction():
        repo.insert_observations(
            [crash(make_observation, m) for m in (50, 9)]
            + [game_error(make_observation, m) for m in (10, 9.5, 9, 8.5, 8)]
        )


def test_related_findings_become_one_incident_with_a_hypothesis(database, repo, make_observation):
    seed(repo, make_observation)
    result = analysis(database).run()
    assert len(result.created) == 2
    (incident_id,) = result.incidents_created
    incident = repo.get_incident(incident_id)
    assert incident.title == "Problems involving application game.exe"
    assert incident.reasons == ["Both involve application game.exe"]
    assert len(incident.finding_ids) == 2
    (hypothesis,) = repo.hypotheses_for(incident_id)
    assert hypothesis.template_id == "crash_with_errors:app:game.exe"
    assert hypothesis.confidence == "low"
    assert [i.id for i in result.new_incidents] == [incident_id]


def test_rerunning_does_not_duplicate_incidents(database, repo, make_observation):
    seed(repo, make_observation)
    analysis(database).run()
    again = analysis(database).run()
    assert again.incidents_created == []
    assert again.incidents_updated == []
    assert len(repo.list_incidents()) == 1
    assert len(repo.hypotheses_for(repo.list_incidents()[0].id)) == 1


def test_new_related_finding_updates_and_reopens_the_incident(database, repo, make_observation):
    seed(repo, make_observation)
    (incident_id,) = analysis(database).run().incidents_created
    with repo.transaction():
        repo.set_incident_status(incident_id, IncidentStatus.RESOLVED, NOW)
        repo.insert_observations(
            [
                make_observation(
                    "Service GameSvc terminated unexpectedly",
                    source_id="winevt:System",
                    source_type=SourceType.WINDOWS_EVENT,
                    provider="Service Control Manager",
                    event_code="7034",
                    at=NOW - timedelta(minutes=m),
                    metadata={"entity": "service:gamesvc"},
                )
                for m in (7, 6)
            ]
        )
    result = analysis(database).run()
    assert incident_id in result.incidents_updated
    incident = repo.get_incident(incident_id)
    assert len(incident.finding_ids) == 3
    assert incident.status is IncidentStatus.OPEN
    assert any("timing only" in r for r in incident.reasons)


def test_resolved_findings_leave_incident_grouping(database, repo, make_observation):
    seed(repo, make_observation)
    analysis(database).run()
    with repo.transaction():
        for finding in repo.list_findings():
            repo.set_finding_status(finding.id, FindingStatus.RESOLVED, NOW)
    result = AnalysisService(database.path, AppConfig(), clock=lambda: NOW).run()
    assert result.incidents_created == []


def test_incident_survives_reopen_of_repository(database, make_observation):
    repo = Repository.open(database.path)
    try:
        seed(repo, make_observation)
    finally:
        repo.close()
    analysis(database).run()
    reopened = Repository.open(database.path)
    try:
        (incident,) = reopened.list_incidents()
        assert reopened.hypotheses_for(incident.id)
    finally:
        reopened.close()
