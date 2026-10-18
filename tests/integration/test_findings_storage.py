from datetime import timedelta

from sentinel.models import (
    EvidenceRef,
    EvidenceType,
    FindingDraft,
    FindingSeverity,
    FindingStatus,
    Hypothesis,
    Incident,
    IncidentStatus,
)
from tests.support import BASE_TIME


def draft(subject="service:vgc", severity=FindingSeverity.MEDIUM, refs=(1, 2), minutes=0, **kw):
    start = BASE_TIME + timedelta(minutes=minutes)
    return FindingDraft(
        rule_id=kw.pop("rule_id", "service_failure"),
        subject=subject,
        title=f"Repeated failures of {subject}",
        severity=severity,
        explanation="explained",
        recommendation="do something safe",
        window_start=start,
        window_end=start + timedelta(minutes=5),
        evidence=[EvidenceRef(EvidenceType.OBSERVATION, r) for r in refs],
        entities=kw.pop("entities", [subject]),
        details=kw.pop("details", {"count": len(refs)}),
    )


class TestFindings:
    def test_insert_and_read_back(self, repo):
        with repo.transaction():
            finding_id = repo.insert_finding(draft(), FindingStatus.OPEN, BASE_TIME)
        finding = repo.get_finding(finding_id)
        assert finding.rule_id == "service_failure"
        assert finding.subject == "service:vgc"
        assert finding.status is FindingStatus.OPEN
        assert finding.evidence_count == 2
        assert finding.entities == ["service:vgc"]
        assert finding.details == {"count": 2}
        assert finding.detected_at == BASE_TIME
        assert [e.ref_id for e in repo.finding_evidence(finding_id)] == [1, 2]

    def test_merge_widens_window_keeps_max_severity_and_dedupes_evidence(self, repo):
        with repo.transaction():
            finding_id = repo.insert_finding(
                draft(severity=FindingSeverity.HIGH), FindingStatus.OPEN, BASE_TIME
            )
            later = draft(severity=FindingSeverity.LOW, refs=(2, 3), minutes=30, entities=["app:x"])
            repo.merge_finding(finding_id, later, BASE_TIME + timedelta(minutes=35))
        merged = repo.get_finding(finding_id)
        assert merged.severity is FindingSeverity.HIGH
        assert merged.occurrences == 2
        assert merged.window_start == BASE_TIME
        assert merged.window_end == BASE_TIME + timedelta(minutes=35)
        assert merged.evidence_count == 3
        assert merged.entities == ["app:x", "service:vgc"]

    def test_find_active_finding_ignores_resolved_and_old(self, repo):
        with repo.transaction():
            old_id = repo.insert_finding(draft(), FindingStatus.OPEN, BASE_TIME)
        assert repo.find_active_finding("service_failure", "service:vgc", BASE_TIME).id == old_id
        assert (
            repo.find_active_finding(
                "service_failure", "service:vgc", BASE_TIME + timedelta(hours=1)
            )
            is None
        )
        assert repo.find_active_finding("service_failure", "service:other", BASE_TIME) is None
        with repo.transaction():
            repo.set_finding_status(old_id, FindingStatus.RESOLVED, BASE_TIME, "fixed driver")
        assert repo.find_active_finding("service_failure", "service:vgc", BASE_TIME) is None
        assert repo.get_finding(old_id).status_note == "fixed driver"

    def test_list_filters_and_counts(self, repo):
        with repo.transaction():
            a = repo.insert_finding(
                draft(severity=FindingSeverity.CRITICAL), FindingStatus.OPEN, BASE_TIME
            )
            b = repo.insert_finding(
                draft(subject="app:x", rule_id="app_crash"), FindingStatus.OPEN, BASE_TIME
            )
            c = repo.insert_finding(draft(subject="app:y"), FindingStatus.SUPPRESSED, BASE_TIME)
        assert {f.id for f in repo.list_findings()} == {a, b, c}
        assert [f.id for f in repo.list_findings(statuses=[FindingStatus.SUPPRESSED])] == [c]
        assert [f.id for f in repo.list_findings(min_severity=FindingSeverity.HIGH)] == [a]
        assert [f.id for f in repo.list_findings(rule_ids=["app_crash"])] == [b]
        assert repo.list_findings(since=BASE_TIME + timedelta(days=1)) == []
        counts = repo.open_finding_counts()
        assert counts[FindingSeverity.CRITICAL] == 1
        assert counts[FindingSeverity.MEDIUM] == 1


class TestSuppressions:
    def test_add_check_list_remove(self, repo):
        with repo.transaction():
            repo.add_suppression(
                "service_failure", "service:vgc", "known anti-cheat noise", BASE_TIME
            )
            repo.add_suppression("service_failure", "service:vgc", "updated reason", BASE_TIME)
        assert repo.is_suppressed("service_failure", "service:vgc")
        assert not repo.is_suppressed("service_failure", "service:other")
        (entry,) = repo.list_suppressions()
        assert entry["reason"] == "updated reason"
        with repo.transaction():
            repo.remove_suppression("service_failure", "service:vgc")
        assert repo.list_suppressions() == []


def incident(**kw) -> Incident:
    return Incident(
        id=0,
        title=kw.get("title", "Service vgc keeps failing"),
        severity=kw.get("severity", FindingSeverity.HIGH),
        status=kw.get("status", IncidentStatus.OPEN),
        created_at=BASE_TIME,
        updated_at=BASE_TIME,
        window_start=BASE_TIME,
        window_end=BASE_TIME + timedelta(minutes=10),
        summary="two findings",
        reasons=["both involve service vgc"],
    )


class TestIncidentsAndHypotheses:
    def test_incident_lifecycle(self, repo):
        with repo.transaction():
            f1 = repo.insert_finding(draft(), FindingStatus.OPEN, BASE_TIME)
            f2 = repo.insert_finding(
                draft(subject="app:x", minutes=2), FindingStatus.OPEN, BASE_TIME
            )
            created = incident()
            incident_id = repo.create_incident(created)
            repo.assign_findings([f1, f2], incident_id)
        stored = repo.get_incident(incident_id)
        assert stored.finding_ids == [f1, f2]
        assert stored.reasons == ["both involve service vgc"]
        assert [f.id for f in repo.list_findings(incident_id=incident_id)] == [f2, f1]
        assert repo.list_findings(unassigned=True) == []

        stored.title = "updated"
        stored.severity = FindingSeverity.CRITICAL
        with repo.transaction():
            repo.update_incident(stored)
            repo.set_incident_status(incident_id, IncidentStatus.ACKNOWLEDGED, BASE_TIME)
        again = repo.get_incident(incident_id)
        assert (again.title, again.severity, again.status) == (
            "updated",
            FindingSeverity.CRITICAL,
            IncidentStatus.ACKNOWLEDGED,
        )
        assert [i.id for i in repo.list_incidents(statuses=[IncidentStatus.ACKNOWLEDGED])] == [
            incident_id
        ]

    def test_empty_incidents_are_deleted(self, repo):
        with repo.transaction():
            finding_id = repo.insert_finding(draft(), FindingStatus.OPEN, BASE_TIME)
            keep = repo.create_incident(incident())
            drop = repo.create_incident(incident(title="empty"))
            repo.assign_findings([finding_id], keep)
            assert repo.delete_empty_incidents() == 1
        assert repo.get_incident(drop) is None
        assert repo.get_incident(keep) is not None

    def test_hypotheses_upsert_and_prune(self, repo):
        with repo.transaction():
            incident_id = repo.create_incident(incident())
            for template, confidence in (
                ("crash_after_error", "low"),
                ("service_dependency", "low"),
            ):
                repo.upsert_hypothesis(
                    Hypothesis(
                        incident_id=incident_id,
                        template_id=template,
                        statement=f"{template} statement",
                        rationale="co-occurrence only",
                        confidence=confidence,
                        basis=["finding:1"],
                    )
                )
            repo.upsert_hypothesis(
                Hypothesis(
                    incident_id=incident_id,
                    template_id="crash_after_error",
                    statement="revised",
                    rationale="more evidence",
                    confidence="medium",
                )
            )
        hypotheses = {h.template_id: h for h in repo.hypotheses_for(incident_id)}
        assert hypotheses["crash_after_error"].statement == "revised"
        assert hypotheses["crash_after_error"].confidence == "medium"
        with repo.transaction():
            repo.prune_hypotheses(incident_id, ["service_dependency"])
        assert [h.template_id for h in repo.hypotheses_for(incident_id)] == ["service_dependency"]
        with repo.transaction():
            repo.prune_hypotheses(incident_id, [])
        assert repo.hypotheses_for(incident_id) == []
