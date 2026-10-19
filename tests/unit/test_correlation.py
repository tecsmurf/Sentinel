from datetime import timedelta

from sentinel.analysis.correlation import (
    correlate,
    hypotheses_for_group,
    incident_summary,
    incident_title,
)
from sentinel.models import Finding, FindingSeverity, FindingStatus
from tests.support import BASE_TIME

_ids = iter(range(1, 10_000))


def finding(
    rule_id,
    subject,
    *,
    entities=(),
    start_minutes=0,
    length_minutes=5,
    severity=FindingSeverity.MEDIUM,
    details=None,
):
    start = BASE_TIME + timedelta(minutes=start_minutes)
    return Finding(
        id=next(_ids),
        rule_id=rule_id,
        subject=subject,
        title=f"{rule_id} for {subject}",
        severity=severity,
        status=FindingStatus.OPEN,
        explanation="",
        recommendation="",
        detected_at=start,
        updated_at=start,
        window_start=start,
        window_end=start + timedelta(minutes=length_minutes),
        entities=list(entities),
        details=details or {},
    )


class TestLinking:
    def test_shared_specific_entity_links_findings(self):
        crash = finding("app_crash", "app:game.exe", entities=["app:game.exe"])
        error = finding(
            "repeated_error", "fingerprint:1", entities=["app:game.exe", "fingerprint:1"],
            start_minutes=120,
        )  # fmt: skip
        (group,) = correlate([crash, error])
        assert {f.id for f in group.findings} == {crash.id, error.id}
        assert group.reasons == ["Both involve application game.exe"]

    def test_shared_entity_far_apart_is_not_linked(self):
        a = finding("app_crash", "app:x", entities=["app:x"])
        b = finding("repeated_error", "fingerprint:2", entities=["app:x"], start_minutes=60 * 48)
        assert correlate([a, b]) == []

    def test_generic_entities_do_not_link(self):
        a = finding("temp_growth", "root:a", entities=["source:winevt:Application"])
        b = finding("log_growth", "log:b", entities=["source:winevt:Application"])
        assert correlate([a, b]) == []

    def test_failure_findings_close_in_time_are_linked_with_a_timing_caveat(self):
        a = finding("service_failure", "service:spooler", entities=["service:spooler"])
        b = finding("repeated_error", "fingerprint:3", entities=["fingerprint:3"], start_minutes=8)
        (group,) = correlate([a, b])
        assert "timing only" in group.reasons[0]
        assert "does not show that they are related" in group.reasons[0]

    def test_timing_alone_does_not_link_non_failure_rules(self):
        a = finding("temp_growth", "root:a", entities=["path:c:\\temp"])
        b = finding("repeated_error", "fingerprint:4", entities=["fingerprint:4"])
        assert correlate([a, b]) == []

    def test_links_are_transitive_and_reasons_accumulate(self):
        a = finding("app_crash", "app:x", entities=["app:x"])
        b = finding(
            "repeated_error", "fingerprint:5", entities=["app:x", "service:svc"], start_minutes=30
        )
        c = finding("service_failure", "service:svc", entities=["service:svc"], start_minutes=200)
        (group,) = correlate([a, b, c])
        assert len(group.findings) == 3
        assert set(group.reasons) == {
            "Both involve application x",
            "Both involve service 'svc'",
        }

    def test_single_high_severity_finding_is_its_own_incident(self):
        lone = finding("critical_event", "event:x:1", severity=FindingSeverity.HIGH)
        low = finding(
            "collector_health", "collector:y", severity=FindingSeverity.LOW, start_minutes=500
        )
        (group,) = correlate([lone, low])
        assert group.findings == [lone]
        assert group.reasons == ["A single finding of high severity"]


class TestIncidentText:
    def test_title_names_the_common_entity(self):
        a = finding("service_failure", "service:vgc", entities=["service:vgc"])
        b = finding("repeated_error", "fingerprint:6", entities=["service:vgc", "fingerprint:6"])
        (group,) = correlate([a, b])
        assert incident_title(group) == "Problems involving service 'vgc'"
        assert incident_summary(group).startswith("2 finding(s) between")

    def test_title_for_timing_only_groups_lists_rule_types(self):
        a = finding("service_failure", "service:a", entities=["service:a"])
        b = finding("app_crash", "app:b", entities=["app:b"], start_minutes=3)
        (group,) = correlate([a, b])
        assert incident_title(group) == "2 related findings: application crashes, service failures"

    def test_single_finding_title(self):
        lone = finding("critical_event", "event:x:1", severity=FindingSeverity.HIGH)
        (group,) = correlate([lone])
        assert incident_title(group) == lone.title


class TestHypotheses:
    def _group(self, *findings):
        (group,) = correlate(list(findings))
        return group

    def test_crash_with_matching_repeated_error(self):
        crash = finding("app_crash", "app:game.exe", entities=["app:game.exe"])
        error = finding(
            "repeated_error", "fingerprint:7", entities=["app:game.exe"],
            details={"message": "GPU device removed"},
        )  # fmt: skip
        (hyp,) = hypotheses_for_group(self._group(crash, error), incident_id=9)
        assert hyp.template_id == "crash_with_errors:app:game.exe"
        assert "GPU device removed" in hyp.statement
        assert hyp.confidence == "low"
        assert "does not establish" in hyp.rationale
        assert hyp.basis == [f"finding:{crash.id}", f"finding:{error.id}"]

    def test_service_failure_alongside_other_failures(self):
        service = finding("service_failure", "service:db", entities=["service:db"])
        error = finding("repeated_error", "fingerprint:8", entities=["service:db"])
        templates = [h.template_id for h in hypotheses_for_group(self._group(service, error), 1)]
        assert templates == ["service_affects_others:service:db"]

    def test_log_inside_growing_temp_folder(self):
        log = finding(
            "log_growth", "log:c:\\temp\\app\\debug.log", entities=["path:c:\\temp"],
            details={"path": "C:\\Temp\\app\\debug.log"},
        )  # fmt: skip
        temp = finding(
            "temp_growth", "root:c:\\temp", entities=["path:c:\\temp"],
            details={"root": "C:\\Temp"},
        )  # fmt: skip
        (hyp,) = hypotheses_for_group(self._group(log, temp), 1)
        assert hyp.confidence == "medium"
        assert "C:\\Temp\\app\\debug.log" in hyp.statement

    def test_system_wide_disturbance_needs_several_findings(self):
        cluster = finding("error_cluster", "cluster:1", entities=["fingerprint:a"])
        a = finding("app_crash", "app:a", entities=["app:a"], start_minutes=2)
        b = finding("service_failure", "service:b", entities=["service:b"], start_minutes=3)
        templates = {h.template_id for h in hypotheses_for_group(self._group(cluster, a, b), 1)}
        assert "system_wide_disturbance" in templates

    def test_unexpected_restart(self):
        restart = finding(
            "critical_event",
            "event:microsoft-windows-kernel-power:41",
            severity=FindingSeverity.HIGH,
        )
        crash = finding("app_crash", "app:a", entities=["app:a"], start_minutes=2)
        templates = {h.template_id for h in hypotheses_for_group(self._group(restart, crash), 1)}
        assert "unexpected_restart:event:microsoft-windows-kernel-power:41" in templates

    def test_monitoring_gap(self):
        health = finding("collector_health", "collector:x", entities=["service:x"])
        failure = finding("service_failure", "service:x", entities=["service:x"])
        templates = {h.template_id for h in hypotheses_for_group(self._group(health, failure), 1)}
        assert "monitoring_gap" in templates

    def test_no_hypothesis_is_ever_high_confidence(self):
        groups = [
            self._group(
                finding("app_crash", "app:z", entities=["app:z"]),
                finding("repeated_error", "fingerprint:z", entities=["app:z"]),
                finding("error_cluster", "cluster:z", entities=["app:z"]),
                finding("collector_health", "collector:z", entities=["app:z"]),
            )
        ]
        for group in groups:
            for hypothesis in hypotheses_for_group(group, 1):
                assert hypothesis.confidence in {"low", "medium"}
                assert hypothesis.basis
