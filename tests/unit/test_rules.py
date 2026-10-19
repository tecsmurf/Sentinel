"""Detection rules over synthetic inputs (pure functions; no database)."""

from datetime import timedelta

import pytest

from sentinel.analysis.normalize import fingerprint
from sentinel.analysis.rules import (
    RULES,
    AnalysisInput,
    TempComparison,
    fmt_bytes,
    lookback,
    resolve_rule_params,
    run_rules,
)
from sentinel.models import EvidenceType, FindingSeverity, Observation, Severity, SourceType
from tests.support import BASE_TIME

NOW = BASE_TIME
PARAMS, _ = resolve_rule_params({})


def obs(
    i,
    *,
    minutes_ago=1.0,
    severity=Severity.ERROR,
    provider="App",
    code="",
    source_id="textlog-app",
    source_type=SourceType.TEXT_LOG,
    message="Payment service timeout",
    entity=None,
    process_name=None,
    metadata=None,
):
    meta = dict(metadata or {})
    if entity:
        meta["entity"] = entity
    return Observation(
        id=i,
        source_id=source_id,
        source_type=source_type,
        event_timestamp=NOW - timedelta(minutes=minutes_ago),
        severity=severity,
        message=message,
        dedup_key=f"k{i}",
        fingerprint=fingerprint(provider, code, message=message),
        provider=provider,
        event_code=code,
        process_name=process_name,
        metadata=meta,
    )


def winevt(i, provider, code, entity, *, minutes_ago=1.0, severity=Severity.ERROR, **kw):
    return obs(
        i,
        minutes_ago=minutes_ago,
        severity=severity,
        provider=provider,
        code=code,
        source_id="winevt:Application",
        source_type=SourceType.WINDOWS_EVENT,
        entity=entity,
        message=f"{provider} event {code}",
        **kw,
    )


def run(rule_id, *, params=None, **inputs):
    resolved, warnings = resolve_rule_params({rule_id: params or {}})
    assert warnings == []
    only = {r.rule_id: {**resolved[r.rule_id], "enabled": r.rule_id == rule_id} for r in RULES}
    drafts, errors = run_rules(AnalysisInput(now=NOW, **inputs), only)
    assert errors == []
    return drafts


class TestRepeatedError:
    def test_fires_at_threshold_with_evidence_and_explanation(self):
        observations = [obs(i, minutes_ago=i) for i in range(1, 6)]
        (draft,) = run("repeated_error", observations=observations)
        assert draft.rule_id == "repeated_error"
        assert draft.subject.startswith("fingerprint:")
        assert draft.severity is FindingSeverity.MEDIUM
        assert [e.ref_id for e in draft.evidence] == [5, 4, 3, 2, 1]
        assert all(e.evidence_type is EvidenceType.OBSERVATION for e in draft.evidence)
        assert "reported 5 times by App" in draft.explanation
        assert "does not by itself identify the cause" in draft.explanation
        assert "source:textlog-app" in draft.entities

    def test_below_threshold_or_outside_window_does_not_fire(self):
        assert run("repeated_error", observations=[obs(i) for i in range(1, 5)]) == []
        old = [obs(i, minutes_ago=20 + i) for i in range(1, 10)]
        assert run("repeated_error", observations=old) == []

    def test_warnings_and_health_records_are_ignored(self):
        warnings = [obs(i, severity=Severity.WARNING) for i in range(1, 10)]
        health = [obs(i, source_type=SourceType.SENTINEL) for i in range(10, 20)]
        assert run("repeated_error", observations=warnings + health) == []

    def test_variable_parts_still_group_together(self):
        observations = [obs(i, message=f"Timeout after {i * 100} ms") for i in range(1, 6)]
        assert len(run("repeated_error", observations=observations)) == 1

    def test_severity_scales_with_volume(self):
        observations = [obs(i, minutes_ago=0.1) for i in range(1, 21)]
        (draft,) = run("repeated_error", observations=observations)
        assert draft.severity is FindingSeverity.HIGH

    def test_crashes_and_service_failures_are_left_to_specific_rules(self):
        crashes = [winevt(i, "Application Error", "1000", "app:x.exe") for i in range(1, 8)]
        assert run("repeated_error", observations=crashes) == []

    def test_known_event_meaning_is_included(self):
        observations = [
            obs(i, provider="Microsoft-Windows-DistributedCOM", code="10016") for i in range(1, 6)
        ]
        (draft,) = run("repeated_error", observations=observations)
        assert "commonly benign" in draft.explanation

    def test_custom_threshold(self):
        observations = [obs(i) for i in range(1, 3)]
        assert len(run("repeated_error", params={"threshold": 2}, observations=observations)) == 1


class TestCrashesAndServices:
    def test_repeated_crashes_of_one_application(self):
        observations = [
            winevt(1, "Application Error", "1000", "app:game.exe", process_name="Game.exe"),
            winevt(2, "Windows Error Reporting", "1001", "app:game.exe", minutes_ago=30),
            winevt(3, "Application Error", "1000", "app:other.exe"),
        ]
        (draft,) = run("app_crash", observations=observations)
        assert draft.subject == "app:game.exe"
        assert draft.severity is FindingSeverity.HIGH
        assert draft.title == "Game.exe crashed or stopped responding 2 times"
        assert "Application Error 1000" in draft.explanation

    def test_many_crashes_are_critical(self):
        observations = [
            winevt(i, "Application Error", "1000", "app:x.exe", minutes_ago=i) for i in range(1, 7)
        ]
        assert run("app_crash", observations=observations)[0].severity is FindingSeverity.CRITICAL

    def test_crash_events_without_an_application_are_ignored(self):
        observations = [
            winevt(i, "Windows Error Reporting", "1001", "wer:LiveKernelEvent:117")
            for i in range(5)
        ]
        assert run("app_crash", observations=observations) == []

    def test_repeated_service_failure(self):
        observations = [
            winevt(1, "Service Control Manager", "7023", "service:vgc", minutes_ago=600),
            winevt(2, "Service Control Manager", "7023", "service:vgc", minutes_ago=60),
            winevt(3, "Service Control Manager", "7036", "service:vgc"),  # state change: ignored
        ]
        (draft,) = run("service_failure", observations=observations)
        assert draft.subject == "service:vgc"
        assert draft.title == "Service 'vgc' failed 2 times"
        assert "stopped with an error" in draft.explanation
        assert draft.details["event_ids"] == ["7023"]

    def test_service_failures_outside_window_are_ignored(self):
        observations = [
            winevt(i, "Service Control Manager", "7031", "service:spooler", minutes_ago=60 * 30)
            for i in range(1, 4)
        ]
        assert run("service_failure", observations=observations) == []


class TestCriticalEvent:
    def test_critical_windows_event_is_reported_with_known_meaning(self):
        observation = winevt(
            1, "Microsoft-Windows-Kernel-Power", "41", None, severity=Severity.CRITICAL
        )
        (draft,) = run("critical_event", observations=[observation])
        assert draft.subject == "event:microsoft-windows-kernel-power:41"
        assert "without first shutting down cleanly" in draft.explanation

    def test_critical_text_logs_are_not_windows_events(self):
        assert run("critical_event", observations=[obs(1, severity=Severity.CRITICAL)]) == []


class TestLogGrowth:
    def samples(self, megabytes_per_sample, count=6):
        return [
            (
                i,
                "C:\\logs\\app.log",
                NOW - timedelta(minutes=10 * i),
                megabytes_per_sample * 1024 * 1024,
            )
            for i in range(count)
        ]

    def test_fast_growth_fires_with_metric_evidence(self):
        (draft,) = run("log_growth", metric_samples=self.samples(25))  # 150 MB in an hour
        assert draft.subject == "log:c:\\logs\\app.log"
        assert {e.evidence_type for e in draft.evidence} == {EvidenceType.METRIC}
        assert draft.details["rate_mb_per_hour"] == 150.0

    def test_normal_growth_does_not_fire(self):
        assert run("log_growth", metric_samples=self.samples(1)) == []


def comparison(delta_mb, before_mb=1000, hours_ago=1, **kw):
    return TempComparison(
        scan_id=7,
        root="C:\\Users\\me\\AppData\\Local\\Temp",
        root_key="c:\\users\\me\\appdata\\local\\temp",
        baseline_snapshot_id=1,
        current_snapshot_id=2,
        baseline_at=NOW - timedelta(days=1),
        current_at=NOW - timedelta(hours=hours_ago),
        bytes_before=before_mb * 1024 * 1024,
        bytes_after=(before_mb + delta_mb) * 1024 * 1024,
        dir_changes=({"rel_path": "BigApp", "delta_bytes": delta_mb * 1024 * 1024},),
        **kw,
    )


class TestTempGrowth:
    def test_absolute_growth(self):
        (draft,) = run("temp_growth", temp_comparisons=[comparison(600)])
        assert draft.title == "Temporary folder grew by 600.0 MB"
        assert "BigApp (+600.0 MB)" in draft.explanation
        kinds = [(e.evidence_type, e.ref_id) for e in draft.evidence]
        assert kinds == [
            (EvidenceType.SCAN_RUN, 7),
            (EvidenceType.ROOT_SNAPSHOT, 1),
            (EvidenceType.ROOT_SNAPSHOT, 2),
        ]

    def test_relative_growth_needs_a_minimum_size(self):
        assert len(run("temp_growth", temp_comparisons=[comparison(150, before_mb=200)])) == 1
        assert run("temp_growth", temp_comparisons=[comparison(50, before_mb=20)]) == []

    def test_small_or_stale_growth_is_ignored(self):
        assert run("temp_growth", temp_comparisons=[comparison(10)]) == []
        assert run("temp_growth", temp_comparisons=[comparison(900, hours_ago=48)]) == []

    def test_caveats_are_carried_into_the_explanation(self):
        (draft,) = run(
            "temp_growth", temp_comparisons=[comparison(700, caveats=("Access changed.",))]
        )
        assert "Caveats: Access changed." in draft.explanation

    def test_from_summary_round_trip_and_malformed_input(self):
        data = {
            "root": "C:\\Temp", "root_key": "c:\\temp", "baseline_snapshot_id": 1,
            "current_snapshot_id": 2, "baseline_at": "2026-10-14T12:00:00+00:00",
            "current_at": "2026-10-15T12:00:00+00:00", "bytes_before": 1, "bytes_after": 5,
        }  # fmt: skip
        parsed = TempComparison.from_summary(3, data)
        assert parsed.delta_bytes == 4
        assert TempComparison.from_summary(3, {"root": "x"}) is None


class TestEventBurst:
    def volume(self, baseline_count=10, recent_count=400, buckets=48):
        start = NOW - timedelta(minutes=5 * buckets)
        series = [(start + timedelta(minutes=5 * i), baseline_count) for i in range(buckets - 1)]
        series.append((NOW - timedelta(minutes=1), recent_count))
        return {"winevt:System": series}

    def test_burst_far_above_baseline(self):
        calls = []

        def samples(source_id, start, end, limit):
            calls.append((source_id, start, end))
            return [101, 102]

        (draft,) = run("event_burst", volume_by_source=self.volume(), sample_ids=samples)
        assert draft.subject.startswith("burst:winevt:System:")
        assert [e.ref_id for e in draft.evidence] == [101, 102]
        assert calls[0][0] == "winevt:System"
        assert draft.details["count"] == 400
        assert "standard deviations above normal" in draft.explanation

    def test_normal_volume_does_not_fire(self):
        assert run("event_burst", volume_by_source=self.volume(recent_count=12)) == []

    def test_below_minimum_events_does_not_fire(self):
        assert (
            run("event_burst", volume_by_source=self.volume(baseline_count=0, recent_count=50))
            == []
        )

    def test_insufficient_history_does_not_fire(self):
        assert run("event_burst", volume_by_source=self.volume(buckets=5)) == []


class TestErrorCluster:
    def test_errors_from_several_components_close_together(self):
        observations = [
            obs(1, provider="Disk", source_id="winevt:System", minutes_ago=3.0),
            obs(2, provider="Ntfs", source_id="winevt:System", minutes_ago=2.5),
            obs(3, provider="App", source_id="textlog-app", minutes_ago=2.0),
            obs(4, provider="App", source_id="textlog-app", minutes_ago=1.9),
        ]
        (draft,) = run("error_cluster", observations=observations)
        assert draft.details["components"] == ["App", "Disk", "Ntfs"]
        assert "does not prove they are related" in draft.explanation
        assert len(draft.evidence) == 4

    def test_one_component_alone_is_not_a_cluster(self):
        observations = [obs(i, minutes_ago=1 + i / 10) for i in range(10)]
        assert run("error_cluster", observations=observations) == []

    def test_spread_out_errors_are_not_a_cluster(self):
        observations = [
            obs(1, provider="A", minutes_ago=50),
            obs(2, provider="B", minutes_ago=30),
            obs(3, provider="C", minutes_ago=10),
        ]
        assert run("error_cluster", observations=observations) == []


class TestCollectorHealth:
    def health(self, i, kind, source="winevt:Application", severity=Severity.WARNING):
        return obs(
            i,
            source_type=SourceType.SENTINEL,
            source_id="sentinel:monitoring",
            provider="Sentinel Local",
            code=kind,
            severity=severity,
            metadata={"source": source},
            message=f"{kind} happened",
        )

    def test_repeated_problems_for_one_source(self):
        items = [self.health(i, "decode_errors", source="app") for i in range(3)]
        (draft,) = run("collector_health", observations=items)
        assert draft.subject == "collector:app"
        assert draft.severity is FindingSeverity.LOW
        assert "3 x decode_errors" in draft.explanation

    def test_possible_data_loss_is_reported_immediately(self):
        (draft,) = run("collector_health", observations=[self.health(1, "log_gap")])
        assert draft.severity is FindingSeverity.MEDIUM

    def test_informational_notes_are_ignored(self):
        items = [self.health(i, "rotated", severity=Severity.INFO) for i in range(5)]
        assert run("collector_health", observations=items) == []


class TestParameters:
    def test_defaults_cover_every_rule(self):
        assert set(PARAMS) == {spec.rule_id for spec in RULES}
        assert all(p["enabled"] for p in PARAMS.values())

    def test_overrides_are_validated_and_clamped(self):
        params, warnings = resolve_rule_params(
            {
                "repeated_error": {"threshold": 1, "window_minutes": 30.0, "enabled": False},
                "app_crash": {"threshold": "two", "bogus": 1},
                "made_up_rule": {},
                "service_failure": "nope",
            }
        )
        assert params["repeated_error"] == {"enabled": False, "window_minutes": 30, "threshold": 2}
        assert params["app_crash"]["threshold"] == 2
        assert any("clamped" in w for w in warnings)
        assert any("expected a number" in w for w in warnings)
        assert any("unknown parameter" in w for w in warnings)
        assert any("made_up_rule" in w for w in warnings)
        assert any("expected an object" in w for w in warnings)

    def test_disabled_rule_does_not_run(self):
        observations = [obs(i) for i in range(1, 10)]
        params, _ = resolve_rule_params({"repeated_error": {"enabled": False}})
        drafts, _ = run_rules(AnalysisInput(now=NOW, observations=observations), params)
        assert all(d.rule_id != "repeated_error" for d in drafts)

    def test_failing_rule_is_isolated(self, monkeypatch):
        from sentinel.analysis import rules as rules_module

        def boom(inp, params):
            raise RuntimeError("bug")

        spec = rules_module.RULES_BY_ID["log_growth"]
        broken = rules_module.RuleSpec(
            spec.rule_id,
            spec.title,
            spec.description,
            spec.params,
            boom,
            spec.window_param,
            spec.window_unit,
        )
        monkeypatch.setattr(
            rules_module, "RULES", (broken, *[r for r in RULES if r.rule_id != "log_growth"])
        )
        drafts, errors = run_rules(
            AnalysisInput(now=NOW, observations=[obs(i) for i in range(1, 6)]), PARAMS
        )
        assert errors == ["log_growth: RuntimeError"]
        assert any(d.rule_id == "repeated_error" for d in drafts)

    def test_lookback_covers_the_longest_window(self):
        params, _ = resolve_rule_params({"app_crash": {"window_hours": 72}})
        assert lookback(params) == timedelta(hours=72)

    def test_dedup_windows(self):
        from sentinel.analysis.rules import RULES_BY_ID

        assert RULES_BY_ID["repeated_error"].dedup_window(PARAMS["repeated_error"]) == timedelta(
            minutes=15
        )
        assert RULES_BY_ID["app_crash"].dedup_window(PARAMS["app_crash"]) == timedelta(hours=24)


@pytest.mark.parametrize(
    ("count", "text"),
    [(0, "0 B"), (1023, "1023 B"), (1536, "1.5 KB"), (5 * 1024**3, "5.0 GB"), (-2048, "-2.0 KB")],
)
def test_fmt_bytes(count, text):
    assert fmt_bytes(count) == text
