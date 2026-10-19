"""Correlation of findings into incidents, and labelled hypotheses (DECISIONS.md D-010).

Two findings are linked when:

* they share a *specific* entity — the same application, service, path, or error
  fingerprint — and their time windows are within ``entity_gap`` of each other; or
* both come from failure-type rules and their windows are within ``time_gap`` of each
  other (a weaker, purely temporal link that the incident reason states as such).

Generic keys (an event channel, a provider name) are deliberately not used for linking:
they would merge unrelated events. Linked findings form an incident; a single finding of
high or critical severity also becomes an incident of its own.

Hypotheses are produced from a small set of templates. They are never presented as
conclusions: confidence is at most "medium", and every rationale states the evidence and
that co-occurrence does not establish causation.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sentinel.models import Finding, FindingSeverity, Hypothesis

SPECIFIC_PREFIXES = ("app:", "service:", "path:", "fingerprint:")
TEMPORAL_RULES = frozenset(
    {
        "repeated_error",
        "app_crash",
        "service_failure",
        "critical_event",
        "error_cluster",
        "event_burst",
    }
)
RULE_LABELS = {
    "repeated_error": "repeated error",
    "app_crash": "application crashes",
    "service_failure": "service failures",
    "critical_event": "critical event",
    "log_growth": "rapid log growth",
    "temp_growth": "temporary folder growth",
    "event_burst": "event burst",
    "error_cluster": "simultaneous errors",
    "collector_health": "monitoring problem",
}
_UNEXPECTED_RESTART = frozenset({"event:microsoft-windows-kernel-power:41", "event:eventlog:6008"})


@dataclass(frozen=True, slots=True)
class CorrelationSettings:
    entity_gap: timedelta = timedelta(hours=6)
    time_gap: timedelta = timedelta(minutes=10)
    lookback: timedelta = timedelta(days=7)
    max_findings: int = 500


@dataclass(slots=True)
class FindingGroup:
    findings: list[Finding]
    reasons: list[str] = field(default_factory=list)

    @property
    def severity(self) -> FindingSeverity:
        return max(f.severity for f in self.findings)

    @property
    def window_start(self) -> datetime:
        return min(f.window_start for f in self.findings)

    @property
    def window_end(self) -> datetime:
        return max(f.window_end for f in self.findings)

    @property
    def rule_ids(self) -> set[str]:
        return {f.rule_id for f in self.findings}


def describe_entity(entity: str) -> str:
    kind, _, value = entity.partition(":")
    return {
        "app": f"application {value}",
        "service": f"service '{value}'",
        "path": f"path {value}",
        "fingerprint": "the same error message",
    }.get(kind, entity)


def specific_entities(finding: Finding) -> set[str]:
    return {e for e in finding.entities if e.startswith(SPECIFIC_PREFIXES)}


def _gap(a: Finding, b: Finding) -> timedelta:
    """Time between two findings' windows (zero if they overlap)."""
    later_start = max(a.window_start, b.window_start)
    earlier_end = min(a.window_end, b.window_end)
    return max(later_start - earlier_end, timedelta(0))


def _minutes(delta: timedelta) -> str:
    minutes = max(int(delta.total_seconds() // 60), 0)
    return "the same time window" if minutes == 0 else f"{minutes} minute(s) of each other"


def correlate(
    findings: Sequence[Finding], settings: CorrelationSettings | None = None
) -> list[FindingGroup]:
    """Group findings into incident candidates. Order: oldest group first."""
    settings = settings or CorrelationSettings()
    items = sorted(findings, key=lambda f: (f.window_start, f.id))[-settings.max_findings :]
    parent = list(range(len(items)))
    reasons: dict[int, list[str]] = {}

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(i: int, j: int, reason: str) -> None:
        root_i, root_j = find(i), find(j)
        combined = reasons.pop(root_i, [])
        if root_j != root_i:
            parent[root_j] = root_i
            combined += [r for r in reasons.pop(root_j, []) if r not in combined]
        if reason not in combined:
            combined.append(reason)
        reasons[root_i] = combined

    entities = [specific_entities(f) for f in items]
    for i in range(len(items)):
        for j in range(i + 1, len(items)):
            a, b = items[i], items[j]
            gap = _gap(a, b)
            shared = entities[i] & entities[j]
            if shared and gap <= settings.entity_gap:
                names = sorted(describe_entity(e) for e in shared)
                union(i, j, "Both involve " + " and ".join(names[:2]))
            elif (
                a.rule_id in TEMPORAL_RULES
                and b.rule_id in TEMPORAL_RULES
                and gap <= settings.time_gap
            ):
                union(
                    i,
                    j,
                    f"Occurred within {_minutes(gap)} (timing only; this does not show "
                    "that they are related)",
                )

    members: dict[int, list[Finding]] = {}
    for index, finding in enumerate(items):
        members.setdefault(find(index), []).append(finding)

    groups = []
    for root, group_findings in members.items():
        if len(group_findings) >= 2:
            groups.append(FindingGroup(group_findings, reasons.get(root, [])))
        elif group_findings[0].severity >= FindingSeverity.HIGH:
            groups.append(FindingGroup(group_findings, ["A single finding of high severity"]))
    groups.sort(key=lambda g: (g.window_start, min(f.id for f in g.findings)))
    return groups


def _fmt(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")


def incident_title(group: FindingGroup) -> str:
    if len(group.findings) == 1:
        return group.findings[0].title
    counts = Counter(e for f in group.findings for e in specific_entities(f))
    common = [e for e, n in counts.most_common() if n == len(group.findings)]
    if common and not common[0].startswith("fingerprint:"):
        return f"Problems involving {describe_entity(common[0])}"
    labels = sorted({RULE_LABELS.get(f.rule_id, f.rule_id) for f in group.findings})
    return f"{len(group.findings)} related findings: {', '.join(labels[:3])}"


def incident_summary(group: FindingGroup) -> str:
    labels = Counter(RULE_LABELS.get(f.rule_id, f.rule_id) for f in group.findings)
    parts = ", ".join(f"{label} ({n})" if n > 1 else label for label, n in labels.items())
    return (
        f"{len(group.findings)} finding(s) between {_fmt(group.window_start)} and "
        f"{_fmt(group.window_end)}: {parts}."
    )


# --------------------------------------------------------------------------------------
# Hypotheses
# --------------------------------------------------------------------------------------

_CAUSATION_NOTE = "Co-occurrence alone does not establish that one caused the other."


def _basis(findings: Iterable[Finding]) -> list[str]:
    return [f"finding:{f.id}" for f in findings]


def _by_rule(group: FindingGroup, rule_id: str) -> list[Finding]:
    return [f for f in group.findings if f.rule_id == rule_id]


def hypotheses_for_group(group: FindingGroup, incident_id: int) -> list[Hypothesis]:
    found: list[Hypothesis] = []
    crashes = _by_rule(group, "app_crash")
    errors = _by_rule(group, "repeated_error")
    services = _by_rule(group, "service_failure")
    clusters = _by_rule(group, "error_cluster") + _by_rule(group, "event_burst")
    restarts = [f for f in _by_rule(group, "critical_event") if f.subject in _UNEXPECTED_RESTART]

    for crash in crashes:
        related = [e for e in errors if specific_entities(e) & specific_entities(crash)]
        if related:
            message = related[0].details.get("message", "a repeated error")
            found.append(
                Hypothesis(
                    incident_id=incident_id,
                    template_id=f"crash_with_errors:{crash.subject}",
                    statement=(
                        f"The repeated error “{message}” may be related to the crashes "
                        f"of {crash.subject.removeprefix('app:')}."
                    ),
                    rationale=(
                        "Both were recorded for the same application within this incident. "
                        + _CAUSATION_NOTE
                    ),
                    confidence="low",
                    basis=_basis([crash, *related]),
                )
            )

    for service in services:
        others = [f for f in group.findings if f.rule_id in ("app_crash", "repeated_error")]
        if others:
            name = service.subject.removeprefix("service:")
            found.append(
                Hypothesis(
                    incident_id=incident_id,
                    template_id=f"service_affects_others:{service.subject}",
                    statement=f"The failures of service '{name}' may be affecting the other "
                    "failures in this incident.",
                    rationale=(
                        "The service failures overlap in time or share components with the other "
                        "findings. " + _CAUSATION_NOTE
                    ),
                    confidence="low",
                    basis=_basis([service, *others]),
                )
            )

    for log in _by_rule(group, "log_growth"):
        log_path = log.subject.removeprefix("log:")
        for temp in _by_rule(group, "temp_growth"):
            root = temp.subject.removeprefix("root:")
            if log_path.startswith(root.rstrip("\\/") + "\\") or log_path.startswith(
                root.rstrip("\\/") + "/"
            ):
                found.append(
                    Hypothesis(
                        incident_id=incident_id,
                        template_id=f"log_fills_temp:{log.subject}",
                        statement=(
                            f"Rapid writes to {log.details.get('path', log_path)} may be "
                            f"contributing to the growth of {temp.details.get('root', root)}."
                        ),
                        rationale=(
                            "The growing log file is located inside the temporary folder that "
                            "grew. The share of the growth it accounts for is not measured."
                        ),
                        confidence="medium",
                        basis=_basis([log, temp]),
                    )
                )

    if (
        clusters
        and len(group.rule_ids - {"error_cluster", "event_burst"}) >= 1
        and len(group.findings) >= 3
    ):
        found.append(
            Hypothesis(
                incident_id=incident_id,
                template_id="system_wide_disturbance",
                statement=(
                    "A system-wide event (for example an update, a driver problem, sleep or "
                    "resume, or a resource shortage) may have triggered several failures at once."
                ),
                rationale=(
                    "Several components reported problems in the same short period. Timing is "
                    "the only link; check what happened on the system at that time."
                ),
                confidence="low",
                basis=_basis(group.findings),
            )
        )

    for restart in restarts:
        others = [f for f in group.findings if f is not restart]
        if others:
            found.append(
                Hypothesis(
                    incident_id=incident_id,
                    template_id=f"unexpected_restart:{restart.subject}",
                    statement=(
                        "The unexpected restart recorded in this incident may explain some of "
                        "the other failures recorded around it."
                    ),
                    rationale=(
                        "The system did not shut down cleanly near the time of the other "
                        "findings. " + _CAUSATION_NOTE
                    ),
                    confidence="low",
                    basis=_basis([restart, *others]),
                )
            )

    health = _by_rule(group, "collector_health")
    if health and len(group.findings) > len(health):
        found.append(
            Hypothesis(
                incident_id=incident_id,
                template_id="monitoring_gap",
                statement="Some evidence for this incident may be missing because Sentinel's "
                "monitoring was degraded at the time.",
                rationale="A monitoring problem was recorded during this incident's window.",
                confidence="medium",
                basis=_basis(health),
            )
        )
    return found
