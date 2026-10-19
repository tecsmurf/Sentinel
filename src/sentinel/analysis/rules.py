"""Deterministic detection rules (DECISIONS.md D-009).

Every rule is a pure function of an :class:`AnalysisInput` (data already fetched by the
analysis service) and its validated parameters, and returns :class:`FindingDraft` values.
Each draft carries a stable rule ID, a subject used for deduplication and suppression,
severity, evidence references, an explanation written for the user, and a safe next step.

Wording rules: a finding describes what the evidence shows. It never claims malware, a
breach, or a definite root cause; possible causes belong in hypotheses (correlation).
"""

from __future__ import annotations

import logging
import statistics
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sentinel.analysis.recommendations import explain_event, next_step
from sentinel.models import (
    EvidenceRef,
    EvidenceType,
    FindingDraft,
    FindingSeverity,
    Observation,
    Severity,
    SourceType,
)

logger = logging.getLogger(__name__)

MAX_EVIDENCE = 50
EXCERPT_CHARS = 160
MAX_CLUSTER_EVENTS = 5000
MB = 1024 * 1024

CRASH_EVENTS = frozenset(
    {
        ("application error", "1000"),
        ("application hang", "1002"),
        ("windows error reporting", "1001"),
        (".net runtime", "1026"),
    }
)
SERVICE_FAILURE_CODES = frozenset(
    {"7000", "7001", "7009", "7011", "7022", "7023", "7024", "7031", "7034"}
)
# Monitoring problems that may mean data was missed: reported on first occurrence.
IMMEDIATE_HEALTH_KINDS = frozenset({"log_gap", "log_cleared", "ingestion_delayed"})

SampleIds = Callable[[str | None, datetime, datetime, int], list[int]]


def _no_samples(source_id: str | None, start: datetime, end: datetime, limit: int) -> list[int]:
    return []


# --------------------------------------------------------------------------------------
# Inputs
# --------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TempComparison:
    """A stored comparison between two temp-scan snapshots of one root."""

    scan_id: int
    root: str
    root_key: str
    baseline_snapshot_id: int
    current_snapshot_id: int | None
    baseline_at: datetime
    current_at: datetime
    bytes_before: int
    bytes_after: int
    files_before: int = 0
    files_after: int = 0
    dir_changes: tuple[dict[str, Any], ...] = ()
    caveats: tuple[str, ...] = ()

    @property
    def delta_bytes(self) -> int:
        return self.bytes_after - self.bytes_before

    @classmethod
    def from_summary(cls, scan_id: int, data: Mapping[str, Any]) -> TempComparison | None:
        """Rebuild from a scan's ``summary['comparisons']`` entry; ``None`` if malformed."""
        try:
            return cls(
                scan_id=scan_id,
                root=str(data["root"]),
                root_key=str(data["root_key"]),
                baseline_snapshot_id=int(data["baseline_snapshot_id"]),
                current_snapshot_id=(
                    None
                    if data.get("current_snapshot_id") is None
                    else int(data["current_snapshot_id"])
                ),
                baseline_at=datetime.fromisoformat(data["baseline_at"]).astimezone(UTC),
                current_at=datetime.fromisoformat(data["current_at"]).astimezone(UTC),
                bytes_before=int(data["bytes_before"]),
                bytes_after=int(data["bytes_after"]),
                files_before=int(data.get("files_before", 0)),
                files_after=int(data.get("files_after", 0)),
                dir_changes=tuple(d for d in data.get("dir_changes", []) if isinstance(d, dict)),
                caveats=tuple(str(c) for c in data.get("caveats", [])),
            )
        except (KeyError, TypeError, ValueError):
            return None


@dataclass(slots=True)
class AnalysisInput:
    now: datetime
    observations: list[Observation] = field(default_factory=list)
    volume_by_source: dict[str, list[tuple[datetime, int]]] = field(default_factory=dict)
    metric_samples: list[tuple[int, str, datetime, float]] = field(default_factory=list)
    temp_comparisons: list[TempComparison] = field(default_factory=list)
    sample_ids: SampleIds = _no_samples


# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------


def _fmt_time(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")


def fmt_bytes(count: float) -> str:
    value = float(abs(count))
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            text = f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
            return f"-{text}" if count < 0 else text
        value /= 1024
    return f"{count} B"


def _excerpt(text: str, limit: int = EXCERPT_CHARS) -> str:
    line = " ".join(text.split())
    return line if len(line) <= limit else line[: limit - 1] + "…"


def _refs(observations: Iterable[Observation]) -> list[EvidenceRef]:
    items = sorted(
        (o for o in observations if o.id is not None), key=lambda o: (o.event_timestamp, o.id)
    )
    return [EvidenceRef(EvidenceType.OBSERVATION, o.id) for o in items[-MAX_EVIDENCE:]]  # type: ignore[arg-type]


def entity_of(observation: Observation) -> str | None:
    value = observation.metadata.get("entity")
    return value if isinstance(value, str) else None


def _entities(observations: Iterable[Observation]) -> list[str]:
    found: set[str] = set()
    for o in observations:
        found.add(f"source:{o.source_id}")
        if o.provider:
            found.add(f"provider:{o.provider.casefold()}")
        entity = entity_of(o)
        if entity:
            found.add(entity)
    return sorted(found)


def is_crash(o: Observation) -> bool:
    return (
        o.source_type is SourceType.WINDOWS_EVENT
        and (o.provider.casefold(), o.event_code) in CRASH_EVENTS
        and (entity_of(o) or "").startswith("app:")
    )


def is_service_failure(o: Observation) -> bool:
    return (
        o.source_type is SourceType.WINDOWS_EVENT
        and o.provider.casefold() == "service control manager"
        and o.event_code in SERVICE_FAILURE_CODES
        and (entity_of(o) or "").startswith("service:")
    )


def _in_window(o: Observation, start: datetime, end: datetime) -> bool:
    return start <= o.event_timestamp <= end


def _floor(moment: datetime, step: timedelta) -> datetime:
    seconds = step.total_seconds()
    epoch = moment.timestamp()
    return datetime.fromtimestamp(epoch - (epoch % seconds), UTC)


def _kinds_summary(observations: Iterable[Observation]) -> str:
    counts = Counter(f"{o.provider} {o.event_code}".strip() for o in observations)
    return ", ".join(f"{n} x {kind}" for kind, n in counts.most_common(4))


# --------------------------------------------------------------------------------------
# Rules
# --------------------------------------------------------------------------------------


def _repeated_error(inp: AnalysisInput, p: Mapping[str, Any]) -> list[FindingDraft]:
    window = timedelta(minutes=p["window_minutes"])
    start = inp.now - window
    groups: dict[str, list[Observation]] = defaultdict(list)
    for o in inp.observations:
        if o.severity < Severity.ERROR or o.source_type is SourceType.SENTINEL:
            continue
        if not _in_window(o, start, inp.now) or is_crash(o) or is_service_failure(o):
            continue  # crashes and service failures have dedicated rules
        groups[o.fingerprint].append(o)

    drafts = []
    for fp, items in groups.items():
        count = len(items)
        if count < p["threshold"]:
            continue
        items.sort(key=lambda o: o.event_timestamp)
        latest = items[-1]
        who = latest.provider or latest.source_id
        explanation = (
            f"The same error was reported {count} times by {who} between "
            f"{_fmt_time(items[0].event_timestamp)} and {_fmt_time(latest.event_timestamp)} "
            f"(threshold: {p['threshold']} within {p['window_minutes']} minutes). "
            f"Latest message: “{_excerpt(latest.message)}”."
        )
        advice = explain_event(latest.provider, latest.event_code)
        if advice is not None:
            explanation += f" Known meaning: {advice.meaning}"
            if advice.commonly_benign:
                explanation += " This event is commonly benign."
        explanation += (
            " Repetition shows a persistent failure; it does not by itself identify the cause."
        )
        drafts.append(
            FindingDraft(
                rule_id="repeated_error",
                subject=f"fingerprint:{fp}",
                title=f"Repeated error from {who}",
                severity=FindingSeverity.HIGH
                if count >= p["threshold"] * 4
                else FindingSeverity.MEDIUM,
                explanation=explanation,
                recommendation=next_step("repeated_error", latest.provider, latest.event_code),
                window_start=items[0].event_timestamp,
                window_end=latest.event_timestamp,
                evidence=_refs(items),
                entities=[*_entities(items), f"fingerprint:{fp}"],
                details={
                    "count": count,
                    "fingerprint": fp,
                    "source_id": latest.source_id,
                    "provider": latest.provider,
                    "event_code": latest.event_code,
                    "message": _excerpt(latest.message),
                },
            )
        )
    return drafts


def _grouped_by_entity(
    inp: AnalysisInput, hours: float, predicate: Callable[[Observation], bool]
) -> dict[str, list[Observation]]:
    start = inp.now - timedelta(hours=hours)
    groups: dict[str, list[Observation]] = defaultdict(list)
    for o in inp.observations:
        if predicate(o) and _in_window(o, start, inp.now):
            groups[entity_of(o) or ""].append(o)
    return groups


def _app_crash(inp: AnalysisInput, p: Mapping[str, Any]) -> list[FindingDraft]:
    drafts = []
    for entity, items in _grouped_by_entity(inp, p["window_hours"], is_crash).items():
        count = len(items)
        if count < p["threshold"]:
            continue
        items.sort(key=lambda o: o.event_timestamp)
        latest = items[-1]
        name = latest.process_name or entity.removeprefix("app:")
        severity = (
            FindingSeverity.CRITICAL
            if count >= max(5, p["threshold"] * 3)
            else FindingSeverity.HIGH
        )
        drafts.append(
            FindingDraft(
                rule_id="app_crash",
                subject=entity,
                title=f"{name} crashed or stopped responding {count} times",
                severity=severity,
                explanation=(
                    f"{name} crashed or stopped responding {count} times between "
                    f"{_fmt_time(items[0].event_timestamp)} and "
                    f"{_fmt_time(latest.event_timestamp)} ({_kinds_summary(items)}). Repeated "
                    "failures of the same application point to a persistent problem with that "
                    "application or something it depends on; the events identify the faulting "
                    "module where Windows recorded one."
                ),
                recommendation=next_step("app_crash"),
                window_start=items[0].event_timestamp,
                window_end=latest.event_timestamp,
                evidence=_refs(items),
                entities=_entities(items),
                details={"count": count, "application": name},
            )
        )
    return drafts


def _service_failure(inp: AnalysisInput, p: Mapping[str, Any]) -> list[FindingDraft]:
    drafts = []
    for entity, items in _grouped_by_entity(inp, p["window_hours"], is_service_failure).items():
        count = len(items)
        if count < p["threshold"]:
            continue
        items.sort(key=lambda o: o.event_timestamp)
        latest = items[-1]
        service = entity.removeprefix("service:")
        codes = sorted({o.event_code for o in items})
        meanings = [a.meaning for c in codes if (a := explain_event(latest.provider, c))]
        drafts.append(
            FindingDraft(
                rule_id="service_failure",
                subject=entity,
                title=f"Service '{service}' failed {count} times",
                severity=FindingSeverity.HIGH,
                explanation=(
                    f"The Service Control Manager reported {count} failures of the service "
                    f"'{service}' between {_fmt_time(items[0].event_timestamp)} and "
                    f"{_fmt_time(latest.event_timestamp)} (event IDs {', '.join(codes)}). "
                    + (" ".join(meanings) + " " if meanings else "")
                    + "A service that keeps failing may affect the software that relies on it."
                ),
                recommendation=next_step("service_failure", latest.provider, latest.event_code),
                window_start=items[0].event_timestamp,
                window_end=latest.event_timestamp,
                evidence=_refs(items),
                entities=_entities(items),
                details={"count": count, "service": service, "event_ids": codes},
            )
        )
    return drafts


def _critical_event(inp: AnalysisInput, p: Mapping[str, Any]) -> list[FindingDraft]:
    def predicate(o: Observation) -> bool:
        return (
            o.source_type is SourceType.WINDOWS_EVENT
            and o.severity >= Severity.CRITICAL
            and not is_crash(o)
            and not is_service_failure(o)
        )

    start = inp.now - timedelta(hours=p["window_hours"])
    groups: dict[tuple[str, str], list[Observation]] = defaultdict(list)
    for o in inp.observations:
        if predicate(o) and _in_window(o, start, inp.now):
            groups[(o.provider, o.event_code)].append(o)
    drafts = []
    for (provider, code), items in groups.items():
        items.sort(key=lambda o: o.event_timestamp)
        latest = items[-1]
        advice = explain_event(provider, code)
        meaning = advice.meaning if advice else f"“{_excerpt(latest.message)}”"
        drafts.append(
            FindingDraft(
                rule_id="critical_event",
                subject=f"event:{provider.casefold()}:{code}",
                title=f"Critical event: {provider} {code}",
                severity=FindingSeverity.HIGH,
                explanation=(
                    f"Windows logged {len(items)} critical-level event(s) from {provider} (event "
                    f"ID {code}), most recently at {_fmt_time(latest.event_timestamp)}. {meaning}"
                ),
                recommendation=next_step("critical_event", provider, code),
                window_start=items[0].event_timestamp,
                window_end=latest.event_timestamp,
                evidence=_refs(items),
                entities=_entities(items),
                details={"count": len(items), "provider": provider, "event_code": code},
            )
        )
    return drafts


def _log_growth(inp: AnalysisInput, p: Mapping[str, Any]) -> list[FindingDraft]:
    window = timedelta(minutes=p["window_minutes"])
    start = inp.now - window
    per_path: dict[str, list[tuple[int, datetime, float]]] = defaultdict(list)
    for sample_id, subject, ts, value in inp.metric_samples:
        if start <= ts <= inp.now:
            per_path[subject].append((sample_id, ts, value))
    hours = window.total_seconds() / 3600
    drafts = []
    for path, samples in per_path.items():
        total = sum(v for _, _, v in samples)
        rate_mb = total / MB / hours
        if rate_mb < p["threshold_mb_per_hour"]:
            continue
        samples.sort(key=lambda s: s[1])
        severity = (
            FindingSeverity.HIGH
            if rate_mb >= p["threshold_mb_per_hour"] * 5
            else FindingSeverity.MEDIUM
        )
        drafts.append(
            FindingDraft(
                rule_id="log_growth",
                subject=f"log:{path.casefold()}",
                title=f"Log file growing quickly: {path}",
                severity=severity,
                explanation=(
                    f"{fmt_bytes(total)} was appended to {path} in the last "
                    f"{p['window_minutes']} minutes (about {rate_mb:.0f} MB per hour; threshold "
                    f"{p['threshold_mb_per_hour']} MB per hour), as measured by Sentinel while "
                    "reading it. Rapid log growth usually means something is logging repeatedly."
                ),
                recommendation=next_step("log_growth"),
                window_start=samples[0][1],
                window_end=samples[-1][1],
                evidence=[
                    EvidenceRef(EvidenceType.METRIC, s) for s, _, _ in samples[-MAX_EVIDENCE:]
                ],
                entities=[f"path:{path.casefold()}"],
                details={"bytes": total, "rate_mb_per_hour": round(rate_mb, 1), "path": path},
            )
        )
    return drafts


def _temp_growth(inp: AnalysisInput, p: Mapping[str, Any]) -> list[FindingDraft]:
    drafts = []
    min_growth = p["min_growth_mb"] * MB
    ratio_min = p["ratio_min_mb"] * MB
    cutoff = inp.now - timedelta(hours=p["lookback_hours"])
    for c in inp.temp_comparisons:
        if c.current_at < cutoff:
            continue
        delta = c.delta_bytes
        ratio = None if c.bytes_before == 0 else delta / c.bytes_before
        triggered = delta >= min_growth or (
            ratio is not None and ratio >= p["ratio_threshold"] and delta >= ratio_min
        )
        if not triggered:
            continue
        grew = [d for d in c.dir_changes if int(d.get("delta_bytes", 0)) > 0][:3]
        top = ", ".join(f"{d.get('rel_path')} (+{fmt_bytes(int(d['delta_bytes']))})" for d in grew)
        ratio_text = f" ({ratio:+.0%})" if ratio is not None else ""
        explanation = (
            f"{c.root} grew by {fmt_bytes(delta)}{ratio_text} between the scans at "
            f"{_fmt_time(c.baseline_at)} and {_fmt_time(c.current_at)} "
            f"({fmt_bytes(c.bytes_before)} → {fmt_bytes(c.bytes_after)}; "
            f"{c.files_after - c.files_before:+d} files)."
        )
        if top:
            explanation += f" Largest increases: {top}."
        if c.caveats:
            explanation += " Caveats: " + " ".join(c.caveats)
        evidence = [
            EvidenceRef(EvidenceType.SCAN_RUN, c.scan_id),
            EvidenceRef(EvidenceType.ROOT_SNAPSHOT, c.baseline_snapshot_id, "baseline"),
        ]
        if c.current_snapshot_id is not None:
            evidence.append(
                EvidenceRef(EvidenceType.ROOT_SNAPSHOT, c.current_snapshot_id, "current")
            )
        drafts.append(
            FindingDraft(
                rule_id="temp_growth",
                subject=f"root:{c.root_key}",
                title=f"Temporary folder grew by {fmt_bytes(delta)}",
                severity=FindingSeverity.HIGH
                if delta >= min_growth * 4
                else FindingSeverity.MEDIUM,
                explanation=explanation,
                recommendation=next_step("temp_growth"),
                window_start=c.baseline_at,
                window_end=c.current_at,
                evidence=evidence,
                entities=[f"path:{c.root_key}"],
                details={
                    "root": c.root,
                    "delta_bytes": delta,
                    "ratio": ratio,
                    "top_changes": grew,
                },
            )
        )
    return drafts


def _event_burst(inp: AnalysisInput, p: Mapping[str, Any]) -> list[FindingDraft]:
    bucket = timedelta(minutes=p["bucket_minutes"])
    current = _floor(inp.now, bucket)
    recent = (current - bucket, current)  # last complete bucket and the current one
    baseline_from = current - timedelta(hours=p["baseline_hours"])
    drafts = []
    for source_id, series in inp.volume_by_source.items():
        counts: dict[datetime, int] = defaultdict(int)
        for ts, n in series:
            counts[_floor(ts, bucket)] += n
        if not counts:
            continue
        slot = max(min(counts), baseline_from)
        baseline: list[int] = []
        while slot < recent[0]:
            baseline.append(counts.get(slot, 0))
            slot += bucket
        if len(baseline) < p["min_history_buckets"]:
            continue  # not enough history to know what is normal
        mean = statistics.fmean(baseline)
        spread = statistics.pstdev(baseline)
        threshold = max(p["min_events"], mean + p["z_score"] * max(spread, 1.0), 3 * mean)
        candidates = [(counts.get(start, 0), start) for start in recent]
        count, start = max(candidates)
        if count < threshold:
            continue
        end = start + bucket
        z = (count - mean) / max(spread, 1.0)
        drafts.append(
            FindingDraft(
                rule_id="event_burst",
                subject=f"burst:{source_id}:{start.isoformat()}",
                title=f"Unusual burst of events from {source_id}",
                severity=FindingSeverity.HIGH
                if z >= p["z_score"] * 2 and count >= 10 * max(mean, 1)
                else FindingSeverity.MEDIUM,
                explanation=(
                    f"{source_id} recorded {count} events between {_fmt_time(start)} and "
                    f"{_fmt_time(end)}, compared with an average of {mean:.1f} (standard "
                    f"deviation {spread:.1f}) per {p['bucket_minutes']}-minute interval over the "
                    f"previous {len(baseline)} intervals (about {z:.1f} standard deviations "
                    "above normal). A burst shows that something changed; the events in the "
                    "window show what."
                ),
                recommendation=next_step("event_burst"),
                window_start=start,
                window_end=end,
                evidence=[
                    EvidenceRef(EvidenceType.OBSERVATION, i)
                    for i in inp.sample_ids(source_id, start, end, MAX_EVIDENCE)
                ],
                entities=[f"source:{source_id}"],
                details={
                    "count": count,
                    "baseline_mean": round(mean, 2),
                    "baseline_stdev": round(spread, 2),
                    "baseline_intervals": len(baseline),
                    "z_score": round(z, 1),
                },
            )
        )
    return drafts


def _actor(o: Observation) -> str:
    return entity_of(o) or f"{o.source_id}|{o.provider}".casefold()


def _error_cluster(inp: AnalysisInput, p: Mapping[str, Any]) -> list[FindingDraft]:
    span = timedelta(minutes=p["window_minutes"])
    start = inp.now - timedelta(minutes=p["lookback_minutes"])
    errors = sorted(
        (
            o
            for o in inp.observations
            if o.severity >= Severity.ERROR
            and o.source_type is not SourceType.SENTINEL
            and _in_window(o, start, inp.now)
        ),
        key=lambda o: o.event_timestamp,
    )[-MAX_CLUSTER_EVENTS:]
    drafts = []
    i = 0
    while i < len(errors):
        first = errors[i].event_timestamp
        j = i
        actors: dict[str, Observation] = {}
        while j < len(errors) and errors[j].event_timestamp - first <= span:
            actors.setdefault(_actor(errors[j]), errors[j])
            j += 1
        if len(actors) < p["min_sources"]:
            i += 1
            continue
        items = errors[i:j]
        names = sorted({o.provider or o.source_id for o in actors.values()})
        bucket = _floor(first, span)
        drafts.append(
            FindingDraft(
                rule_id="error_cluster",
                subject=f"cluster:{bucket.isoformat()}",
                title=f"Errors from {len(actors)} components within {p['window_minutes']} minutes",
                severity=FindingSeverity.MEDIUM,
                explanation=(
                    f"{len(items)} errors from {len(actors)} different components occurred "
                    f"between {_fmt_time(first)} and {_fmt_time(items[-1].event_timestamp)}: "
                    f"{', '.join(names[:8])}. Errors from unrelated components at the same time "
                    "can share a common trigger, but timing alone does not prove they are related."
                ),
                recommendation=next_step("error_cluster"),
                window_start=first,
                window_end=items[-1].event_timestamp,
                evidence=_refs(items),
                entities=_entities(items),
                details={"errors": len(items), "components": names},
            )
        )
        i = j
    return drafts


def _collector_health(inp: AnalysisInput, p: Mapping[str, Any]) -> list[FindingDraft]:
    start = inp.now - timedelta(minutes=p["window_minutes"])
    groups: dict[str, list[Observation]] = defaultdict(list)
    for o in inp.observations:
        if (
            o.source_type is SourceType.SENTINEL
            and o.severity >= Severity.WARNING
            and _in_window(o, start, inp.now)
        ):
            groups[str(o.metadata.get("source") or o.source_id)].append(o)
    drafts = []
    for source, items in groups.items():
        immediate = any(o.event_code in IMMEDIATE_HEALTH_KINDS for o in items)
        if len(items) < p["threshold"] and not immediate:
            continue
        items.sort(key=lambda o: o.event_timestamp)
        latest = items[-1]
        kinds = Counter(o.event_code for o in items)
        drafts.append(
            FindingDraft(
                rule_id="collector_health",
                subject=f"collector:{source}",
                title=f"Monitoring problem: {source}",
                severity=FindingSeverity.MEDIUM if immediate else FindingSeverity.LOW,
                explanation=(
                    f"Sentinel recorded {len(items)} monitoring problem(s) for {source} in the "
                    f"last {p['window_minutes']} minutes ("
                    + ", ".join(f"{n} x {k}" for k, n in kinds.most_common())
                    + f"). Latest: “{_excerpt(latest.message)}”. While this persists, "
                    "data from this source may be incomplete."
                ),
                recommendation=next_step("collector_health"),
                window_start=items[0].event_timestamp,
                window_end=latest.event_timestamp,
                evidence=_refs(items),
                entities=[f"source:{source}"],
                details={"count": len(items), "kinds": dict(kinds)},
            )
        )
    return drafts


# --------------------------------------------------------------------------------------
# Registry and parameters
# --------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RuleParam:
    name: str
    default: int | float
    minimum: float
    maximum: float
    description: str = ""


@dataclass(frozen=True, slots=True)
class RuleSpec:
    rule_id: str
    title: str
    description: str
    params: tuple[RuleParam, ...]
    evaluate: Callable[[AnalysisInput, Mapping[str, Any]], list[FindingDraft]]
    window_param: str
    window_unit: str  # "minutes" or "hours"

    def dedup_window(self, params: Mapping[str, Any]) -> timedelta:
        value = float(params[self.window_param])
        return timedelta(hours=value) if self.window_unit == "hours" else timedelta(minutes=value)


RULES: tuple[RuleSpec, ...] = (
    RuleSpec(
        "repeated_error", "Repeated error",
        "The same error (by fingerprint) repeats within a short window.",
        (RuleParam("window_minutes", 15, 1, 1440, "time window"),
         RuleParam("threshold", 5, 2, 100_000, "occurrences that trigger the rule")),
        _repeated_error, "window_minutes", "minutes",
    ),
    RuleSpec(
        "app_crash", "Repeated application crash",
        "The same application crashes or hangs repeatedly.",
        (RuleParam("window_hours", 24, 1, 720, "time window"),
         RuleParam("threshold", 2, 1, 1000, "crashes that trigger the rule")),
        _app_crash, "window_hours", "hours",
    ),
    RuleSpec(
        "service_failure", "Repeated service failure",
        "The same Windows service fails repeatedly (Service Control Manager events).",
        (RuleParam("window_hours", 24, 1, 720, "time window"),
         RuleParam("threshold", 2, 1, 1000, "failures that trigger the rule")),
        _service_failure, "window_hours", "hours",
    ),
    RuleSpec(
        "critical_event", "Critical Windows event",
        "Windows logged an event at the Critical level.",
        (RuleParam("window_hours", 24, 1, 720, "time window"),),
        _critical_event, "window_hours", "hours",
    ),
    RuleSpec(
        "log_growth", "Rapid log growth",
        "A monitored log file grows faster than a threshold.",
        (RuleParam("window_minutes", 60, 5, 1440, "time window"),
         RuleParam("threshold_mb_per_hour", 100, 1, 100_000, "growth rate that triggers the rule")),
        _log_growth, "window_minutes", "minutes",
    ),
    RuleSpec(
        "temp_growth", "Temporary folder growth",
        "A temporary folder grew substantially between two complete scans.",
        (RuleParam("min_growth_mb", 500, 1, 1_000_000, "absolute growth that triggers the rule"),
         RuleParam("ratio_threshold", 0.5, 0.05, 100, "relative growth that triggers the rule"),
         RuleParam("ratio_min_mb", 100, 1, 1_000_000, "minimum growth for the relative test"),
         RuleParam("lookback_hours", 24, 1, 720, "how recent the scan must be")),
        _temp_growth, "lookback_hours", "hours",
    ),
    RuleSpec(
        "event_burst", "Event burst",
        "A source's event volume is far above its recent baseline.",
        (RuleParam("bucket_minutes", 5, 1, 60, "interval size"),
         RuleParam("baseline_hours", 24, 1, 168, "baseline period"),
         RuleParam("z_score", 4.0, 1, 20, "standard deviations above the mean"),
         RuleParam("min_events", 100, 5, 1_000_000, "minimum events in the interval"),
         RuleParam("min_history_buckets", 12, 3, 10_000, "baseline intervals required")),
        _event_burst, "bucket_minutes", "minutes",
    ),
    RuleSpec(
        "error_cluster", "Related errors at the same time",
        "Several different components report errors within a few minutes.",
        (RuleParam("window_minutes", 5, 1, 60, "cluster window"),
         RuleParam("min_sources", 3, 2, 50, "distinct components required"),
         RuleParam("lookback_minutes", 60, 5, 1440, "how far back to look")),
        _error_cluster, "window_minutes", "minutes",
    ),
    RuleSpec(
        "collector_health", "Monitoring problem",
        "Sentinel's own collection is failing or incomplete for a source.",
        (RuleParam("window_minutes", 60, 5, 1440, "time window"),
         RuleParam("threshold", 3, 1, 10_000, "problems that trigger the rule")),
        _collector_health, "window_minutes", "minutes",
    ),
)  # fmt: skip
RULES_BY_ID: dict[str, RuleSpec] = {spec.rule_id: spec for spec in RULES}

RuleParams = dict[str, dict[str, Any]]


def resolve_rule_params(overrides: Mapping[str, Any]) -> tuple[RuleParams, list[str]]:
    """Merge configuration overrides with defaults; invalid values are reported and ignored."""
    warnings: list[str] = []
    resolved: RuleParams = {}
    for spec in RULES:
        params: dict[str, Any] = {"enabled": True}
        params.update({param.name: param.default for param in spec.params})
        override = overrides.get(spec.rule_id, {})
        if not isinstance(override, Mapping):
            warnings.append(f"rules.{spec.rule_id}: expected an object; defaults used")
            override = {}
        by_name = {param.name: param for param in spec.params}
        for key, value in override.items():
            where = f"rules.{spec.rule_id}.{key}"
            if key == "enabled":
                if isinstance(value, bool):
                    params["enabled"] = value
                else:
                    warnings.append(f"{where}: expected true/false")
                continue
            param = by_name.get(key)
            if param is None:
                warnings.append(f"{where}: unknown parameter ignored")
                continue
            if isinstance(value, bool) or not isinstance(value, int | float):
                warnings.append(f"{where}: expected a number; default used")
                continue
            clamped = min(max(float(value), param.minimum), param.maximum)
            if clamped != value:
                warnings.append(
                    f"{where}: {value} outside {param.minimum} to {param.maximum}; clamped"
                )
            params[key] = int(clamped) if isinstance(param.default, int) else clamped
        resolved[spec.rule_id] = params
    for rule_id in overrides:
        if rule_id not in RULES_BY_ID:
            warnings.append(f"rules.{rule_id}: unknown rule ignored")
    return resolved, warnings


def lookback(params: RuleParams) -> timedelta:
    """How much history the rules need (the analysis service fetches this much)."""
    spans = [timedelta(hours=24)]
    for rule_id in ("app_crash", "service_failure", "critical_event"):
        spans.append(timedelta(hours=params[rule_id]["window_hours"]))
    spans.append(timedelta(minutes=params["repeated_error"]["window_minutes"]))
    spans.append(timedelta(minutes=params["error_cluster"]["lookback_minutes"]))
    spans.append(timedelta(minutes=params["collector_health"]["window_minutes"]))
    spans.append(timedelta(minutes=params["log_growth"]["window_minutes"]))
    return max(spans)


def run_rules(inp: AnalysisInput, params: RuleParams) -> tuple[list[FindingDraft], list[str]]:
    """Evaluate every enabled rule. A failing rule is reported and does not stop the others."""
    drafts: list[FindingDraft] = []
    errors: list[str] = []
    for spec in RULES:
        rule_params = params.get(spec.rule_id)
        if not rule_params or not rule_params.get("enabled", True):
            continue
        try:
            drafts.extend(spec.evaluate(inp, rule_params))
        except Exception as exc:
            logger.exception("detection rule failed", extra={"rule": spec.rule_id})
            errors.append(f"{spec.rule_id}: {type(exc).__name__}")
    return drafts, errors
