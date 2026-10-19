"""Exportable diagnostic reports: JSON, Markdown, and self-contained HTML.

A report contains the scope of monitoring, findings with their supporting evidence,
incidents with labelled hypotheses, recent temporary-folder scans, monitoring-health
problems, and an explicit list of limitations. Facts (observations), inferences
(findings), and possibilities (hypotheses) are kept in separate sections (D-010).

Safety: every value from logs or file names is untrusted. Markdown output escapes HTML
and table syntax; HTML output escapes all content and carries a Content Security Policy
that forbids scripts and remote resources, so a hostile log line cannot execute anything
in a viewer. Optional redaction replaces personal and machine identifiers.
"""

from __future__ import annotations

import contextlib
import html
import json
import os
import platform
import re
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from sentinel import APP_NAME, __version__
from sentinel.analysis.rules import RULES_BY_ID, fmt_bytes
from sentinel.config import AppConfig
from sentinel.models import (
    EvidenceType,
    Finding,
    FindingSeverity,
    FindingStatus,
    Severity,
    SourceType,
    utc_now,
)
from sentinel.services.redaction import Redactor
from sentinel.services.scan_service import TEMP_SCAN
from sentinel.storage import ObservationFilter, Repository

ReportFormat = Literal["json", "md", "html"]
FORMATS: tuple[str, ...] = ("json", "md", "html")
FORMAT_VERSION = 1
MAX_FINDINGS = 500
MAX_HEALTH = 50
MESSAGE_LIMIT = 2000


@dataclass(slots=True)
class ReportOptions:
    since: datetime | None = None  # default: the last 7 days
    finding_ids: Sequence[int] | None = None  # export only these findings
    include_resolved: bool = False
    include_raw_messages: bool = True
    redact: bool = True
    max_evidence_per_finding: int = 20


def _iso(moment: datetime | None) -> str | None:
    return None if moment is None else moment.astimezone(UTC).isoformat()


def _system_info() -> dict[str, Any]:
    info: dict[str, Any] = {
        "computer": platform.node(),
        "user": os.environ.get("USERNAME") or os.environ.get("USER") or "",
        "operating_system": platform.platform(),
        "python": platform.python_version(),
    }
    try:
        import psutil

        info["boot_time"] = _iso(datetime.fromtimestamp(psutil.boot_time(), UTC))
    except Exception:  # psutil is optional context; its absence must not break a report
        info["boot_time"] = None
    return info


class ReportService:
    def __init__(
        self,
        database_path: Path,
        config: AppConfig,
        *,
        clock: Callable[[], datetime] = utc_now,
        redactor: Redactor | None = None,
    ) -> None:
        self.database_path = database_path
        self.config = config
        self.clock = clock
        self.redactor = redactor

    # ------------------------------------------------------------------ building

    def build(self, options: ReportOptions | None = None) -> dict[str, Any]:
        options = options or ReportOptions()
        now = self.clock()
        since = options.since or now - timedelta(days=7)
        repo = Repository.open(self.database_path)
        try:
            findings = self._findings(repo, options, since)
            incident_ids = sorted({f.incident_id for f in findings if f.incident_id})
            report: dict[str, Any] = {
                "report": {
                    "generator": f"{APP_NAME} {__version__}",
                    "generated_at": _iso(now),
                    "format_version": FORMAT_VERSION,
                    "redacted": options.redact,
                    "period": {"since": _iso(since), "until": _iso(now)},
                },
                "system": _system_info(),
                "scope": self._scope(),
                "summary": self._summary(repo, since, findings, incident_ids),
                "incidents": [self._incident(repo, i) for i in incident_ids],
                "findings": [self._finding(repo, f, options) for f in findings],
                "temp_scans": self._scans(repo, since),
                "monitoring_health": self._health(repo, since),
            }
            report["limitations"] = self._limitations(report, options)
        finally:
            repo.close()
        if options.redact:
            report = (self.redactor or Redactor()).apply(report)
        for finding in report["findings"]:  # truncate *after* redaction
            for item in finding["evidence"]:
                if "message" in item:
                    item["message"] = item["message"][:MESSAGE_LIMIT]
        return report

    def _findings(self, repo: Repository, options: ReportOptions, since: datetime) -> list[Finding]:
        if options.finding_ids is not None:
            found = [repo.get_finding(i) for i in options.finding_ids]
            findings = [f for f in found if f is not None]
        else:
            statuses = [FindingStatus.OPEN, FindingStatus.ACKNOWLEDGED]
            if options.include_resolved:
                statuses += [FindingStatus.RESOLVED, FindingStatus.SUPPRESSED]
            findings = repo.list_findings(statuses=statuses, since=since, limit=MAX_FINDINGS)
        return sorted(findings, key=lambda f: (-int(f.severity), -f.updated_at.timestamp()))

    def _scope(self) -> dict[str, Any]:
        cfg = self.config
        return {
            "event_log_channels": list(cfg.event_logs.channels) if cfg.event_logs.enabled else [],
            "event_log_min_severity": cfg.event_logs.min_severity,
            "text_log_sources": [
                {"name": s.name or s.id, "path": s.path, "enabled": s.enabled}
                for s in cfg.text_logs
            ],
            "temp_scan": {
                "user_temp": cfg.temp_scan.include_user_temp,
                "windows_temp": cfg.temp_scan.include_windows_temp,
                "extra_roots": list(cfg.temp_scan.extra_roots),
            },
            "retention_days": cfg.retention.observation_days,
        }

    def _summary(
        self, repo: Repository, since: datetime, findings: list[Finding], incident_ids: list[int]
    ) -> dict[str, Any]:
        counts = repo.severity_counts(since)
        by_severity: dict[str, int] = {}
        for finding in findings:
            by_severity[finding.severity.label] = by_severity.get(finding.severity.label, 0) + 1
        return {
            "observations_by_severity": {s.label: n for s, n in counts.items()},
            "observations_total": sum(counts.values()),
            "findings_total": len(findings),
            "findings_by_severity": by_severity,
            "incidents_total": len(incident_ids),
        }

    def _finding(
        self, repo: Repository, finding: Finding, options: ReportOptions
    ) -> dict[str, Any]:
        refs = repo.finding_evidence(finding.id, limit=options.max_evidence_per_finding)
        observation_ids = [r.ref_id for r in refs if r.evidence_type is EvidenceType.OBSERVATION]
        evidence: list[dict[str, Any]] = []
        for obs in repo.get_observations(observation_ids):
            item: dict[str, Any] = {
                "type": "observation",
                "id": obs.id,
                "timestamp": _iso(obs.event_timestamp),
                "source": obs.source_id,
                "provider": obs.provider,
                "event_code": obs.event_code,
                "severity": obs.severity.label,
            }
            if options.include_raw_messages:
                # Truncated only after redaction (see build), so that a cut can never
                # split an identifier and leave a fragment the redactor cannot recognise.
                item["message"] = obs.message
            evidence.append(item)
        for ref in refs:
            if ref.evidence_type is EvidenceType.SCAN_RUN:
                scan = repo.get_scan_run(ref.ref_id)
                if scan is not None:
                    evidence.append(
                        {
                            "type": "scan_run",
                            "id": scan.id,
                            "timestamp": _iso(scan.started_at),
                            "status": str(scan.status),
                            "roots": scan.roots,
                        }
                    )
            elif ref.evidence_type is EvidenceType.ROOT_SNAPSHOT:
                snap = repo.get_root_snapshot(ref.ref_id, with_dirs=False)
                if snap is not None:
                    evidence.append(
                        {
                            "type": "root_snapshot",
                            "id": snap.id,
                            "role": ref.note,
                            "root": snap.root,
                            "total_bytes": snap.total_bytes,
                            "file_count": snap.file_count,
                            "complete": snap.complete,
                        }
                    )
            elif ref.evidence_type is EvidenceType.METRIC:
                evidence.append({"type": "metric", "id": ref.ref_id})
        spec = RULES_BY_ID.get(finding.rule_id)
        return {
            "id": finding.id,
            "rule_id": finding.rule_id,
            "rule": spec.title if spec else finding.rule_id,
            "title": finding.title,
            "severity": finding.severity.label,
            "status": str(finding.status),
            "status_note": finding.status_note,
            "window": {"start": _iso(finding.window_start), "end": _iso(finding.window_end)},
            "detected_at": _iso(finding.detected_at),
            "occurrences": finding.occurrences,
            "explanation": finding.explanation,
            "recommendation": finding.recommendation,
            "incident_id": finding.incident_id,
            "evidence_total": finding.evidence_count,
            "evidence": evidence,
        }

    def _incident(self, repo: Repository, incident_id: int) -> dict[str, Any]:
        incident = repo.get_incident(incident_id)
        if incident is None:
            return {"id": incident_id, "missing": True}
        return {
            "id": incident.id,
            "title": incident.title,
            "severity": incident.severity.label,
            "status": str(incident.status),
            "window": {"start": _iso(incident.window_start), "end": _iso(incident.window_end)},
            "summary": incident.summary,
            "grouped_because": incident.reasons,
            "finding_ids": incident.finding_ids,
            "hypotheses": [
                {
                    "statement": h.statement,
                    "rationale": h.rationale,
                    "confidence": h.confidence,
                    "basis": h.basis,
                    "note": "Unconfirmed possibility, not a conclusion.",
                }
                for h in repo.hypotheses_for(incident.id)
            ],
        }

    def _scans(self, repo: Repository, since: datetime) -> list[dict[str, Any]]:
        scans = []
        for scan in repo.list_scan_runs(TEMP_SCAN, limit=3):
            if scan.started_at < since:
                continue
            scans.append(
                {
                    "id": scan.id,
                    "started_at": _iso(scan.started_at),
                    "finished_at": _iso(scan.finished_at),
                    "status": str(scan.status),
                    "files": scan.files_scanned,
                    "bytes": scan.bytes_total,
                    "errors": scan.error_count,
                    "roots": [
                        {
                            "root": s.root,
                            "total_bytes": s.total_bytes,
                            "files": s.file_count,
                            "inaccessible": s.inaccessible_count,
                            "complete": s.complete,
                        }
                        for s in repo.root_snapshots(scan.id or 0)
                    ],
                    "skipped_roots": scan.summary.get("skipped_roots", []),
                    "comparisons": scan.summary.get("comparisons", []),
                }
            )
        return scans

    def _health(self, repo: Repository, since: datetime) -> list[dict[str, Any]]:
        notes = repo.query_observations(
            ObservationFilter(
                since=since, source_types=[SourceType.SENTINEL], min_severity=Severity.WARNING
            ),
            limit=MAX_HEALTH,
        )
        return [
            {
                "timestamp": _iso(o.event_timestamp),
                "kind": o.event_code,
                "source": o.metadata.get("source", ""),
                "message": o.message,
            }
            for o in notes
        ]

    @staticmethod
    def _limitations(report: dict[str, Any], options: ReportOptions) -> list[str]:
        items = [
            "Sentinel Local reads only what the current user can access without administrator "
            "rights; restricted channels (such as Security) are excluded unless readable.",
            "Findings come from deterministic rules with configurable thresholds; hypotheses are "
            "unconfirmed possibilities, not conclusions.",
            f"Data older than {report['scope']['retention_days']} days may have been removed by "
            "retention, except evidence referenced by retained findings.",
        ]
        kinds = sorted({h["kind"] for h in report["monitoring_health"]})
        if kinds:
            items.append(
                "Monitoring problems were recorded during this period (" + ", ".join(kinds) + "); "
                "data from the affected sources may be incomplete."
            )
        partial = [s for s in report["temp_scans"] if s["status"] != "completed"]
        if partial:
            items.append(
                f"{len(partial)} temporary-folder scan(s) were partial or cancelled; their totals "
                "may be underestimated."
            )
        if not options.include_raw_messages:
            items.append("Raw log messages were omitted from this report at the user's request.")
        if options.redact:
            items.append(
                "Identifiers (user and computer names, profile paths, e-mail and IP addresses, "
                "domain SIDs) were redacted on a best-effort basis; review before sharing."
            )
        return items

    # ------------------------------------------------------------------ writing

    def export(self, options: ReportOptions, directory: Path, fmt: ReportFormat = "html") -> Path:
        stamp = self.clock().astimezone(UTC).strftime("%Y%m%d-%H%M%S")
        return self.write(self.build(options), directory / f"sentinel-report-{stamp}.{fmt}", fmt)

    @staticmethod
    def write(report: dict[str, Any], path: Path, fmt: ReportFormat) -> Path:
        if fmt not in FORMATS:
            raise ValueError(f"unsupported report format: {fmt}")
        if fmt == "json":
            content = json.dumps(report, indent=2, ensure_ascii=False, default=str) + "\n"
        elif fmt == "md":
            content = render_markdown(report)
        else:
            content = render_html(report)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=f"{path.name}.", suffix=".tmp", dir=path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(content)
            os.replace(tmp, path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise
        return path


# --------------------------------------------------------------------------------------
# Markdown
# --------------------------------------------------------------------------------------


_MD_PUNCTUATION = re.compile(r"([\\`*_{}\[\]()#+!|~])")


def _md(text: Any) -> str:
    """Escape untrusted text for inline Markdown.

    HTML is entity-encoded, and every character that can start a link, image, emphasis,
    code span, heading, or table cell is backslash-escaped, so text such as
    ``![x](http://host/pixel)`` renders literally instead of loading a remote image.
    """
    value = "" if text is None else str(text)
    value = value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    value = _MD_PUNCTUATION.sub(r"\\\1", value)
    return " ".join(value.split())


def _md_code(text: Any) -> str:
    """Untrusted multi-line text as a fenced code block that the content cannot close."""
    value = "" if text is None else str(text)
    lines = value.splitlines()[:40] or [""]
    body = "\n".join(lines)
    longest = max((len(run) for run in re.findall(r"`+", body)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}text\n{body}\n{fence}"


def render_markdown(report: dict[str, Any]) -> str:
    meta = report["report"]
    out = [
        "# Sentinel Local diagnostic report",
        "",
        f"Generated {_md(meta['generated_at'])} by {_md(meta['generator'])} for the period "
        f"{_md(meta['period']['since'])} to {_md(meta['period']['until'])}.",
        f"Redacted: {'yes' if meta['redacted'] else 'no'}.",
        "",
        "## System",
        "",
    ]
    out += [f"- **{_md(k)}:** {_md(v)}" for k, v in report["system"].items()]
    summary = report["summary"]
    out += [
        "",
        "## Summary",
        "",
        f"- Observations: {summary['observations_total']}",
        f"- Findings: {summary['findings_total']} "
        + _md(", ".join(f"{k}: {v}" for k, v in summary["findings_by_severity"].items())),
        f"- Incidents: {summary['incidents_total']}",
        "",
        "## Incidents",
        "",
    ]
    if not report["incidents"]:
        out.append("No incidents in this period.")
    for incident in report["incidents"]:
        if incident.get("missing"):
            continue
        out += [
            f"### Incident {incident['id']}: {_md(incident['title'])}",
            "",
            f"Severity **{_md(incident['severity'])}**, status {_md(incident['status'])}, "
            f"{_md(incident['window']['start'])} to {_md(incident['window']['end'])}.",
            "",
            _md(incident["summary"]),
            "",
            "Grouped because:",
            *[f"- {_md(r)}" for r in incident["grouped_because"]],
            "",
        ]
        if incident["hypotheses"]:
            out.append("Hypotheses (unconfirmed possibilities, not conclusions):")
            out += [
                f"- *{_md(h['statement'])}* (confidence: {_md(h['confidence'])}). "
                f"{_md(h['rationale'])}"
                for h in incident["hypotheses"]
            ]
            out.append("")
    out += ["## Findings", ""]
    if not report["findings"]:
        out.append("No findings in this period.")
    for finding in report["findings"]:
        out += [
            f"### [{_md(finding['severity'])}] {_md(finding['title'])}",
            "",
            f"Rule `{_md(finding['rule_id'])}` · status {_md(finding['status'])} · "
            f"{_md(finding['window']['start'])} to {_md(finding['window']['end'])} · "
            f"{finding['occurrences']} occurrence(s)",
            "",
            _md(finding["explanation"]),
            "",
            f"**Next step:** {_md(finding['recommendation'])}",
            "",
            f"Evidence ({len(finding['evidence'])} of {finding['evidence_total']} shown):",
            "",
        ]
        for item in finding["evidence"]:
            if item["type"] == "observation":
                out.append(
                    f"- {_md(item['timestamp'])} · {_md(item['source'])} · {_md(item['provider'])} "
                    f"{_md(item['event_code'])} · {_md(item['severity'])}"
                )
                if "message" in item:
                    out += ["", _md_code(item["message"]), ""]
            else:
                details = ", ".join(f"{k}={v}" for k, v in item.items() if k != "type")
                out.append(f"- {_md(item['type'])}: {_md(details)}")
        out.append("")
    out += ["## Temporary-folder scans", ""]
    if not report["temp_scans"]:
        out.append("No scans in this period.")
    for scan in report["temp_scans"]:
        out.append(
            f"- Scan {scan['id']} at {_md(scan['started_at'])}: {_md(scan['status'])}, "
            f"{scan['files']} files, {_md(fmt_bytes(scan['bytes']))}, {scan['errors']} error(s)"
        )
        for root in scan["roots"]:
            out.append(
                f"  - {_md(root['root'])}: {_md(fmt_bytes(root['total_bytes']))}, "
                f"{root['files']} files, {root['inaccessible']} inaccessible"
            )
    out += ["", "## Monitoring health", ""]
    if not report["monitoring_health"]:
        out.append("No monitoring problems recorded.")
    out += [
        f"- {_md(h['timestamp'])} · {_md(h['kind'])} · {_md(h['source'])}: {_md(h['message'])}"
        for h in report["monitoring_health"]
    ]
    out += ["", "## Limitations", ""]
    out += [f"- {_md(item)}" for item in report["limitations"]]
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------------------
# HTML
# --------------------------------------------------------------------------------------

_SEVERITY_CLASS = {s.label: f"sev-{s.name.lower()}" for s in FindingSeverity}
_SEVERITY_CLASS.update({s.label: f"sev-{s.name.lower()}" for s in Severity})


def _h(text: Any) -> str:
    return html.escape("" if text is None else str(text), quote=True)


def _badge(severity: str) -> str:
    css = _SEVERITY_CLASS.get(severity, "sev-info")
    return f'<span class="badge {css}">{_h(severity)}</span>'


_CSS = """
:root{--bg:#f6f7f9;--card:#fff;--text:#1d2330;--muted:#5d6675;--line:#dfe3ea;--accent:#2f6fde}
@media (prefers-color-scheme:dark){:root{--bg:#14171c;--card:#1c2027;--text:#e6e9ee;
--muted:#9aa3b0;--line:#2c323c;--accent:#6ea0ff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
font:15px/1.5 "Segoe UI",system-ui,sans-serif}main{max-width:1000px;margin:0 auto;padding:24px 16px}
h1{font-size:24px;margin:0 0 4px}
h2{font-size:18px;margin:32px 0 12px;border-bottom:1px solid var(--line);
padding-bottom:6px}h3{font-size:16px;margin:0 0 6px}.muted{color:var(--muted)}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;
margin:12px 0}
.badge{display:inline-block;border-radius:999px;padding:1px 10px;font-size:12px;font-weight:600}
.sev-critical{background:#b3261e;color:#fff}.sev-high{background:#e8590c;color:#fff}
.sev-medium,.sev-error{background:#f0b400;color:#1d2330}.sev-low,.sev-warning{background:#d7e3f8;color:#1d2330}
.sev-info,.sev-debug{background:#e3e6ea;color:#1d2330}
table{border-collapse:collapse;width:100%;font-size:13px}td,th{border-bottom:1px solid var(--line);
text-align:left;padding:6px;vertical-align:top}
pre{white-space:pre-wrap;word-break:break-word;margin:4px 0;
font:12px/1.4 Consolas,monospace;background:var(--bg);padding:6px;border-radius:6px}
.hyp{border-left:3px solid var(--accent);padding-left:10px;margin:8px 0}
ul{padding-left:20px}
"""


def render_html(report: dict[str, Any]) -> str:
    meta = report["report"]
    parts: list[str] = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width, initial-scale=1'>",
        # Nothing in the report may load or execute anything.
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "
        "style-src 'unsafe-inline'; img-src 'none'; form-action 'none'\">",
        "<title>Sentinel Local report</title>",
        f"<style>{_CSS}</style></head><body><main>",
        "<h1>Sentinel Local diagnostic report</h1>",
        f"<p class='muted'>Generated {_h(meta['generated_at'])} by {_h(meta['generator'])} · "
        f"period {_h(meta['period']['since'])} to {_h(meta['period']['until'])} · "
        f"{'redacted' if meta['redacted'] else 'not redacted'}</p>",
    ]
    summary = report["summary"]
    parts.append("<div class='card'><table>")
    for key, value in report["system"].items():
        parts.append(f"<tr><th>{_h(key.replace('_', ' '))}</th><td>{_h(value)}</td></tr>")
    parts.append(
        f"<tr><th>observations</th><td>{_h(summary['observations_total'])}</td></tr>"
        f"<tr><th>findings</th><td>{_h(summary['findings_total'])}</td></tr>"
        f"<tr><th>incidents</th><td>{_h(summary['incidents_total'])}</td></tr></table></div>"
    )

    parts.append("<h2>Incidents</h2>")
    if not report["incidents"]:
        parts.append("<p class='muted'>No incidents in this period.</p>")
    for incident in report["incidents"]:
        if incident.get("missing"):
            continue
        parts.append(
            f"<div class='card'><h3>{_badge(incident['severity'])} {_h(incident['title'])}</h3>"
            f"<p class='muted'>Incident {_h(incident['id'])} · {_h(incident['status'])} · "
            f"{_h(incident['window']['start'])} to {_h(incident['window']['end'])}</p>"
            f"<p>{_h(incident['summary'])}</p><p><strong>Grouped because:</strong></p><ul>"
            + "".join(f"<li>{_h(r)}</li>" for r in incident["grouped_because"])
            + "</ul>"
        )
        if incident["hypotheses"]:
            parts.append("<p><strong>Hypotheses</strong> (unconfirmed possibilities):</p>")
            for h in incident["hypotheses"]:
                parts.append(
                    f"<div class='hyp'><em>{_h(h['statement'])}</em><br>"
                    f"<span class='muted'>Confidence: {_h(h['confidence'])}. "
                    f"{_h(h['rationale'])}</span></div>"
                )
        parts.append("</div>")

    parts.append("<h2>Findings</h2>")
    if not report["findings"]:
        parts.append("<p class='muted'>No findings in this period.</p>")
    for finding in report["findings"]:
        parts.append(
            f"<div class='card'><h3>{_badge(finding['severity'])} {_h(finding['title'])}</h3>"
            f"<p class='muted'>Rule {_h(finding['rule'])} · {_h(finding['status'])} · "
            f"{_h(finding['window']['start'])} to {_h(finding['window']['end'])} · "
            f"{_h(finding['occurrences'])} occurrence(s)</p>"
            f"<p>{_h(finding['explanation'])}</p>"
            f"<p><strong>Next step:</strong> {_h(finding['recommendation'])}</p>"
            f"<p class='muted'>Evidence: {len(finding['evidence'])} of "
            f"{_h(finding['evidence_total'])} shown</p>"
            "<table><tr><th>Time</th><th>Source</th><th>Event</th><th>Detail</th></tr>"
        )
        for item in finding["evidence"]:
            if item["type"] == "observation":
                detail = f"<pre>{_h(item['message'])}</pre>" if "message" in item else ""
                parts.append(
                    f"<tr><td>{_h(item['timestamp'])}</td><td>{_h(item['source'])}</td>"
                    f"<td>{_h(item['provider'])} {_h(item['event_code'])} "
                    f"{_badge(item['severity'])}</td>"
                    f"<td>{detail}</td></tr>"
                )
            else:
                details = ", ".join(f"{k}={v}" for k, v in item.items() if k != "type")
                parts.append(
                    f"<tr><td colspan='2'>{_h(item['type'])}</td>"
                    f"<td colspan='2'>{_h(details)}</td></tr>"
                )
        parts.append("</table></div>")

    parts.append("<h2>Temporary-folder scans</h2>")
    if not report["temp_scans"]:
        parts.append("<p class='muted'>No scans in this period.</p>")
    for scan in report["temp_scans"]:
        parts.append(
            f"<div class='card'><h3>Scan {_h(scan['id'])} · {_h(scan['status'])}</h3>"
            f"<p class='muted'>{_h(scan['started_at'])} · {_h(scan['files'])} files · "
            f"{_h(fmt_bytes(scan['bytes']))} · {_h(scan['errors'])} error(s)</p><table>"
            "<tr><th>Folder</th><th>Size</th><th>Files</th><th>Inaccessible</th></tr>"
            + "".join(
                f"<tr><td>{_h(r['root'])}</td><td>{_h(fmt_bytes(r['total_bytes']))}</td>"
                f"<td>{_h(r['files'])}</td><td>{_h(r['inaccessible'])}</td></tr>"
                for r in scan["roots"]
            )
            + "</table></div>"
        )

    parts.append("<h2>Monitoring health</h2>")
    if not report["monitoring_health"]:
        parts.append("<p class='muted'>No monitoring problems recorded.</p>")
    else:
        parts.append("<table><tr><th>Time</th><th>Kind</th><th>Source</th><th>Message</th></tr>")
        parts += [
            f"<tr><td>{_h(h['timestamp'])}</td><td>{_h(h['kind'])}</td><td>{_h(h['source'])}</td>"
            f"<td>{_h(h['message'])}</td></tr>"
            for h in report["monitoring_health"]
        ]
        parts.append("</table>")

    parts.append("<h2>Limitations</h2><ul>")
    parts += [f"<li>{_h(item)}</li>" for item in report["limitations"]]
    parts.append("</ul></main></body></html>")
    return "\n".join(parts) + "\n"
