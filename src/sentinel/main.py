"""Entry point: the desktop application and headless commands.

Every capability is available headless, so it can be scripted and tested without a display:

    sentinel status | scan | collect | analyze | findings | report

Exit codes: 0 success, 1 failure, 2 configuration or database problem, 130 cancelled.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from sentinel import APP_NAME, __version__
from sentinel.analysis.rules import fmt_bytes
from sentinel.config import AppConfig, load_config
from sentinel.logging_config import configure_logging, install_exception_hooks
from sentinel.models import FindingStatus, IncidentStatus, ScanStatus, utc_now
from sentinel.paths import AppPaths, default_data_dir
from sentinel.storage import Database, DatabaseError, ObservationFilter, Repository

EXIT_OK, EXIT_ERROR, EXIT_SETUP, EXIT_CANCELLED = 0, 1, 2, 130

logger = logging.getLogger(__name__)


class SetupError(Exception):
    """The data directory, configuration, or database cannot be used."""


@dataclass(slots=True)
class Context:
    paths: AppPaths
    config: AppConfig
    config_warnings: list[str]


def _local(moment: datetime | None) -> str:
    return "-" if moment is None else moment.astimezone().strftime("%Y-%m-%d %H:%M")


def _emit(data: Any, as_json: bool, text: Callable[[], None]) -> None:
    if as_json:
        print(json.dumps(data, indent=2, default=str))
    else:
        text()


def setup(data_dir: Path | None, *, verbose: bool = False) -> Context:
    """Prepare the data directory, logging, configuration, and database."""
    try:
        paths = AppPaths(data_dir or default_data_dir()).ensure()
    except OSError as exc:
        raise SetupError(f"cannot use data directory: {exc}") from exc
    configure_logging(paths.log_dir, level="DEBUG" if verbose else "INFO", console=verbose)
    install_exception_hooks()
    loaded = load_config(paths.config_file)
    try:
        Database(paths.database_file).initialize()
    except DatabaseError as exc:
        raise SetupError(
            f"{exc}. To keep the existing file and start over, rename it; Sentinel will create "
            "a new database."
        ) from exc
    logger.info("sentinel started", extra={"version": __version__, "data_dir": str(paths.root)})
    return Context(paths=paths, config=loaded.config, config_warnings=loaded.warnings)


# --------------------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------------------


def cmd_status(ctx: Context, args: argparse.Namespace) -> int:
    repo = Repository.open(ctx.paths.database_file)
    try:
        scans = repo.list_scan_runs("temp", limit=1)
        last_scan = scans[0] if scans else None
        data = {
            "version": __version__,
            "data_dir": str(ctx.paths.root),
            "observations": repo.count_observations(),
            "sources": repo.source_stats(),
            "open_findings": {s.label: n for s, n in repo.open_finding_counts().items()},
            "open_incidents": len(
                repo.list_incidents(statuses=[IncidentStatus.OPEN, IncidentStatus.ACKNOWLEDGED])
            ),
            "last_temp_scan": None
            if last_scan is None
            else {
                "id": last_scan.id,
                "started_at": last_scan.started_at,
                "status": str(last_scan.status),
                "bytes": last_scan.bytes_total,
            },
        }
    finally:
        repo.close()

    def text() -> None:
        print(f"{APP_NAME} {__version__}")
        print(f"Data directory : {data['data_dir']}")
        print(f"Observations   : {data['observations']}")
        findings = ", ".join(f"{k} {v}" for k, v in data["open_findings"].items() if v) or "none"
        print(f"Open findings  : {findings}")
        print(f"Open incidents : {data['open_incidents']}")
        if last_scan is not None:
            print(
                f"Last temp scan : {_local(last_scan.started_at)} ({last_scan.status}, "
                f"{fmt_bytes(last_scan.bytes_total)})"
            )
        for source in data["sources"]:
            print(
                f"  {source['source_id']:<40} {source['total']:>8} events, {source['errors']:>6} "
                f"errors, last {_local(source['last_event'])}"
            )

    _emit(data, args.json, text)
    return EXIT_OK


def _run_analysis(ctx: Context) -> Any:
    from sentinel.services.analysis_service import AnalysisService

    return AnalysisService(ctx.paths.database_file, ctx.config).run()


def cmd_scan(ctx: Context, args: argparse.Namespace) -> int:
    from sentinel.services.scan_service import ScanService

    cancel = threading.Event()
    outcome: dict[str, Any] = {}
    service = ScanService(ctx.paths.database_file, ctx.config.temp_scan)

    def progress(update) -> None:
        if not args.json:
            line = f"  scanning {update.root}: {update.files} files, {fmt_bytes(update.bytes)}"
            print("\r" + line.ljust(100)[:100], end="", file=sys.stderr, flush=True)

    def work() -> None:
        try:
            outcome["result"] = service.run_temp_scan(cancel=cancel, progress=progress)
        except Exception as exc:  # reported below; the scan run is already marked failed
            outcome["error"] = exc

    worker = threading.Thread(target=work, name="sentinel-cli-scan")
    worker.start()
    try:
        while worker.is_alive():
            worker.join(0.2)
    except KeyboardInterrupt:
        cancel.set()
        worker.join()
    if not args.json:
        print(file=sys.stderr)
    if "error" in outcome:
        print(f"scan failed: {outcome['error']}", file=sys.stderr)
        return EXIT_ERROR
    result = outcome["result"]
    if not args.no_analyze and result.scan.status is not ScanStatus.CANCELLED:
        _run_analysis(ctx)

    scan = result.scan
    data = {
        "scan_id": scan.id,
        "status": str(scan.status),
        "files": scan.files_scanned,
        "bytes": scan.bytes_total,
        "errors": scan.error_count,
        "roots": [
            {
                "root": r.snapshot.root,
                "bytes": r.snapshot.total_bytes,
                "files": r.snapshot.file_count,
                "inaccessible": r.snapshot.inaccessible_count,
                "complete": r.snapshot.complete,
            }
            for r in result.results
        ],
        "skipped_roots": [{"path": p, "reason": reason} for p, reason in result.skipped_roots],
        "comparisons": [c.to_dict() for c in result.comparisons],
    }

    def text() -> None:
        print(f"Scan {scan.id}: {scan.status} - {scan.files_scanned} files, "
              f"{fmt_bytes(scan.bytes_total)}, {scan.error_count} error(s)")  # fmt: skip
        for root in data["roots"]:
            note = "" if root["complete"] else " (incomplete)"
            print(f"  {root['root']}: {fmt_bytes(root['bytes'])} in {root['files']} files, "
                  f"{root['inaccessible']} inaccessible{note}")  # fmt: skip
        for path, reason in result.skipped_roots:
            print(f"  skipped {path}: {reason}")
        for comparison in result.comparisons:
            print(f"  {comparison.root}: {fmt_bytes(comparison.delta_bytes)} since "
                  f"{_local(comparison.baseline_at)}")  # fmt: skip

    _emit(data, args.json, text)
    return EXIT_CANCELLED if scan.status is ScanStatus.CANCELLED else EXIT_OK


def cmd_collect(ctx: Context, args: argparse.Namespace) -> int:
    from sentinel.services.monitoring import IngestionPipeline

    repo = Repository.open(ctx.paths.database_file)
    try:
        inserted = IngestionPipeline(ctx.config).run_once(repo)
    finally:
        repo.close()
    analysis = None if args.no_analyze else _run_analysis(ctx)
    data = {
        "observations_added": inserted,
        "findings_created": len(analysis.created) if analysis else None,
    }

    def text() -> None:
        print(f"Collected {inserted} new observation(s).")
        if analysis is not None:
            created, updated = len(analysis.created), len(analysis.updated)
            print(f"Analysis: {created} new, {updated} updated finding(s).")

    _emit(data, args.json, text)
    return EXIT_OK


def cmd_analyze(ctx: Context, args: argparse.Namespace) -> int:
    result = _run_analysis(ctx)
    data = {
        "created": result.created,
        "updated": result.updated,
        "suppressed": result.suppressed,
        "incidents_created": result.incidents_created,
        "warnings": result.warnings,
    }

    def text() -> None:
        print(f"{len(result.created)} new, {len(result.updated)} updated, "
              f"{len(result.suppressed)} suppressed finding(s); "
              f"{len(result.incidents_created)} new incident(s).")  # fmt: skip
        for finding in result.new_open:
            print(f"  [{finding.severity.label}] {finding.title}")
        for warning in result.warnings:
            print(f"  warning: {warning}", file=sys.stderr)

    _emit(data, args.json, text)
    return EXIT_OK


def cmd_findings(ctx: Context, args: argparse.Namespace) -> int:
    statuses = [] if args.all else [FindingStatus.OPEN, FindingStatus.ACKNOWLEDGED]
    repo = Repository.open(ctx.paths.database_file)
    try:
        findings = repo.list_findings(statuses=statuses, limit=args.limit)
    finally:
        repo.close()
    data = [
        {
            "id": f.id,
            "severity": f.severity.label,
            "status": str(f.status),
            "rule_id": f.rule_id,
            "title": f.title,
            "last_seen": f.window_end,
            "evidence": f.evidence_count,
            "incident_id": f.incident_id,
        }
        for f in findings
    ]

    def text() -> None:
        if not findings:
            print("No findings.")
        for f in findings:
            print(f"#{f.id:<5} {f.severity.label:<8} {f.status!s:<12} {_local(f.window_end)}  "
                  f"{f.title}")  # fmt: skip

    _emit(data, args.json, text)
    return EXIT_OK


def cmd_report(ctx: Context, args: argparse.Namespace) -> int:
    from sentinel.services.report_service import ReportOptions, ReportService

    redact = ctx.config.privacy.redact_exports_by_default if args.redact is None else args.redact
    options = ReportOptions(
        since=utc_now() - timedelta(days=args.days),
        include_resolved=args.include_resolved,
        include_raw_messages=ctx.config.privacy.include_raw_messages_in_reports
        and not args.no_messages,
        redact=redact,
    )
    service = ReportService(ctx.paths.database_file, ctx.config)
    if args.out:
        path = service.write(service.build(options), Path(args.out), args.format)
    else:
        path = service.export(options, ctx.paths.reports_dir, args.format)
    print(str(path))
    return EXIT_OK


def cmd_events(ctx: Context, args: argparse.Namespace) -> int:
    repo = Repository.open(ctx.paths.database_file)
    try:
        events = repo.query_observations(ObservationFilter(text=args.search), limit=args.limit)
    finally:
        repo.close()
    for o in reversed(events):
        print(f"{_local(o.event_timestamp)} {o.severity.label:<8} {o.source_id:<28} "
              f"{o.provider} {o.event_code}: {o.message[:160]}")  # fmt: skip
    return EXIT_OK


COMMANDS: dict[str, Callable[[Context, argparse.Namespace], int]] = {
    "status": cmd_status,
    "scan": cmd_scan,
    "collect": cmd_collect,
    "analyze": cmd_analyze,
    "findings": cmd_findings,
    "events": cmd_events,
    "report": cmd_report,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description=f"{APP_NAME}: local-first Windows log monitoring and temp-file analysis.",
    )
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {__version__}")
    parser.add_argument("--data-dir", type=Path, help="data directory (default: per-user)")
    parser.add_argument("-v", "--verbose", action="store_true", help="log to the console too")
    sub = parser.add_subparsers(dest="command", metavar="command")

    status = sub.add_parser("status", help="show monitoring and database status")
    status.add_argument("--json", action="store_true")
    scan = sub.add_parser("scan", help="scan temporary folders now")
    scan.add_argument("--json", action="store_true")
    scan.add_argument("--no-analyze", action="store_true", help="skip running the rules")
    collect = sub.add_parser("collect", help="collect new log and event data once")
    collect.add_argument("--json", action="store_true")
    collect.add_argument("--no-analyze", action="store_true")
    analyze = sub.add_parser("analyze", help="run the detection rules now")
    analyze.add_argument("--json", action="store_true")
    findings = sub.add_parser("findings", help="list findings")
    findings.add_argument("--json", action="store_true")
    findings.add_argument("--all", action="store_true", help="include resolved and suppressed")
    findings.add_argument("--limit", type=int, default=100)
    events = sub.add_parser("events", help="show recent observations")
    events.add_argument("--search", help="text to search for")
    events.add_argument("--limit", type=int, default=50)
    report = sub.add_parser("report", help="export a diagnostic report")
    report.add_argument("--format", choices=("html", "md", "json"), default="html")
    report.add_argument("--out", help="output file (default: the reports folder)")
    report.add_argument("--days", type=int, default=7, help="period to cover (default 7)")
    report.add_argument("--include-resolved", action="store_true")
    report.add_argument("--no-messages", action="store_true", help="omit raw log messages")
    redaction = report.add_mutually_exclusive_group()
    redaction.add_argument("--redact", dest="redact", action="store_true", default=None)
    redaction.add_argument("--no-redact", dest="redact", action="store_false")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    command = args.command
    if command is None:
        parser.print_help()
        return EXIT_OK
    try:
        ctx = setup(args.data_dir, verbose=args.verbose)
    except SetupError as exc:
        print(f"sentinel: {exc}", file=sys.stderr)
        return EXIT_SETUP
    for warning in ctx.config_warnings:
        print(f"config warning: {warning}", file=sys.stderr)
    try:
        return COMMANDS[command](ctx, args)
    except KeyboardInterrupt:
        print("cancelled", file=sys.stderr)
        return EXIT_CANCELLED


if __name__ == "__main__":
    raise SystemExit(main())
