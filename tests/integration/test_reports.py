import json
import re
from datetime import timedelta

import pytest

from sentinel.collectors.base import HealthNote
from sentinel.config import AppConfig, TempScanSettings, TextLogSource
from sentinel.models import Severity, SourceType
from sentinel.services.analysis_service import AnalysisService
from sentinel.services.monitoring import health_observation
from sentinel.services.redaction import Redactor
from sentinel.services.report_service import ReportOptions, ReportService
from sentinel.services.scan_service import ScanService
from tests.support import BASE_TIME

NOW = BASE_TIME
HOSTILE = r"<script>alert('x')</script> | C:\Users\alice\app.log contact alice@example.com"


@pytest.fixture
def seeded(database, repo, make_observation, tmp_path):
    config = AppConfig()
    config.text_logs = [TextLogSource(path=r"C:\Users\alice\app.log", id="app", name="Billing")]
    observations = [
        make_observation(HOSTILE, source_id="app", at=NOW - timedelta(minutes=10 - i))
        for i in range(6)
    ]
    observations.append(
        health_observation(
            "winevt:Security",
            HealthNote("access_denied", Severity.WARNING, "access to Security was denied"),
            NOW - timedelta(minutes=1),
        )
    )
    with repo.transaction():
        repo.insert_observations(observations)
    AnalysisService(database.path, config, clock=lambda: NOW).run()

    temp = tmp_path / "Temp"
    temp.mkdir()
    (temp / "a.tmp").write_bytes(b"x" * 100)
    ScanService(
        database.path,
        TempScanSettings(
            include_user_temp=False, include_windows_temp=False, extra_roots=[str(temp)]
        ),
        environ={},
        clock=lambda: NOW - timedelta(minutes=5),
    ).run_temp_scan()
    return config


def service(database, config):
    return ReportService(
        database.path,
        config,
        clock=lambda: NOW,
        redactor=Redactor(usernames=["alice"], computers=["TEST-PC"]),
    )


def test_report_structure_and_evidence(database, seeded):
    report = service(database, seeded).build(ReportOptions(redact=False))
    assert set(report) == {
        "report", "system", "scope", "summary", "incidents", "findings", "temp_scans",
        "monitoring_health", "limitations",
    }  # fmt: skip
    assert report["report"]["format_version"] == 1
    (finding,) = report["findings"]
    assert finding["rule_id"] == "repeated_error"
    assert finding["evidence_total"] == 6
    assert finding["evidence"][0]["message"] == HOSTILE
    assert report["summary"]["findings_total"] == 1
    assert report["temp_scans"][0]["roots"][0]["total_bytes"] == 100
    assert report["monitoring_health"][0]["kind"] == "access_denied"
    assert any("administrator" in item for item in report["limitations"])
    assert any("Monitoring problems" in item for item in report["limitations"])
    assert report["scope"]["text_log_sources"][0]["name"] == "Billing"


def test_redaction_removes_identifiers_everywhere(database, seeded):
    report = service(database, seeded).build(ReportOptions(redact=True))
    text = json.dumps(report)
    assert not re.search("alice", text, re.IGNORECASE)
    assert "<user>" in text and "<email>" in text
    assert report["report"]["redacted"] is True
    assert any("redacted on a best-effort basis" in item for item in report["limitations"])


def test_raw_messages_can_be_omitted(database, seeded):
    report = service(database, seeded).build(
        ReportOptions(redact=False, include_raw_messages=False)
    )
    assert all("message" not in e for f in report["findings"] for e in f["evidence"])
    assert any("omitted" in item for item in report["limitations"])


def test_selected_findings_only(database, seeded):
    svc = service(database, seeded)
    assert svc.build(ReportOptions(finding_ids=[999_999]))["findings"] == []
    full = svc.build(ReportOptions())
    chosen = svc.build(ReportOptions(finding_ids=[full["findings"][0]["id"]]))
    assert len(chosen["findings"]) == 1


def test_json_markdown_and_html_are_safe(database, seeded, tmp_path):
    svc = service(database, seeded)
    report = svc.build(ReportOptions(redact=False))

    data = json.loads(svc.write(report, tmp_path / "r.json", "json").read_text(encoding="utf-8"))
    assert data["findings"][0]["rule_id"] == "repeated_error"

    markdown = svc.write(report, tmp_path / "r.md", "md").read_text(encoding="utf-8")
    assert "<script>" not in markdown
    assert "&lt;script&gt;" in markdown
    assert r"\|" in markdown  # pipes cannot break tables
    assert markdown.startswith("# Sentinel Local diagnostic report")

    page = svc.write(report, tmp_path / "r.html", "html").read_text(encoding="utf-8")
    assert "<script" not in page.lower()
    assert "&lt;script&gt;" in page
    assert "Content-Security-Policy" in page
    assert "default-src 'none'" in page
    assert "Hypotheses" not in page or "unconfirmed" in page


def test_export_names_files_and_leaves_no_temporary_files(database, seeded, tmp_path):
    svc = service(database, seeded)
    path = svc.export(ReportOptions(), tmp_path / "reports", "html")
    assert path.name == "sentinel-report-20261015-120000.html"
    assert [p.name for p in path.parent.iterdir()] == [path.name]


def test_unknown_format_is_rejected(database, seeded, tmp_path):
    with pytest.raises(ValueError, match="unsupported"):
        service(database, seeded).write({}, tmp_path / "x.pdf", "pdf")


def test_empty_database_produces_a_valid_report(database, tmp_path):
    report = ReportService(database.path, AppConfig(), clock=lambda: NOW).build()
    assert report["findings"] == [] and report["incidents"] == []
    html_page = ReportService.write(report, tmp_path / "empty.html", "html").read_text(
        encoding="utf-8"
    )
    assert "No findings in this period." in html_page


def test_health_records_are_sentinel_observations(database, seeded, repo):
    from sentinel.storage import ObservationFilter

    (record,) = repo.query_observations(ObservationFilter(source_types=[SourceType.SENTINEL]))
    assert record.metadata["source"] == "winevt:Security"
