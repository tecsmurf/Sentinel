# Sentinel Local — Project Context

> Operational source of truth for continuing development. Update it whenever architecture,
> implementation status, configuration, dependencies, or workflow change materially.
> Architectural reasoning lives in [DECISIONS.md](DECISIONS.md); this file describes **state**.
>
> Status vocabulary: **planned** (designed, no code), **implemented** (code exists),
> **tested** (automated tests pass), **verified on Windows** (exercised on a real Windows
> machine), **known-broken**.

Last updated: 2026-10-18 — Phase 3 (text-log monitoring).

## 1. Project identity

- **Name:** Sentinel Local
- **Purpose:** A local-first Windows desktop application that monitors Windows Event Logs and
  configured application log files, analyses temporary-directory storage and growth, detects
  meaningful patterns (repeated errors, crashes, service failures, bursts, abnormal growth),
  correlates them into investigation timelines, and explains findings with evidence and safe
  recommendations.
- **Problem solved:** Diagnosing "my PC is acting up / filling up" on Windows means manually
  combing Event Viewer, scattered log files, and temp folders. Sentinel Local gathers the
  evidence, keeps a searchable history, and points at what changed — without sending data
  anywhere.
- **Target OS:** Windows 10/11 (x64). Analysis, parsing, storage and the temp scanner are
  platform-neutral so they can be tested on any OS.
- **Intended users:** power users, developers, support engineers, and IT staff investigating a
  single Windows machine.
- **Core principles:** collect, analyse, and store locally; evidence before conclusions;
  read-only by default; least privilege; bounded resource use; honest reporting of gaps
  (inaccessible sources, dropped events, partial scans).

## 2. Repository audit (2026-10-15)

- Local repository: initialised, branch `master`, **no commits, no files**.
- Remote: none was configured. The owner confirmed adding
  `origin = https://github.com/tecsmurf/Sentinel.git` (public, empty, no branches) and pushing
  to `master`.
- No existing code, tests, dependency manifests, CI, or documentation — the project is built
  from scratch following the specification.
- Development machine: Windows 11 Home (10.0.26200), Python 3.12.10 and 3.14.4 available,
  `uv` 0.11.32, `gh` 2.102.0.

## 3. Architecture (planned)

Layered, one-directional dependencies (see D-007):

```
ui  ──►  services  ──►  collectors / scanner / analysis / storage  ──►  models
```

Planned layout (`src/` layout, D-018):

```
src/sentinel/
├── __init__.py, __main__.py, main.py   entry points (GUI + headless CLI)
├── config.py          typed configuration, JSON persistence, validation, defaults
├── paths.py           app-data location, env-var expansion, path normalisation
├── logging_config.py  structured (JSON-lines) application logging with rotation
├── models.py          shared dataclasses/enums: Observation, Finding, Incident, ...
├── collectors/        windows_events.py, text_logs.py, file_watcher.py
├── scanner/           temp_scanner.py, snapshots.py, classification.py
├── analysis/          parser.py, rules.py, correlation.py, recommendations.py
├── storage/           database.py (schema/migrations), repository.py
├── services/          monitoring.py, scan_service.py, report_service.py
└── ui/                main_window.py, dashboard.py, events_view.py, files_view.py,
                       incidents_view.py, scan_view.py, settings_view.py, reports_view.py
tests/  unit/  integration/  windows/  fixtures/
```

### Data flow (planned)

1. Collectors (Event Log channels, text-log tailers) run on worker threads and push normalised
   `Observation`s into a bounded queue (backpressure, counted drops — D-008).
2. A single writer thread batches observations into SQLite and advances collector
   checkpoints in the same transaction.
3. The temp scanner runs on demand (cancellable, iterative, no reparse-point traversal) and
   stores per-root and per-subdirectory aggregates plus bounded per-file samples.
4. The analysis service periodically runs deterministic rules over recent data, upserts
   findings (with deduplication/suppression), correlates findings into incidents, and attaches
   labelled hypotheses.
5. The UI reads through its own SQLite connection and receives worker progress via Qt signals.

### Storage (implemented — `storage/database.py`, `storage/repository.py`)

- SQLite file `sentinel.db` in the data directory. WAL journaling, `synchronous=NORMAL`,
  `foreign_keys=ON`, `auto_vacuum=INCREMENTAL` (set at creation).
- Connections use autocommit mode; writes go through `transaction()` (`BEGIN IMMEDIATE`).
  One `Repository` per thread/connection.
- Schema version in `PRAGMA user_version` (currently **1**). `MIGRATIONS` in `database.py` is
  append-only; a database from a newer version is refused with a clear `DatabaseError`, as is
  a corrupt/foreign file.
- Timestamps: UTC, INTEGER microseconds since the Unix epoch (`models.to_micros`).
- Tables: `observations` (unique `dedup_key`, indexes on time, severity+time, source+time,
  fingerprint+time), `checkpoints`, `metric_samples`, `scan_runs`, `root_snapshots`,
  `dir_snapshots`, `file_samples`, `findings`, `finding_evidence`, `incidents`, `hypotheses`,
  `suppressions`. The finding/incident tables exist in schema v1; their repository methods
  arrive with the detection engine.
- Search uses `LIKE … ESCAPE '\'` with wildcards escaped (no FTS yet).

### Detection (implemented — `analysis/rules.py`, `services/analysis_service.py`)

Rules are pure functions over data fetched by `AnalysisService` (warning+ observations for
the longest window, per-source volume buckets, log-growth metric samples, recent temp-scan
comparisons). Defaults below; overrides go in `config.rules.<rule_id>` and are validated.

| Rule ID | Fires when (defaults) | Subject (dedup/suppression key) | Evidence |
|---------|-----------------------|----------------------------------|----------|
| `repeated_error` | same fingerprint ≥5 errors in 15 min (excl. crashes/service failures) | `fingerprint:<fp>` | observations |
| `app_crash` | same app ≥2 crash/hang events (App Error 1000, Hang 1002, WER 1001 app crash, .NET 1026) in 24 h | `app:<exe>` | observations |
| `service_failure` | same service ≥2 SCM failures (7000/7001/7009/7011/7022/7023/7024/7031/7034) in 24 h | `service:<name>` | observations |
| `critical_event` | any Critical-level Windows event in 24 h (e.g. Kernel-Power 41) | `event:<provider>:<id>` | observations |
| `log_growth` | ≥100 MB/h appended to a monitored log (60 min) | `log:<path>` | metric samples |
| `temp_growth` | temp root grew ≥500 MB, or ≥50 % and ≥100 MB, between complete scans (last 24 h) | `root:<root key>` | scan run + both snapshots |
| `event_burst` | 5-min bucket ≥100 events and ≥ mean + 4σ and ≥3× mean of ≥12 baseline buckets (24 h) | `burst:<source>:<bucket>` | sampled observations |
| `error_cluster` | errors from ≥3 distinct components within 5 min (last 60 min) | `cluster:<bucket>` | observations |
| `collector_health` | ≥3 monitoring warnings for a source in 60 min, or any `log_gap`/`log_cleared`/`ingestion_delayed` | `collector:<source>` | health observations |

Dedup: a draft merges into the unresolved finding with the same (rule, subject) whose window
ended within the rule's window; drafts that add no new evidence change nothing. Suppressed
(rule, subject) pairs are stored with status `suppressed`. Evidence per finding is capped at 200.

## 4. Product requirements (summary)

Real-time monitoring and on-demand scans; Windows Event Log support (Application, System, and
user-selected channels); configurable text-log monitoring (`.log`, `.txt`, JSON lines) with
rotation/truncation handling and checkpoints; temp-directory analysis and growth tracking;
repeated-error, crash, service-failure, burst, log-growth, temp-growth, co-occurring-error,
and collector-health rules; correlation into incidents; searchable local history; JSON,
Markdown, and HTML reports with optional redaction; safe, explained cleanup candidates
(no deletion).

## 5. Security and privacy

- Local-only storage; no telemetry; no network access needed; no external AI API.
- Runs as the current user; never self-elevates; access-denied is reported, not hidden.
- Log content and file names are treated as sensitive and as untrusted data: parsed with
  bounded sizes, never executed, never used to build shell commands; HTML exports escape all
  content.
- Parameterised SQL only.
- Read-only toward the filesystem and the OS (no deletion, no service/registry/process
  changes, no event-log modification) — D-011.
- Retention limits on observations, scan history, and metrics — D-014.
- Exports support redaction of usernames in paths, computer names, email addresses, IP
  addresses, and SIDs.

## 6. Current project state

| Area | Status |
|------|--------|
| Documentation (README, CONTEXT, DECISIONS) | implemented |
| Configuration (`config.py`), paths (`paths.py`), structured logging (`logging_config.py`) | implemented, tested (unit) |
| Shared models (`models.py`), fingerprints/message bounding (`analysis/normalize.py`) | implemented, tested (unit) |
| SQLite storage: schema v1, migrations, repository for observations, checkpoints, metrics, scans | implemented, tested (integration) |
| Findings/incidents/hypotheses/suppressions persistence (`storage/findings.py`) and retention (`storage/retention.py`: age + row cap, evidence and scan baselines protected, incremental vacuum) | implemented, tested (integration) |
| Temp-directory scanner (`scanner/temp_scanner.py`, `scanner/classification.py`): root resolution/dedup, iterative read-only traversal, reparse points skipped, limits, cancellation, progress, candidates with reasons | implemented, tested (unit + Windows: junctions, ACL denial, locked files, 8.3 names) |
| Scan persistence and growth comparison (`scanner/snapshots.py`, `services/scan_service.py`): one scan run per multi-root scan, complete-only baselines, per-subfolder changes, caveats | implemented, tested (unit + integration) |
| Text-log parsing (`analysis/parser.py`) and incremental tailing (`collectors/text_logs.py`): checkpoints, partial lines, multiline, rotation/truncation/rewrite detection, backfill limit, BOM/UTF-16/legacy encodings, shared-delete opens on Windows | implemented, tested (unit + integration + Windows) |
| File watching (`collectors/file_watcher.py`, watchdog) as a low-latency trigger; reconciliation by the monitoring service | implemented, tested (integration, real observers) |
| Windows Event Log collector (`collectors/windows_events.py`): backend interface, pywin32 backend (EvtQuery/EvtRender/EvtFormatMessage, cached publisher metadata, pull-mode subscriptions as wake-up), bounded look-back import, record-ID checkpoints, gap/cleared-log detection, access-denied handling, entity extraction (service/app/WER) | implemented, tested (unit with fake backend + read-only Windows API tests) |
| Monitoring pipeline (`services/monitoring.py`): `IngestionPipeline` (sync, CLI) and `MonitoringService` (text worker with watcher + reconciliation, event worker with subscriptions, batching writer, bounded queue, checkpoint-based backpressure, epoch rewind after failed writes, health observations, log-growth metrics, status snapshot) | implemented, tested (integration, threaded) |
| Detection rules (`analysis/rules.py`, 9 rules), event knowledge base (`analysis/recommendations.py`), `AnalysisService` (input building, dedup/merge, suppression) | implemented, tested (unit + integration) |
| Correlation into incidents with reasons + template hypotheses (`analysis/correlation.py`, D-021) | implemented, tested (unit + integration) |
| Periodic analysis (every `analysis_interval_seconds`) + retention (every 6 h) on a `sentinel-analysis` thread; `request_analysis()`, `on_analysis` callback | implemented, tested (integration) |
| Reports (`services/report_service.py`: JSON/Markdown/HTML, evidence, incidents + labelled hypotheses, scans, health, limitations; HTML escaped + CSP; atomic writes) and redaction (`services/redaction.py`) | implemented, tested (unit + integration) |
| Headless CLI | planned |
| Desktop UI | planned |
| Build tooling (pyproject, pins, ruff, pytest) | implemented, tested locally |
| CI workflow | implemented (first run pending) |
| Packaging (PyInstaller) | planned (deferred, D-016) |

- **Known bugs:** none (no code yet).
- **Test results:** no tests yet.
- **Unresolved technical decisions:** whether to use SQLite FTS5 for message search (start
  with indexed `LIKE` queries; revisit if search on large databases is slow).
- **Current phase:** Phase 0 — audit and documentation.
- **Next three tasks:**
  1. Implement the read-only temp-directory scanner (iterative, cancellable, no reparse-point
     traversal) with tests.
  2. Persist scan snapshots and compare growth between scans.
  3. Implement text-log parsing and incremental tailing with rotation handling.

## 7. Development workflow

### Environment

- Python **3.12** (validated: 3.12.10). The repository lives in a OneDrive-synced folder on the
  original development machine, so the development virtual environment was created outside it
  (`%USERPROFILE%\.venvs\sentinel-local`) to avoid syncing ~300 MB of binaries. A conventional
  `.venv` in the repository also works and is git-ignored.

### Dependencies

`pyproject.toml` declares compatible ranges; `requirements.txt` (runtime) and
`requirements-dev.txt` (runtime + dev tools) hold exact pins generated with
`uv pip compile --universal` (the command is recorded in each file's header).

| Package | Pinned | Purpose |
|---------|--------|---------|
| PySide6-Essentials | 6.12.0 | Desktop UI (Qt Core/Gui/Widgets only) |
| pywin32 | 312 (Windows only) | Windows Event Log API (`win32evtlog`) |
| watchdog | 6.0.0 | Filesystem notifications for monitored log files |
| psutil | 7.2.2 | Own-process resource usage and system context (boot time) |
| pytest / pytest-qt | 9.1.1 / 4.5.0 | Tests, Qt widget tests |
| ruff | 0.17.0 | Lint + format |
| pyinstaller (extra `build`) | 6.22.3 validated | Packaging (deferred, D-016) |

### Setup, test, lint

```powershell
py -3.12 -m venv .venv                     # or: uv venv --python 3.12 .venv
.venv\Scripts\python -m pip install -r requirements-dev.txt
.venv\Scripts\python -m pip install --no-deps -e .
.venv\Scripts\python -m pytest             # full suite
.venv\Scripts\python -m pytest -m "not windows and not ui"   # platform-neutral subset
.venv\Scripts\python -m ruff check . ; .venv\Scripts\python -m ruff format --check .
```

Test markers: `windows` (real Windows API, read-only) and `ui` (needs a Qt platform; set
`QT_QPA_PLATFORM=offscreen` for headless runs).

### Continuous integration

`.github/workflows/tests.yml` runs on pushes to `master`: ruff lint/format (Ubuntu),
platform-neutral tests (Ubuntu), and the full suite including Windows-API and Qt tests
(`windows-latest`, offscreen Qt). JUnit XML results are uploaded as artifacts. No secrets,
no deployment, no releases.

### Git policy (D-017)

- Branch `master`, remote `origin` → `https://github.com/tecsmurf/Sentinel.git`.
- Small logical changes; each one linted, tested, staged selectively, reviewed as a staged
  diff, committed with a conventional commit message, and pushed before starting the next.
- No pull requests, no force pushes, no history rewriting, no committing of databases, logs,
  virtual environments, build output, or secrets.

### Code-quality standards

- `ruff` for linting and formatting; `pytest` for tests.
- Type hints on public functions; dataclasses for value types; no bare `except`.
- Exceptions isolated per source/collector; errors reported, never swallowed silently.
- Regression test for every bug fix.
