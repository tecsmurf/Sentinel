# Sentinel Local — Architectural Decision Record

This document records the architectural, implementation, security, and product decisions
made while building Sentinel Local, and **why** they were made. It is not a technology list.

Rules for maintaining this file:

- Add a new entry when a decision is actually made. Do not back-date entries or invent history.
- Never delete an entry. If a decision changes, mark the old entry `superseded`, link to the
  replacement, and add a new entry explaining what changed and why.
- Status values: `proposed`, `accepted`, `superseded`, `rejected`.
- Dates are ISO 8601 (`YYYY-MM-DD`).

## Index

| ID | Title | Status |
|----|-------|--------|
| D-001 | Windows-first desktop application | accepted |
| D-002 | PySide6 for the initial user interface | accepted |
| D-003 | Local-first operation | accepted |
| D-004 | SQLite for persistent storage | accepted |
| D-005 | Windows Event Log API instead of parsing `.evtx` files | accepted |
| D-006 | Filesystem events plus periodic reconciliation | accepted |
| D-007 | Collectors, services, and UI are separate layers | accepted |
| D-008 | Worker threads, bounded queues, and batched persistence | accepted |
| D-009 | Deterministic rules before machine learning | accepted |
| D-010 | Observations, findings, incidents, and hypotheses stored separately | accepted |
| D-011 | Read-only filesystem behaviour; cleanup disabled by default | accepted |
| D-012 | No administrator privileges for ordinary operation | accepted |
| D-013 | No cloud dependencies or remote AI services in the MVP | accepted |
| D-014 | Bounded retention, database size, and scan scope | accepted |
| D-015 | Synthetic fixtures and mocked OS interfaces in automated tests | accepted |
| D-016 | Executable packaging deferred until the application is stable | accepted |
| D-017 | Small, verified commits pushed directly to the working branch | accepted |
| D-018 | `src/` package layout with a single `sentinel` package | accepted |
| D-019 | Text logs: shared-delete opens, bounded backfill, generations for rotation | accepted |
| D-020 | Backpressure by not advancing checkpoints; epochs after failed writes | accepted |

---

## D-001 — Windows-first desktop application

- **Date:** 2026-10-15
- **Status:** accepted
- **Context and problem:** The product monitors Windows Event Logs, Windows temporary
  directories (`%TEMP%`, `C:\Windows\Temp`), and local application logs. These data sources
  only exist, with the required semantics, on a Windows machine, and the people investigating
  them are usually sitting at that machine.
- **Options considered:** (a) cross-platform desktop app with equal support for Linux/macOS;
  (b) Windows-first desktop app with platform-neutral analysis code; (c) a background Windows
  service with a separate web UI; (d) a command-line tool only.
- **Decision:** Build a Windows-first desktop application. Platform-specific code (Event Log
  access, Windows path semantics) sits behind interfaces so the analysis, storage, and parsing
  layers stay platform-neutral and testable anywhere.
- **Reasons:** The core data sources are Windows-specific. A desktop app runs in the user's
  own security context, needs no installation of a service or open network port, and lets the
  user see and control exactly what is collected.
- **Trade-offs:** No first-class Linux/macOS experience. Monitoring only happens while the app
  (or its tray icon) is running, unlike a Windows service.
- **Alternatives rejected:** (a) would dilute effort on sources that do not exist elsewhere;
  (c) needs elevated installation, a listening port, and an auth story — disproportionate for
  an MVP; (d) is kept as a secondary headless interface but is not sufficient for investigation
  workflows (timelines, evidence browsing).
- **Consequences:** Windows-only modules are isolated (`collectors/windows_events.py`), and
  tests for them run on Windows CI runners. Text-log parsing and the temp scanner must work on
  any OS for testing purposes.
- **Revisit when:** there is demand for unattended monitoring (consider a Windows service) or
  for other operating systems.

## D-002 — PySide6 for the initial user interface

- **Date:** 2026-10-15
- **Status:** accepted
- **Context and problem:** The UI must stay responsive while scans and event bursts happen in
  the background, present tables of tens of thousands of rows, and look like a professional
  diagnostic tool on Windows.
- **Options considered:** PySide6 (Qt 6, LGPL), PyQt6 (GPL/commercial), Tkinter, a local web
  UI (FastAPI + browser/React), Electron.
- **Decision:** PySide6, using the `PySide6-Essentials` wheel (Qt Core/Gui/Widgets without the
  add-on modules).
- **Reasons:** Mature native widgets, model/view tables that scale to large datasets, a
  well-defined threading model (signals/slots with queued connections across threads),
  first-party Qt for Python bindings with an LGPL licence, and good PyInstaller support.
  `Essentials` keeps the install and packaged size smaller; charts are drawn with `QPainter`
  instead of pulling in QtCharts.
- **Trade-offs:** Large binary dependency (~80 MB wheel); Qt idioms (models, delegates, QSS)
  have a learning curve; UI tests need an offscreen Qt platform.
- **Alternatives rejected:** PyQt6 — licence is less permissive for a project that may be
  shared. Tkinter — limited table performance and styling. Local web UI — adds a server, a
  listening port, and a JavaScript build chain, contradicting D-003 and D-013. Electron —
  heavy and introduces a second runtime.
- **Consequences:** All long-running work runs off the UI thread; widgets are only touched from
  the UI thread (see D-008). UI tests use `pytest-qt` with `QT_QPA_PLATFORM=offscreen`.
- **Revisit when:** Qt licensing or packaging constraints change, or a remote/multi-machine UI
  becomes a requirement.

## D-003 — Local-first operation

- **Date:** 2026-10-15
- **Status:** accepted
- **Context and problem:** Event logs, file paths, and application logs frequently contain
  usernames, hostnames, file names, internal URLs, and occasionally secrets. Users must be able
  to trust that the tool does not leak them.
- **Options considered:** local-only; local with optional cloud sync; cloud-first SaaS agent.
- **Decision:** Collect, analyse, and store everything locally. No telemetry, no automatic
  upload, no network calls are needed for any core function.
- **Reasons:** Privacy by construction, works offline and on air-gapped machines, no account
  or subscription, simpler threat model.
- **Trade-offs:** No cross-machine aggregation; no fleet view; users are responsible for their
  own backups of the local database.
- **Alternatives rejected:** Cloud options add accounts, credentials, compliance obligations,
  and a data-exfiltration surface that the target users did not ask for.
- **Consequences:** Data lives under `%LOCALAPPDATA%\SentinelLocal` by default. Exports are
  explicit user actions and support redaction.
- **Revisit when:** users explicitly request opt-in multi-machine aggregation.

## D-004 — SQLite for persistent storage

- **Date:** 2026-10-15
- **Status:** accepted
- **Context and problem:** Observations, findings, scan history, and checkpoints must survive
  restarts and be searchable, without requiring the user to install or run a database server.
- **Options considered:** SQLite (stdlib `sqlite3`), SQLite through SQLAlchemy, PostgreSQL,
  flat JSON/CSV files, an embedded document store.
- **Decision:** SQLite via the standard-library `sqlite3` module, wrapped in a small repository
  layer with explicit SQL, parameterised queries, WAL journaling, and versioned schema
  migrations driven by `PRAGMA user_version`.
- **Reasons:** Zero-install, single file, transactional, fast enough for millions of rows with
  appropriate indexes, and supports concurrent readers with one writer under WAL — which
  matches our one-writer-thread design (D-008). Explicit SQL keeps queries reviewable; the
  schema is small enough that an ORM would add more abstraction than it removes.
- **Trade-offs:** Single-writer concurrency; schema migrations must be hand-written; no
  built-in retention, so it is implemented explicitly (D-014).
- **Alternatives rejected:** PostgreSQL — a server dependency for a single-user desktop app.
  Flat files — no indexing, no transactions, painful search. SQLAlchemy — useful for larger
  domain models; not justified for ~10 tables with hand-tuned queries.
- **Consequences:** A single writer thread owns write transactions; UI and analysis open
  separate read connections. Timestamps are stored as integer microseconds since the Unix
  epoch, UTC, so range queries and bucketing are simple integer arithmetic.
- **Revisit when:** the schema grows enough that an ORM's migration tooling pays for itself, or
  multi-writer workloads appear.

## D-005 — Windows Event Log API instead of parsing `.evtx` files

- **Date:** 2026-10-15
- **Status:** accepted
- **Context and problem:** Windows Event Logs are stored in binary `.evtx` files under
  `C:\Windows\System32\winevt\Logs`, which are locked by the Event Log service and are not
  readable by ordinary users. Message text is not stored in the file; it is rendered from
  provider resource DLLs at read time.
- **Options considered:** Windows Event Log API (`EvtQuery`, `EvtSubscribe`, `EvtRender`,
  `EvtFormatMessage`) via `pywin32`; parsing `.evtx` with a third-party parser; shelling out
  to `wevtutil` or PowerShell `Get-WinEvent`.
- **Decision:** Use the Windows Event Log API through `pywin32`'s `win32evtlog` module, behind
  a backend interface so the rest of the collector can be tested with a fake backend.
- **Reasons:** The API respects channel access control (no privilege tricks), returns properly
  rendered messages, supports XPath filtering, record-ID-based resumption, and pull-mode
  real-time subscriptions. Verified on the development machine (Windows 11, pywin32 312):
  `EvtNext` returns an empty tuple when exhausted, the `Security` channel returns
  `ERROR_ACCESS_DENIED` (5) for a non-elevated user, unknown channels return error 15007, and
  `EvtFormatMessage` fails for some providers (so a fallback to raw `EventData` is required).
- **Trade-offs:** Windows-only code path; message rendering can be slow or fail for providers
  whose resource DLLs are missing; pywin32 is a native dependency.
- **Alternatives rejected:** `.evtx` parsing — needs the locked file (admin + copying),
  produces no rendered message text, and duplicates what the OS already does. Shelling out —
  slow, locale-dependent output parsing, and spawning processes per poll.
- **Consequences:** Each event is normalised from its rendered XML plus a best-effort
  formatted message. Checkpoints store the last processed `EventRecordID` per channel.
  Inaccessible channels are reported as monitoring-health warnings, not crashes.
- **Revisit when:** a maintained pure-Python wrapper offers clear advantages, or offline
  analysis of exported `.evtx` files becomes a requirement (then add it as a separate importer).

## D-006 — Filesystem events plus periodic reconciliation

- **Date:** 2026-10-15
- **Status:** accepted
- **Context and problem:** Monitored text logs must be ingested promptly, but filesystem
  notifications are not a reliable source of truth: `ReadDirectoryChangesW` can overflow its
  buffer under heavy activity, notifications can be coalesced or missed (network shares, some
  sync tools), and nothing is delivered while the app is not running.
- **Options considered:** events only (watchdog); polling only; events plus periodic
  reconciliation.
- **Decision:** Use `watchdog` notifications as a low-latency trigger, and run a periodic
  reconciliation pass that `stat`s every configured source and compares it with its stored
  checkpoint. Ingestion itself is always driven by checkpoints, never by the event payload.
- **Reasons:** Notifications give near-real-time behaviour; reconciliation guarantees eventual
  correctness after missed notifications, restarts, rotation, or truncation. Because reading is
  checkpoint-based, a duplicate or spurious notification costs one cheap `stat`.
- **Trade-offs:** Slight extra I/O from periodic `stat` calls; worst-case latency for a missed
  notification equals the reconciliation interval.
- **Alternatives rejected:** Events only — silently loses data after overflow. Polling only —
  either slow or wasteful at short intervals.
- **Consequences:** The tailer is idempotent and safe to invoke at any time for any source.
- **Revisit when:** measurements show reconciliation cost is significant for very large
  numbers of sources.

## D-007 — Collectors, services, and UI are separate layers

- **Date:** 2026-10-15
- **Status:** accepted
- **Context and problem:** Collection code touches the operating system, analysis code must be
  deterministic and testable, and UI code must not block. Mixing them makes each harder to
  test and reason about.
- **Options considered:** layered packages (collectors / scanner / analysis / storage /
  services / ui); a feature-oriented layout; a single application module.
- **Decision:** Layered packages with one-directional dependencies:
  `ui → services → (collectors, scanner, analysis, storage) → models`. Collectors and the
  scanner never import the UI or storage; analysis never imports collectors.
- **Reasons:** Each layer can be tested in isolation; Windows-specific code is contained;
  the same services back both the desktop UI and the headless CLI.
- **Trade-offs:** More modules and explicit wiring in the service layer.
- **Alternatives rejected:** Feature-oriented layout couples OS access with analysis; a single
  module does not scale and cannot be tested without Windows.
- **Consequences:** Shared data types live in `sentinel.models`. Dependency direction is
  checked in code review.
- **Revisit when:** the layering forces awkward indirection for a real feature.

## D-008 — Worker threads, bounded queues, and batched persistence

- **Date:** 2026-10-15
- **Status:** accepted
- **Context and problem:** Event bursts (hundreds of events per second after an update or a
  crash loop) must not freeze the UI, exhaust memory, or overwhelm SQLite with one transaction
  per event.
- **Options considered:** synchronous processing on the UI thread; asyncio; worker threads with
  bounded queues; multiple processes.
- **Decision:** Collectors run on worker threads and put normalised observations onto a
  bounded `queue.Queue`. A single writer thread drains it and persists observations in batched
  transactions (by count or time, whichever comes first). When the queue is full, producers
  wait briefly (backpressure); if it remains full, the item is dropped and counted, and the
  writer records a monitoring-health warning. The UI reads through its own connection and
  receives progress through Qt signals with queued connections.
- **Reasons:** Most work is blocking I/O (Win32 API calls, file reads), which threads handle
  well despite the GIL; bounded queues cap memory; batching gives large write-throughput gains
  in SQLite; a single writer avoids lock contention.
- **Trade-offs:** Thread lifecycle and shutdown must be handled carefully; dropped events are
  possible under extreme overload (but are always reported, never silent).
- **Alternatives rejected:** UI-thread processing freezes the window. asyncio — `pywin32` and
  file I/O are blocking, so it would still need executors. Multiprocessing — serialisation and
  packaging complexity without a CPU-bound need.
- **Consequences:** Every worker takes a stop event and must exit promptly; shutdown flushes
  the queue before closing the database.
- **Revisit when:** profiling shows CPU-bound analysis is limiting throughput.

## D-009 — Deterministic rules before machine learning

- **Date:** 2026-10-15
- **Status:** accepted
- **Context and problem:** Users need findings they can verify and trust. There is no labelled
  dataset of "anomalous" Windows activity for this application to evaluate a model against.
- **Options considered:** deterministic rules plus statistical baselines; unsupervised ML
  (Isolation Forest) from day one; LLM-based classification.
- **Decision:** Implement deterministic, configurable rules and simple statistical baselines
  (mean and standard deviation of event volume) first. Every finding carries the rule ID,
  thresholds, explanation, and evidence references.
- **Reasons:** Rules are explainable, testable with synthetic fixtures, and produce
  reproducible results. Statistical baselines cover burst detection without training data.
- **Trade-offs:** Rules only catch patterns someone anticipated; thresholds need tuning per
  machine (hence configurable thresholds and suppression).
- **Alternatives rejected:** ML without a dataset or evaluation strategy would produce
  unverifiable claims; LLM classification needs external services (D-013) and can hallucinate.
- **Consequences:** No accuracy claims are made for anomaly detection. ML may be added later
  as an optional, separately evaluated component.
- **Revisit when:** sufficient representative data and a defined evaluation method exist.

## D-010 — Observations, findings, incidents, and hypotheses stored separately

- **Date:** 2026-10-15
- **Status:** accepted
- **Context and problem:** Diagnostic tools often blur what the system reported with what the
  tool inferred, which misleads users and makes conclusions impossible to audit.
- **Options considered:** a single "events" table with annotations; separate entities with
  explicit evidence links.
- **Decision:** Separate tables and types: **observations** (what a source reported),
  **findings** (a rule matched; links to evidence), **incidents** (findings grouped by
  correlation, with the reason they were grouped), and **hypotheses** (possible explanations,
  always labelled as unconfirmed, with confidence and rationale).
- **Reasons:** Users can always trace a conclusion back to the raw evidence; reports can label
  facts and hypotheses differently; retention can protect evidence that findings reference.
- **Trade-offs:** More tables and joins; evidence references must be maintained across
  retention.
- **Alternatives rejected:** A single annotated table makes it easy to present an inference as
  a fact.
- **Consequences:** Retention never deletes observations that are referenced as evidence by a
  retained finding.
- **Revisit when:** never expected; this is a core product principle.

## D-011 — Read-only filesystem behaviour; cleanup disabled by default

- **Date:** 2026-10-15
- **Status:** accepted
- **Context and problem:** Temporary directories contain files that are in use by running
  programs, installer caches needed for repair/uninstall, and crash dumps needed for
  diagnosis. Age alone does not prove a file is safe to delete.
- **Options considered:** automatic cleanup; one-click cleanup; read-only analysis with
  explained cleanup candidates.
- **Decision:** The first release never deletes, moves, or modifies files, settings, services,
  processes, the registry, or event logs. It lists cleanup **candidates** with the reasons they
  were selected and the caveats that apply.
- **Reasons:** Avoids irreversible damage; keeps the tool safe to run on any machine; builds
  trust before any destructive capability exists.
- **Trade-offs:** Users must perform cleanup themselves.
- **Alternatives rejected:** Automatic or one-click cleanup without preview and eligibility
  checks risks data loss and breaking installed software.
- **Consequences:** No code path calls file-deletion APIs. A future cleanup feature must be a
  separate, explicitly enabled capability with preview, confirmation, eligibility checks, and
  error reporting, recorded here as a new decision. No AI or rule output may authorise a
  destructive action.
- **Revisit when:** a cleanup workflow is deliberately designed and reviewed.

## D-012 — No administrator privileges for ordinary operation

- **Date:** 2026-10-15
- **Status:** accepted
- **Context and problem:** Running diagnostic tools elevated increases the blast radius of any
  bug and normalises unnecessary elevation. Some sources (the `Security` channel,
  `C:\Windows\Temp`) are restricted for standard users.
- **Options considered:** require elevation; request elevation on demand; run as the current
  user and report what is inaccessible.
- **Decision:** Run as the current user. Never self-elevate. Report inaccessible channels,
  directories, and files explicitly as limitations rather than failures.
- **Reasons:** Least privilege; the main sources (Application/System channels, the user's
  `%TEMP%`, user-owned log files) are readable without elevation.
- **Trade-offs:** Less coverage on restricted sources unless the user chooses to launch the app
  elevated themselves.
- **Alternatives rejected:** Requiring elevation is disproportionate; on-demand UAC prompts add
  complexity and a privilege boundary inside the app.
- **Consequences:** Access-denied errors are first-class results in scans, reports, and the UI.
- **Revisit when:** a specific, justified feature needs elevated access.

## D-013 — No cloud dependencies or remote AI services in the MVP

- **Date:** 2026-10-15
- **Status:** accepted
- **Context and problem:** A remote LLM could summarise findings, but would require sending
  local log content off the machine, an account or API key, and network access.
- **Options considered:** remote LLM as a core feature; optional remote LLM; optional local
  model later; deterministic explanations only.
- **Decision:** The MVP uses deterministic explanations: per-rule explanation templates and a
  small local knowledge base of well-known Windows event IDs. No network calls. An optional
  local-model integration may be considered after the core is stable.
- **Reasons:** Consistent with D-003; explanations are reproducible and testable; no API keys
  in the codebase.
- **Trade-offs:** Explanations are less fluent and only cover known patterns.
- **Alternatives rejected:** A remote LLM as a core dependency contradicts local-first operation
  and introduces hallucination risk into evidence-based findings.
- **Consequences:** Any future AI component must cite the observations and findings it used,
  label hypotheses, never invent log entries, and never execute or authorise actions.
- **Revisit when:** a local model is evaluated against real findings with a defined method.

## D-014 — Bounded retention, database size, and scan scope

- **Date:** 2026-10-15
- **Status:** accepted
- **Context and problem:** A tool that monitors logs can itself become a disk-space problem,
  and a temp scan that wanders into the whole drive can take hours and expose unrelated data.
- **Options considered:** unbounded storage and scanning; fixed hard-coded limits;
  configurable limits with safe defaults.
- **Decision:** Configurable limits with safe defaults: observation retention by age and by
  maximum row count, maximum stored message length, maximum read size per tail cycle, bounded
  error lists, scan limits on depth and entry count, and scan roots restricted to known temp
  directories plus explicitly configured paths.
- **Reasons:** Predictable resource use; the user stays in control of what is scanned.
- **Trade-offs:** Old data is eventually removed; a scan may stop early (reported as partial).
- **Alternatives rejected:** Unbounded growth is a reliability defect; hard-coded limits do not
  fit every machine.
- **Consequences:** Every limit that truncates data records that it did so (truncated
  messages, partial scans, dropped events).
- **Revisit when:** defaults prove too tight or too loose in practice.

## D-015 — Synthetic fixtures and mocked OS interfaces in automated tests

- **Date:** 2026-10-15
- **Status:** accepted
- **Context and problem:** Tests must be deterministic and must not read or alter the real
  machine's logs or temp directories, and most analysis code must be testable off Windows.
- **Options considered:** tests against live system data; synthetic fixtures with fakes for
  OS interfaces; a mix with clearly separated Windows integration tests.
- **Decision:** Unit and integration tests use synthetic log files, generated directory trees
  under pytest's `tmp_path`, and a fake Event Log backend. Tests that need the real Windows
  API are marked `windows` and only read data (never write to or clear event logs).
- **Reasons:** Reproducible results, no dependence on machine state, safe to run anywhere.
- **Trade-offs:** Fakes can drift from real API behaviour; mitigated by a small set of
  read-only Windows integration tests run on a Windows CI runner.
- **Alternatives rejected:** Live-data tests are non-deterministic and could expose real data
  in CI logs.
- **Consequences:** Never write to, clear, or depend on the content of real event logs in tests.
- **Revisit when:** a sandboxed Windows test environment with controlled event injection is
  available.

## D-016 — Executable packaging deferred until the application is stable

- **Date:** 2026-10-15
- **Status:** accepted
- **Context and problem:** Packaging with PyInstaller surfaces hidden-import and data-file
  issues that change whenever the module structure changes.
- **Options considered:** package from day one; package once the module layout is stable.
- **Decision:** Add PyInstaller packaging in the hardening phase, once the module layout and
  dependencies are stable, and verify that the packaged executable starts.
- **Reasons:** Avoids repeatedly reworking the packaging configuration.
- **Trade-offs:** Packaging problems are discovered later.
- **Alternatives rejected:** Early packaging would churn with every structural change.
- **Consequences:** Until then, the supported way to run the app is `python -m sentinel`.
- **Revisit when:** packaging is implemented (record the outcome here).

## D-017 — Small, verified commits pushed directly to the working branch

- **Date:** 2026-10-15
- **Status:** accepted
- **Context and problem:** The repository owner asked for changes committed and pushed in
  small logical increments to the existing branch, without pull requests. The local
  repository had no remote; the owner confirmed `origin` =
  `https://github.com/tecsmurf/Sentinel` and the working branch `master`.
- **Options considered:** one large final commit; feature branches with pull requests; small
  verified commits pushed directly to `master`.
- **Decision:** Each logical change is implemented, linted, tested, reviewed as a staged diff,
  committed with a conventional commit message, and pushed to `origin/master` before the next
  change starts. No force pushes, no history rewriting, no pull requests.
- **Reasons:** Keeps history reviewable and bisectable; a failure is isolated to one change;
  the remote always reflects verified work.
- **Trade-offs:** More commits; CI runs on every push.
- **Alternatives rejected:** A giant final commit is unreviewable; pull requests were
  explicitly not requested.
- **Consequences:** Generated artifacts, virtual environments, databases, and caches are
  excluded via `.gitignore`.
- **Revisit when:** more contributors join (then consider branch protection and pull requests).

## D-018 — `src/` package layout with a single `sentinel` package

- **Date:** 2026-10-15
- **Status:** accepted
- **Context and problem:** The specification suggests an `app/sentinel/` layout. The project
  needs reliable imports in tests, an installable package for the CLI entry point, and clean
  PyInstaller packaging.
- **Options considered:** `app/sentinel/`; flat `sentinel/` at the repository root;
  `src/sentinel/`.
- **Decision:** Use `src/sentinel/` with a `pyproject.toml` build configuration.
- **Reasons:** The `src/` layout forces tests to run against the installed package rather
  than accidentally importing from the working directory, which is the standard Python
  packaging recommendation. The internal subpackages follow the specification
  (`collectors`, `scanner`, `analysis`, `storage`, `services`, `ui`).
- **Trade-offs:** Requires an editable install (`pip install -e .`) for development.
- **Alternatives rejected:** `app/` is not a packaging convention; a flat layout allows tests
  to pass against uninstalled code.
- **Consequences:** Tests import `sentinel.*`; the console entry point is `sentinel`.
- **Revisit when:** not expected.

## D-019 — Text logs: shared-delete opens, bounded backfill, generations for rotation

- **Date:** 2026-10-18
- **Status:** accepted
- **Context and problem:** Applications rotate their logs by renaming or deleting the active
  file. On Windows, Python's built-in `open()` does not pass `FILE_SHARE_DELETE`, so while
  Sentinel holds a log open, the application's rename fails (verified by
  `tests/windows/test_text_logs_windows.py`). Separately, a newly configured log can already
  be gigabytes long, and rotation can reuse byte offsets that were already ingested.
- **Options considered:** plain `open()` with very short read windows; `CreateFile` with
  `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE`; copying the file before reading.
  For history: import everything vs. start at the end vs. a bounded backfill. For offset
  reuse: rely on content hashes only vs. generation counters plus content hashes.
- **Decision:** On Windows, open logs through `CreateFile` with all three share flags
  (`collectors.text_logs.open_shared`). A newly discovered file is read from at most
  `monitoring.initial_backfill_bytes` (default 1 MiB) before its end, starting at the next
  line boundary, and this is reported. Rotation, truncation, and in-place rewrites (detected
  from file identity, size, and a SHA-256 of the first 1 KiB) start a new *generation*;
  deduplication keys combine source, path, generation, offset, and a content hash.
- **Reasons:** Monitoring must never interfere with the monitored application. Bounded
  backfill keeps first ingestion fast and the database small while still capturing recent
  context. Generations make keys unique across rotations even on filesystems without stable
  file IDs.
- **Trade-offs:** Windows-specific open path (covered by Windows tests); history older than
  the backfill window is not imported; data written to a file after Sentinel's last read but
  before rotation can be missed — when detectable, this is reported as a warning.
- **Alternatives rejected:** Plain `open()` blocks rotation; copying files doubles I/O and
  still races the writer; importing full history is unbounded (D-014).
- **Consequences:** Checkpoints store `file_id`, `generation`, `offset`, `head_hash`,
  encoding, and pending-record state per file.
- **Revisit when:** reading rotated predecessor files (`app.log.1`) to close the rotation gap
  becomes a requirement.

## D-020 — Backpressure by not advancing checkpoints; epochs after failed writes

- **Date:** 2026-10-18
- **Status:** accepted
- **Context and problem:** D-008 requires bounded queues and backpressure, and that any
  dropped data is reported. Both collectors are pull-based and checkpointed (text-log byte
  offsets, Event Log record IDs), so data that is not yet persisted can always be read again.
  A naive design that advances checkpoints when data is *read* would lose data whenever the
  queue is full or a database write fails.
- **Options considered:** drop and count when the queue is full; block producers
  indefinitely; advance working checkpoints only when a batch is accepted by the queue, and
  rewind to the last committed checkpoints after a failed write.
- **Decision:** A worker advances its working checkpoints only when the writer queue accepts
  the batch. When the queue is full (after `enqueue_timeout_seconds`) the batch is discarded,
  checkpoints stay put, an `ingestion_delayed` health warning is recorded (rate-limited), and
  the worker retries shortly — re-reading the same data. If a database write fails, the
  pipeline restores the last *committed* checkpoints and increments an epoch counter; batches
  stamped with an older epoch are discarded both when offered and when dequeued, closing the
  race where a batch collected before the rewind could advance past un-persisted data.
- **Reasons:** No silent loss and no unbounded memory; the only cost of overload is latency,
  which is reported. Deduplication keys make the re-reads idempotent.
- **Trade-offs:** Under sustained overload the same data is read repeatedly; collection
  latency grows until the writer catches up.
- **Alternatives rejected:** Drop-and-count loses data that could have been kept; blocking
  indefinitely stalls shutdown and health reporting.
- **Consequences:** `MonitoringService` keeps working and committed checkpoint maps and an
  epoch; `IngestionPipeline.run_once` provides the same semantics synchronously for the CLI.
- **Revisit when:** a push-based source (one that cannot re-read) is added; it would need a
  local spool or explicit drop accounting.
