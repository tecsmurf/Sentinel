# Sentinel Local

**Windows system intelligence, log monitoring, and temporary-file analysis — entirely on your
own machine.**

Sentinel Local is a desktop application for Windows that watches Windows Event Logs and the
application log files you choose, analyses temporary directories and how they grow, detects
meaningful patterns (repeated errors, application crashes, service failures, event bursts,
abnormal log or temp growth), groups related findings into investigation timelines, and
explains each finding with the evidence behind it.

It needs no internet connection, account, subscription, cloud service, or external AI API.

> **Project status: early development (Phase 0 — documentation and architecture).**
> No application code has been written yet. This README describes what is implemented as the
> project progresses; see [CONTEXT.md](CONTEXT.md) for the exact current state and
> [DECISIONS.md](DECISIONS.md) for the reasoning behind the architecture.

## Principles

- **Local-first:** collect, analyse, and store locally. No telemetry.
- **Evidence before conclusions:** every finding links to the observations that triggered it;
  possible explanations are labelled as hypotheses, never as facts.
- **Read-only:** Sentinel Local never deletes files or changes system settings. It can point
  out cleanup *candidates* and explain why, but you decide what to do.
- **Least privilege:** runs as your normal user account and tells you plainly what it could
  not access.
- **Bounded:** configurable retention and scan limits so the monitoring tool never becomes the
  disk-space problem.

## Planned features

- Real-time monitoring of the Windows Application and System event logs (plus channels you
  select) and of configured `.log`, `.txt`, and JSON-lines files.
- On-demand scans of `%TEMP%`, `C:\Windows\Temp` (when accessible), and folders you add, with
  size, age, and type breakdowns and growth between scans.
- Deterministic detection rules with configurable thresholds, deduplication, acknowledgement,
  and suppression.
- Incident timelines that show which events were grouped and why.
- Searchable local history.
- JSON, Markdown, and HTML reports with optional redaction.

## Requirements

- Windows 10 or 11 (x64)
- Python 3.12

Installation, usage, and testing instructions will be added as the corresponding features are
implemented.

## Documentation

- [CONTEXT.md](CONTEXT.md) — current implementation state and how to continue development.
- [DECISIONS.md](DECISIONS.md) — architectural decision record.
