"""Deterministic, local explanations and safe next steps (DECISIONS.md D-009, D-013).

``explain_event`` covers well-known Windows events in plain language. Every recommendation
is a *diagnostic* step the user can take; none changes the system automatically, and the
wording never presents a pattern as proof of a root cause or of a security incident.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class EventAdvice:
    meaning: str
    next_step: str
    commonly_benign: bool = False


_SCM = "service control manager"
_SERVICE_STEP = (
    "Open Services (services.msc), find the service, and review its Recovery settings and "
    "dependencies; check the vendor's own logs and whether an update is available."
)

_KNOWN_EVENTS: dict[tuple[str, str], EventAdvice] = {
    (_SCM, "7000"): EventAdvice("A service failed to start.", _SERVICE_STEP),
    (_SCM, "7001"): EventAdvice(
        "A service could not start because a service it depends on failed.", _SERVICE_STEP
    ),
    (_SCM, "7009"): EventAdvice("A service did not respond in time while starting.", _SERVICE_STEP),
    (_SCM, "7011"): EventAdvice(
        "A service did not respond to a control request in time.", _SERVICE_STEP
    ),
    (_SCM, "7022"): EventAdvice("A service hung while starting.", _SERVICE_STEP),
    (_SCM, "7023"): EventAdvice("A service stopped with an error.", _SERVICE_STEP),
    (_SCM, "7024"): EventAdvice("A service stopped with a service-specific error.", _SERVICE_STEP),
    (_SCM, "7031"): EventAdvice(
        "A service terminated unexpectedly and Windows applied its recovery action.",
        _SERVICE_STEP,
    ),
    (_SCM, "7034"): EventAdvice("A service terminated unexpectedly.", _SERVICE_STEP),
    ("application error", "1000"): EventAdvice(
        "An application crashed (an unhandled fault ended the process).",
        "Note the faulting module named in the event; update or repair the application, "
        "and check Reliability Monitor (perfmon /rel) for the crash history.",
    ),
    ("application hang", "1002"): EventAdvice(
        "An application stopped responding and was closed.",
        "Check whether the hang coincides with heavy disk, network, or memory use; update "
        "the application if hangs repeat.",
    ),
    ("windows error reporting", "1001"): EventAdvice(
        "Windows Error Reporting recorded a fault report (crash, hang, or kernel event).",
        "Open the event details to see the reported problem type and bucket; Reliability "
        "Monitor (perfmon /rel) shows the related history.",
    ),
    (".net runtime", "1026"): EventAdvice(
        "A .NET application terminated because of an unhandled exception.",
        "Read the exception type and stack in the event message; report it to the "
        "application's vendor or developer if it repeats.",
    ),
    ("microsoft-windows-kernel-power", "41"): EventAdvice(
        "The system restarted without first shutting down cleanly (power loss, a crash, "
        "or a forced reset).",
        "Check for a crash dump or bug-check event at the same time, and review power "
        "supply, overheating, and recent driver or hardware changes.",
    ),
    ("eventlog", "6008"): EventAdvice(
        "The previous system shutdown was unexpected.",
        "Look for crash, power, or hardware events immediately before this time.",
    ),
    ("microsoft-windows-whea-logger", "17"): EventAdvice(
        "A corrected hardware error was reported by the platform.",
        "Occasional corrected errors can be harmless; frequent ones warrant checking "
        "firmware/BIOS updates, drivers, and hardware health.",
    ),
    ("microsoft-windows-whea-logger", "18"): EventAdvice(
        "A fatal hardware error was reported by the processor or platform.",
        "Check firmware/BIOS and chipset driver updates, temperatures, and any recent "
        "overclocking; consider hardware diagnostics.",
    ),
    ("microsoft-windows-whea-logger", "19"): EventAdvice(
        "A corrected hardware error was reported.",
        "Monitor how often this occurs; frequent repeats suggest a hardware or firmware "
        "issue worth investigating.",
    ),
    ("disk", "7"): EventAdvice(
        "The disk reported a bad block.",
        "Back up important data, then check the drive's health with the manufacturer's "
        "tool or `chkdsk` (read-only scan first).",
    ),
    ("disk", "51"): EventAdvice(
        "An error was detected during a paging operation on a disk.",
        "Check cables/connections and drive health; back up important data.",
    ),
    ("disk", "153"): EventAdvice(
        "Disk I/O operations were retried.",
        "Repeated retries can indicate a failing drive or connection; check drive health "
        "and cabling.",
    ),
    ("ntfs", "55"): EventAdvice(
        "The file system detected corruption on a volume.",
        "Back up data and run a read-only `chkdsk` scan of the volume to assess the damage.",
    ),
    ("microsoft-windows-ntfs", "55"): EventAdvice(
        "The file system detected corruption on a volume.",
        "Back up data and run a read-only `chkdsk` scan of the volume to assess the damage.",
    ),
    ("display", "4101"): EventAdvice(
        "The display driver stopped responding and recovered.",
        "Update the graphics driver from the GPU vendor and check GPU temperatures.",
    ),
    ("microsoft-windows-distributedcom", "10016"): EventAdvice(
        "A component requested a COM permission it was not granted.",
        "This is commonly benign on Windows; consider suppressing it unless an "
        "application is visibly failing.",
        commonly_benign=True,
    ),
    ("microsoft-windows-windowsupdateclient", "20"): EventAdvice(
        "A Windows Update installation failed.",
        "Open Settings > Windows Update to retry and note the error code shown there.",
    ),
}

RULE_NEXT_STEPS: dict[str, str] = {
    "repeated_error": (
        "Open the supporting events to compare the repeated message and its source; check "
        "the application's documentation or vendor support for that error."
    ),
    "app_crash": (
        "Check Reliability Monitor (perfmon /rel) for the crash history, update or repair "
        "the application, and note the faulting module named in the events."
    ),
    "service_failure": _SERVICE_STEP,
    "critical_event": (
        "Review the critical event and anything that happened shortly before it; the event "
        "details explain what Windows recorded."
    ),
    "log_growth": (
        "Look at what the application is writing (often a repeating error or debug logging "
        "left on) and whether its log rotation is configured."
    ),
    "temp_growth": (
        "Review the folders that grew in File Intelligence. Close the applications that own "
        "them before removing anything; Sentinel does not delete files."
    ),
    "event_burst": (
        "Inspect the events in the burst window for a common provider or message; bursts "
        "often follow updates, driver problems, or a failing component retrying rapidly."
    ),
    "error_cluster": (
        "Review the timeline: errors from several components at the same moment often share "
        "a common trigger such as a resource shortage, sleep/resume, or an update."
    ),
    "collector_health": (
        "Open Settings to check the affected source (path, permissions, encoding). Sentinel's "
        "own monitoring gaps mean the data shown may be incomplete."
    ),
}


def explain_event(provider: str, event_code: str) -> EventAdvice | None:
    """Plain-language meaning of a well-known Windows event, if it is known."""
    return _KNOWN_EVENTS.get((provider.strip().casefold(), event_code.strip()))


def next_step(rule_id: str, provider: str = "", event_code: str = "") -> str:
    """The recommended next step for a finding, preferring event-specific advice."""
    advice = explain_event(provider, event_code) if provider and event_code else None
    if advice is not None:
        return advice.next_step
    return RULE_NEXT_STEPS.get(rule_id, "Review the supporting evidence before taking any action.")
