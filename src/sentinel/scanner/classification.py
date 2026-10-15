"""File classification and cleanup-candidate assessment from metadata only.

Classification uses the file name and extension; it never reads file contents. A
cleanup *candidate* is a file worth reviewing — never a file declared safe to delete.
Age alone is not treated as sufficient evidence (D-011).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

UNKNOWN = "other"

_BY_EXTENSION: dict[str, str] = {
    **dict.fromkeys((".tmp", ".temp", "._mp", ".~tmp"), "temporary"),
    **dict.fromkeys((".log", ".log1", ".log2", ".etl", ".evtx", ".trace"), "log"),
    **dict.fromkeys((".dmp", ".mdmp", ".hdmp"), "crash_dump"),
    **dict.fromkeys((".wer",), "error_report"),
    **dict.fromkeys((".msi", ".msp", ".msu", ".cab"), "installer"),
    **dict.fromkeys((".zip", ".7z", ".rar", ".gz", ".tgz", ".tar", ".xz", ".bz2"), "archive"),
    **dict.fromkeys((".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl"), "executable"),
    **dict.fromkeys(
        (".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta"),
        "script",
    ),
    **dict.fromkeys((".crdownload", ".part", ".partial", ".download", ".opdownload"), "download"),
    **dict.fromkeys((".bak", ".old", ".orig"), "backup"),
    **dict.fromkeys((".cache", ".bin", ".dat"), "cache_data"),
    **dict.fromkeys((".db", ".sqlite", ".sqlite3", ".ldb", ".db-wal", ".db-shm"), "database"),
    **dict.fromkeys((".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".ico"), "image"),
    **dict.fromkeys(
        (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf", ".odt"), "document"
    ),
    **dict.fromkeys((".json", ".xml", ".ini", ".cfg", ".yaml", ".yml", ".txt", ".csv"), "text"),
}

CLASSIFICATION_LABELS: dict[str, str] = {
    "temporary": "Temporary file",
    "log": "Log or trace file",
    "crash_dump": "Crash dump",
    "error_report": "Windows Error Reporting file",
    "installer": "Installer package",
    "archive": "Archive",
    "executable": "Executable or library",
    "script": "Script",
    "download": "Incomplete download",
    "backup": "Backup copy",
    "cache_data": "Cache or binary data",
    "database": "Database file",
    "image": "Image",
    "document": "Document",
    "text": "Text or configuration",
    "office_lock": "Office owner/lock file",
    UNKNOWN: "Other",
}

# Classes that are reasonable to *review* for cleanup once they are old.
_REVIEWABLE = frozenset(
    {"temporary", "log", "download", "backup", "archive", "office_lock", "error_report"}
)
# Classes that need extra caution: listed only with an explicit caveat.
_CAUTION: dict[str, str] = {
    "crash_dump": "may be needed to diagnose a crash; keep it if the problem is unresolved",
    "installer": "installer caches can be needed to repair or uninstall software",
    "cache_data": "an application may rebuild or still rely on this cache",
}
# Never proposed: removing these could break something that is running or installing.
_NEVER = frozenset({"executable", "script", "database"})

_MAX_EXTENSION_LENGTH = 16


def file_extension(name: str) -> str:
    """Lower-case extension including the dot ('' if none, '(long)' if implausibly long)."""
    dot = name.rfind(".")
    if dot <= 0 or dot == len(name) - 1:
        return ""
    ext = name[dot:].lower()
    return ext if len(ext) <= _MAX_EXTENSION_LENGTH else "(long)"


def classify(name: str, extension: str | None = None) -> str:
    """Classify a file by name and extension. Never reads the file."""
    if name.startswith("~$"):
        return "office_lock"
    ext = file_extension(name) if extension is None else extension
    return _BY_EXTENSION.get(ext, UNKNOWN)


@dataclass(frozen=True, slots=True)
class CandidatePolicy:
    min_age_days: int = 7

    @property
    def unknown_type_min_age_days(self) -> int:
        # Files of unknown type need a stronger signal before being suggested for review.
        return self.min_age_days * 4


def assess_candidate(
    classification: str,
    extension: str,
    modified_at: datetime,
    created_at: datetime | None,
    now: datetime,
    policy: CandidatePolicy,
) -> list[str] | None:
    """Return the reasons a file is worth reviewing for cleanup, or ``None`` if it is not.

    The reasons are written for the user and always explain the evidence; a caveat is
    appended for classes where removal has known risks.
    """
    if classification in _NEVER:
        return None
    last_change = max(modified_at, created_at) if created_at else modified_at
    age = now - last_change
    if classification == UNKNOWN:
        required = timedelta(days=policy.unknown_type_min_age_days)
    elif classification in _REVIEWABLE or classification in _CAUTION:
        required = timedelta(days=policy.min_age_days)
    else:
        return None
    if age < required:
        return None

    label = CLASSIFICATION_LABELS.get(classification, "Other")
    type_text = f"{label} ({extension})" if extension else label
    reasons = [
        f"not modified for {age.days} days",
        f"type: {type_text}",
        "located in a temporary directory",
    ]
    if classification in _CAUTION:
        reasons.append(f"caution: {_CAUTION[classification]}")
    return reasons
