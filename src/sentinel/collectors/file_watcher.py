"""Filesystem notifications for monitored log files.

Notifications are only a low-latency *trigger* (DECISIONS.md D-006): they mark a source
as dirty so the tail worker polls it immediately. Correctness never depends on them —
``ReadDirectoryChangesW`` can overflow, and nothing is delivered while the app is not
running — so the monitoring service also reconciles every source periodically.
"""

from __future__ import annotations

import fnmatch
import logging
import os
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from sentinel.collectors.text_logs import HealthNote
from sentinel.config import TextLogSource
from sentinel.models import Severity
from sentinel.paths import PathError, expand_path

logger = logging.getLogger(__name__)


def _norm(path: str) -> str:
    return os.path.normcase(os.path.abspath(path))


@dataclass(frozen=True, slots=True)
class _Target:
    source_id: str
    directory: str  # normalised
    file_name: str | None  # normalised exact name for file sources
    pattern: str  # lower-case glob for directory sources
    recursive: bool

    def matches(self, path: str) -> bool:
        normalised = _norm(path)
        parent, name = os.path.split(normalised)
        if self.file_name is not None:
            return parent == self.directory and name == self.file_name
        if self.recursive:
            inside = normalised.startswith(self.directory + os.sep)
        else:
            inside = parent == self.directory
        return inside and fnmatch.fnmatch(name.lower(), self.pattern)


class _Handler(FileSystemEventHandler):
    def __init__(self, targets: list[_Target], on_change: Callable[[str], None]) -> None:
        self._targets = targets
        self._on_change = on_change

    def on_any_event(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        paths = [event.src_path, getattr(event, "dest_path", "") or ""]
        notified: set[str] = set()
        for raw in paths:
            if not raw:
                continue
            path = os.fsdecode(raw)
            for target in self._targets:
                if target.source_id not in notified and target.matches(path):
                    notified.add(target.source_id)
                    try:
                        self._on_change(target.source_id)
                    except Exception:  # never let a callback error kill the observer thread
                        logger.exception("log watcher callback failed")


def _target_for(source: TextLogSource) -> _Target | None:
    try:
        path = expand_path(source.path)
    except PathError:
        return None  # reported by discover_files during polling
    if path.is_dir() or (not path.exists() and not path.suffix):
        return _Target(source.id, _norm(str(path)), None, source.pattern.lower(), source.recursive)
    return _Target(
        source.id, _norm(str(path.parent)), os.path.normcase(path.name), "", recursive=False
    )


def _unavailable(directory: str, reason: str) -> HealthNote:
    return HealthNote(
        "watch_unavailable",
        Severity.INFO,
        f"change notifications unavailable ({reason}); the folder is still checked periodically",
        directory,
    )


class LogWatcher:
    """Owns one watchdog observer covering all enabled text-log sources."""

    def __init__(self, on_change: Callable[[str], None]) -> None:
        self._on_change = on_change
        self._observer: Observer | None = None

    @property
    def running(self) -> bool:
        return self._observer is not None and self._observer.is_alive()

    def watch(self, sources: Iterable[TextLogSource]) -> list[HealthNote]:
        """(Re)configure watches. Returns notes for directories that cannot be watched."""
        self.stop()
        targets = [t for s in sources if s.enabled and (t := _target_for(s)) is not None]
        if not targets:
            return []
        by_directory: dict[str, list[_Target]] = {}
        for target in targets:
            by_directory.setdefault(target.directory, []).append(target)

        observer = Observer()
        observer.daemon = True
        handler = _Handler(targets, self._on_change)
        notes: list[HealthNote] = []
        scheduled = 0
        for directory, group in by_directory.items():
            recursive = any(t.recursive for t in group)
            # On Windows a missing folder only fails later, inside observer.start().
            if not os.path.isdir(directory):
                notes.append(_unavailable(directory, "folder does not exist"))
                continue
            try:
                observer.schedule(handler, directory, recursive=recursive)
                scheduled += 1
            except OSError as exc:
                notes.append(_unavailable(directory, str(exc.strerror or exc)))
        if not scheduled:
            return notes
        try:
            observer.start()
        except OSError as exc:  # e.g. a folder removed between the check and start()
            notes.extend(_unavailable(d, str(exc.strerror or exc)) for d in by_directory)
            logger.warning("log watcher could not start; relying on periodic checks")
            return notes
        self._observer = observer
        return notes

    def stop(self) -> None:
        observer, self._observer = self._observer, None
        if observer is None:
            return
        observer.stop()
        observer.join(timeout=5)
