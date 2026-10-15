"""Constants and helpers shared by test modules (importable as ``tests.support``)."""

from __future__ import annotations

import os
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

BASE_TIME = datetime(2026, 10, 15, 12, 0, tzinfo=UTC)


class FlakyEntry:
    """Wraps a real ``os.DirEntry`` and makes ``stat()`` raise a chosen error."""

    def __init__(self, entry: os.DirEntry, error: BaseException | None) -> None:
        self._entry = entry
        self._error = error
        self.name = entry.name
        self.path = entry.path

    def is_symlink(self) -> bool:
        return self._entry.is_symlink()

    def is_junction(self) -> bool:
        return False

    def is_dir(self, *, follow_symlinks: bool = True) -> bool:
        return self._entry.is_dir(follow_symlinks=follow_symlinks)

    def stat(self, *, follow_symlinks: bool = True) -> os.stat_result:
        if self._error is not None:
            raise self._error
        return self._entry.stat(follow_symlinks=follow_symlinks)


def fake_scandir(deny: frozenset[str] | set[str] = frozenset(), entry_errors: dict | None = None):
    """A drop-in for ``os.scandir`` that denies listing named directories or fails stat()."""
    errors = entry_errors or {}

    @contextmanager
    def scandir(path: str):
        if Path(path).name in deny:
            raise PermissionError(13, "Access is denied", path)
        with os.scandir(path) as iterator:
            yield [FlakyEntry(entry, errors.get(entry.name)) for entry in iterator]

    return scandir
