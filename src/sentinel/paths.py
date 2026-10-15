"""Application data locations and Windows-aware path handling.

Paths configured by the user may contain Windows environment variables (``%TEMP%``),
``~``, surrounding quotes, 8.3 short names, or junctions. Everything that compares or
deduplicates paths goes through :func:`canonical_key`, which resolves links and
normalises case the way the operating system does.
"""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

APP_DIR_NAME = "SentinelLocal"
HOME_ENV_VAR = "SENTINEL_HOME"

_PERCENT_VAR = re.compile(r"%([^%\\/:*?\"<>|]+)%")


class PathError(ValueError):
    """A configured path is empty, malformed, relative, or references an unknown variable."""


@dataclass(frozen=True)
class AppPaths:
    """Locations of Sentinel Local's own files (configuration, database, logs, reports)."""

    root: Path

    @property
    def config_file(self) -> Path:
        return self.root / "config.json"

    @property
    def database_file(self) -> Path:
        return self.root / "sentinel.db"

    @property
    def log_dir(self) -> Path:
        return self.root / "logs"

    @property
    def reports_dir(self) -> Path:
        return self.root / "reports"

    def ensure(self) -> AppPaths:
        for directory in (self.root, self.log_dir, self.reports_dir):
            directory.mkdir(parents=True, exist_ok=True)
        return self


def default_data_dir(environ: Mapping[str, str] | None = None) -> Path:
    """Return the per-user data directory, honouring the ``SENTINEL_HOME`` override."""
    env = os.environ if environ is None else environ
    override = env.get(HOME_ENV_VAR)
    if override:
        return Path(override).expanduser()
    if sys.platform == "win32":
        local_app_data = env.get("LOCALAPPDATA")
        base = Path(local_app_data) if local_app_data else Path.home() / "AppData" / "Local"
        return base / APP_DIR_NAME
    xdg = env.get("XDG_DATA_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "share"
    return base / APP_DIR_NAME


def expand_vars(text: str, environ: Mapping[str, str] | None = None) -> str:
    """Expand ``%NAME%`` variables (case-insensitively, as Windows does).

    Raises :class:`PathError` if a referenced variable is not defined, rather than
    leaving a literal ``%NAME%`` that would later be treated as a relative path.
    """
    env = os.environ if environ is None else environ
    lookup = {key.upper(): value for key, value in env.items()}

    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        value = lookup.get(name.upper())
        if value is None:
            raise PathError(f"environment variable %{name}% is not defined")
        return value

    return _PERCENT_VAR.sub(replace, text)


def expand_path(raw: str, environ: Mapping[str, str] | None = None) -> Path:
    """Turn a user-supplied path string into an absolute :class:`Path`.

    Strips surrounding whitespace and quotes, expands ``%VAR%`` and ``~``, and rejects
    empty, NUL-containing, and relative paths.
    """
    text = raw.strip().strip('"').strip()
    if not text:
        raise PathError("path is empty")
    if "\x00" in text:
        raise PathError("path contains a NUL character")
    expanded = os.path.expanduser(expand_vars(text, environ))
    path = Path(expanded)
    if not path.is_absolute():
        raise PathError(f"path must be absolute: {raw!r}")
    return path


def resolve(path: Path | str) -> Path:
    """Resolve junctions, symbolic links, and 8.3 short names without requiring existence."""
    try:
        return Path(os.path.realpath(path))
    except OSError:
        return Path(os.path.abspath(path))


def canonical_key(path: Path | str) -> str:
    """A string that is equal for two paths if and only if they name the same location."""
    return os.path.normcase(str(resolve(path)))


def _key_within(child_key: str, root_key: str) -> bool:
    try:
        return os.path.commonpath([child_key, root_key]) == root_key
    except ValueError:  # different drives, or mixed absolute/relative
        return False


def is_within(child: Path | str, root: Path | str) -> bool:
    """True if ``child`` is ``root`` or is located inside it (after resolution)."""
    return _key_within(canonical_key(child), canonical_key(root))


@dataclass(frozen=True)
class RootSelection:
    """Result of deduplicating scan roots."""

    roots: list[Path] = field(default_factory=list)
    skipped: list[tuple[Path, str]] = field(default_factory=list)


def dedupe_roots(paths: Iterable[Path]) -> RootSelection:
    """Drop duplicate roots and roots nested inside another root.

    Kept roots are returned resolved and in their original order. Each skipped root is
    reported with the reason, so the UI can disclose exactly what will be scanned.
    """
    candidates = [(index, path, resolve(path)) for index, path in enumerate(paths)]
    keyed = [
        (canonical_key(resolved), index, path, resolved) for index, path, resolved in candidates
    ]
    # Shorter keys first so that a parent is always considered before its children.
    keyed.sort(key=lambda item: (len(item[0]), item[1]))

    kept: list[tuple[str, int, Path]] = []
    skipped: list[tuple[int, Path, str]] = []
    for key, index, original, resolved in keyed:
        duplicate = next((root for k, _, root in kept if k == key), None)
        if duplicate is not None:
            skipped.append((index, original, f"same location as {duplicate}"))
            continue
        parent = next((root for k, _, root in kept if _key_within(key, k)), None)
        if parent is not None:
            skipped.append((index, original, f"already covered by {parent}"))
            continue
        kept.append((key, index, resolved))

    kept.sort(key=lambda item: item[1])
    skipped.sort(key=lambda item: item[0])
    return RootSelection(
        roots=[root for _, _, root in kept],
        skipped=[(path, reason) for _, path, reason in skipped],
    )
