"""Typed application configuration with validation and atomic persistence.

The configuration file is user-editable JSON. Loading never fails because of bad
content: invalid values fall back to defaults, out-of-range numbers are clamped, and
every correction is reported as a warning so the UI can show it.
"""

from __future__ import annotations

import codecs
import contextlib
import dataclasses
import hashlib
import json
import os
import re
import tempfile
import time
import types
import typing
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

CONFIG_VERSION = 1

_INVALID = object()  # sentinel: "value rejected, keep the field default"


def _bounded(default: int | float, *, minimum: float | None = None, maximum: float | None = None):
    return field(default=default, metadata={"min": minimum, "max": maximum})


@dataclass
class EventLogSettings:
    enabled: bool = True
    channels: list[str] = field(default_factory=lambda: ["Application", "System"])
    min_severity: Literal["debug", "info", "warning", "error", "critical"] = "info"
    initial_lookback_hours: int = _bounded(24, minimum=0, maximum=24 * 90)
    max_initial_events_per_channel: int = _bounded(5000, minimum=0, maximum=200_000)
    poll_interval_seconds: float = _bounded(5.0, minimum=0.5, maximum=3600)
    exclude_providers: list[str] = field(default_factory=list)
    exclude_event_ids: list[int] = field(default_factory=list)


@dataclass
class TextLogSource:
    """A monitored log file, or a directory of log files matching ``pattern``."""

    path: str = ""
    id: str = ""
    name: str = ""
    pattern: str = "*.log"
    recursive: bool = False
    format: Literal["auto", "text", "json"] = "auto"
    encoding: str = "auto"
    multiline_start: str | None = None
    line_pattern: str | None = None
    timestamp_format: str | None = None
    enabled: bool = True


@dataclass
class TempScanSettings:
    include_user_temp: bool = True
    include_windows_temp: bool = True
    extra_roots: list[str] = field(default_factory=list)
    max_depth: int = _bounded(32, minimum=1, maximum=256)
    max_entries: int = _bounded(500_000, minimum=1_000, maximum=10_000_000)
    top_files_kept: int = _bounded(100, minimum=10, maximum=5_000)
    candidate_min_age_days: int = _bounded(7, minimum=1, maximum=3650)
    max_candidates: int = _bounded(500, minimum=10, maximum=10_000)


@dataclass
class MonitoringSettings:
    start_on_launch: bool = True
    queue_max_size: int = _bounded(10_000, minimum=100, maximum=1_000_000)
    batch_size: int = _bounded(500, minimum=1, maximum=10_000)
    batch_interval_seconds: float = _bounded(1.0, minimum=0.05, maximum=60)
    enqueue_timeout_seconds: float = _bounded(2.0, minimum=0, maximum=60)
    reconcile_interval_seconds: float = _bounded(30.0, minimum=1, maximum=3600)
    analysis_interval_seconds: float = _bounded(60.0, minimum=5, maximum=86_400)
    max_message_chars: int = _bounded(8192, minimum=256, maximum=1_000_000)
    max_line_bytes: int = _bounded(65_536, minimum=1024, maximum=16 * 1024 * 1024)
    max_read_bytes_per_cycle: int = _bounded(
        4 * 1024 * 1024, minimum=64 * 1024, maximum=256 * 1024 * 1024
    )
    multiline_flush_seconds: float = _bounded(5.0, minimum=0.5, maximum=600)


@dataclass
class RetentionSettings:
    observation_days: int = _bounded(30, minimum=1, maximum=3650)
    max_observations: int = _bounded(1_000_000, minimum=10_000, maximum=100_000_000)
    scan_history_days: int = _bounded(90, minimum=1, maximum=3650)
    metric_days: int = _bounded(30, minimum=1, maximum=3650)
    closed_finding_days: int = _bounded(90, minimum=1, maximum=3650)


@dataclass
class NotificationSettings:
    enabled: bool = True
    min_severity: Literal["low", "medium", "high", "critical"] = "high"


@dataclass
class PrivacySettings:
    redact_exports_by_default: bool = True
    include_raw_messages_in_reports: bool = True


@dataclass
class UiSettings:
    theme: Literal["system", "light", "dark"] = "system"
    refresh_interval_ms: int = _bounded(2000, minimum=250, maximum=60_000)


@dataclass
class AppConfig:
    version: int = CONFIG_VERSION
    event_logs: EventLogSettings = field(default_factory=EventLogSettings)
    text_logs: list[TextLogSource] = field(default_factory=list)
    temp_scan: TempScanSettings = field(default_factory=TempScanSettings)
    monitoring: MonitoringSettings = field(default_factory=MonitoringSettings)
    retention: RetentionSettings = field(default_factory=RetentionSettings)
    notifications: NotificationSettings = field(default_factory=NotificationSettings)
    privacy: PrivacySettings = field(default_factory=PrivacySettings)
    ui: UiSettings = field(default_factory=UiSettings)
    # Per-rule overrides, e.g. {"repeated_error": {"threshold": 5}}; validated by the rules module.
    rules: dict[str, dict[str, Any]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, data: Any, warnings: list[str] | None = None) -> AppConfig:
        sink = warnings if warnings is not None else []
        if isinstance(data, dict):
            version = data.get("version")
            if isinstance(version, int) and version > CONFIG_VERSION:
                sink.append(
                    f"configuration was written by a newer version (format {version}); "
                    "unrecognised settings are ignored"
                )
        config = _from_mapping(cls, data, "config", sink)
        if config is _INVALID:
            config = cls()
        config.version = CONFIG_VERSION
        _normalise(config, sink)
        return config


def text_source_id(path: str, pattern: str) -> str:
    """Stable identifier for a text-log source, derived from its location."""
    digest = hashlib.sha256(f"{path.strip().lower()}|{pattern.strip().lower()}".encode())
    return f"textlog-{digest.hexdigest()[:12]}"


# --------------------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------------------


def _from_mapping(cls: type, data: Any, where: str, warnings: list[str]) -> Any:
    if not isinstance(data, dict):
        warnings.append(f"{where}: expected an object, using defaults")
        return _INVALID
    hints = typing.get_type_hints(cls)
    kwargs: dict[str, Any] = {}
    known: set[str] = set()
    for fld in dataclasses.fields(cls):
        known.add(fld.name)
        if fld.name not in data:
            continue
        value = _coerce(data[fld.name], hints[fld.name], fld, f"{where}.{fld.name}", warnings)
        if value is not _INVALID:
            kwargs[fld.name] = value
    for key in data:
        if key not in known:
            warnings.append(f"{where}.{key}: unknown setting ignored")
    return cls(**kwargs)


def _coerce(
    value: Any, tp: Any, fld: dataclasses.Field | None, where: str, warnings: list[str]
) -> Any:
    origin = typing.get_origin(tp)
    args = typing.get_args(tp)

    if origin in (typing.Union, types.UnionType):
        if value is None and type(None) in args:
            return None
        non_none = [arg for arg in args if arg is not type(None)]
        if len(non_none) != 1:
            raise TypeError(f"unsupported union in configuration schema: {tp!r}")
        return _coerce(value, non_none[0], fld, where, warnings)

    if origin is Literal:
        if value in args:
            return value
        warnings.append(f"{where}: {value!r} is not one of {list(args)}; using default")
        return _INVALID

    if tp is Any:
        return value

    if tp is bool:
        if isinstance(value, bool):
            return value
        warnings.append(f"{where}: expected true/false; using default")
        return _INVALID

    if tp is int:
        if isinstance(value, float) and value.is_integer():
            value = int(value)
        if isinstance(value, bool) or not isinstance(value, int):
            warnings.append(f"{where}: expected an integer; using default")
            return _INVALID
        return _clamp(value, fld, where, warnings)

    if tp is float:
        if isinstance(value, bool) or not isinstance(value, int | float):
            warnings.append(f"{where}: expected a number; using default")
            return _INVALID
        return _clamp(float(value), fld, where, warnings)

    if tp is str:
        if isinstance(value, str):
            return value
        warnings.append(f"{where}: expected text; using default")
        return _INVALID

    if origin is list:
        if not isinstance(value, list):
            warnings.append(f"{where}: expected a list; using default")
            return _INVALID
        items = []
        for index, item in enumerate(value):
            coerced = _coerce(item, args[0], None, f"{where}[{index}]", warnings)
            if coerced is not _INVALID:
                items.append(coerced)
        return items

    if origin is dict:
        if not isinstance(value, dict):
            warnings.append(f"{where}: expected an object; using default")
            return _INVALID
        result = {}
        for key, item in value.items():
            coerced = _coerce(item, args[1], None, f"{where}.{key}", warnings)
            if coerced is not _INVALID:
                result[str(key)] = coerced
        return result

    if dataclasses.is_dataclass(tp) and isinstance(tp, type):
        return _from_mapping(tp, value, where, warnings)

    raise TypeError(f"unsupported type in configuration schema: {tp!r}")


def _clamp(
    value: int | float, fld: dataclasses.Field | None, where: str, warnings: list[str]
) -> int | float:
    if fld is None:
        return value
    minimum = fld.metadata.get("min")
    maximum = fld.metadata.get("max")
    if minimum is not None and value < minimum:
        warnings.append(f"{where}: {value} is below the minimum {minimum}; clamped")
        return type(value)(minimum)
    if maximum is not None and value > maximum:
        warnings.append(f"{where}: {value} is above the maximum {maximum}; clamped")
        return type(value)(maximum)
    return value


def _dedupe_casefold(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result = []
    for value in (v.strip() for v in values):
        if value and value.casefold() not in seen:
            seen.add(value.casefold())
            result.append(value)
    return result


def _valid_regex(pattern: str | None, where: str, warnings: list[str]) -> str | None:
    if pattern is None or not pattern.strip():
        return None
    try:
        re.compile(pattern)
    except re.error as exc:
        warnings.append(f"{where}: invalid regular expression ({exc}); ignored")
        return None
    return pattern


def _normalise(config: AppConfig, warnings: list[str]) -> None:
    config.event_logs.channels = _dedupe_casefold(config.event_logs.channels)
    config.event_logs.exclude_providers = _dedupe_casefold(config.event_logs.exclude_providers)
    config.event_logs.exclude_event_ids = sorted(set(config.event_logs.exclude_event_ids))
    config.temp_scan.extra_roots = _dedupe_casefold(config.temp_scan.extra_roots)

    sources: list[TextLogSource] = []
    seen_ids: set[str] = set()
    for index, source in enumerate(config.text_logs):
        where = f"config.text_logs[{index}]"
        source.path = source.path.strip()
        if not source.path:
            warnings.append(f"{where}: path is empty; source removed")
            continue
        source.pattern = source.pattern.strip() or "*.log"
        if not source.id:
            source.id = text_source_id(source.path, source.pattern)
        if source.id in seen_ids:
            warnings.append(f"{where}: duplicate source id {source.id!r}; source removed")
            continue
        seen_ids.add(source.id)
        source.multiline_start = _valid_regex(
            source.multiline_start, f"{where}.multiline_start", warnings
        )
        source.line_pattern = _valid_regex(source.line_pattern, f"{where}.line_pattern", warnings)
        if source.encoding != "auto":
            try:
                codecs.lookup(source.encoding)
            except LookupError:
                warnings.append(
                    f"{where}.encoding: unknown encoding {source.encoding!r}; using auto"
                )
                source.encoding = "auto"
        sources.append(source)
    config.text_logs = sources


# --------------------------------------------------------------------------------------
# Persistence
# --------------------------------------------------------------------------------------


@dataclass
class ConfigLoadResult:
    config: AppConfig
    warnings: list[str] = field(default_factory=list)
    created: bool = False
    backup_path: Path | None = None


def save_config(config: AppConfig, path: Path) -> None:
    """Write the configuration atomically (temp file + rename) so a crash cannot corrupt it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(config.to_dict(), indent=2) + "\n"
    fd, tmp_name = tempfile.mkstemp(prefix=f"{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_name)
        raise


def load_config(path: Path) -> ConfigLoadResult:
    """Load configuration, creating a default file if none exists.

    A file that is not valid JSON is preserved under a timestamped name and replaced by
    defaults. A file that cannot be read at all (for example, access denied) is left
    untouched and defaults are used for this session only.
    """
    if not path.exists():
        config = AppConfig()
        save_config(config, path)
        return ConfigLoadResult(config=config, created=True)

    try:
        raw = path.read_bytes()
    except OSError as exc:
        return ConfigLoadResult(
            config=AppConfig(),
            warnings=[f"configuration file could not be read ({exc.strerror}); using defaults"],
        )

    try:
        data = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        backup = path.with_name(f"{path.name}.invalid-{time.strftime('%Y%m%d-%H%M%S')}")
        try:
            os.replace(path, backup)
        except OSError:
            backup = None
        config = AppConfig()
        save_config(config, path)
        detail = f"kept as {backup.name}" if backup else "could not be backed up"
        return ConfigLoadResult(
            config=config,
            warnings=[f"configuration file is not valid JSON ({exc}); {detail}; defaults loaded"],
            backup_path=backup,
        )

    warnings: list[str] = []
    config = AppConfig.from_dict(data, warnings)
    return ConfigLoadResult(config=config, warnings=warnings)
