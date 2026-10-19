"""Windows Event Log collection through the Event Log API (DECISIONS.md D-005).

Structure:

* :class:`EventQuery` describes what to read; :meth:`EventQuery.xpath` turns it into the
  Event Log XPath subset. Only integers are interpolated into XPath.
* :class:`EventLogBackend` is the OS boundary. :class:`Win32EventLogBackend` uses
  ``win32evtlog``; tests use an in-memory fake, so everything else here is
  platform-neutral.
* :func:`normalize_event` turns rendered event XML (plus the formatted message, when the
  provider's resources are available) into an :class:`Observation`.
* :class:`WindowsEventCollector` keeps one checkpoint per channel (the last processed
  ``EventRecordID``), performs a bounded look-back import the first time, and reports
  inaccessible channels, overwritten events, and cleared logs as health notes.

Nothing here writes to, clears, or modifies any event log.
"""

from __future__ import annotations

import logging
import re
import sys
import xml.etree.ElementTree as ET
from collections import OrderedDict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from sentinel.analysis.normalize import fingerprint, prepare_message
from sentinel.collectors.base import HealthNote
from sentinel.config import EventLogSettings
from sentinel.models import Observation, Severity, SourceType, to_micros, utc_now

logger = logging.getLogger(__name__)

SOURCE_PREFIX = "winevt:"
POLL_BATCH = 500
MAX_DATA_ITEMS = 32
MAX_DATA_CHARS = 512
MAX_EVENT_XML_CHARS = 1_000_000
_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
_SYSTEM_TIME = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})?$"
)
_PROVIDER_NAME = re.compile(r"<Provider Name='([^']*)'")
_RECORD_ID = re.compile(r"<EventRecordID>(\d+)</EventRecordID>")
_DOTNET_APP = re.compile(r"Application:\s*(\S+?\.exe)\b", re.IGNORECASE)

# Windows levels: 0 LogAlways, 1 Critical, 2 Error, 3 Warning, 4 Information, 5 Verbose.
LEVELS_FOR_MIN_SEVERITY: dict[str, tuple[int, ...] | None] = {
    "critical": (1,),
    "error": (1, 2),
    "warning": (1, 2, 3),
    "info": (0, 1, 2, 3, 4),
    "debug": None,
}
_APP_CRASH_WER_EVENTS = frozenset(
    {"appcrash", "bex", "bex64", "apphangb1", "apphangxprocb1", "moappcrash", "moapphang"}
)


def source_id_for(channel: str) -> str:
    return f"{SOURCE_PREFIX}{channel}"


class EventLogAccessError(Exception):
    """A channel cannot be read. ``kind``: access_denied, not_found, invalid_query, error."""

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind


@dataclass(frozen=True, slots=True)
class EventQuery:
    channel: str
    after_record_id: int | None = None
    within: timedelta | None = None
    levels: tuple[int, ...] | None = None
    max_events: int = POLL_BATCH
    newest_first: bool = False

    def xpath(self) -> str:
        conditions: list[str] = []
        if self.levels:
            conditions.append("(" + " or ".join(f"Level={int(lv)}" for lv in self.levels) + ")")
        if self.after_record_id is not None:
            conditions.append(f"EventRecordID > {int(self.after_record_id)}")
        if self.within is not None:
            milliseconds = max(int(self.within.total_seconds() * 1000), 0)
            conditions.append(f"TimeCreated[timediff(@SystemTime) <= {milliseconds}]")
        return f"*[System[{' and '.join(conditions)}]]" if conditions else "*"


@dataclass(frozen=True, slots=True)
class RawEvent:
    xml: str
    message: str | None = None  # formatted by the provider, when available


@dataclass(frozen=True, slots=True)
class ChannelInfo:
    """Record IDs of the oldest and newest events currently in a channel (``None`` if empty).

    Both are read from the events themselves. They are deliberately *not* derived from
    the channel's record count: record numbers are not guaranteed to be contiguous (seen on
    freshly provisioned Windows images), and an underestimated "newest" would look like a
    cleared log and cause events to be re-read.
    """

    oldest_record_id: int | None
    newest_record_id: int | None


class Notifier(Protocol):
    def wait(self, timeout: float) -> bool: ...

    def close(self) -> None: ...


class EventLogBackend(Protocol):
    def query(self, query: EventQuery) -> list[RawEvent]: ...

    def channel_info(self, channel: str) -> ChannelInfo: ...

    def notifier(self, channels: Sequence[str]) -> Notifier | None: ...


# --------------------------------------------------------------------------------------
# Normalisation
# --------------------------------------------------------------------------------------


def _int(text: str | None) -> int | None:
    try:
        return int(text) if text not in (None, "") else None
    except ValueError:
        return None


def parse_system_time(text: str | None) -> datetime | None:
    """Parse ``TimeCreated/@SystemTime`` (100 ns precision) to an aware UTC datetime."""
    if not text:
        return None
    match = _SYSTEM_TIME.match(text.strip())
    if match is None:
        return None
    year, month, day, hour, minute, second, fraction, zone = match.groups()
    micros = int(((fraction or "") + "000000")[:6])
    try:
        moment = datetime(
            int(year), int(month), int(day), int(hour), int(minute), int(second), micros, UTC
        )
    except ValueError:
        return None
    if zone and zone != "Z":
        sign = 1 if zone[0] == "+" else -1
        moment -= sign * timedelta(hours=int(zone[1:3]), minutes=int(zone[4:6]))
    return moment


def _child_text(parent: ET.Element, name: str) -> str | None:
    child = parent.find(f"{_NS}{name}")
    return None if child is None or child.text is None else child.text.strip()


def _event_data(root: ET.Element) -> dict[str, str]:
    data: dict[str, str] = {}
    event_data = root.find(f"{_NS}EventData")
    if event_data is not None:
        for index, item in enumerate(event_data.findall(f"{_NS}Data"), start=1):
            if len(data) >= MAX_DATA_ITEMS:
                break
            key = item.get("Name") or f"#{index}"
            data[key] = (item.text or "").strip()[:MAX_DATA_CHARS]
        return data
    user_data = root.find(f"{_NS}UserData")
    if user_data is not None and len(user_data):
        for item in list(user_data[0])[:MAX_DATA_ITEMS]:
            key = item.tag.rsplit("}", 1)[-1]
            data[key] = "".join(item.itertext()).strip()[:MAX_DATA_CHARS]
    return data


def _entity(provider: str, event_id: str, data: Mapping[str, str], message: str):
    """The thing an event is about, used for grouping: (entity key, process name)."""
    name = provider.lower()
    if name == "service control manager":
        service = data.get("param1") or data.get("#1")
        if service:
            return f"service:{service.lower()}", None
    if name in ("application error", "application hang"):
        app = data.get("AppName") or data.get("#1")
        if app:
            return f"app:{app.lower()}", app
    if name == "windows error reporting":
        kind = data.get("EventName") or data.get("#3") or ""
        p1 = data.get("P1") or ""
        if kind.lower() in _APP_CRASH_WER_EVENTS and p1:
            return f"app:{p1.lower()}", p1
        if kind:
            return (f"wer:{kind}:{p1}" if p1 else f"wer:{kind}"), None
    if name == ".net runtime":
        match = _DOTNET_APP.search(message)
        if match:
            return f"app:{match.group(1).lower()}", match.group(1)
    for key in ("AppName", "ApplicationName", "ProcessName", "Image"):
        value = data.get(key)
        if value:
            base = re.split(r"[\\/]", value)[-1]
            return f"app:{base.lower()}", base
    return None, None


def normalize_event(
    raw: RawEvent,
    channel: str,
    *,
    max_message_chars: int = 8192,
    now: datetime | None = None,
) -> Observation:
    """Convert one rendered event. Raises ``ValueError``/``ET.ParseError`` if malformed."""
    # The XML is rendered locally by the Event Log service, which escapes event content.
    # ElementTree never fetches external entities and Python's bundled expat limits entity
    # expansion; as defence in depth, documents with DTDs or entity declarations, or of
    # implausible size, are rejected outright.
    if len(raw.xml) > MAX_EVENT_XML_CHARS:
        raise ValueError("event XML exceeds the size limit")
    if "<!DOCTYPE" in raw.xml or "<!ENTITY" in raw.xml:
        raise ValueError("event XML contains a document type declaration")
    root = ET.fromstring(raw.xml)  # noqa: S314 - guarded above; locally rendered by the OS
    system = root.find(f"{_NS}System")
    if system is None:
        raise ValueError("event XML has no System element")

    provider_el = system.find(f"{_NS}Provider")
    provider = ""
    if provider_el is not None:
        provider = provider_el.get("Name") or provider_el.get("EventSourceName") or ""
    event_id = _child_text(system, "EventID") or ""
    level = _int(_child_text(system, "Level"))
    record_id = _int(_child_text(system, "EventRecordID"))
    time_el = system.find(f"{_NS}TimeCreated")
    created = parse_system_time(time_el.get("SystemTime") if time_el is not None else None)
    collected = now or utc_now()
    execution = system.find(f"{_NS}Execution")
    process_id = _int(execution.get("ProcessID")) if execution is not None else None
    thread_id = _int(execution.get("ThreadID")) if execution is not None else None
    security = system.find(f"{_NS}Security")
    event_channel = _child_text(system, "Channel") or channel

    data = _event_data(root)
    formatted = bool(raw.message and raw.message.strip())
    if formatted:
        text = raw.message.strip()  # type: ignore[union-attr]
    else:
        values = "; ".join(f"{k}={v}" for k, v in data.items() if v)
        text = f"{provider or 'Unknown provider'} event {event_id}" + (
            f": {values}" if values else ""
        )
    entity, process_name = _entity(provider, event_id, data, text)
    message, truncated = prepare_message(text, max_message_chars)

    metadata: dict[str, Any] = {
        "channel": event_channel,
        "computer": _child_text(system, "Computer") or "",
        "level": level,
        "task": _int(_child_text(system, "Task")),
        "opcode": _int(_child_text(system, "Opcode")),
        "keywords": _child_text(system, "Keywords"),
        "message_formatted": formatted,
    }
    if thread_id:
        metadata["thread_id"] = thread_id
    if security is not None and security.get("UserID"):
        metadata["user_sid"] = security.get("UserID")
    if data:
        metadata["data"] = data
    if entity:
        metadata["entity"] = entity
    if created is None:
        metadata["timestamp_inferred"] = True
    if truncated:
        metadata["truncated"] = True

    timestamp = created or collected
    return Observation(
        source_id=source_id_for(channel),
        source_type=SourceType.WINDOWS_EVENT,
        event_timestamp=timestamp,
        severity=Severity.from_windows_level(level),
        message=message,
        dedup_key=f"{source_id_for(channel)}:{record_id}:{to_micros(timestamp)}",
        fingerprint=fingerprint("windows_event", provider, event_id, message=text),
        collected_at=collected,
        event_type="windows_event",
        provider=provider,
        event_code=event_id,
        record_id=None if record_id is None else str(record_id),
        process_name=process_name,
        process_id=process_id,
        metadata=metadata,
    )


# --------------------------------------------------------------------------------------
# Collector
# --------------------------------------------------------------------------------------


@dataclass(slots=True)
class ChannelPollResult:
    channel: str
    checkpoint_key: str
    state: dict[str, Any]
    observations: list[Observation] = field(default_factory=list)
    notes: list[HealthNote] = field(default_factory=list)
    more: bool = False


_ACCESS_MESSAGES = {
    "access_denied": (
        "access to this event log channel was denied; Sentinel runs without administrator "
        "rights, so this channel is skipped"
    ),
    "not_found": "this event log channel does not exist on this computer",
    "invalid_query": "the event log rejected the query",
    "error": "the event log could not be read",
}


class WindowsEventCollector:
    """Polls configured channels. Owned by one worker thread."""

    def __init__(
        self,
        settings: EventLogSettings,
        backend: EventLogBackend,
        *,
        max_message_chars: int = 8192,
        batch_size: int = POLL_BATCH,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self.settings = settings
        self.backend = backend
        self.max_message_chars = max_message_chars
        self.batch_size = batch_size
        self.clock = clock
        self._excluded_providers = {p.casefold() for p in settings.exclude_providers}
        self._excluded_ids = {str(i) for i in settings.exclude_event_ids}

    @property
    def channels(self) -> list[str]:
        return list(self.settings.channels) if self.settings.enabled else []

    def poll(self, checkpoints: Mapping[str, Mapping[str, Any]]) -> list[ChannelPollResult]:
        results = []
        for channel in self.channels:
            key = source_id_for(channel)
            try:
                results.append(self.poll_channel(channel, checkpoints.get(key)))
            except Exception as exc:  # one channel must not stop the others
                logger.exception(
                    "unexpected error polling event channel", extra={"channel": channel}
                )
                state = dict(checkpoints.get(key) or {"channel": channel, "last_record_id": None})
                note = HealthNote(
                    "read_error",
                    Severity.WARNING,
                    f"unexpected error while reading events ({type(exc).__name__})",
                    channel,
                )
                results.append(ChannelPollResult(channel, key, state, notes=[note]))
        return results

    def poll_channel(self, channel: str, state_data: Mapping[str, Any] | None) -> ChannelPollResult:
        key = source_id_for(channel)
        state: dict[str, Any] = dict(
            state_data or {"channel": channel, "last_record_id": None, "status": "new"}
        )
        result = ChannelPollResult(channel, key, state)
        levels = LEVELS_FOR_MIN_SEVERITY.get(self.settings.min_severity)
        last: int | None = state.get("last_record_id")
        initial = last is None

        try:
            info = self.backend.channel_info(channel)
            newest = info.newest_record_id
            if initial:
                raw_events = self._initial_import(result, channel, levels)
            else:
                if newest is not None and newest < last:
                    result.notes.append(
                        HealthNote(
                            "log_cleared",
                            Severity.WARNING,
                            "event record numbers restarted: the log appears to have been "
                            "cleared; collection continues with the current events",
                            channel,
                        )
                    )
                    last = 0
                elif info.oldest_record_id and info.oldest_record_id > last + 1:
                    missed = info.oldest_record_id - last - 1
                    result.notes.append(
                        HealthNote(
                            "log_gap",
                            Severity.WARNING,
                            f"{missed} event(s) were overwritten before Sentinel could read "
                            "them (the log is full and wrapping)",
                            channel,
                            missed,
                        )
                    )
                raw_events = self.backend.query(
                    EventQuery(
                        channel, after_record_id=last, levels=levels, max_events=self.batch_size
                    )
                )
                result.more = len(raw_events) >= self.batch_size
        except EventLogAccessError as exc:
            if state.get("status") != exc.kind:
                result.notes.append(
                    HealthNote(
                        exc.kind,
                        Severity.WARNING,
                        _ACCESS_MESSAGES.get(exc.kind, str(exc)),
                        channel,
                    )
                )
            state["status"] = exc.kind
            return result

        if state.get("status") not in ("ok", "new"):
            result.notes.append(
                HealthNote(
                    "recovered", Severity.INFO, "event log channel is readable again", channel
                )
            )
        state["status"] = "ok"

        highest = last or 0
        malformed = 0
        now = self.clock()
        for raw in raw_events:
            try:
                observation = normalize_event(
                    raw, channel, max_message_chars=self.max_message_chars, now=now
                )
            except (ET.ParseError, ValueError):
                malformed += 1
                continue
            if observation.record_id is not None:
                highest = max(highest, int(observation.record_id))
            if self._excluded(observation):
                continue
            result.observations.append(observation)
        if malformed:
            result.notes.append(
                HealthNote(
                    "malformed_events",
                    Severity.WARNING,
                    f"{malformed} event(s) could not be interpreted and were skipped",
                    channel,
                    malformed,
                )
            )
        # Once caught up, advance to the channel's newest record even if every event was
        # filtered out, so a quiet channel never looks like it has a gap.
        if not result.more and newest is not None:
            highest = max(highest, newest)
        state["last_record_id"] = highest
        return result

    def _initial_import(
        self, result: ChannelPollResult, channel: str, levels: tuple[int, ...] | None
    ) -> list[RawEvent]:
        limit = self.settings.max_initial_events_per_channel
        hours = self.settings.initial_lookback_hours
        if limit <= 0 or hours <= 0:
            return []
        events = self.backend.query(
            EventQuery(
                channel,
                within=timedelta(hours=hours),
                levels=levels,
                max_events=limit,
                newest_first=True,
            )
        )
        events.reverse()
        if len(events) >= limit:
            result.notes.append(
                HealthNote(
                    "initial_import_limited",
                    Severity.INFO,
                    f"imported the {limit} most recent events from the last {hours} hours; "
                    "older events in that window were not imported",
                    channel,
                )
            )
        return events

    def _excluded(self, observation: Observation) -> bool:
        return (
            observation.provider.casefold() in self._excluded_providers
            or observation.event_code in self._excluded_ids
        )


# --------------------------------------------------------------------------------------
# pywin32 backend (Windows only)
# --------------------------------------------------------------------------------------


def _translate_error(exc: Exception, channel: str) -> EventLogAccessError:
    code = getattr(exc, "winerror", None)
    kind = {5: "access_denied", 15007: "not_found", 15001: "invalid_query"}.get(code, "error")
    return EventLogAccessError(kind, f"{channel}: {getattr(exc, 'strerror', exc)}")


class Win32EventLogBackend:
    """Reads events with ``win32evtlog``. Publisher metadata handles are cached (bounded)."""

    def __init__(self, cache_size: int = 64) -> None:
        import pywintypes
        import win32evtlog

        self._evt = win32evtlog
        self._error = pywintypes.error
        self._cache_size = cache_size
        self._publishers: OrderedDict[str, Any] = OrderedDict()

    def query(self, query: EventQuery) -> list[RawEvent]:
        evt = self._evt
        direction = (
            evt.EvtQueryReverseDirection if query.newest_first else evt.EvtQueryForwardDirection
        )
        try:
            handle = evt.EvtQuery(query.channel, evt.EvtQueryChannelPath | direction, query.xpath())
        except self._error as exc:
            raise _translate_error(exc, query.channel) from None
        events: list[RawEvent] = []
        while len(events) < query.max_events:
            try:
                batch = evt.EvtNext(handle, min(100, query.max_events - len(events)))
            except self._error as exc:
                raise _translate_error(exc, query.channel) from None
            if not batch:  # verified: an exhausted result set returns an empty tuple
                break
            events.extend(self._render(item) for item in batch)
        return events

    def _render(self, handle: Any) -> RawEvent:
        xml = self._evt.EvtRender(handle, self._evt.EvtRenderEventXml)
        match = _PROVIDER_NAME.search(xml)
        message = self._format(handle, match.group(1)) if match else None
        return RawEvent(xml=xml, message=message)

    def _format(self, handle: Any, provider: str) -> str | None:
        metadata = self._publisher(provider)
        if metadata is None:
            return None
        try:
            return self._evt.EvtFormatMessage(metadata, handle, self._evt.EvtFormatMessageEvent)
        except self._error:
            return None  # e.g. the provider's message DLL is missing

    def _publisher(self, provider: str) -> Any:
        if provider in self._publishers:
            self._publishers.move_to_end(provider)
            return self._publishers[provider]
        try:
            metadata = self._evt.EvtOpenPublisherMetadata(provider)
        except self._error:
            metadata = None  # cache the failure too; retrying is slow and will fail again
        self._publishers[provider] = metadata
        if len(self._publishers) > self._cache_size:
            self._publishers.popitem(last=False)
        return metadata

    def channel_info(self, channel: str) -> ChannelInfo:
        return ChannelInfo(
            oldest_record_id=self._edge_record_id(channel, newest=False),
            newest_record_id=self._edge_record_id(channel, newest=True),
        )

    def _edge_record_id(self, channel: str, *, newest: bool) -> int | None:
        """Record ID of the first or last event in a channel (one event, XML only)."""
        evt = self._evt
        direction = evt.EvtQueryReverseDirection if newest else evt.EvtQueryForwardDirection
        try:
            handle = evt.EvtQuery(channel, evt.EvtQueryChannelPath | direction, "*")
            batch = evt.EvtNext(handle, 1)
            if not batch:
                return None
            xml = evt.EvtRender(batch[0], evt.EvtRenderEventXml)
        except self._error as exc:
            raise _translate_error(exc, channel) from None
        match = _RECORD_ID.search(xml)
        return int(match.group(1)) if match else None

    def notifier(self, channels: Sequence[str]) -> Notifier | None:
        try:
            return _Win32Notifier(channels)
        except self._error:
            logger.warning("event subscriptions unavailable; falling back to polling")
            return None


class _Win32Notifier:
    """Pull-mode subscriptions sharing one signal event; used only as a wake-up signal."""

    def __init__(self, channels: Sequence[str]) -> None:
        import pywintypes
        import win32event
        import win32evtlog

        self._evt = win32evtlog
        self._event_api = win32event
        self._error = pywintypes.error
        self._signal = win32event.CreateEvent(None, False, False, None)
        self._subscriptions = []
        for channel in channels:
            try:
                self._subscriptions.append(
                    win32evtlog.EvtSubscribe(
                        channel,
                        win32evtlog.EvtSubscribeToFutureEvents,
                        SignalEvent=self._signal,
                        Query="*",
                    )
                )
            except pywintypes.error:
                continue  # inaccessible channel; it is still polled and reported

    def wait(self, timeout: float) -> bool:
        result = self._event_api.WaitForSingleObject(self._signal, max(int(timeout * 1000), 0))
        if result != self._event_api.WAIT_OBJECT_0:
            return False
        for subscription in self._subscriptions:
            for _ in range(1000):  # drain so the signal is raised again for new events
                try:
                    if not self._evt.EvtNext(subscription, 64, 0):
                        break
                except self._error:
                    break
        return True

    def close(self) -> None:
        self._subscriptions.clear()
        self._signal.Close()


def create_backend() -> EventLogBackend | None:
    """The real backend on Windows; ``None`` elsewhere (Event Log collection is skipped)."""
    if sys.platform != "win32":
        return None
    return Win32EventLogBackend()
