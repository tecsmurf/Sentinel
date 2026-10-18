"""Constants and helpers shared by test modules (importable as ``tests.support``)."""

from __future__ import annotations

import os
import sys
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sentinel.collectors.windows_events import (
    ChannelInfo,
    EventLogAccessError,
    EventQuery,
    RawEvent,
)

BASE_TIME = datetime(2026, 10, 15, 12, 0, tzinfo=UTC)


def backdate(path: Path, when: datetime) -> None:
    """Set a file's modification time (and, on Windows, its creation time) to ``when``.

    Windows stamps files using a precise clock while ``datetime.now()`` on Python 3.12
    uses the coarser system tick, so a file created just before a scan can appear to have
    been created after the scan started. Backdating fixtures removes that race.
    """
    stamp = when.timestamp()
    os.utime(path, (stamp, stamp))
    if sys.platform == "win32":
        import pywintypes
        import win32con
        import win32file

        handle = win32file.CreateFile(
            str(path),
            win32con.GENERIC_WRITE,
            0,
            None,
            win32con.OPEN_EXISTING,
            win32con.FILE_ATTRIBUTE_NORMAL,
            None,
        )
        try:
            moment = pywintypes.Time(when)
            win32file.SetFileTime(handle, moment, moment, moment, UTCTimes=True)
        finally:
            handle.Close()


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


# --------------------------------------------------------------------------------------
# Synthetic Windows events (modelled on real Application/System channel XML)
# --------------------------------------------------------------------------------------

_EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def event_xml(
    *,
    provider: str,
    event_id: int,
    record_id: int,
    when: datetime,
    level: int = 2,
    channel: str = "Application",
    data: dict[str, str] | list[str] | None = None,
    user_data: dict[str, str] | None = None,
    process_id: int = 1234,
) -> str:
    """Build event XML in the shape produced by EvtRender (values are XML-escaped)."""
    from xml.sax.saxutils import escape, quoteattr

    stamp = when.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"
    if isinstance(data, dict):
        items = "".join(f"<Data Name={quoteattr(k)}>{escape(v)}</Data>" for k, v in data.items())
        payload = f"<EventData>{items}</EventData>"
    elif isinstance(data, list):
        payload = (
            "<EventData>" + "".join(f"<Data>{escape(v)}</Data>" for v in data) + "</EventData>"
        )
    elif user_data is not None:
        inner = "".join(f"<{k}>{escape(v)}</{k}>" for k, v in user_data.items())
        payload = f"<UserData><Info xmlns='urn:test'>{inner}</Info></UserData>"
    else:
        payload = ""
    return (
        f"<Event xmlns='{_EVENT_NS}'><System><Provider Name={quoteattr(provider)}/>"
        f"<EventID>{event_id}</EventID><Version>0</Version><Level>{level}</Level><Task>0</Task>"
        f"<Opcode>0</Opcode><Keywords>0x80000000000000</Keywords>"
        f"<TimeCreated SystemTime='{stamp}'/><EventRecordID>{record_id}</EventRecordID>"
        f"<Correlation/><Execution ProcessID='{process_id}' ThreadID='0'/>"
        f"<Channel>{escape(channel)}</Channel><Computer>TEST-PC</Computer>"
        f"<Security UserID='S-1-5-18'/></System>{payload}</Event>"
    )


class FakeBackend:
    """Interprets EventQuery structurally, like the real XPath query would."""

    def __init__(self, now=BASE_TIME):
        self.now = now
        self.channels: dict[str, list[tuple[int, datetime, int, RawEvent]]] = {}
        self.errors: dict[str, str] = {}
        self.queries: list[EventQuery] = []

    def add(self, channel, record_id, *, provider="App", event_id=1, level=2, when=None, **kw):
        when = when or self.now - timedelta(minutes=1)
        message = kw.pop("message", None)
        xml = event_xml(
            provider=provider, event_id=event_id, record_id=record_id, when=when, level=level,
            channel=channel, **kw,
        )  # fmt: skip
        self.channels.setdefault(channel, []).append(
            (record_id, when, level, RawEvent(xml, message))
        )

    def _events(self, channel):
        if channel in self.errors:
            raise EventLogAccessError(self.errors[channel], f"{channel}: simulated")
        if channel not in self.channels:
            raise EventLogAccessError("not_found", f"{channel}: missing")
        return self.channels[channel]

    def query(self, query):
        self.queries.append(query)
        events = sorted(self._events(query.channel), key=lambda e: e[0], reverse=query.newest_first)
        result = []
        for record_id, when, level, raw in events:
            if query.after_record_id is not None and record_id <= query.after_record_id:
                continue
            if query.levels and level not in query.levels:
                continue
            if query.within is not None and when < self.now - query.within:
                continue
            result.append(raw)
            if len(result) >= query.max_events:
                break
        return result

    def channel_info(self, channel):
        events = self._events(channel)
        ids = [e[0] for e in events]
        return ChannelInfo(min(ids) if ids else None, len(ids))

    def notifier(self, channels):
        return None
