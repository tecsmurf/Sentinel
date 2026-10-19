"""Read-only checks against the real Windows Event Log API.

These tests never write to, clear, or depend on the content of any event log (D-015).
"""

import sys

import pytest

from sentinel.collectors.windows_events import (
    EventLogAccessError,
    EventQuery,
    WindowsEventCollector,
    create_backend,
    normalize_event,
)
from sentinel.config import EventLogSettings

pytestmark = [
    pytest.mark.windows,
    pytest.mark.skipif(sys.platform != "win32", reason="Windows-only behaviour"),
]


@pytest.fixture(scope="module")
def backend():
    return create_backend()


def test_channel_info_matches_the_actual_newest_event(backend):
    # Regression: "newest" was computed as oldest + count - 1, which is wrong when record
    # numbers are not contiguous (as on GitHub's Windows runners) and looked like a cleared log.
    info = backend.channel_info("Application")
    (latest,) = backend.query(EventQuery("Application", max_events=1, newest_first=True)) or (None,)
    if latest is None:
        assert info.newest_record_id is None
        return
    assert info.newest_record_id == int(normalize_event(latest, "Application").record_id)
    assert info.oldest_record_id <= info.newest_record_id


def test_recent_events_render_and_normalise(backend):
    events = backend.query(EventQuery("System", max_events=5, newest_first=True))
    assert len(events) <= 5
    for raw in events:
        observation = normalize_event(raw, "System")
        assert observation.source_id == "winevt:System"
        assert observation.record_id is not None
        assert observation.message


def test_unknown_channel_is_not_found(backend):
    with pytest.raises(EventLogAccessError) as info:
        backend.query(EventQuery("Sentinel-Does-Not-Exist/Operational", max_events=1))
    assert info.value.kind == "not_found"


def test_security_channel_is_denied_or_readable(backend):
    try:
        backend.query(EventQuery("Security", max_events=1, newest_first=True))
    except EventLogAccessError as exc:
        assert exc.kind == "access_denied"  # expected without elevation
    else:
        pytest.skip("running elevated: the Security channel is readable")


def test_notifier_waits_without_error(backend):
    notifier = backend.notifier(["Application", "System"])
    assert notifier is not None
    try:
        assert notifier.wait(0.05) in (True, False)
    finally:
        notifier.close()


def test_collector_end_to_end_on_real_channels(backend):
    settings = EventLogSettings(
        channels=["Application", "Sentinel-Does-Not-Exist/Operational"],
        initial_lookback_hours=24,
        max_initial_events_per_channel=25,
    )
    collector = WindowsEventCollector(settings, backend)
    checkpoints = {}
    results = collector.poll(checkpoints)
    by_channel = {r.channel: r for r in results}
    app = by_channel["Application"]
    assert len(app.observations) <= 25
    assert app.state["status"] == "ok"
    assert app.state["last_record_id"] is not None
    assert [n.kind for n in by_channel["Sentinel-Does-Not-Exist/Operational"].notes] == [
        "not_found"
    ]
    for result in results:
        checkpoints[result.checkpoint_key] = result.state
    again = collector.poll(checkpoints)
    first_ids = {o.dedup_key for o in app.observations}
    assert not first_ids & {o.dedup_key for r in again for o in r.observations}
