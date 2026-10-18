"""Real watchdog observers on temporary directories."""

import threading
import time

import pytest

from sentinel.collectors.file_watcher import LogWatcher
from sentinel.config import TextLogSource

WAIT_SECONDS = 5.0


class Recorder:
    def __init__(self):
        self.ids: list[str] = []
        self.event = threading.Event()
        self.lock = threading.Lock()

    def __call__(self, source_id: str) -> None:
        with self.lock:
            self.ids.append(source_id)
        self.event.set()

    def wait(self) -> bool:
        return self.event.wait(WAIT_SECONDS)


@pytest.fixture
def recorder():
    return Recorder()


@pytest.fixture
def watcher(recorder):
    instance = LogWatcher(recorder)
    yield instance
    instance.stop()


def test_change_to_watched_file_notifies_its_source(tmp_path, watcher, recorder):
    log = tmp_path / "app.log"
    log.write_bytes(b"start\n")
    assert watcher.watch([TextLogSource(path=str(log), id="app")]) == []
    assert watcher.running
    with open(log, "ab") as handle:
        handle.write(b"more\n")
    assert recorder.wait()
    assert set(recorder.ids) == {"app"}


def test_directory_source_matches_pattern_only(tmp_path, watcher, recorder):
    logs = tmp_path / "logs"
    logs.mkdir()
    watcher.watch([TextLogSource(path=str(logs), pattern="*.log", id="dir")])
    (logs / "notes.txt").write_bytes(b"ignored\n")
    time.sleep(0.5)  # give a wrong match the chance to appear
    assert recorder.ids == []
    (logs / "service.log").write_bytes(b"hello\n")
    assert recorder.wait()
    assert set(recorder.ids) == {"dir"}


def test_new_file_created_after_watching_starts(tmp_path, watcher, recorder):
    log = tmp_path / "later.log"
    watcher.watch([TextLogSource(path=str(log), id="later")])
    log.write_bytes(b"created\n")
    assert recorder.wait()


def test_missing_directory_is_reported_not_fatal(tmp_path, watcher):
    missing = tmp_path / "does-not-exist"
    notes = watcher.watch([TextLogSource(path=str(missing), id="gone")])
    assert [n.kind for n in notes] == ["watch_unavailable"]
    assert not watcher.running


def test_callback_errors_do_not_stop_the_observer(tmp_path):
    calls = threading.Event()

    def failing(source_id):
        calls.set()
        raise RuntimeError("callback bug")

    log = tmp_path / "app.log"
    log.write_bytes(b"x\n")
    watcher = LogWatcher(failing)
    try:
        watcher.watch([TextLogSource(path=str(log), id="app")])
        with open(log, "ab") as handle:
            handle.write(b"y\n")
        assert calls.wait(WAIT_SECONDS)
        time.sleep(0.2)
        assert watcher.running
    finally:
        watcher.stop()


def test_disabled_sources_and_stop_are_safe(tmp_path, watcher):
    assert watcher.watch([TextLogSource(path=str(tmp_path / "a.log"), id="a", enabled=False)]) == []
    assert not watcher.running
    watcher.stop()
    watcher.stop()
