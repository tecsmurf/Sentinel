"""Text-log tailing behaviour that depends on Windows file-sharing semantics."""

import os
import sys

import pytest

from sentinel.collectors.text_logs import TailSettings, TextLogCollector, open_shared
from sentinel.config import TextLogSource

pytestmark = [
    pytest.mark.windows,
    pytest.mark.skipif(sys.platform != "win32", reason="Windows-only behaviour"),
]


def test_shared_handle_does_not_block_rotation_by_the_writer(tmp_path):
    log = tmp_path / "app.log"
    log.write_bytes(b"line\n")
    with open_shared(str(log)) as handle:
        assert handle.read() == b"line\n"
        os.replace(log, tmp_path / "app.log.1")  # what a log rotator does
    assert (tmp_path / "app.log.1").exists()


def test_plain_open_would_block_rotation(tmp_path):
    # Documents why open_shared exists: Python's open() omits FILE_SHARE_DELETE.
    log = tmp_path / "app.log"
    log.write_bytes(b"line\n")
    with open(log, "rb"), pytest.raises(PermissionError):
        os.replace(log, tmp_path / "app.log.1")


def test_missing_file_maps_to_file_not_found(tmp_path):
    with pytest.raises(FileNotFoundError):
        open_shared(str(tmp_path / "absent.log"))


def test_exclusively_locked_log_is_retried_not_failed(tmp_path):
    import win32con
    import win32file

    log = tmp_path / "locked.log"
    log.write_bytes(b"secret\n")
    handle = win32file.CreateFile(
        str(log), win32con.GENERIC_READ, 0, None, win32con.OPEN_EXISTING, 0, None
    )
    try:
        collector = TextLogCollector([TextLogSource(path=str(log), id="locked")], TailSettings())
        results = collector.poll({})
    finally:
        handle.Close()
    kinds = [note.kind for result in results for note in result.notes]
    assert "file_locked" in kinds
    assert all(not result.observations for result in results)
