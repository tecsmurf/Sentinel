"""Scanner behaviour that depends on real Windows filesystem semantics.

Everything here operates on directories under pytest's tmp_path only.
"""

import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from sentinel.config import TempScanSettings
from sentinel.paths import canonical_key
from sentinel.scanner.temp_scanner import TempScanner, resolve_scan_roots

pytestmark = [
    pytest.mark.windows,
    pytest.mark.skipif(sys.platform != "win32", reason="Windows-only behaviour"),
]


def _icacls() -> str:
    return str(Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32" / "icacls.exe")


def _current_user_sid() -> str:
    import win32api
    import win32security

    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32security.TOKEN_QUERY)
    sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
    return win32security.ConvertSidToStringSid(sid)


def test_junction_is_counted_but_not_followed(tmp_path):
    import _winapi

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "big.bin").write_bytes(b"x" * 4096)
    root = tmp_path / "Temp"
    root.mkdir()
    (root / "real.tmp").write_bytes(b"x")
    _winapi.CreateJunction(str(outside), str(root / "junction"))

    snapshot = TempScanner().scan_root(root).snapshot
    assert snapshot.file_count == 1
    assert snapshot.total_bytes == 1
    assert snapshot.skipped_links == 1


def test_access_denied_directory_is_reported(tmp_path):
    root = tmp_path / "Temp"
    locked = root / "locked"
    locked.mkdir(parents=True)
    (locked / "hidden.tmp").write_bytes(b"x" * 10)
    (root / "visible.tmp").write_bytes(b"x" * 5)
    sid = _current_user_sid()
    deny = [_icacls(), str(locked), "/deny", f"*{sid}:(RD)"]
    subprocess.run(deny, check=True, capture_output=True)  # noqa: S603 - fixed binary, test dir
    try:
        result = TempScanner().scan_root(root)
    finally:
        restore = [_icacls(), str(locked), "/remove:d", f"*{sid}"]
        subprocess.run(restore, check=True, capture_output=True)  # noqa: S603
    assert result.snapshot.inaccessible_count == 1
    assert [e.kind for e in result.errors] == ["access_denied"]
    assert result.snapshot.file_count == 1
    assert result.snapshot.total_bytes == 5


def test_exclusively_locked_file_is_still_measured(tmp_path):
    import win32con
    import win32file

    root = tmp_path / "Temp"
    root.mkdir()
    target = root / "in-use.tmp"
    target.write_bytes(b"x" * 123)
    handle = win32file.CreateFile(
        str(target), win32con.GENERIC_READ, 0, None, win32con.OPEN_EXISTING, 0, None
    )
    try:
        snapshot = TempScanner().scan_root(root).snapshot
    finally:
        handle.Close()
    assert snapshot.file_count == 1
    assert snapshot.total_bytes == 123


def test_short_8dot3_path_resolves_to_same_root(tmp_path):
    import win32api

    long_dir = tmp_path / "A Rather Long Directory Name"
    long_dir.mkdir()
    short = win32api.GetShortPathName(str(long_dir))
    assert canonical_key(short) == canonical_key(long_dir)


def test_real_user_temp_is_resolved():
    resolved = resolve_scan_roots(TempScanSettings(include_windows_temp=False))
    assert len(resolved.roots) == 1
    assert canonical_key(resolved.roots[0]) == canonical_key(os.environ["TEMP"])


def test_creation_time_identifies_new_files(tmp_path):
    root = tmp_path / "Temp"
    root.mkdir()
    since = datetime.now(UTC) - timedelta(minutes=5)
    path = root / "fresh.tmp"
    path.write_bytes(b"x")
    old = (datetime.now(UTC) - timedelta(days=100)).timestamp()
    os.utime(path, (old, old))  # an old mtime does not hide a newly created file
    snapshot = TempScanner().scan_root(root, since=since).snapshot
    assert (snapshot.new_files, snapshot.modified_files) == (1, 0)
