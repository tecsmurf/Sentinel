import sys
from pathlib import Path

import pytest

from sentinel.paths import (
    APP_DIR_NAME,
    AppPaths,
    PathError,
    canonical_key,
    dedupe_roots,
    default_data_dir,
    expand_path,
    expand_vars,
    is_within,
)


class TestDefaultDataDir:
    def test_override_env_var_wins(self, tmp_path):
        assert default_data_dir({"SENTINEL_HOME": str(tmp_path)}) == tmp_path

    def test_windows_uses_localappdata(self, monkeypatch, tmp_path):
        monkeypatch.setattr(sys, "platform", "win32")
        result = default_data_dir({"LOCALAPPDATA": str(tmp_path)})
        assert result == tmp_path / APP_DIR_NAME

    def test_non_windows_uses_xdg_data_home(self, monkeypatch, tmp_path):
        monkeypatch.setattr(sys, "platform", "linux")
        assert default_data_dir({"XDG_DATA_HOME": str(tmp_path)}) == tmp_path / APP_DIR_NAME


def test_app_paths_layout_and_ensure(tmp_path):
    paths = AppPaths(tmp_path / "data").ensure()
    assert paths.config_file == tmp_path / "data" / "config.json"
    assert paths.database_file.name == "sentinel.db"
    assert paths.log_dir.is_dir()
    assert paths.reports_dir.is_dir()


class TestExpandVars:
    def test_expands_case_insensitively(self):
        assert expand_vars(r"%temp%\x", {"TEMP": "T"}) == r"T\x"

    def test_multiple_variables(self):
        env = {"A": "one", "B": "two"}
        assert expand_vars("%A%/%b%", env) == "one/two"

    def test_undefined_variable_raises(self):
        with pytest.raises(PathError, match="NOPE"):
            expand_vars("%NOPE%/x", {})

    def test_text_without_variables_is_unchanged(self):
        assert expand_vars("100% sure", {}) == "100% sure"


class TestExpandPath:
    def test_strips_quotes_and_whitespace(self, tmp_path):
        assert expand_path(f'  "{tmp_path}"  ') == tmp_path

    def test_expands_variable(self, tmp_path):
        assert expand_path("%ROOT%", {"ROOT": str(tmp_path)}) == tmp_path

    @pytest.mark.parametrize("raw", ["", "   ", '""'])
    def test_rejects_empty(self, raw):
        with pytest.raises(PathError, match="empty"):
            expand_path(raw)

    def test_rejects_relative(self):
        with pytest.raises(PathError, match="absolute"):
            expand_path("relative/dir")

    def test_rejects_nul(self, tmp_path):
        with pytest.raises(PathError, match="NUL"):
            expand_path(f"{tmp_path}\x00evil")


class TestCanonicalisation:
    def test_dot_segments_resolve_to_same_key(self, tmp_path):
        (tmp_path / "a").mkdir()
        assert canonical_key(tmp_path / "a" / ".." / "a") == canonical_key(tmp_path / "a")

    @pytest.mark.skipif(sys.platform != "win32", reason="case-insensitive paths are Windows-only")
    def test_case_insensitive_on_windows(self, tmp_path):
        assert canonical_key(str(tmp_path).upper()) == canonical_key(str(tmp_path).lower())

    def test_is_within(self, tmp_path):
        child = tmp_path / "a" / "b"
        assert is_within(child, tmp_path)
        assert is_within(tmp_path, tmp_path)
        assert not is_within(tmp_path, child)
        assert not is_within(tmp_path / "ab", tmp_path / "a")


class TestDedupeRoots:
    def test_keeps_distinct_roots_in_input_order(self, tmp_path):
        a, b = tmp_path / "b-dir", tmp_path / "a-dir"
        selection = dedupe_roots([a, b])
        assert [p.name for p in selection.roots] == ["b-dir", "a-dir"]
        assert selection.skipped == []

    def test_drops_exact_duplicates(self, tmp_path):
        target = tmp_path / "temp"
        selection = dedupe_roots([target, tmp_path / "x" / ".." / "temp"])
        assert len(selection.roots) == 1
        assert len(selection.skipped) == 1
        assert "same location" in selection.skipped[0][1]

    def test_drops_nested_roots_even_when_listed_first(self, tmp_path):
        parent, child = tmp_path / "temp", tmp_path / "temp" / "sub"
        selection = dedupe_roots([child, parent])
        assert [canonical_key(p) for p in selection.roots] == [canonical_key(parent)]
        assert selection.skipped[0][0] == child
        assert "already covered" in selection.skipped[0][1]

    def test_sibling_prefix_is_not_nested(self, tmp_path):
        selection = dedupe_roots([tmp_path / "temp", tmp_path / "temp2"])
        assert len(selection.roots) == 2


def test_resolved_roots_are_paths(tmp_path):
    selection = dedupe_roots([tmp_path])
    assert all(isinstance(p, Path) for p in selection.roots)
