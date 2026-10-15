import json

import pytest

from sentinel.config import (
    CONFIG_VERSION,
    AppConfig,
    TextLogSource,
    load_config,
    save_config,
    text_source_id,
)


@pytest.fixture
def config_path(tmp_path):
    return tmp_path / "data" / "config.json"


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


class TestLoadAndSave:
    def test_missing_file_creates_defaults(self, config_path):
        result = load_config(config_path)
        assert result.created
        assert result.warnings == []
        assert config_path.exists()
        assert result.config == AppConfig()

    def test_round_trip_preserves_values(self, config_path):
        config = AppConfig()
        config.event_logs.channels = ["Application", "Setup"]
        config.text_logs = [TextLogSource(path="C:/logs/app.log", pattern="*.log", recursive=True)]
        config.retention.observation_days = 7
        config.rules = {"repeated_error": {"threshold": 3}}
        save_config(config, config_path)

        result = load_config(config_path)
        assert result.warnings == []
        assert result.config.event_logs.channels == ["Application", "Setup"]
        assert result.config.text_logs[0].recursive is True
        assert result.config.text_logs[0].id == text_source_id("C:/logs/app.log", "*.log")
        assert result.config.retention.observation_days == 7
        assert result.config.rules == {"repeated_error": {"threshold": 3}}

    def test_save_is_atomic_and_leaves_no_temp_files(self, config_path):
        save_config(AppConfig(), config_path)
        save_config(AppConfig(), config_path)
        assert [p.name for p in config_path.parent.iterdir()] == ["config.json"]

    def test_invalid_json_is_backed_up_and_replaced(self, config_path):
        config_path.parent.mkdir(parents=True)
        config_path.write_text("{ not json", encoding="utf-8")
        result = load_config(config_path)
        assert result.config == AppConfig()
        assert result.backup_path is not None
        assert result.backup_path.read_text(encoding="utf-8") == "{ not json"
        assert "not valid JSON" in result.warnings[0]
        assert json.loads(config_path.read_text(encoding="utf-8"))["version"] == CONFIG_VERSION

    def test_utf8_bom_is_accepted(self, config_path):
        config_path.parent.mkdir(parents=True)
        config_path.write_bytes(b"\xef\xbb\xbf" + json.dumps({"version": 1}).encode())
        assert load_config(config_path).warnings == []

    def test_newer_version_warns(self, config_path):
        write_json(config_path, {"version": CONFIG_VERSION + 1})
        result = load_config(config_path)
        assert any("newer version" in w for w in result.warnings)
        assert result.config.version == CONFIG_VERSION


class TestValidation:
    def test_wrong_types_fall_back_to_defaults(self):
        warnings: list[str] = []
        config = AppConfig.from_dict(
            {
                "event_logs": {"enabled": "yes", "channels": "Application"},
                "monitoring": {"batch_size": "many"},
                "ui": {"theme": "neon"},
            },
            warnings,
        )
        defaults = AppConfig()
        assert config.event_logs.enabled is True
        assert config.event_logs.channels == defaults.event_logs.channels
        assert config.monitoring.batch_size == defaults.monitoring.batch_size
        assert config.ui.theme == "system"
        assert len(warnings) == 4

    def test_out_of_range_numbers_are_clamped(self):
        warnings: list[str] = []
        config = AppConfig.from_dict(
            {"retention": {"observation_days": 0}, "temp_scan": {"max_entries": 10**12}}, warnings
        )
        assert config.retention.observation_days == 1
        assert config.temp_scan.max_entries == 10_000_000
        assert all("clamped" in w for w in warnings)

    def test_integral_float_accepted_for_int(self):
        warnings: list[str] = []
        config = AppConfig.from_dict({"retention": {"observation_days": 14.0}}, warnings)
        assert config.retention.observation_days == 14
        assert warnings == []

    def test_bool_is_not_accepted_as_number(self):
        warnings: list[str] = []
        config = AppConfig.from_dict({"retention": {"observation_days": True}}, warnings)
        assert config.retention.observation_days == AppConfig().retention.observation_days
        assert warnings

    def test_unknown_keys_are_reported(self):
        warnings: list[str] = []
        AppConfig.from_dict({"surprise": 1, "ui": {"colour": "red"}}, warnings)
        assert "config.surprise: unknown setting ignored" in warnings
        assert "config.ui.colour: unknown setting ignored" in warnings

    def test_non_object_root_uses_defaults(self):
        warnings: list[str] = []
        assert AppConfig.from_dict([1, 2, 3], warnings) == AppConfig()
        assert warnings

    def test_invalid_list_items_are_dropped(self):
        warnings: list[str] = []
        config = AppConfig.from_dict(
            {"event_logs": {"exclude_event_ids": ["x", 7036, 7036, 10016]}}, warnings
        )
        assert config.event_logs.exclude_event_ids == [7036, 10016]
        assert len(warnings) == 1

    def test_channels_are_trimmed_and_deduplicated(self):
        config = AppConfig.from_dict(
            {"event_logs": {"channels": [" Application", "application", "", "System"]}}
        )
        assert config.event_logs.channels == ["Application", "System"]


class TestTextLogSources:
    def test_empty_path_is_removed(self):
        warnings: list[str] = []
        config = AppConfig.from_dict({"text_logs": [{"path": "  "}]}, warnings)
        assert config.text_logs == []
        assert "path is empty" in warnings[0]

    def test_non_object_entry_is_removed(self):
        config = AppConfig.from_dict({"text_logs": ["C:/logs/app.log"]})
        assert config.text_logs == []

    def test_id_is_derived_and_stable(self):
        a = AppConfig.from_dict({"text_logs": [{"path": "C:/Logs/App.log"}]})
        b = AppConfig.from_dict({"text_logs": [{"path": "c:/logs/app.log"}]})
        assert a.text_logs[0].id == b.text_logs[0].id
        assert a.text_logs[0].id.startswith("textlog-")

    def test_duplicate_ids_are_removed(self):
        warnings: list[str] = []
        config = AppConfig.from_dict(
            {"text_logs": [{"path": "C:/a.log", "id": "x"}, {"path": "C:/b.log", "id": "x"}]},
            warnings,
        )
        assert [s.path for s in config.text_logs] == ["C:/a.log"]
        assert "duplicate source id" in warnings[0]

    def test_invalid_regex_is_ignored(self):
        warnings: list[str] = []
        config = AppConfig.from_dict(
            {"text_logs": [{"path": "C:/a.log", "multiline_start": "([", "line_pattern": "ok"}]},
            warnings,
        )
        assert config.text_logs[0].multiline_start is None
        assert config.text_logs[0].line_pattern == "ok"
        assert "invalid regular expression" in warnings[0]

    def test_unknown_encoding_falls_back_to_auto(self):
        warnings: list[str] = []
        config = AppConfig.from_dict(
            {"text_logs": [{"path": "C:/a.log", "encoding": "klingon-8"}]}, warnings
        )
        assert config.text_logs[0].encoding == "auto"
        assert warnings

    def test_known_encoding_kept(self):
        config = AppConfig.from_dict({"text_logs": [{"path": "C:/a.log", "encoding": "cp1252"}]})
        assert config.text_logs[0].encoding == "cp1252"
