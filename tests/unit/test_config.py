"""Unit tests for layered configuration."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from secret_shield.config import (
    ENV_PREFIX,
    ConfigError,
    ConfigLayer,
    load_config,
)


def write_pyproject(root: Path, **settings: object) -> None:
    content = ["[tool.secretshield]"]
    for key, value in settings.items():
        if isinstance(value, bool):
            content.append(f'"{key}" = {str(value).lower()}')
        elif isinstance(value, (int, float)):
            content.append(f'"{key}" = {value}')
        elif isinstance(value, str):
            content.append(f'"{key}" = {json.dumps(value)}')
        elif isinstance(value, list):
            content.append(f'"{key}" = {json.dumps(value)}')
        else:
            content.append(f'"{key}" = {json.dumps(value)}')
    (root / "pyproject.toml").write_text("\n".join(content) + "\n", encoding="utf-8")


def write_toml(root: Path, **settings: object) -> None:
    content = []
    for key, value in settings.items():
        if isinstance(value, bool):
            content.append(f'"{key}" = {str(value).lower()}')
        elif isinstance(value, (int, float)):
            content.append(f'"{key}" = {value}')
        elif isinstance(value, str):
            content.append(f'"{key}" = {json.dumps(value)}')
        elif isinstance(value, list):
            content.append(f'"{key}" = {json.dumps(value)}')
        else:
            content.append(f'"{key}" = {json.dumps(value)}')
    (root / ".secretshield.toml").write_text(
        "\n".join(content) + "\n", encoding="utf-8"
    )


def write_json(root: Path, **settings: object) -> None:
    (root / ".secretshield.json").write_text(
        json.dumps(settings, indent=2) + "\n", encoding="utf-8"
    )


def test_load_config_with_no_files_returns_defaults(tmp_path: Path) -> None:
    cfg = load_config(project_root=tmp_path)
    assert cfg.root == tmp_path.resolve()
    assert cfg.origins == ()


def test_load_config_rejects_non_directory(tmp_path: Path) -> None:
    f = tmp_path / "file.txt"
    f.write_text("hi")
    with pytest.raises(ConfigError):
        load_config(project_root=f)


def test_load_config_rejects_non_path_root(tmp_path: Path) -> None:
    with pytest.raises(TypeError):
        load_config(project_root="not-a-path")  # type: ignore[arg-type]


def test_load_config_rejects_bad_environ(tmp_path: Path) -> None:
    with pytest.raises(TypeError):
        load_config(project_root=tmp_path, environ="bad")  # type: ignore[arg-type]


def test_load_config_rejects_bad_overrides(tmp_path: Path) -> None:
    with pytest.raises(TypeError):
        load_config(project_root=tmp_path, overrides="bad")  # type: ignore[arg-type]


def test_pyproject_toml_loads_nested_section(tmp_path: Path) -> None:
    write_pyproject(tmp_path, **{"scan.max_files": 42})
    cfg = load_config(project_root=tmp_path)
    assert cfg.path_scan.max_files == 42
    assert len(cfg.origins) == 1
    assert cfg.origins[0].layer is ConfigLayer.PYPROJECT


def test_pyproject_toml_with_no_section_is_ignored(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        "[tool.other]\nkey = 1\n", encoding="utf-8"
    )
    cfg = load_config(project_root=tmp_path)
    assert cfg.origins == ()


def test_secretshield_toml_loaded(tmp_path: Path) -> None:
    write_toml(tmp_path, **{"scan.max_files": 10})
    cfg = load_config(project_root=tmp_path)
    assert cfg.path_scan.max_files == 10
    assert cfg.origins[0].layer is ConfigLayer.TOML


def test_secretshield_json_loaded(tmp_path: Path) -> None:
    write_json(tmp_path, **{"scan.max_files": 11})
    cfg = load_config(project_root=tmp_path)
    assert cfg.path_scan.max_files == 11
    assert cfg.origins[0].layer is ConfigLayer.JSON


def test_json_rejects_duplicate_keys(tmp_path: Path) -> None:
    (tmp_path / ".secretshield.json").write_text(
        '{"scan": {"max_files": 1}, "scan.max_files": 2}\n', encoding="utf-8"
    )
    with pytest.raises(ConfigError):
        load_config(project_root=tmp_path)


def test_toml_with_directory_name_is_error(tmp_path: Path) -> None:
    d = tmp_path / ".secretshield.toml"
    d.mkdir()
    with pytest.raises(ConfigError):
        load_config(project_root=tmp_path)


def test_precedence_order_is_correct(tmp_path: Path) -> None:
    write_pyproject(tmp_path, **{"scan.max_files": 1})
    write_toml(tmp_path, **{"scan.max_files": 2})
    write_json(tmp_path, **{"scan.max_files": 3})
    env = {f"{ENV_PREFIX}MAX_FILES": "4"}
    cfg = load_config(
        project_root=tmp_path, environ=env, overrides={"scan.max_files": 5}
    )
    assert cfg.path_scan.max_files == 5
    layers = [o.layer for o in cfg.origins]
    assert layers == [
        ConfigLayer.PYPROJECT,
        ConfigLayer.TOML,
        ConfigLayer.JSON,
        ConfigLayer.ENVIRONMENT,
        ConfigLayer.OVERRIDES,
    ]


def test_env_boolean_parsing(tmp_path: Path) -> None:
    for val in ("1", "true", "yes", "on", "TRUE", "Yes"):
        cfg = load_config(
            project_root=tmp_path, environ={f"{ENV_PREFIX}FOLLOW_SYMLINKS": val}
        )
        assert cfg.path_scan.filters.follow_symlinks is True
    for val in ("0", "false", "no", "off", "FALSE", "No"):
        cfg = load_config(
            project_root=tmp_path, environ={f"{ENV_PREFIX}FOLLOW_SYMLINKS": val}
        )
        assert cfg.path_scan.filters.follow_symlinks is False


def test_env_boolean_rejects_bad(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load_config(
            project_root=tmp_path, environ={f"{ENV_PREFIX}FOLLOW_SYMLINKS": "maybe"}
        )


def test_env_optional_integer_null_words(tmp_path: Path) -> None:
    for val in ("none", "null", "unlimited", "UNSET"):
        cfg = load_config(
            project_root=tmp_path, environ={f"{ENV_PREFIX}MAX_DEPTH": val}
        )
        assert cfg.path_scan.filters.max_depth is None


def test_env_optional_integer_empty_is_not_null(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load_config(project_root=tmp_path, environ={f"{ENV_PREFIX}MAX_DEPTH": ""})


def test_list_replacement_not_extension(tmp_path: Path) -> None:
    write_toml(tmp_path, **{"paths.ignored_directories": ["custom"]})
    cfg = load_config(project_root=tmp_path)
    assert cfg.path_scan.filters.ignored_directories == frozenset({"custom"})


def test_unknown_key_raises(tmp_path: Path) -> None:
    write_toml(tmp_path, **{"unknown_key": 123})
    with pytest.raises(ConfigError) as excinfo:
        load_config(project_root=tmp_path)
    assert "unknown setting" in str(excinfo.value).lower()


def test_unknown_key_gives_suggestion(tmp_path: Path) -> None:
    write_toml(tmp_path, **{"scan.max_filez": 10})
    with pytest.raises(ConfigError) as excinfo:
        load_config(project_root=tmp_path)
    assert "did you mean" in str(excinfo.value).lower()


def test_unknown_env_var_raises(tmp_path: Path) -> None:
    env = {f"{ENV_PREFIX}UNKNOWN": "1"}
    with pytest.raises(ConfigError):
        load_config(project_root=tmp_path, environ=env)


def test_incomplete_env_var_raises_exact(tmp_path: Path) -> None:
    env = {ENV_PREFIX: "1"}
    with pytest.raises(ConfigError):
        load_config(project_root=tmp_path, environ=env)


def test_max_file_size_type_validation(tmp_path: Path) -> None:
    write_toml(tmp_path, **{"scan.max_file_size": "10"})
    with pytest.raises(ConfigError):
        load_config(project_root=tmp_path)


def test_optional_integer_accepts_null_json(tmp_path: Path) -> None:
    write_json(tmp_path, **{"paths.max_depth": None})
    cfg = load_config(project_root=tmp_path)
    assert cfg.path_scan.filters.max_depth is None


def test_number_bounds(tmp_path: Path) -> None:
    write_toml(tmp_path, **{"binary.max_control_ratio": -1})
    with pytest.raises(ConfigError):
        load_config(project_root=tmp_path)
    write_toml(tmp_path, **{"binary.max_control_ratio": 1.5})
    with pytest.raises(ConfigError):
        load_config(project_root=tmp_path)
    write_toml(tmp_path, **{"binary.max_control_ratio": 0.3})
    cfg = load_config(project_root=tmp_path)
    assert cfg.path_scan.binary.max_control_ratio == 0.3


def test_config_produces_same_scanner_behavior_as_defaults(tmp_path: Path) -> None:
    cfg = load_config(project_root=tmp_path)
    from secret_shield.sources.filesystem import default_path_scan_config

    assert cfg.path_scan.max_files == default_path_scan_config().max_files
    assert cfg.path_scan.max_line_length == default_path_scan_config().max_line_length
    assert (
        cfg.path_scan.scan.max_file_size
        == default_path_scan_config().scan.max_file_size
    )


def test_setting_source_tracking(tmp_path: Path) -> None:
    write_toml(tmp_path, **{"scan.max_files": 5})
    cfg = load_config(project_root=tmp_path)
    src = cfg.source_of("scan.max_files")
    assert src is not None
    assert src.layer is ConfigLayer.TOML
    assert cfg.is_default("scan.max_files") is False
    assert cfg.is_default("scan.max_file_size") is True


def test_config_accessors(tmp_path: Path) -> None:
    cfg = load_config(project_root=tmp_path)
    assert cfg.path_scan_config() == cfg.path_scan
    assert cfg.scan_config == cfg.path_scan.scan


def test_explicit_overrides_accept_both_spellings(tmp_path: Path) -> None:
    cfg1 = load_config(project_root=tmp_path, overrides={"scan.max_files": 10})
    cfg2 = load_config(project_root=tmp_path, overrides={"scan": {"max_files": 10}})
    assert cfg1.path_scan.max_files == cfg2.path_scan.max_files == 10
