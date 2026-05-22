"""Tests for ShimConfig and load_config layered loading."""

from __future__ import annotations

from pathlib import Path

from autogpt_local_executor.config import ShimConfig, load_config


def test_default_values_present() -> None:
    cfg = ShimConfig()
    assert cfg.oauth_client_id == "autogpt-local-executor"
    assert cfg.oauth_redirect_port == 41899
    assert cfg.max_concurrent == 4
    assert cfg.command_timeout_seconds == 30
    assert cfg.max_file_size_bytes == 10 * 1024 * 1024


def test_env_var_override(monkeypatch) -> None:
    monkeypatch.setenv("AUTOGPT_SHIM_OAUTH_REDIRECT_PORT", "42000")
    cfg = ShimConfig()
    assert cfg.oauth_redirect_port == 42000


def test_load_config_with_toml_overrides(tmp_path: Path) -> None:
    toml_file = tmp_path / "config.toml"
    toml_file.write_text(
        'platform_url = "http://localhost:8000"\n'
        'oauth_redirect_port = 42010\n'
        f'allowed_root = "{tmp_path}/ws"\n'
    )
    cfg = load_config(config_path=toml_file)
    assert cfg.platform_url == "http://localhost:8000"
    assert cfg.oauth_redirect_port == 42010
    assert cfg.allowed_root == tmp_path / "ws"


def test_load_config_overrides_win(tmp_path: Path) -> None:
    toml_file = tmp_path / "config.toml"
    toml_file.write_text('oauth_redirect_port = 42010\n')
    cfg = load_config(
        config_path=toml_file,
        overrides={"oauth_redirect_port": 42050},
    )
    assert cfg.oauth_redirect_port == 42050


def test_derived_ws_url_from_https() -> None:
    cfg = ShimConfig(platform_url="https://platform.example.com")
    assert cfg.derived_ws_url == "wss://platform.example.com/ws/local-executor"


def test_derived_ws_url_from_http() -> None:
    cfg = ShimConfig(platform_url="http://localhost:8000")
    assert cfg.derived_ws_url == "ws://localhost:8000/ws/local-executor"


def test_derived_oauth_url_from_wss() -> None:
    cfg = ShimConfig(platform_url="wss://platform.example.com")
    assert cfg.derived_oauth_url == "https://platform.example.com/auth"


def test_explicit_overrides_take_priority() -> None:
    cfg = ShimConfig(
        platform_url="https://x",
        platform_ws_url="ws://explicit-override/ws",
    )
    assert cfg.derived_ws_url == "ws://explicit-override/ws"
