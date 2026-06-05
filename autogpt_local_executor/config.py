"""
ShimConfig — runtime configuration for the shim.

Loaded from (highest precedence first):
1. CLI flags (constructed via ShimConfig(...) overrides)
2. Environment variables (AUTOGPT_SHIM_*)
3. TOML file at ~/.config/autogpt-local-executor/config.toml (or per-OS equivalent)
4. Built-in defaults below

Per-OS defaults for allowed_root and audit_log_path follow the tables in
docs/CROSS_PLATFORM.md "Default allowed_root" and "Audit log location".
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore[no-redef]

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from . import platform_info


def _default_config_path() -> Path:
    """Per-OS config file location. Used by `load_config()`."""
    plat = platform_info.detect_platform()
    if plat == "windows":
        import os as _os

        base = Path(_os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming")))
        return base / "autogpt-local-executor" / "config.toml"
    if plat == "darwin":
        return (
            Path.home()
            / "Library"
            / "Application Support"
            / "autogpt-local-executor"
            / "config.toml"
        )
    # linux / wsl2
    import os as _os

    xdg = _os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "autogpt-local-executor" / "config.toml"


class ShimConfig(BaseSettings):
    """All configuration for the local executor shim.

    Wire-visible fields (`allowed_root`, capability flags, `machine_id`) are
    advertised in HELLO. Server-side overrides (`max_concurrent`,
    `command_timeout_seconds`, `max_file_size_bytes`) arrive in HELLO_ACK and
    the daemon updates the live config to honor them.
    """

    model_config = SettingsConfigDict(
        env_prefix="AUTOGPT_SHIM_",
        extra="ignore",
        env_file=None,
    )

    # ── Platform / OAuth ───────────────────────────────────────────────────
    platform_url: str = Field(
        default="wss://platform.autogpt.net",
        description="Base URL of the AutoGPT platform. WebSocket and OAuth "
        "endpoints are derived from this.",
    )
    platform_ws_url: str | None = Field(
        default=None,
        description="Override for the WebSocket base URL. Defaults to "
        "<platform_url>/ws/local-executor (with ws/wss adjusted).",
    )
    platform_oauth_url: str | None = Field(
        default=None,
        description="Override for the OAuth base URL. Defaults to "
        "<platform_url>/auth (with http/https adjusted).",
    )
    oauth_client_id: str = Field(default="autogpt-local-executor")
    oauth_redirect_port: int = Field(
        default=41899,
        description="First port in the 41899-41910 fallback range to bind "
        "for the OAuth callback listener.",
    )

    # ── Session ────────────────────────────────────────────────────────────
    session_id: str | None = Field(default=None)

    # ── Identity ───────────────────────────────────────────────────────────
    machine_id: str = Field(
        default_factory=lambda: platform_info.detect_machine_id(),
        description="Stable identifier for this machine.",
    )

    # ── File jail / audit ──────────────────────────────────────────────────
    allowed_root: Path = Field(
        default_factory=lambda: platform_info.default_allowed_root(),
        description="All file ops are jailed to this directory.",
    )
    audit_log_path: Path = Field(
        default_factory=lambda: platform_info.default_audit_log_path(),
        description="Append-only command audit log.",
    )

    # ── Capabilities (advertised in HELLO) ─────────────────────────────────
    enable_shell: bool = Field(default=True)
    enable_computer_use: bool = Field(default=False)
    enable_local_llm: bool = Field(default=False)
    enable_hardware: bool = Field(default=False)

    # ── Limits (also negotiated via HELLO_ACK) ─────────────────────────────
    max_concurrent: int = Field(default=4, description="Concurrent in-flight requests.")
    max_concurrent_commands: int = Field(
        default=10,
        description="Concurrent EXECUTE_COMMAND requests (≤ max_concurrent).",
    )
    command_timeout_seconds: int = Field(default=30)
    max_file_size_bytes: int = Field(default=10 * 1024 * 1024)  # 10 MiB
    max_commands_per_minute: int = Field(default=60)

    # ── Reconnect ──────────────────────────────────────────────────────────
    reconnect_base_delay: float = Field(default=1.0)
    reconnect_max_delay: float = Field(default=60.0)
    reconnect_jitter_seconds: float = Field(default=5.0)

    # ── Computer use ───────────────────────────────────────────────────────
    max_screenshots_per_minute: int = Field(default=10)
    enable_clipboard: bool = Field(
        default=False,
        description="Allow CLIPBOARD_READ / CLIPBOARD_WRITE. Without this "
        "flag clipboard sub-ops return FEATURE_NOT_SUPPORTED. See "
        "docs/COMPUTER_USE.md Q3.",
    )
    enable_clipboard_read_foreign: bool = Field(
        default=False,
        description="When set together with --enable-clipboard, allow "
        "CLIPBOARD_READ to return foreign (non-shim-written) contents, "
        "subject to ConcealedType / CF_PRIVATE checks. Without this, "
        "CLIPBOARD_READ is writeback-only with a 30s window. See "
        "docs/COMPUTER_USE.md Q3.",
    )

    @property
    def derived_ws_url(self) -> str:
        if self.platform_ws_url:
            return self.platform_ws_url
        base = self.platform_url.rstrip("/")
        # Convert https→wss, http→ws when needed.
        if base.startswith("https://"):
            base = "wss://" + base[len("https://") :]
        elif base.startswith("http://"):
            base = "ws://" + base[len("http://") :]
        return base + "/ws/local-executor"

    @property
    def derived_oauth_url(self) -> str:
        if self.platform_oauth_url:
            return self.platform_oauth_url
        base = self.platform_url.rstrip("/")
        if base.startswith("wss://"):
            base = "https://" + base[len("wss://") :]
        elif base.startswith("ws://"):
            base = "http://" + base[len("ws://") :]
        return base + "/auth"


def load_config(
    config_path: Path | None = None,
    overrides: dict[str, Any] | None = None,
) -> ShimConfig:
    """Layered config load: defaults → TOML file → env (via pydantic-settings)
    → caller overrides (dict, typically from CLI args).
    """
    overrides = dict(overrides or {})
    file_overrides: dict[str, Any] = {}
    path = config_path or _default_config_path()
    if path.is_file():
        with open(path, "rb") as f:
            file_overrides = tomllib.load(f)
        # Coerce string paths into Path objects so pydantic doesn't choke.
        for key in ("allowed_root", "audit_log_path"):
            if key in file_overrides and isinstance(file_overrides[key], str):
                file_overrides[key] = Path(file_overrides[key])
    merged = {**file_overrides, **overrides}
    return ShimConfig(**merged)
