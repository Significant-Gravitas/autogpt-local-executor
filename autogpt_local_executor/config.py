"""
Shim configuration — loaded from environment vars or CLI args.
"""

from __future__ import annotations

import platform
import uuid
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class ShimConfig(BaseSettings):
    """
    All configuration for the local executor shim.

    Loaded from (in order of precedence):
    1. CLI flags
    2. Environment variables (AUTOGPT_SHIM_*)
    3. Defaults below
    """

    model_config = SettingsConfigDict(env_prefix="AUTOGPT_SHIM_", extra="ignore")

    # --- Platform connection ---
    platform_ws_url: str = Field(
        default="wss://platform.autogpt.net/ws/local-executor",
        description="WebSocket URL of the AutoGPT platform. Override for self-hosted.",
    )
    platform_oauth_url: str = Field(
        default="https://platform.autogpt.net/auth",
        description="Base URL for the AutoGPT OAuth endpoints.",
    )
    oauth_client_id: str = Field(
        default="autogpt-local-executor",
        description="Well-known OAuth client ID for the shim.",
    )
    oauth_redirect_port: int = Field(
        default=41899,
        description="Local port for the OAuth callback server during auth flow.",
    )

    # --- Session ---
    session_id: str | None = Field(
        default=None,
        description="Session ID assigned by the platform. Set by daemon at connect time.",
    )

    # --- Machine identity ---
    machine_id: str = Field(
        default_factory=lambda: f"{platform.node()}-{uuid.uuid4().hex[:8]}",
        description="Stable identifier for this machine.",
    )

    # --- File access ---
    allowed_root: Path = Field(
        default_factory=lambda: Path.home() / ".autogpt" / "workspace",
        description="All file operations are jailed to this directory.",
    )

    # --- Capabilities to advertise ---
    enable_shell: bool = Field(default=True)
    enable_computer_use: bool = Field(default=False)
    enable_local_llm: bool = Field(default=False)
    enable_hardware: bool = Field(default=False)

    # --- Rate limits ---
    max_commands_per_minute: int = Field(default=60)
    max_concurrent_commands: int = Field(default=4)
    max_file_size_bytes: int = Field(default=100 * 1024 * 1024)  # 100MB
    command_timeout_seconds: int = Field(default=30)

    # --- Audit ---
    audit_log_path: Path = Field(
        default_factory=lambda: Path.home() / ".autogpt" / "shim-audit.log",
    )

    # --- Reconnect ---
    reconnect_base_delay: float = Field(default=1.0)
    reconnect_max_delay: float = Field(default=60.0)
