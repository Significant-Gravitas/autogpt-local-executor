"""CLI safety and capability opt-in tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from autogpt_local_executor import cli
from autogpt_local_executor.config import ShimConfig


@pytest.mark.parametrize("session_after_start", [False, True])
def test_start_session_id_is_accepted_before_or_after_subcommand_without_overwrite(
    tmp_path: Path, session_after_start: bool
) -> None:
    parser = cli._build_parser()
    argv = [
        "--config",
        str(tmp_path / "missing.toml"),
        "--allowed-root",
        str(tmp_path),
    ]
    if not session_after_start:
        argv.extend(["--session-id", "session-123"])
    argv.append("start")
    if session_after_start:
        argv.extend(["--session-id", "session-123"])
    argv.extend(["--enable-shell", "--enable-recording"])
    args = parser.parse_args(argv)

    config = cli._build_config(args)

    assert config.session_id == "session-123"
    assert config.allowed_root == tmp_path
    assert config.enable_shell is True
    assert config.enable_recording is True


@pytest.mark.asyncio
@pytest.mark.parametrize("session_id", [None, "", "   "])
async def test_start_without_session_uses_persistent_control_mode(
    tmp_path: Path,
    session_id: str | None,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import autogpt_local_executor.daemon as daemon_module

    ran = False

    class ControlDaemon:
        def __init__(self, **_kwargs) -> None:
            pass

        async def run(self) -> None:
            nonlocal ran
            ran = True

    monkeypatch.setattr(daemon_module, "ShimDaemon", ControlDaemon)
    config = ShimConfig(
        session_id=session_id,
        allowed_root=tmp_path,
        audit_log_path=tmp_path / "audit.log",
    )

    assert await cli._cmd_start(config) == 0
    assert ran is True
    assert "persistent machine control" in capsys.readouterr().out


@pytest.mark.asyncio
async def test_recording_preview_fails_startup_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import autogpt_local_executor.daemon as daemon_module

    monkeypatch.setattr(daemon_module, "get_or_create_audit_key", lambda: b"a" * 32)
    config = ShimConfig(
        session_id="session-1",
        enable_recording=True,
        allowed_root=tmp_path,
        audit_log_path=tmp_path / "audit.log",
    )

    assert await cli._cmd_start(config) == 78
    output = capsys.readouterr().out
    assert "design preview" in output
    assert "capture and interpretation are incomplete" in output


@pytest.mark.asyncio
async def test_audit_initialization_failure_returns_ex_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import autogpt_local_executor.daemon as daemon_module

    def fail_audit(_config):
        raise daemon_module.DaemonPreflightError("audit unavailable")

    monkeypatch.setattr(
        daemon_module.ShimDaemon,
        "_build_audit_writer",
        staticmethod(fail_audit),
    )
    config = ShimConfig(
        session_id="session-1",
        allowed_root=tmp_path,
        audit_log_path=tmp_path / "audit.log",
    )

    assert await cli._cmd_start(config) == 78
    assert "Preflight failed: audit unavailable" in capsys.readouterr().out


@pytest.mark.asyncio
async def test_terminal_authentication_failure_returns_ex_noperm(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import autogpt_local_executor.daemon as daemon_module

    class RejectedDaemon:
        def __init__(self, **_kwargs) -> None:
            pass

        async def run(self) -> None:
            raise daemon_module.DaemonAuthenticationError("session denied")

    monkeypatch.setattr(daemon_module, "ShimDaemon", RejectedDaemon)
    config = ShimConfig(
        session_id="session-1",
        allowed_root=tmp_path,
        audit_log_path=tmp_path / "audit.log",
    )

    assert await cli._cmd_start(config) == 77
    assert "Authentication failed: session denied" in capsys.readouterr().out
