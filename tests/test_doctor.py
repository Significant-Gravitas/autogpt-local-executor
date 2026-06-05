"""Tests for `autogpt-shim doctor` and the daemon TCC preflight."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from autogpt_local_executor import doctor
from autogpt_local_executor.config import ShimConfig


def _config(tmp_path: Path, **overrides) -> ShimConfig:
    return ShimConfig(
        allowed_root=tmp_path,
        audit_log_path=tmp_path / "_audit.log",
        platform_url="http://localhost:9999",
        machine_id="test-machine",
        **overrides,
    )


def test_doctor_returns_zero_when_computer_use_not_requested(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    """No computer-use requested → blocking permissions don't block."""
    monkeypatch.setattr(doctor.platform_info, "detect_platform", lambda: "darwin")
    monkeypatch.setattr(doctor, "_ax_trusted_with_prompt", lambda: False)
    monkeypatch.setattr(doctor, "_screen_recording_granted", lambda: False)
    monkeypatch.setattr(
        "autogpt_local_executor.computer_use.get_backend",
        lambda _: MagicMock(display_info=lambda: []),
    )
    config = _config(tmp_path, enable_computer_use=False)
    rc = doctor.run_doctor(config)
    assert rc == 0


def test_doctor_returns_78_when_ax_denied_and_computer_use_requested(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(doctor.platform_info, "detect_platform", lambda: "darwin")
    monkeypatch.setattr(doctor, "_ax_trusted_with_prompt", lambda: False)
    monkeypatch.setattr(doctor, "_screen_recording_granted", lambda: True)
    monkeypatch.setattr(
        "autogpt_local_executor.computer_use.get_backend",
        lambda _: MagicMock(display_info=lambda: []),
    )
    config = _config(tmp_path, enable_computer_use=True)
    rc = doctor.run_doctor(config)
    assert rc == doctor.EX_CONFIG


def test_doctor_linux_wayland_warns_when_computer_use_on(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(doctor.platform_info, "detect_platform", lambda: "linux")
    monkeypatch.setenv("XDG_SESSION_TYPE", "wayland")
    monkeypatch.setattr(
        "autogpt_local_executor.computer_use.get_backend",
        lambda _: MagicMock(display_info=lambda: []),
    )
    config = _config(tmp_path, enable_computer_use=True)
    rc = doctor.run_doctor(config)
    assert rc == doctor.EX_CONFIG


def test_doctor_linux_x11_ok_when_computer_use_on(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(doctor.platform_info, "detect_platform", lambda: "linux")
    monkeypatch.setenv("XDG_SESSION_TYPE", "x11")
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    monkeypatch.setattr(
        "autogpt_local_executor.computer_use.get_backend",
        lambda _: MagicMock(display_info=lambda: []),
    )
    config = _config(tmp_path, enable_computer_use=True)
    rc = doctor.run_doctor(config)
    assert rc == 0


def test_doctor_wsl2_blocks_when_computer_use_on(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(doctor.platform_info, "detect_platform", lambda: "wsl2")
    monkeypatch.setattr(
        "autogpt_local_executor.computer_use.get_backend",
        lambda _: MagicMock(display_info=lambda: []),
    )
    config = _config(tmp_path, enable_computer_use=True)
    rc = doctor.run_doctor(config)
    assert rc == doctor.EX_CONFIG


# ── Daemon TCC preflight (C2) ───────────────────────────────────────────


def test_daemon_preflight_passes_when_computer_use_off(tmp_path) -> None:
    from autogpt_local_executor.daemon import ShimDaemon

    config = _config(tmp_path, enable_computer_use=False)
    d = ShimDaemon(config=config, token_store=MagicMock(), audit=None)
    d._preflight_or_raise()  # should not raise


def test_daemon_preflight_raises_when_ax_denied_on_macos(tmp_path, monkeypatch) -> None:
    """Q5: macOS + computer_use requested + AX denied → DaemonPreflightError."""
    from autogpt_local_executor.daemon import DaemonPreflightError, ShimDaemon

    monkeypatch.setattr(
        "autogpt_local_executor.daemon.platform_info.detect_platform",
        lambda: "darwin",
    )
    import sys
    fake_appsvc = MagicMock()
    fake_appsvc.AXIsProcessTrusted = lambda: False
    monkeypatch.setitem(sys.modules, "ApplicationServices", fake_appsvc)
    config = _config(tmp_path, enable_computer_use=True)
    d = ShimDaemon(config=config, token_store=MagicMock(), audit=None)
    with pytest.raises(DaemonPreflightError):
        d._preflight_or_raise()


def test_daemon_preflight_passes_when_ax_granted_on_macos(tmp_path, monkeypatch) -> None:
    from autogpt_local_executor.daemon import ShimDaemon

    monkeypatch.setattr(
        "autogpt_local_executor.daemon.platform_info.detect_platform",
        lambda: "darwin",
    )
    import sys
    fake_appsvc = MagicMock()
    fake_appsvc.AXIsProcessTrusted = lambda: True
    monkeypatch.setitem(sys.modules, "ApplicationServices", fake_appsvc)
    config = _config(tmp_path, enable_computer_use=True)
    d = ShimDaemon(config=config, token_store=MagicMock(), audit=None)
    d._preflight_or_raise()


def test_daemon_preflight_no_op_on_non_macos(tmp_path, monkeypatch) -> None:
    """Per Q5, the AX gate only applies to macOS — Windows/Linux are
    handled by their own permission models."""
    from autogpt_local_executor.daemon import ShimDaemon

    monkeypatch.setattr(
        "autogpt_local_executor.daemon.platform_info.detect_platform",
        lambda: "linux",
    )
    config = _config(tmp_path, enable_computer_use=True)
    d = ShimDaemon(config=config, token_store=MagicMock(), audit=None)
    d._preflight_or_raise()  # no raise
