"""Tests for the daemon's wire-protocol version negotiation (#35).

These tests mock the WebSocket end-to-end — no live network. They focus on
the handshake-level behavior: HELLO carries `protocol_version`, the
daemon respects the platform's HELLO_ACK negotiation, and a major
mismatch triggers WS close code 4426 plus a `_disable_reconnect` flag
that suppresses the auto-reconnect loop.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from autogpt_local_executor.config import ShimConfig
from autogpt_local_executor.daemon import (
    WS_CLOSE_PROTOCOL_VERSION_MISMATCH,
    ShimDaemon,
)
from autogpt_local_executor.protocol import (
    VERSION,
    ProtocolVersionMismatch,
    dump_message,
    new_id,
    now_ts,
)
from autogpt_local_executor.protocol import (
    HelloAckMessage,
    HelloAckPayload,
)


class _FakeWebSocket:
    """Minimal WS double — collects sent frames, replays a script of inbound
    raw strings, and records close() calls.

    The script is consumed in order. `recv()` after the script is exhausted
    raises asyncio.CancelledError so the daemon's inbound loop exits cleanly.
    """

    def __init__(self, inbound: list[str]) -> None:
        self._inbound = list(inbound)
        self.sent: list[str] = []
        self.close_calls: list[dict[str, Any]] = []
        self._closed = False

    async def send(self, raw: str) -> None:
        if self._closed:
            raise RuntimeError("send after close")
        self.sent.append(raw)

    async def recv(self) -> str:
        if not self._inbound:
            # Simulate "no more frames" by parking forever; tests assert
            # behavior before this point.
            await asyncio.sleep(3600)
            raise AssertionError("recv() should not block this long in tests")
        return self._inbound.pop(0)

    async def close(self, *, code: int = 1000, reason: str = "") -> None:
        self.close_calls.append({"code": code, "reason": reason})
        self._closed = True


@pytest.fixture()
def shim_config(tmp_path: Path) -> ShimConfig:
    return ShimConfig(
        allowed_root=tmp_path / "workspace",
        audit_log_path=tmp_path / "audit.log",
        session_id="test-session",
        machine_id="test-machine",
    )


@pytest.fixture()
def daemon(shim_config: ShimConfig) -> ShimDaemon:
    # audit=None disables the audit writer for simplicity.
    return ShimDaemon(shim_config, token_store=None, audit=None)


def _make_hello_ack(protocol_version: str = VERSION, **overrides: Any) -> str:
    payload = HelloAckPayload(
        session_id=overrides.pop("session_id", "s-fake"),
        granted_capabilities=overrides.pop("granted_capabilities", ["shell", "files"]),
        max_file_size_bytes=overrides.pop("max_file_size_bytes", 1024),
        command_timeout_seconds=overrides.pop("command_timeout_seconds", 30),
        max_concurrent=overrides.pop("max_concurrent", 4),
        protocol_version=protocol_version,
    )
    return dump_message(HelloAckMessage(id=new_id(), ts=now_ts(), payload=payload))


async def test_hello_includes_protocol_version(daemon: ShimDaemon) -> None:
    """The HELLO frame the daemon sends advertises VERSION as protocol_version."""
    ws = _FakeWebSocket(inbound=[_make_hello_ack()])
    await daemon._handshake(ws)
    assert len(ws.sent) == 1
    hello = json.loads(ws.sent[0])
    assert hello["type"] == "HELLO"
    assert hello["payload"]["protocol_version"] == VERSION
    # Envelope-level version too.
    assert hello["version"] == VERSION


async def test_handshake_negotiates_minor_floor(daemon: ShimDaemon) -> None:
    """Platform advertises a higher minor; shim wins the floor."""
    ws = _FakeWebSocket(inbound=[_make_hello_ack(protocol_version="1.9")])
    await daemon._handshake(ws)
    # Effective version is min(shim_minor, platform_minor) on shared major.
    shim_major = int(VERSION.split(".")[0])
    shim_minor = int(VERSION.split(".")[1])
    expected = f"{shim_major}.{min(shim_minor, 9)}"
    assert daemon._negotiated_version == expected


async def test_handshake_negotiates_when_shim_higher_minor(daemon: ShimDaemon) -> None:
    """Platform reports an older minor; negotiation floors to platform's."""
    ws = _FakeWebSocket(inbound=[_make_hello_ack(protocol_version="1.0")])
    await daemon._handshake(ws)
    # Shim and platform both at 1.0 in the default VERSION; this also covers
    # the case where the shim is on 1.x and platform is on 1.0.
    assert daemon._negotiated_version == "1.0"


async def test_handshake_major_mismatch_closes_with_4426(daemon: ShimDaemon) -> None:
    """A platform announcing a different major triggers close-code 4426
    with a structured JSON reason and raises ProtocolVersionMismatch."""
    ws = _FakeWebSocket(inbound=[_make_hello_ack(protocol_version="2.0")])
    with pytest.raises(ProtocolVersionMismatch) as exc_info:
        await daemon._handshake(ws)
    err = exc_info.value
    assert err.shim_max == VERSION
    assert err.platform_max == "2.0"
    # ws.close() called with the structured close reason.
    assert ws.close_calls, "expected ws.close() to be invoked"
    call = ws.close_calls[-1]
    assert call["code"] == WS_CLOSE_PROTOCOL_VERSION_MISMATCH == 4426
    reason = json.loads(call["reason"])
    assert reason["error"] == "PROTOCOL_VERSION_MISMATCH"
    assert reason["shim_max"] == VERSION
    assert reason["platform_max"] == "2.0"
    assert "hint" in reason


async def test_run_disables_reconnect_on_version_mismatch(
    daemon: ShimDaemon, monkeypatch: pytest.MonkeyPatch
) -> None:
    """run() catches ProtocolVersionMismatch, sets _disable_reconnect, and
    exits without scheduling a retry. This prevents hot-reconnect storms."""
    call_count = {"n": 0}

    async def fake_session() -> None:
        call_count["n"] += 1
        raise ProtocolVersionMismatch(
            shim_max=VERSION,
            platform_max="2.0",
            hint="upgrade",
        )

    # Bypass preflight + audit emits.
    monkeypatch.setattr(daemon, "_preflight_or_raise", lambda: None)
    monkeypatch.setattr(daemon, "_audit_shim_start", _coro_noop)
    monkeypatch.setattr(daemon, "_audit_shim_stop", _coro_arg_noop)
    monkeypatch.setattr(daemon, "_session", fake_session)

    await asyncio.wait_for(daemon.run(), timeout=2.0)

    assert call_count["n"] == 1, "should not retry after version mismatch"
    assert daemon._disable_reconnect is True


async def _coro_noop() -> None:
    return None


async def _coro_arg_noop(*_args: Any, **_kwargs: Any) -> None:
    return None
