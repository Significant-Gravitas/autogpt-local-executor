"""Tests for FileHandler and CommandHandler."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest

from autogpt_local_executor.config import ShimConfig
from autogpt_local_executor.handlers import CommandHandler, FileHandler
from autogpt_local_executor.protocol import MessageType


def make_config(tmp_path: Path) -> ShimConfig:
    return ShimConfig(
        allowed_root=tmp_path,
        platform_ws_url="ws://localhost:9999/ws/local-executor",
        platform_oauth_url="http://localhost:9999/auth",
        machine_id="test-machine",
    )


def make_msg(msg_type: str, payload: dict) -> dict:
    return {"type": msg_type, "id": str(uuid.uuid4()), "ts": 0.0, "payload": payload}


# ── FileHandler ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_file_write_and_read(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    handler = FileHandler(config)

    write_msg = make_msg(MessageType.FILE_WRITE, {
        "path": str(tmp_path / "hello.txt"),
        "content": "hello world",
        "encoding": "utf-8",
        "create_parents": False,
    })
    resp = await handler.handle(write_msg)
    assert resp["type"] == MessageType.ACK
    assert resp["payload"]["ok"] is True

    read_msg = make_msg(MessageType.FILE_READ, {
        "path": str(tmp_path / "hello.txt"),
        "encoding": "utf-8",
    })
    resp = await handler.handle(read_msg)
    assert resp["type"] == MessageType.FILE_CONTENTS
    assert resp["payload"]["content"] == "hello world"


@pytest.mark.asyncio
async def test_file_read_missing(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    handler = FileHandler(config)
    msg = make_msg(MessageType.FILE_READ, {"path": str(tmp_path / "nope.txt")})
    resp = await handler.handle(msg)
    assert resp["type"] == MessageType.ERROR
    assert resp["payload"]["code"] == "FILE_NOT_FOUND"


@pytest.mark.asyncio
async def test_file_path_jail(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    handler = FileHandler(config)
    msg = make_msg(MessageType.FILE_READ, {"path": "/etc/passwd"})
    resp = await handler.handle(msg)
    assert resp["type"] == MessageType.ERROR
    assert "PATH_OUTSIDE_ALLOWED_ROOT" in resp["payload"]["code"]


# ── CommandHandler ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_command_echo(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    handler = CommandHandler(config)
    msg = make_msg(MessageType.EXECUTE_COMMAND, {
        "command": "echo hello",
        "cwd": str(tmp_path),
    })
    resp = await handler.handle(msg)
    assert resp["type"] == MessageType.COMMAND_RESULT
    assert "hello" in resp["payload"]["stdout"]
    assert resp["payload"]["exit_code"] == 0
    assert resp["payload"]["timed_out"] is False


@pytest.mark.asyncio
async def test_command_exit_code(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    handler = CommandHandler(config)
    msg = make_msg(MessageType.EXECUTE_COMMAND, {
        "command": "exit 42",
        "cwd": str(tmp_path),
    })
    resp = await handler.handle(msg)
    assert resp["payload"]["exit_code"] == 42


@pytest.mark.asyncio
async def test_command_timeout(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    handler = CommandHandler(config)
    msg = make_msg(MessageType.EXECUTE_COMMAND, {
        "command": "sleep 10",
        "cwd": str(tmp_path),
        "timeout_seconds": 1,
    })
    resp = await handler.handle(msg)
    assert resp["payload"]["timed_out"] is True


@pytest.mark.asyncio
async def test_command_stderr(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    handler = CommandHandler(config)
    msg = make_msg(MessageType.EXECUTE_COMMAND, {
        "command": "echo err >&2",
        "cwd": str(tmp_path),
    })
    resp = await handler.handle(msg)
    assert "err" in resp["payload"]["stderr"]
