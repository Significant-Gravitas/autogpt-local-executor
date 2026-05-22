"""Tests for protocol parsing and message envelopes."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from autogpt_local_executor.protocol import (
    ErrorCode,
    ExecuteCommandMessage,
    FileReadMessage,
    HelloAckMessage,
    HelloMessage,
    HelloPayload,
    MessageType,
    Platform,
    Shell,
    dump_message,
    make_ack,
    make_error,
    make_pong,
    new_id,
    parse_message,
)


def test_parse_ping() -> None:
    msg = parse_message('{"type": "PING", "id": "abc", "ts": 1.0, "payload": {}}')
    assert msg.type == MessageType.PING
    assert msg.id == "abc"


def test_parse_hello_ack() -> None:
    raw = json.dumps(
        {
            "type": "HELLO_ACK",
            "id": "abc",
            "ts": 1.0,
            "payload": {
                "session_id": "s1",
                "granted_capabilities": ["shell", "files"],
                "max_file_size_bytes": 1024,
                "command_timeout_seconds": 5,
                "max_concurrent": 2,
            },
        }
    )
    msg = parse_message(raw)
    assert isinstance(msg, HelloAckMessage)
    assert msg.payload.session_id == "s1"
    assert msg.payload.granted_capabilities == ["shell", "files"]


def test_parse_execute_command_with_argv() -> None:
    raw = json.dumps(
        {
            "type": "EXECUTE_COMMAND",
            "id": "abc",
            "ts": 1.0,
            "payload": {
                "argv": ["ls", "-la"],
                "command": None,
                "shell": "auto",
                "cwd": "/tmp",
                "timeout_seconds": 5,
                "env": {},
            },
        }
    )
    msg = parse_message(raw)
    assert isinstance(msg, ExecuteCommandMessage)
    assert msg.payload.argv == ["ls", "-la"]
    assert msg.payload.command is None


def test_parse_file_read_format_text_default() -> None:
    raw = json.dumps(
        {
            "type": "FILE_READ",
            "id": "abc",
            "ts": 1.0,
            "payload": {"path": "/tmp/a.txt"},
        }
    )
    msg = parse_message(raw)
    assert isinstance(msg, FileReadMessage)
    assert msg.payload.format == "text"
    assert msg.payload.encoding == "utf-8"


def test_parse_rejects_unknown_type() -> None:
    raw = json.dumps({"type": "BOGUS", "id": "x", "ts": 1.0, "payload": {}})
    with pytest.raises(ValidationError):
        parse_message(raw)


def test_parse_rejects_missing_id() -> None:
    raw = json.dumps({"type": "PING", "ts": 1.0, "payload": {}})
    with pytest.raises(ValidationError):
        parse_message(raw)


def test_parse_rejects_extra_payload_field() -> None:
    raw = json.dumps(
        {
            "type": "PING",
            "id": "x",
            "ts": 1.0,
            "payload": {"unexpected": "value"},
        }
    )
    with pytest.raises(ValidationError):
        parse_message(raw)


def test_dump_round_trip_hello() -> None:
    msg = HelloMessage(
        id=new_id(),
        ts=1.0,
        payload=HelloPayload(
            shim_version="0.0.1",
            machine_id="m1",
            platform=Platform.LINUX,
            arch="x86_64",  # type: ignore[arg-type]
            capabilities=["shell", "files"],
            allowed_root="/home/u/ws",
        ),
    )
    raw = dump_message(msg)
    again = parse_message(raw)
    assert isinstance(again, HelloMessage)
    assert again.payload.machine_id == "m1"


def test_make_error_uses_code_enum() -> None:
    err = make_error("x", ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT, "oops")
    payload = json.loads(dump_message(err))["payload"]
    assert payload["code"] == "PATH_OUTSIDE_ALLOWED_ROOT"


def test_make_ack_round_trip() -> None:
    ack = make_ack("x")
    raw = dump_message(ack)
    again = parse_message(raw)
    assert again.type == MessageType.ACK
    assert again.payload.ok is True


def test_make_pong_round_trip() -> None:
    pong = make_pong("x")
    raw = dump_message(pong)
    again = parse_message(raw)
    assert again.type == MessageType.PONG


def test_shell_enum_accepts_auto() -> None:
    raw = json.dumps(
        {
            "type": "EXECUTE_COMMAND",
            "id": "x",
            "ts": 1.0,
            "payload": {"command": "echo hi", "argv": None},
        }
    )
    msg = parse_message(raw)
    assert isinstance(msg, ExecuteCommandMessage)
    assert msg.payload.shell == Shell.AUTO
