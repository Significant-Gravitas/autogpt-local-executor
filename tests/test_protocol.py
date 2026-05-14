"""Tests for protocol message builders and parsers."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from autogpt_local_executor.protocol import MessageType, build_hello, parse_message


def make_config() -> MagicMock:
    cfg = MagicMock()
    cfg.enable_shell = True
    cfg.enable_computer_use = False
    cfg.enable_local_llm = False
    cfg.enable_hardware = False
    cfg.machine_id = "test-machine-abc123"
    cfg.allowed_root = Path("/tmp/workspace")
    return cfg


def test_build_hello_structure() -> None:
    cfg = make_config()
    msg = build_hello(cfg)
    assert msg["type"] == MessageType.HELLO
    assert "id" in msg
    assert "ts" in msg
    p = msg["payload"]
    assert p["machine_id"] == "test-machine-abc123"
    assert "shell" in p["capabilities"]
    assert "files" in p["capabilities"]
    assert "computer_use" not in p["capabilities"]


def test_build_hello_with_computer_use() -> None:
    cfg = make_config()
    cfg.enable_computer_use = True
    msg = build_hello(cfg)
    assert "computer_use" in msg["payload"]["capabilities"]


def test_parse_message_valid() -> None:
    raw = json.dumps({"type": "HELLO_ACK", "id": "abc-123", "ts": 1234.0, "payload": {}})
    msg = parse_message(raw)
    assert msg["type"] == "HELLO_ACK"
    assert msg["id"] == "abc-123"


def test_parse_message_invalid_json() -> None:
    with pytest.raises((json.JSONDecodeError, ValueError)):
        parse_message("not-json{{{")


def test_parse_message_missing_fields() -> None:
    raw = json.dumps({"type": "HELLO_ACK"})  # missing id
    with pytest.raises(ValueError, match="missing type or id"):
        parse_message(raw)
