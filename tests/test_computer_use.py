"""Tests for ComputerUseHandler."""

from __future__ import annotations

import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from autogpt_local_executor.config import ShimConfig
from autogpt_local_executor.handlers import ComputerUseHandler
from autogpt_local_executor.protocol import MessageType


def make_config(tmp_path: Path, enable: bool = True) -> ShimConfig:
    return ShimConfig(
        allowed_root=tmp_path,
        enable_computer_use=enable,
        platform_ws_url="ws://localhost:9999/ws/local-executor",
        platform_oauth_url="http://localhost:9999/auth",
        machine_id="test-machine",
    )


def make_msg(msg_type: str, payload: dict) -> dict:
    return {"type": msg_type, "id": str(uuid.uuid4()), "ts": 0.0, "payload": payload}


@pytest.mark.asyncio
async def test_screenshot_disabled(tmp_path: Path) -> None:
    config = make_config(tmp_path, enable=False)
    handler = ComputerUseHandler(config)
    msg = make_msg(MessageType.SCREENSHOT_REQUEST, {})
    resp = await handler.handle(msg)
    assert resp["type"] == MessageType.ERROR
    assert resp["payload"]["code"] == "CAPABILITY_NOT_GRANTED"


@pytest.mark.asyncio
async def test_screenshot_no_pyautogui(tmp_path: Path) -> None:
    config = make_config(tmp_path, enable=True)
    handler = ComputerUseHandler(config)
    msg = make_msg(MessageType.SCREENSHOT_REQUEST, {})

    import autogpt_local_executor.handlers as h_mod
    original = h_mod._pyautogui
    h_mod._pyautogui = None
    try:
        resp = await handler.handle(msg)
    finally:
        h_mod._pyautogui = original

    assert resp["type"] == MessageType.ERROR
    assert resp["payload"]["code"] == "DEPENDENCY_MISSING"


@pytest.mark.asyncio
async def test_screenshot_returns_base64(tmp_path: Path) -> None:
    config = make_config(tmp_path, enable=True)
    handler = ComputerUseHandler(config)
    msg = make_msg(MessageType.SCREENSHOT_REQUEST, {"quality": 75})

    import io
    from unittest.mock import MagicMock
    from PIL import Image

    fake_img = Image.new("RGB", (100, 50), color=(255, 0, 0))

    mock_pyautogui = MagicMock()
    mock_pyautogui.screenshot.return_value = fake_img

    import autogpt_local_executor.handlers as h_mod
    original_pg = h_mod._pyautogui
    original_img = h_mod._Image
    h_mod._pyautogui = mock_pyautogui
    h_mod._Image = Image
    try:
        resp = await handler.handle(msg)
    finally:
        h_mod._pyautogui = original_pg
        h_mod._Image = original_img

    assert resp["type"] == MessageType.SCREENSHOT_RESPONSE
    assert resp["payload"]["encoding"] == "base64"
    assert len(resp["payload"]["image"]) > 0
    assert resp["payload"]["width"] == 100
    assert resp["payload"]["height"] == 50
