"""
Capability handlers — one class per capability type.
"""

from __future__ import annotations

import asyncio
import base64
import io
import os
import subprocess
import time
from pathlib import Path
from typing import Any

from .config import ShimConfig
from .protocol import MessageType

try:
    import pyautogui as _pyautogui
    from PIL import Image as _Image
except ImportError:
    _pyautogui = None  # type: ignore[assignment]
    _Image = None  # type: ignore[assignment]


def _jail_path(path_str: str, allowed_root: Path) -> Path:
    allowed = allowed_root.resolve()
    target = (allowed / path_str).resolve() if not Path(path_str).is_absolute() else Path(path_str).resolve()
    if not str(target).startswith(str(allowed)):
        raise PermissionError(f"PATH_OUTSIDE_ALLOWED_ROOT: {target} is outside {allowed}")
    return target


def _ack(msg_id: str) -> dict:
    return {"type": MessageType.ACK, "id": msg_id, "ts": time.time(), "payload": {"ok": True}}


def _error(msg_id: str, code: str, message: str, fatal: bool = False) -> dict:
    return {
        "type": MessageType.ERROR,
        "id": msg_id,
        "ts": time.time(),
        "payload": {"code": code, "message": message, "fatal": fatal},
    }


class FileHandler:
    def __init__(self, config: ShimConfig) -> None:
        self.config = config

    async def handle(self, msg: dict) -> dict:
        if msg["type"] == MessageType.FILE_READ:
            return await self._read(msg)
        return await self._write(msg)

    async def _read(self, msg: dict) -> dict:
        payload = msg["payload"]
        try:
            path = _jail_path(payload["path"], self.config.allowed_root)
        except PermissionError as e:
            return _error(msg["id"], "PATH_OUTSIDE_ALLOWED_ROOT", str(e))

        if not path.exists():
            return _error(msg["id"], "FILE_NOT_FOUND", f"{path} does not exist")

        size = path.stat().st_size
        if size > self.config.max_file_size_bytes:
            return _error(msg["id"], "FILE_TOO_LARGE", f"{size} bytes exceeds limit")

        encoding = payload.get("encoding", "utf-8")
        offset = payload.get("offset", 0)
        length = payload.get("length")

        raw = path.read_bytes()
        chunk = raw[offset: offset + length] if length else raw[offset:]
        truncated = length is not None and len(raw) - offset > length

        content = base64.b64encode(chunk).decode("ascii") if encoding == "base64" else chunk.decode("utf-8", errors="replace")

        return {
            "type": MessageType.FILE_CONTENTS,
            "id": msg["id"],
            "ts": time.time(),
            "payload": {"content": content, "encoding": encoding, "size_bytes": len(chunk), "truncated": truncated},
        }

    async def _write(self, msg: dict) -> dict:
        payload = msg["payload"]
        try:
            path = _jail_path(payload["path"], self.config.allowed_root)
        except PermissionError as e:
            return _error(msg["id"], "PATH_OUTSIDE_ALLOWED_ROOT", str(e))

        if payload.get("create_parents", False):
            path.parent.mkdir(parents=True, exist_ok=True)

        encoding = payload.get("encoding", "utf-8")
        content = payload["content"]
        raw = base64.b64decode(content) if encoding == "base64" else content.encode("utf-8")

        if len(raw) > self.config.max_file_size_bytes:
            return _error(msg["id"], "FILE_TOO_LARGE", "Content exceeds size limit")

        path.write_bytes(raw)
        return _ack(msg["id"])


class CommandHandler:
    SAFE_ENV_VARS = {"PATH", "HOME", "USER", "SHELL", "LANG", "LC_ALL", "TMPDIR"}

    def __init__(self, config: ShimConfig) -> None:
        self.config = config
        self._semaphore = asyncio.Semaphore(config.max_concurrent_commands)

    async def handle(self, msg: dict) -> dict:
        payload = msg["payload"]
        command = payload["command"]
        cwd_str = payload.get("cwd") or str(self.config.allowed_root)
        timeout = payload.get("timeout_seconds", self.config.command_timeout_seconds)
        extra_env = payload.get("env", {})

        try:
            cwd = _jail_path(cwd_str, self.config.allowed_root)
        except PermissionError as e:
            return _error(msg["id"], "PATH_OUTSIDE_ALLOWED_ROOT", str(e))

        safe_env = {k: v for k, v in os.environ.items() if k in self.SAFE_ENV_VARS}
        safe_env.update(extra_env)

        async with self._semaphore:
            start = time.monotonic()
            timed_out = False
            stdout_b = b""
            stderr_b = b""
            exit_code = -1
            try:
                proc = await asyncio.create_subprocess_shell(
                    command,
                    cwd=str(cwd),
                    env=safe_env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                try:
                    stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
                    exit_code = proc.returncode
                except asyncio.TimeoutError:
                    timed_out = True
                    try:
                        proc.kill()
                    except Exception:
                        pass
            except Exception as exc:
                return _error(msg["id"], "EXEC_ERROR", str(exc))
            duration = time.monotonic() - start

        return {
            "type": MessageType.COMMAND_RESULT,
            "id": msg["id"],
            "ts": time.time(),
            "payload": {
                "stdout": stdout_b.decode("utf-8", errors="replace"),
                "stderr": stderr_b.decode("utf-8", errors="replace"),
                "exit_code": exit_code,
                "timed_out": timed_out,
                "duration_seconds": round(duration, 3),
            },
        }


class ComputerUseHandler:
    def __init__(self, config: ShimConfig) -> None:
        self.config = config

    async def handle(self, msg: dict) -> dict:
        if not self.config.enable_computer_use:
            return _error(msg["id"], "CAPABILITY_NOT_GRANTED", "Computer use is not enabled on this shim.")

        if msg["type"] == MessageType.SCREENSHOT_REQUEST:
            return await self._screenshot(msg)
        return await self._execute_action(msg)

    async def _screenshot(self, msg: dict) -> dict:
        if _pyautogui is None or _Image is None:
            return _error(msg["id"], "DEPENDENCY_MISSING", "pyautogui/Pillow not installed. pip install autogpt-local-executor[computer-use]")

        quality = msg["payload"].get("quality", 75)

        def _capture() -> tuple[bytes, int, int]:
            img = _pyautogui.screenshot()
            buf = io.BytesIO()
            img.convert("RGB").save(buf, format="JPEG", quality=quality)
            return buf.getvalue(), img.width, img.height

        loop = asyncio.get_event_loop()
        try:
            img_bytes, w, h = await loop.run_in_executor(None, _capture)
        except Exception as exc:
            return _error(msg["id"], "SCREENSHOT_FAILED", str(exc))

        return {
            "type": MessageType.SCREENSHOT_RESPONSE,
            "id": msg["id"],
            "ts": time.time(),
            "payload": {
                "image": base64.b64encode(img_bytes).decode("ascii"),
                "encoding": "base64",
                "format": "jpeg",
                "width": w,
                "height": h,
            },
        }

    async def _execute_action(self, msg: dict) -> dict:
        if _pyautogui is None:
            return _error(msg["id"], "DEPENDENCY_MISSING", "pyautogui not installed.")

        payload = msg["payload"]
        action = payload["action"]
        coordinate = payload.get("coordinate")
        text = payload.get("text")
        key = payload.get("key")

        def _run():
            _pyautogui.FAILSAFE = True
            if action == "mouse_move" and coordinate:
                _pyautogui.moveTo(coordinate[0], coordinate[1])
            elif action in ("left_click", "click") and coordinate:
                _pyautogui.click(coordinate[0], coordinate[1])
            elif action == "right_click" and coordinate:
                _pyautogui.rightClick(coordinate[0], coordinate[1])
            elif action == "double_click" and coordinate:
                _pyautogui.doubleClick(coordinate[0], coordinate[1])
            elif action == "type" and text:
                _pyautogui.write(text, interval=0.02)
            elif action == "key" and key:
                _pyautogui.hotkey(*key.split("+"))
            elif action == "hotkey" and key:
                _pyautogui.hotkey(*key.split("+"))
            elif action == "scroll" and coordinate:
                direction = payload.get("direction", "down")
                clicks = payload.get("clicks", 3)
                _pyautogui.scroll(clicks if direction == "up" else -clicks, x=coordinate[0], y=coordinate[1])
            elif action == "drag" and coordinate:
                dest = payload.get("destination", coordinate)
                _pyautogui.dragTo(dest[0], dest[1], duration=0.5)
            else:
                raise ValueError(f"Unknown action: {action}")

        loop = asyncio.get_event_loop()
        try:
            await loop.run_in_executor(None, _run)
        except Exception as exc:
            return _error(msg["id"], "ACTION_FAILED", str(exc))

        return _ack(msg["id"])
