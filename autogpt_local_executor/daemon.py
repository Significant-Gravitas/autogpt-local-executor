"""
ShimDaemon — the main event loop.

Connects to the AutoGPT platform WebSocket, dispatches incoming messages
to the appropriate handler, and sends back results.
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import time
from typing import Any

import websockets
import websockets.exceptions

from .config import ShimConfig
from .handlers import CommandHandler, ComputerUseHandler, FileHandler
from .protocol import MessageType, build_hello, parse_message

logger = logging.getLogger(__name__)


class ShimDaemon:
    def __init__(self, config: ShimConfig, token_store: Any) -> None:
        self.config = config
        self.token_store = token_store
        self._file_handler = FileHandler(config)
        self._command_handler = CommandHandler(config)
        self._computer_handler = ComputerUseHandler(config)
        self._handlers = {
            MessageType.EXECUTE_COMMAND: self._command_handler,
            MessageType.FILE_READ: self._file_handler,
            MessageType.FILE_WRITE: self._file_handler,
            MessageType.SCREENSHOT_REQUEST: self._computer_handler,
            MessageType.INPUT_ACTION: self._computer_handler,
        }
        self._running = False
        self._ws: Any = None

    async def run(self) -> None:
        self._running = True
        attempt = 0
        while self._running:
            try:
                await self._session()
                attempt = 0
            except Exception as exc:
                delay = min(
                    self.config.reconnect_base_delay * (2 ** attempt),
                    self.config.reconnect_max_delay,
                ) + random.uniform(0, 5)
                logger.warning(
                    "Disconnected (%s). Reconnecting in %.1fs (attempt %d)",
                    exc, delay, attempt + 1,
                )
                await asyncio.sleep(delay)
                attempt += 1

    async def stop(self) -> None:
        self._running = False
        if self._ws:
            await self._ws.close()

    async def _session(self) -> None:
        token = await self.token_store.get_access_token()
        session_id = self.config.session_id or "default"
        url = f"{self.config.platform_ws_url}/{session_id}?token={token}"

        logger.info("Connecting to %s", url)
        async with websockets.connect(
            url,
            ping_interval=20,
            ping_timeout=10,
        ) as ws:
            self._ws = ws
            await self._handshake(ws)
            async for raw in ws:
                msg = parse_message(raw)
                asyncio.create_task(self._dispatch(ws, msg))

    async def _handshake(self, ws: Any) -> dict:
        hello = build_hello(self.config)
        await ws.send(json.dumps(hello))
        raw_ack = await asyncio.wait_for(ws.recv(), timeout=10.0)
        ack = parse_message(raw_ack)
        if ack["type"] != MessageType.HELLO_ACK:
            raise ValueError(f"Expected HELLO_ACK, got {ack['type']}")
        logger.info(
            "Connected. Granted capabilities: %s",
            ack["payload"].get("granted_capabilities", []),
        )
        return ack

    async def _dispatch(self, ws: Any, msg: dict) -> None:
        msg_type = msg.get("type")
        msg_id = msg.get("id")

        if msg_type == MessageType.PING:
            await ws.send(json.dumps({
                "type": MessageType.PONG,
                "id": msg_id,
                "ts": time.time(),
                "payload": {},
            }))
            return

        handler = self._handlers.get(msg_type)
        if handler is None:
            logger.warning("Unknown message type: %s", msg_type)
            return

        try:
            result = await handler.handle(msg)
            await ws.send(json.dumps(result))
        except Exception as exc:
            logger.exception("Handler error for %s", msg_type)
            await ws.send(json.dumps({
                "type": MessageType.ERROR,
                "id": msg_id,
                "ts": time.time(),
                "payload": {
                    "code": "INTERNAL_ERROR",
                    "message": str(exc),
                    "fatal": False,
                },
            }))
