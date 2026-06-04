"""
ShimDaemon — the main event loop.

Connects to the AutoGPT platform over WebSocket, sends HELLO with
detected capabilities, consumes HELLO_ACK (which may revise concurrency
and timeout limits), then pumps inbound messages through handlers.

Concurrency model: one task per inbound request, capped by a semaphore
sized from HELLO_ACK.max_concurrent (default 4). PING is handled inline
on the main loop (not via the semaphore) so a saturated handler queue
can't starve keepalive.
"""

from __future__ import annotations

import asyncio
import logging
import random
from typing import Any

import websockets
from pydantic import BaseModel, ValidationError

from . import platform_info
from .audit import AuditWriter, get_or_create_audit_key
from .auth import KeychainTokenStore
from .config import ShimConfig
from .handlers import CommandHandler, ComputerUseHandler, FileHandler
from .protocol import (
    ErrorCode,
    ExecuteCommandMessage,
    FileDeleteMessage,
    FileListMessage,
    FileMoveMessage,
    FileReadMessage,
    FileStatMessage,
    FileWriteMessage,
    HelloAckMessage,
    HelloMessage,
    HelloPayload,
    InputActionMessage,
    Message,
    PingMessage,
    ScreenshotRequestMessage,
    dump_message,
    make_error,
    make_pong,
    new_id,
    now_ts,
    parse_message,
)

logger = logging.getLogger(__name__)


class ShimDaemon:
    def __init__(
        self,
        config: ShimConfig,
        token_store: KeychainTokenStore | Any | None = None,
        audit: AuditWriter | None = None,
    ) -> None:
        self.config = config
        self.token_store = token_store or KeychainTokenStore()
        self.audit = audit if audit is not None else self._build_audit_writer(config)
        if self.audit is not None:
            self.audit.set_machine_id(config.machine_id)
            if config.session_id:
                self.audit.set_session_id(config.session_id)
        self._file_handler = FileHandler(config, audit=self.audit)
        self._command_handler = CommandHandler(config, audit=self.audit)
        self._computer_handler = ComputerUseHandler(config, audit=self.audit)
        self._running = False
        self._ws: Any = None
        self._semaphore: asyncio.Semaphore | None = None
        self._shim_start_logged = False

    @staticmethod
    def _build_audit_writer(config: ShimConfig) -> AuditWriter | None:
        """Best-effort AuditWriter construction. Returns None and emits a
        warning when the audit key can't be acquired so the daemon can still
        start in degraded mode; production deployments should treat this as
        fatal but for v0 we don't want to brick a fresh install over a
        keychain hiccup."""
        try:
            key = get_or_create_audit_key()
            return AuditWriter(
                path=config.audit_log_path,
                audit_key=key,
                machine_id=config.machine_id,
                session_id=config.session_id,
            )
        except Exception as exc:
            logger.warning(
                "Audit log disabled — could not acquire audit key: %s", exc
            )
            return None

    # ── Public API ────────────────────────────────────────────────────────

    async def run(self) -> None:
        """Connect → handshake → pump messages, with exponential backoff
        reconnect on any failure.
        """
        self._running = True
        await self._audit_shim_start()
        attempt = 0
        try:
            while self._running:
                try:
                    await self._session()
                    attempt = 0
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    if not self._running:
                        break
                    delay = self._backoff_delay(attempt)
                    logger.warning(
                        "Disconnected (%s). Reconnecting in %.1fs (attempt %d)",
                        exc,
                        delay,
                        attempt + 1,
                    )
                    await asyncio.sleep(delay)
                    attempt += 1
        finally:
            await self._audit_shim_stop("graceful")

    async def stop(self) -> None:
        self._running = False
        if self._ws is not None:
            try:
                await self._ws.close()
            except Exception:
                pass

    async def _audit_shim_start(self) -> None:
        if self.audit is None or self._shim_start_logged:
            return
        try:
            await self.audit.shim_start(self.config.machine_id)
            self._shim_start_logged = True
        except Exception:
            logger.debug("SHIM_START audit emit failed", exc_info=True)

    async def _audit_shim_stop(self, reason: str) -> None:
        if self.audit is None or not self._shim_start_logged:
            return
        try:
            await self.audit.shim_stop(reason)
        except Exception:
            logger.debug("SHIM_STOP audit emit failed", exc_info=True)

    # ── Connection lifecycle ──────────────────────────────────────────────

    def _backoff_delay(self, attempt: int) -> float:
        """Per docs/PROTOCOL.md Reconnection: 2^attempt * 1s, capped at 60s,
        plus 0-5s jitter."""
        cap = self.config.reconnect_max_delay
        base = min(self.config.reconnect_base_delay * (2 ** attempt), cap)
        jitter = random.uniform(0, self.config.reconnect_jitter_seconds)
        return base + jitter

    async def _session(self) -> None:
        url = self._connect_url()
        token = await self._get_access_token(refresh_on_fail=False)
        headers = self._auth_headers(token)
        try:
            async with websockets.connect(
                url,
                additional_headers=headers,
                ping_interval=20,
                ping_timeout=10,
            ) as ws:
                await self._run_session(ws)
        except websockets.exceptions.InvalidStatus as exc:
            status_code = getattr(exc.response, "status_code", None)
            if status_code != 401:
                raise
            # On 401, try refreshing once and retry the connect.
            logger.info("401 on WebSocket upgrade — refreshing token and retrying once")
            token = await self._get_access_token(refresh_on_fail=True)
            headers = self._auth_headers(token)
            async with websockets.connect(
                url,
                additional_headers=headers,
                ping_interval=20,
                ping_timeout=10,
            ) as ws:
                await self._run_session(ws)

    async def _run_session(self, ws) -> None:
        self._ws = ws
        if self.audit is not None:
            try:
                await self.audit.ws_connected(self._connect_url())
            except Exception:
                logger.debug("WS_CONNECTED audit emit failed", exc_info=True)
        disconnect_reason = "clean_exit"
        try:
            await self._handshake(ws)
            try:
                async for raw in ws:
                    await self._on_frame(ws, raw)
            except Exception as exc:
                disconnect_reason = f"loop_error: {exc.__class__.__name__}"
                raise
        finally:
            self._ws = None
            if self.audit is not None:
                try:
                    await self.audit.ws_disconnected(disconnect_reason)
                except Exception:
                    logger.debug("WS_DISCONNECTED audit emit failed", exc_info=True)

    def _connect_url(self) -> str:
        session_id = self.config.session_id or "default"
        base = self.config.derived_ws_url.rstrip("/")
        return f"{base}/{session_id}"

    @staticmethod
    def _auth_headers(token: str | None) -> dict[str, str]:
        if not token:
            return {}
        return {"Authorization": f"Bearer {token}"}

    async def _get_access_token(self, *, refresh_on_fail: bool) -> str | None:
        token = await self.token_store.get_access_token()
        if token is not None:
            return token
        if not refresh_on_fail:
            return None
        # Try to refresh.
        try:
            from .auth import OAuthFlow

            flow = OAuthFlow(self.config, self.token_store)
            await flow.refresh_token()
            if self.audit is not None:
                try:
                    await self.audit.token_refreshed()
                except Exception:
                    logger.debug("TOKEN_REFRESHED audit emit failed", exc_info=True)
            return await self.token_store.get_access_token()
        except Exception as exc:
            logger.warning("Token refresh failed: %s", exc)
            return None

    # ── Handshake ─────────────────────────────────────────────────────────

    async def _handshake(self, ws) -> HelloAckMessage:
        hello = self._build_hello()
        await ws.send(dump_message(hello))
        raw_ack = await asyncio.wait_for(ws.recv(), timeout=10.0)
        ack = parse_message(raw_ack)
        if not isinstance(ack, HelloAckMessage):
            raise RuntimeError(
                f"Expected HELLO_ACK, got {type(ack).__name__}"
            )
        # Honor the server's negotiated limits.
        payload = ack.payload
        self.config.max_concurrent = payload.max_concurrent
        self.config.command_timeout_seconds = payload.command_timeout_seconds
        self.config.max_file_size_bytes = payload.max_file_size_bytes
        self._semaphore = asyncio.Semaphore(payload.max_concurrent)
        # Tell the AuditWriter about the now-known session_id so subsequent
        # records get correctly attributed.
        if self.audit is not None:
            self.audit.set_session_id(payload.session_id)
            try:
                await self.audit.config_reloaded(payload.granted_capabilities)
            except Exception:
                logger.debug("CONFIG_RELOADED audit emit failed", exc_info=True)
        logger.info(
            "Connected. session=%s granted_capabilities=%s max_concurrent=%d timeout=%ds",
            payload.session_id,
            payload.granted_capabilities,
            payload.max_concurrent,
            payload.command_timeout_seconds,
        )
        return ack

    def _build_hello(self) -> HelloMessage:
        cfg = self.config
        caps = platform_info.detect_capabilities(
            enable_shell=cfg.enable_shell,
            enable_computer_use=cfg.enable_computer_use,
            enable_local_llm=cfg.enable_local_llm,
            enable_hardware=cfg.enable_hardware,
        )
        screen = platform_info.detect_screen_resolution()
        payload = HelloPayload(
            shim_version=__import__("autogpt_local_executor").__version__,
            machine_id=cfg.machine_id,
            platform=platform_info.detect_platform(),
            arch=platform_info.detect_arch(),
            screen_resolution=screen,
            capabilities=caps,
            allowed_root=str(cfg.allowed_root),
            local_llm_models=[],
            hardware_devices=[],
        )
        return HelloMessage(id=new_id(), ts=now_ts(), payload=payload)

    # ── Frame dispatch ────────────────────────────────────────────────────

    async def _on_frame(self, ws, raw: str | bytes) -> None:
        try:
            msg = parse_message(raw)
        except (ValidationError, ValueError) as exc:
            logger.warning("Failed to parse inbound frame: %s", exc)
            return

        # PING is handled inline so a saturated semaphore can't starve keepalive.
        if isinstance(msg, PingMessage):
            try:
                await ws.send(dump_message(make_pong(msg.id)))
            except Exception:
                logger.debug("Failed to send PONG", exc_info=True)
            return

        if self._semaphore is None:
            # We somehow got a request before HELLO_ACK; be defensive.
            self._semaphore = asyncio.Semaphore(self.config.max_concurrent)

        asyncio.create_task(self._dispatch(ws, msg))

    async def _dispatch(self, ws, msg: Any) -> None:
        assert self._semaphore is not None
        try:
            async with self._semaphore:
                response = await self._handle(msg)
        except Exception as exc:
            logger.exception("Handler crashed for %s", type(msg).__name__)
            response = make_error(
                msg.id if hasattr(msg, "id") else new_id(),
                ErrorCode.INTERNAL_ERROR,
                str(exc),
            )
        if response is None:
            return
        try:
            await ws.send(dump_message(response))
        except Exception:
            logger.debug("Failed to send response", exc_info=True)

    async def _handle(self, msg: Any) -> BaseModel | None:
        if isinstance(msg, ExecuteCommandMessage):
            return await self._command_handler.handle(msg)
        if isinstance(msg, FileReadMessage):
            return await self._file_handler.handle_read(msg)
        if isinstance(msg, FileWriteMessage):
            return await self._file_handler.handle_write(msg)
        if isinstance(msg, FileStatMessage):
            return await self._file_handler.handle_stat(msg)
        if isinstance(msg, FileListMessage):
            return await self._file_handler.handle_list(msg)
        if isinstance(msg, FileDeleteMessage):
            return await self._file_handler.handle_delete(msg)
        if isinstance(msg, FileMoveMessage):
            return await self._file_handler.handle_move(msg)
        if isinstance(msg, (ScreenshotRequestMessage, InputActionMessage)):
            return await self._computer_handler.handle(msg)
        # Anything else (e.g., responses we didn't ask for) is silently dropped.
        logger.debug("No handler for %s; dropping", type(msg).__name__)
        return None


__all__ = ["ShimDaemon"]
