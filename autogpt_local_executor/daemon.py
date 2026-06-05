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
import json
import logging
import random
from typing import Any

import websockets
from pydantic import BaseModel, ValidationError

from . import platform_info
from .audit import AuditWriter, get_or_create_audit_key
from .auth import KeychainTokenStore
from .config import ShimConfig
from .handlers import CommandHandler, ComputerUseHandler, FileHandler, LocalLLMHandler
from .protocol import (
    VERSION as PROTOCOL_VERSION,
)
from .protocol import (
    AppLaunchMessage,
    AppListRequestMessage,
    ClipboardReadMessage,
    ClipboardWriteMessage,
    CursorPositionRequestMessage,
    DisplayInfoRequestMessage,
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
    LocalLLMCompletionMessage,
    PermissionsCheckRequestMessage,
    PingMessage,
    ProtocolVersionMismatch,
    ScreenshotRequestMessage,
    SessionRevokedMessage,
    StatusMessage,
    StatusPayload,
    WindowFocusMessage,
    WindowListRequestMessage,
    dump_message,
    make_error,
    make_pong,
    negotiate_version,
    new_id,
    now_ts,
    parse_message,
)

# How often the shim unprompted-emits a STATUS frame (backpressure / health).
# Also emitted on the full → not-full capacity transition edge.
STATUS_INTERVAL_SECONDS: float = 30.0

# WebSocket close codes the platform may use to signal structured failures.
# Mirrors docs/PROTOCOL.md → Close codes. Application-range (4000-4999).
WS_CLOSE_PROTOCOL_VERSION_MISMATCH = 4426
WS_CLOSE_SESSION_TAKEN_OVER = 4427
WS_CLOSE_SESSION_REVOKED = 4428
WS_CLOSE_PLATFORM_SHUTDOWN = 4429

# Close codes the shim treats as fatal: after receiving them on the WS,
# the shim MUST NOT auto-reconnect. Operator must restart.
_FATAL_CLOSE_CODES: frozenset[int] = frozenset(
    {
        WS_CLOSE_PROTOCOL_VERSION_MISMATCH,
        WS_CLOSE_SESSION_TAKEN_OVER,
        WS_CLOSE_SESSION_REVOKED,
        WS_CLOSE_PLATFORM_SHUTDOWN,
    }
)

_CLOSE_CODE_LABELS: dict[int, str] = {
    WS_CLOSE_PROTOCOL_VERSION_MISMATCH: "PROTOCOL_VERSION_MISMATCH",
    WS_CLOSE_SESSION_TAKEN_OVER: "SESSION_TAKEN_OVER",
    WS_CLOSE_SESSION_REVOKED: "SESSION_REVOKED",
    WS_CLOSE_PLATFORM_SHUTDOWN: "PLATFORM_SHUTDOWN",
}


class DaemonPreflightError(RuntimeError):
    """Raised when daemon refuses to bind due to a missing OS permission.

    Per docs/COMPUTER_USE.md Q5: when computer_use is requested but
    AXIsProcessTrusted() returns false (macOS), the daemon emits a
    clear audit record and exits with EX_CONFIG (78). launchd's
    KeepAlive: SuccessfulExit=false re-launches us on the next TCC
    change.
    """


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
        self._local_llm_handler = LocalLLMHandler(config, audit=self.audit)
        self._running = False
        self._ws: Any = None
        self._semaphore: asyncio.Semaphore | None = None
        self._shim_start_logged = False
        # Effective negotiated protocol version, populated on HELLO_ACK.
        # `None` before handshake completes.
        self._negotiated_version: str | None = None
        # Set true when a session terminates fatally and the shim MUST NOT
        # auto-reconnect (protocol version mismatch, session revoked, etc.).
        # The reconnect loop checks this and exits cleanly.
        self._disable_reconnect: bool = False
        # Backpressure / health bookkeeping (#38). _in_flight = tasks
        # currently holding the semaphore; _queue_depth = tasks waiting
        # to acquire it. Maintained explicitly so we don't have to poke
        # at asyncio.Semaphore internals.
        self._in_flight: int = 0
        self._queue_depth: int = 0
        # Wall-clock when the current session started (set in _run_session).
        # Used for STATUS.uptime_seconds.
        self._session_started_at: float | None = None
        # Background task that emits periodic STATUS frames.
        self._status_task: asyncio.Task[None] | None = None

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
            logger.warning("Audit log disabled — could not acquire audit key: %s", exc)
            return None

    # ── Public API ────────────────────────────────────────────────────────

    async def run(self) -> None:
        """Connect → handshake → pump messages, with exponential backoff
        reconnect on any failure.
        """
        self._running = True
        # Preflight: per Q5, refuse to bind if computer-use is requested
        # but OS permissions are missing. We do this BEFORE shim_start
        # audit so the audit log carries the failure record cleanly.
        self._preflight_or_raise()
        await self._audit_shim_start()
        attempt = 0
        try:
            while self._running:
                try:
                    await self._session()
                    attempt = 0
                except asyncio.CancelledError:
                    raise
                except ProtocolVersionMismatch as exc:
                    # Refuse to retry: a hot-reconnect loop against an
                    # incompatible platform just spams logs and burns rate
                    # limits. Operator must restart the shim after upgrading
                    # one side.
                    logger.error(
                        "Protocol version mismatch (shim=%s platform=%s). "
                        "Will not auto-reconnect; restart the shim after "
                        "upgrading. Hint: %s",
                        exc.shim_max,
                        exc.platform_max,
                        exc.hint,
                    )
                    self._disable_reconnect = True
                    break
                except Exception as exc:
                    if not self._running or self._disable_reconnect:
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
        base = min(self.config.reconnect_base_delay * (2**attempt), cap)
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
        self._session_started_at = now_ts()
        # Reset per-session counters so reconnects don't carry over.
        self._in_flight = 0
        self._queue_depth = 0
        if self.audit is not None:
            try:
                await self.audit.ws_connected(self._connect_url())
            except Exception:
                logger.debug("WS_CONNECTED audit emit failed", exc_info=True)
        disconnect_reason = "clean_exit"
        try:
            await self._handshake(ws)
            # Start the periodic STATUS ticker AFTER handshake — we want
            # max_concurrent from HELLO_ACK before announcing capacity.
            self._status_task = asyncio.create_task(self._status_ticker(ws))
            try:
                async for raw in ws:
                    await self._on_frame(ws, raw)
            except websockets.exceptions.ConnectionClosed as exc:
                # Translate fatal application close codes into the
                # _disable_reconnect flag so run() doesn't loop on us.
                # Prefer the new rcvd.code (websockets >=13.1) and fall
                # back to the deprecated attribute on older versions.
                code: int | None
                rcvd = getattr(exc, "rcvd", None)
                if rcvd is not None and getattr(rcvd, "code", None) is not None:
                    code = int(rcvd.code)
                else:
                    code = getattr(exc, "code", None)
                label = _CLOSE_CODE_LABELS.get(code or -1, "unknown")
                disconnect_reason = f"ws_closed_{code}_{label}"
                if code in _FATAL_CLOSE_CODES:
                    logger.warning(
                        "WebSocket closed with fatal code %s (%s); will not auto-reconnect.",
                        code,
                        label,
                    )
                    self._disable_reconnect = True
                    await self._audit_session_revoked(
                        reason=label.lower(),
                        source="ws_close_code",
                        close_code=code,
                    )
                raise
            except Exception as exc:
                disconnect_reason = f"loop_error: {exc.__class__.__name__}"
                raise
        finally:
            # Cancel the periodic STATUS ticker first so it doesn't fight
            # us for the dying WS.
            if self._status_task is not None:
                self._status_task.cancel()
                try:
                    await self._status_task
                except (asyncio.CancelledError, Exception):
                    pass
                self._status_task = None
            self._ws = None
            self._session_started_at = None
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
        # Per COMPUTER_USE.md Q2: every HELLO wipes window IDs.
        if self.config.enable_computer_use:
            try:
                self._computer_handler.on_hello()
            except Exception:
                logger.debug("computer-use on_hello failed", exc_info=True)
        hello = await self._build_hello()
        await ws.send(dump_message(hello))
        raw_ack = await asyncio.wait_for(ws.recv(), timeout=10.0)
        ack = parse_message(raw_ack)
        if not isinstance(ack, HelloAckMessage):
            raise RuntimeError(f"Expected HELLO_ACK, got {type(ack).__name__}")
        # Honor the server's negotiated limits.
        payload = ack.payload
        # Negotiate wire-protocol version BEFORE applying any other limits.
        # If majors disagree we tear the WS down with 4426 and surface
        # ProtocolVersionMismatch so the run() loop disables reconnect.
        try:
            self._negotiated_version = negotiate_version(
                shim_max=PROTOCOL_VERSION,
                platform_max=payload.protocol_version,
            )
        except ProtocolVersionMismatch as exc:
            close_reason = json.dumps(exc.to_close_reason())
            try:
                await ws.close(
                    code=WS_CLOSE_PROTOCOL_VERSION_MISMATCH,
                    reason=close_reason,
                )
            except Exception:
                logger.debug("ws.close after version mismatch failed", exc_info=True)
            raise
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
            "Connected. session=%s granted_capabilities=%s max_concurrent=%d "
            "timeout=%ds protocol=%s",
            payload.session_id,
            payload.granted_capabilities,
            payload.max_concurrent,
            payload.command_timeout_seconds,
            self._negotiated_version,
        )
        return ack

    async def _build_hello(self) -> HelloMessage:
        cfg = self.config
        caps = platform_info.detect_capabilities(
            enable_shell=cfg.enable_shell,
            enable_computer_use=cfg.enable_computer_use,
            enable_local_llm=cfg.enable_local_llm,
            enable_hardware=cfg.enable_hardware,
        )
        screen = platform_info.detect_screen_resolution()
        cu_features: list[str] = []
        cu_features_coarse: list[str] = []
        if "computer_use" in caps:
            try:
                cu_features = list(self._computer_handler.backend.features())
                cu_features_coarse = list(self._computer_handler.backend.coarse_features())
            except Exception:
                logger.debug("computer-use feature probe failed", exc_info=True)
        # Per LOCAL_LLM.md: probe Ollama at HELLO time. On any failure we
        # OMIT the local_llm capability AND leave local_llm_models empty.
        local_llm_models: list[str] = []
        if cfg.enable_local_llm:
            try:
                local_llm_models = await self._local_llm_handler.probe()
            except Exception:
                logger.debug("Local LLM probe raised; treating as unavailable", exc_info=True)
                local_llm_models = []
            if local_llm_models:
                if "local_llm" not in caps:
                    caps.append("local_llm")
            else:
                # Probe failed or returned no models — strip the capability
                # so the platform doesn't try to route to us.
                caps = [c for c in caps if c != "local_llm"]
        payload = HelloPayload(
            shim_version=__import__("autogpt_local_executor").__version__,
            machine_id=cfg.machine_id,
            platform=platform_info.detect_platform(),
            arch=platform_info.detect_arch(),
            screen_resolution=screen,
            capabilities=caps,
            allowed_root=str(cfg.allowed_root),
            local_llm_models=local_llm_models,
            hardware_devices=[],
            computer_use_features=cu_features,
            computer_use_features_coarse=cu_features_coarse,
            protocol_version=PROTOCOL_VERSION,
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

        # SESSION_REVOKED is a one-shot lifecycle event. We audit it, send
        # nothing further, gracefully close, and disable auto-reconnect.
        if isinstance(msg, SessionRevokedMessage):
            await self._handle_session_revoked(ws, msg)
            return

        if self._semaphore is None:
            # We somehow got a request before HELLO_ACK; be defensive.
            self._semaphore = asyncio.Semaphore(self.config.max_concurrent)

        asyncio.create_task(self._dispatch(ws, msg))

    async def _handle_session_revoked(self, ws, msg: SessionRevokedMessage) -> None:
        """Per PROTOCOL.md → Session ownership: log, stop sending, close,
        and don't auto-reconnect."""
        reason = msg.payload.reason
        new_machine = msg.payload.new_shim_machine_id
        logger.warning(
            "SESSION_REVOKED received (reason=%s, new_shim_machine_id=%s); "
            "closing connection without retry.",
            reason,
            new_machine,
        )
        self._disable_reconnect = True
        await self._audit_session_revoked(
            reason=reason,
            source="frame",
            new_shim_machine_id=new_machine,
        )
        try:
            # We send no further protocol frames; just close cleanly.
            await ws.close(code=WS_CLOSE_SESSION_REVOKED, reason="session_revoked")
        except Exception:
            logger.debug("ws.close after SESSION_REVOKED failed", exc_info=True)

    async def _audit_session_revoked(
        self,
        *,
        reason: str,
        source: str,
        close_code: int | None = None,
        new_shim_machine_id: str | None = None,
    ) -> None:
        """Emit a structured audit record for session revocation. Best-effort —
        a failure here must not block close."""
        if self.audit is None:
            return
        details: dict[str, Any] = {
            "reason": reason,
            "source": source,
        }
        if close_code is not None:
            details["close_code"] = close_code
        if new_shim_machine_id is not None:
            details["new_shim_machine_id"] = new_shim_machine_id
        try:
            await self.audit.write(
                "SESSION_REVOKED",
                request_id=None,
                details=details,
            )
        except Exception:
            logger.debug("SESSION_REVOKED audit emit failed", exc_info=True)

    # ── Backpressure / health (STATUS frame, #38) ───────────────────────

    def _build_status_message(self) -> StatusMessage:
        """Snapshot the shim's current backpressure / health state."""
        audit_bytes = 0
        try:
            if self.config.audit_log_path.is_file():
                audit_bytes = self.config.audit_log_path.stat().st_size
        except OSError:
            # Best-effort — a missing/unreadable audit log shouldn't break
            # health reporting.
            audit_bytes = 0
        uptime = 0.0
        if self._session_started_at is not None:
            uptime = max(now_ts() - self._session_started_at, 0.0)
        payload = StatusPayload(
            in_flight=self._in_flight,
            max_concurrent=self.config.max_concurrent,
            queue_depth=self._queue_depth,
            audit_log_bytes=audit_bytes,
            uptime_seconds=uptime,
        )
        msg = StatusMessage(id=new_id(), ts=now_ts(), payload=payload)
        # STATUS itself carries pending_capacity too — it IS a backpressure
        # signal, so be explicit.
        msg.pending_capacity = self._available_capacity()
        return msg

    async def _emit_status(self, ws, *, source: str) -> None:
        """Send a STATUS frame on the WS, swallowing transient send errors.

        `source` is a debug label (capacity_edge, periodic) — not on the wire,
        just for logging.
        """
        try:
            msg = self._build_status_message()
            await ws.send(dump_message(msg))
            logger.debug("STATUS emitted (%s): %s", source, msg.payload)
        except Exception:
            logger.debug("STATUS emit failed (%s)", source, exc_info=True)

    async def _status_ticker(self, ws) -> None:
        """Background task: emit STATUS every STATUS_INTERVAL_SECONDS. The
        loop exits when the WS is gone or the daemon is told to stop.
        """
        try:
            while self._running and self._ws is ws:
                await asyncio.sleep(STATUS_INTERVAL_SECONDS)
                if self._ws is not ws:
                    return
                await self._emit_status(ws, source="periodic")
        except asyncio.CancelledError:
            raise

    async def _dispatch(self, ws, msg: Any) -> None:
        assert self._semaphore is not None
        # Track queue depth: incremented now, decremented exactly once when
        # we either acquire the semaphore (transition to in_flight) or bail
        # out before acquiring (cancellation / error in waiter).
        self._queue_depth += 1
        queue_owed = True
        in_flight_owed = False
        was_full_after_decrement = False
        response = None

        # Streaming ops (LOCAL_LLM_COMPLETION) emit intermediate frames
        # via this callback before the terminal RESPONSE flows through the
        # standard one-frame-per-request path below. CHUNK frames do NOT
        # carry pending_capacity (we're still mid-request) and aren't
        # treated as responses for the backpressure accounting.
        async def _stream_send(frame: Any) -> None:
            try:
                await ws.send(dump_message(frame))
            except Exception:
                logger.debug("Failed to send streaming frame", exc_info=True)

        try:
            try:
                async with self._semaphore:
                    # We've acquired — move the credit from queue → in_flight.
                    self._queue_depth -= 1
                    queue_owed = False
                    self._in_flight += 1
                    in_flight_owed = True
                    try:
                        response = await self._handle(msg, send=_stream_send)
                    finally:
                        was_full_after_decrement = self._in_flight == self.config.max_concurrent
                        self._in_flight -= 1
                        in_flight_owed = False
            except Exception as exc:
                logger.exception("Handler crashed for %s", type(msg).__name__)
                response = make_error(
                    msg.id if hasattr(msg, "id") else new_id(),
                    ErrorCode.INTERNAL_ERROR,
                    str(exc),
                )
        finally:
            # Belt-and-braces: if either counter is still owed (e.g. we got
            # cancelled mid-acquire), make it whole. Without this a crashed
            # waiter would skew queue_depth forever.
            if queue_owed:
                self._queue_depth -= 1
            if in_flight_owed:
                self._in_flight -= 1

        if response is None:
            return

        # Stamp pending_capacity on the response envelope so the platform can
        # throttle issuance before we trip SHIM_OVERLOADED. Compute AFTER
        # decrementing _in_flight so the number reflects post-response slots.
        try:
            response.pending_capacity = self._available_capacity()
        except Exception:
            # _Envelope subclasses all carry the field via the base; this
            # is just paranoia for any future hand-rolled response model.
            logger.debug("could not stamp pending_capacity", exc_info=True)

        try:
            await ws.send(dump_message(response))
        except Exception:
            logger.debug("Failed to send response", exc_info=True)

        # If we just freed a slot from a fully-saturated state, push an
        # unsolicited STATUS frame so the platform's throttle releases
        # promptly (don't wait for the 30s tick).
        if was_full_after_decrement:
            await self._emit_status(ws, source="capacity_edge")

    def _available_capacity(self) -> int:
        """Free request slots right now. Floored at 0."""
        return max(self.config.max_concurrent - self._in_flight, 0)

    _COMPUTER_USE_MESSAGE_TYPES = (
        ScreenshotRequestMessage,
        InputActionMessage,
        CursorPositionRequestMessage,
        DisplayInfoRequestMessage,
        WindowListRequestMessage,
        WindowFocusMessage,
        AppListRequestMessage,
        AppLaunchMessage,
        ClipboardReadMessage,
        ClipboardWriteMessage,
        PermissionsCheckRequestMessage,
    )

    async def _handle(self, msg: Any, *, send: Any | None = None) -> BaseModel | None:
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
        if isinstance(msg, self._COMPUTER_USE_MESSAGE_TYPES):
            return await self._computer_handler.handle(msg)
        if isinstance(msg, LocalLLMCompletionMessage):
            return await self._local_llm_handler.handle(msg, send=send)
        # Anything else (e.g., responses we didn't ask for) is silently dropped.
        logger.debug("No handler for %s; dropping", type(msg).__name__)
        return None

    # ── Preflight ────────────────────────────────────────────────────

    def _preflight_or_raise(self) -> None:
        """Per COMPUTER_USE.md Q5: when computer_use is requested but the
        required OS permission isn't granted, write a structured audit
        record and raise DaemonPreflightError so the CLI exits 78.
        """
        if not self.config.enable_computer_use:
            return
        plat = platform_info.detect_platform()
        if plat != "darwin":
            return
        try:
            from ApplicationServices import (  # type: ignore[import-not-found]
                AXIsProcessTrusted,
            )
        except ImportError:
            # No pyobjc — can't check. Treat as a warning, not a fail.
            logger.warning("Cannot probe Accessibility: pyobjc/ApplicationServices not installed.")
            return
        try:
            trusted = bool(AXIsProcessTrusted())
        except Exception as exc:
            logger.warning("AXIsProcessTrusted() failed: %s", exc)
            return
        if trusted:
            return
        # Refuse to bind. Emit a synthetic audit entry so the user has
        # a record of the refusal.
        if self.audit is not None:
            try:
                # Use the existing write helper with a synthetic op name.
                # We don't await here from a sync method; just queue best-effort.
                try:
                    loop = asyncio.get_running_loop()
                except RuntimeError:
                    loop = None
                if loop is not None:
                    loop.create_task(
                        self.audit.write(
                            "DAEMON_PREFLIGHT_FAILED",
                            request_id=new_id(),
                            details={
                                "missing_permissions": ["accessibility"],
                                "platform": plat,
                                "hint": "Run `autogpt-shim doctor` and grant access.",
                            },
                            result={
                                "ok": False,
                                "exit_code": 78,
                                "duration_ms": 0,
                                "error_code": ErrorCode.PERMISSION_PENDING.value,
                            },
                        )
                    )
            except Exception:
                logger.debug("preflight audit emit failed", exc_info=True)
        raise DaemonPreflightError(
            "Accessibility permission not granted; computer_use requires it. "
            "Run `autogpt-shim doctor` to surface the prompt."
        )


__all__ = ["ShimDaemon"]
