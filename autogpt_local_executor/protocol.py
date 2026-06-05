"""
Protocol messages — pydantic models, envelope, and helpers.

Every wire message has the envelope:

    {"type": ..., "id": ..., "ts": ..., "payload": ...}

See docs/PROTOCOL.md for the authoritative spec. The models below are the
single source of truth on the shim side; if a model and the doc disagree,
the doc wins — fix the model.
"""

from __future__ import annotations

import json
import time
import uuid
from enum import Enum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError

# ── Protocol version ─────────────────────────────────────────────────────────

# Wire protocol version this shim speaks. Format: "<major>.<minor>" string.
# Negotiation rules (see docs/PROTOCOL.md → Versioning):
#   * Major MUST match between shim and platform. Mismatch → connection
#     closed with WS code 4426 and reason PROTOCOL_VERSION_MISMATCH; shim
#     MUST NOT auto-reconnect.
#   * Minor floor wins: effective negotiated minor is min(shim, platform).
#     Both sides MUST tolerate forward-compatible additions within a major.
#   * Every envelope SHOULD carry `version` matching the negotiated value,
#     but receivers MUST be lenient — HELLO-time negotiation is the truth.
VERSION: str = "1.0"


def _split_version(v: str) -> tuple[int, int]:
    """Parse a "major.minor" string. Raises ValueError on malformed input.

    Pre-release/build suffixes are not part of the wire format — we only
    need major.minor for compat negotiation.
    """
    parts = v.split(".")
    if len(parts) != 2:
        raise ValueError(f"protocol version must be 'major.minor', got {v!r}")
    try:
        return int(parts[0]), int(parts[1])
    except (TypeError, ValueError) as exc:
        raise ValueError(f"protocol version components must be integers, got {v!r}") from exc


def negotiate_version(shim_max: str, platform_max: str) -> str:
    """Compute the effective negotiated protocol version.

    Returns a "major.minor" string. Raises ProtocolVersionMismatch when the
    majors don't match — caller is responsible for tearing down the WS with
    code 4426 and surfacing the structured close reason.
    """
    shim_major, shim_minor = _split_version(shim_max)
    plat_major, plat_minor = _split_version(platform_max)
    if shim_major != plat_major:
        raise ProtocolVersionMismatch(
            shim_max=shim_max,
            platform_max=platform_max,
            hint=(
                "Major version mismatch — update the side running the older "
                "major. Shims and platforms within a major are "
                "forward-compatible on minor."
            ),
        )
    return f"{shim_major}.{min(shim_minor, plat_minor)}"


class ProtocolVersionMismatch(Exception):
    """Raised when shim_max and platform_max have different majors.

    Carries the structured fields that go into the WS close reason and
    the SESSION_REVOKED-style audit record.
    """

    def __init__(self, *, shim_max: str, platform_max: str, hint: str) -> None:
        self.shim_max = shim_max
        self.platform_max = platform_max
        self.hint = hint
        super().__init__(
            f"protocol version mismatch: shim_max={shim_max} platform_max={platform_max}"
        )

    def to_close_reason(self) -> dict[str, str]:
        return {
            "error": "PROTOCOL_VERSION_MISMATCH",
            "shim_max": self.shim_max,
            "platform_max": self.platform_max,
            "hint": self.hint,
        }


# ── Enums ────────────────────────────────────────────────────────────────────


class MessageType(str, Enum):
    HELLO = "HELLO"
    HELLO_ACK = "HELLO_ACK"
    EXECUTE_COMMAND = "EXECUTE_COMMAND"
    COMMAND_RESULT = "COMMAND_RESULT"
    FILE_READ = "FILE_READ"
    FILE_CONTENTS = "FILE_CONTENTS"
    FILE_WRITE = "FILE_WRITE"
    FILE_STAT = "FILE_STAT"
    FILE_STAT_RESPONSE = "FILE_STAT_RESPONSE"
    FILE_LIST = "FILE_LIST"
    FILE_LIST_RESPONSE = "FILE_LIST_RESPONSE"
    FILE_DELETE = "FILE_DELETE"
    FILE_MOVE = "FILE_MOVE"
    SCREENSHOT_REQUEST = "SCREENSHOT_REQUEST"
    SCREENSHOT_RESPONSE = "SCREENSHOT_RESPONSE"
    INPUT_ACTION = "INPUT_ACTION"
    CURSOR_POSITION_REQUEST = "CURSOR_POSITION_REQUEST"
    CURSOR_POSITION_RESPONSE = "CURSOR_POSITION_RESPONSE"
    DISPLAY_INFO_REQUEST = "DISPLAY_INFO_REQUEST"
    DISPLAY_INFO_RESPONSE = "DISPLAY_INFO_RESPONSE"
    WINDOW_LIST_REQUEST = "WINDOW_LIST_REQUEST"
    WINDOW_LIST_RESPONSE = "WINDOW_LIST_RESPONSE"
    WINDOW_FOCUS = "WINDOW_FOCUS"
    APP_LIST_REQUEST = "APP_LIST_REQUEST"
    APP_LIST_RESPONSE = "APP_LIST_RESPONSE"
    APP_LAUNCH = "APP_LAUNCH"
    CLIPBOARD_READ = "CLIPBOARD_READ"
    CLIPBOARD_READ_RESPONSE = "CLIPBOARD_READ_RESPONSE"
    CLIPBOARD_WRITE = "CLIPBOARD_WRITE"
    PERMISSIONS_CHECK_REQUEST = "PERMISSIONS_CHECK_REQUEST"
    PERMISSIONS_CHECK_RESPONSE = "PERMISSIONS_CHECK_RESPONSE"
    ACK = "ACK"
    ERROR = "ERROR"
    PING = "PING"
    PONG = "PONG"
    # Session ownership / lifecycle (see PROTOCOL.md → Session ownership).
    SESSION_REVOKED = "SESSION_REVOKED"


class ErrorCode(str, Enum):
    PATH_OUTSIDE_ALLOWED_ROOT = "PATH_OUTSIDE_ALLOWED_ROOT"
    PATH_RESERVED_NAME = "PATH_RESERVED_NAME"
    PATH_INVALID_CHARS = "PATH_INVALID_CHARS"
    PATH_NOT_FOUND = "PATH_NOT_FOUND"
    PATH_NOT_EMPTY = "PATH_NOT_EMPTY"
    PATH_EXISTS = "PATH_EXISTS"
    COMMAND_TIMEOUT = "COMMAND_TIMEOUT"
    SHELL_NOT_AVAILABLE = "SHELL_NOT_AVAILABLE"
    UNSUPPORTED_ARCH = "UNSUPPORTED_ARCH"
    CAPABILITY_NOT_GRANTED = "CAPABILITY_NOT_GRANTED"
    AUTH_FAILED = "AUTH_FAILED"
    SHIM_OVERLOADED = "SHIM_OVERLOADED"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    FILE_TOO_LARGE = "FILE_TOO_LARGE"
    DEPENDENCY_MISSING = "DEPENDENCY_MISSING"
    # Computer-use additions (see docs/COMPUTER_USE.md Q1-Q5).
    WINDOW_STALE = "WINDOW_STALE"
    PERMISSION_PENDING = "PERMISSION_PENDING"
    FEATURE_NOT_SUPPORTED = "FEATURE_NOT_SUPPORTED"
    CLIPBOARD_CONCEALED = "CLIPBOARD_CONCEALED"
    INPUT_OUT_OF_BOUNDS = "INPUT_OUT_OF_BOUNDS"


class Platform(str, Enum):
    DARWIN = "darwin"
    LINUX = "linux"
    WINDOWS = "windows"
    WSL2 = "wsl2"


class Arch(str, Enum):
    X86_64 = "x86_64"
    ARM64 = "arm64"


class Shell(str, Enum):
    AUTO = "auto"
    BASH = "bash"
    SH = "sh"
    ZSH = "zsh"
    PWSH = "pwsh"
    POWERSHELL = "powershell"
    CMD = "cmd"


class Encoding(str, Enum):
    UTF8 = "utf-8"
    BASE64 = "base64"


class FileFormat(str, Enum):
    TEXT = "text"
    BYTES = "bytes"


# ── Payload models ───────────────────────────────────────────────────────────


class _Payload(BaseModel):
    """Common config — payloads forbid extras so unknown fields fail loudly."""

    model_config = ConfigDict(extra="forbid")


class HelloPayload(_Payload):
    shim_version: str
    machine_id: str
    platform: Platform
    arch: Arch
    screen_resolution: tuple[int, int] | None = None
    capabilities: list[str]
    allowed_root: str
    local_llm_models: list[str] = Field(default_factory=list)
    hardware_devices: list[dict[str, Any]] = Field(default_factory=list)
    # Computer-use feature advertisement, per COMPUTER_USE.md.
    computer_use_features: list[str] = Field(default_factory=list)
    computer_use_features_coarse: list[str] = Field(default_factory=list)
    # Highest wire-protocol version this shim supports. "major.minor".
    # Receiving side negotiates the effective version (see VERSION docs).
    protocol_version: str = VERSION


class HelloAckPayload(_Payload):
    session_id: str
    granted_capabilities: list[str]
    max_file_size_bytes: int = 10 * 1024 * 1024
    command_timeout_seconds: int = 30
    max_concurrent: int = 4
    # Highest wire-protocol version this platform supports. "major.minor".
    # Effective negotiated version = same major, min(shim_minor, plat_minor).
    protocol_version: str = VERSION


class ExecuteCommandPayload(_Payload):
    command: str | None = None
    argv: list[str] | None = None
    shell: Shell = Shell.AUTO
    cwd: str | None = None
    timeout_seconds: int | None = None
    env: dict[str, str] = Field(default_factory=dict)


class CommandResultPayload(_Payload):
    stdout: str
    stderr: str
    exit_code: int
    timed_out: bool
    duration_seconds: float


class FileReadPayload(_Payload):
    path: str
    encoding: Encoding = Encoding.UTF8
    format: FileFormat = FileFormat.TEXT
    offset: int = 0
    length: int | None = None


class FileContentsPayload(_Payload):
    content: str
    encoding: Encoding
    size_bytes: int
    truncated: bool = False


class FileWritePayload(_Payload):
    path: str
    content: str
    encoding: Encoding = Encoding.UTF8
    create_parents: bool = False


class AckPayload(_Payload):
    ok: bool = True


class FileStatPayload(_Payload):
    path: str
    follow_symlinks: bool = True


class FileStatResponsePayload(_Payload):
    exists: bool
    is_file: bool | None = None
    is_dir: bool | None = None
    is_symlink: bool | None = None
    size_bytes: int | None = None
    mtime: float | None = None
    ctime: float | None = None
    mode: str | None = None
    owner_uid: int | None = None
    owner_gid: int | None = None
    mime_type: str | None = None
    path: str | None = None  # resolved path, when follow_symlinks=True


class FileListPayload(_Payload):
    path: str
    glob: str | None = None
    recursive: bool = False
    include_hidden: bool = False
    max_entries: int = 1000


class FileEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    path: str
    is_file: bool
    is_dir: bool
    is_symlink: bool
    size_bytes: int | None = None
    mtime: float | None = None


class FileListResponsePayload(_Payload):
    entries: list[FileEntry]
    truncated: bool = False


class FileDeletePayload(_Payload):
    path: str
    recursive: bool = False
    missing_ok: bool = False


class FileMovePayload(_Payload):
    src: str
    dst: str
    overwrite: bool = False


class ScreenshotRequestPayload(_Payload):
    monitor: int = 0
    quality: int = 75
    region: tuple[int, int, int, int] | None = None
    window_id: str | None = None
    format: Literal["jpeg", "png"] = "jpeg"
    include_cursor: bool = True


class ScreenshotResponseMeta(BaseModel):
    """Echo block for region/window crops, per COMPUTER_USE.md Q1."""

    model_config = ConfigDict(extra="forbid")

    origin: tuple[int, int] = (0, 0)
    display_id: int = 0


class ScreenshotResponsePayload(_Payload):
    image_base64: str
    mime_type: str = "image/jpeg"
    width: int
    height: int
    monitor: int = 0
    region: tuple[int, int, int, int] | None = None
    display_scale: float = 1.0
    logical_size: tuple[int, int] | None = None
    meta: ScreenshotResponseMeta = Field(default_factory=ScreenshotResponseMeta)


class InputActionPayload(_Payload):
    action: Literal[
        "left_click",
        "right_click",
        "double_click",
        "middle_click",
        "triple_click",
        "mouse_move",
        "mouse_down",
        "mouse_up",
        "drag",
        "type",
        "key",
        "hold_key",
        "scroll",
        "wait",
    ]
    coordinate: tuple[int, int] | None = None
    text: str | None = None
    key: str | None = None
    direction: Literal["up", "down"] | None = None
    clicks: int | None = None
    # v1 additions, per COMPUTER_USE.md.
    button: Literal["left", "middle", "right"] | None = None
    modifiers: list[Literal["shift", "ctrl", "alt", "super"]] | None = None
    scroll_amount: int | None = None
    scroll_direction: Literal["up", "down", "left", "right"] | None = None
    duration_ms: int | None = None
    path: list[tuple[int, int]] | None = None
    paste: bool = False
    preserve_clipboard: bool = False


class CursorPositionRequestPayload(_Payload):
    pass


class CursorPositionResponsePayload(_Payload):
    x: int
    y: int
    monitor: int = 0


class DisplayInfoRequestPayload(_Payload):
    pass


class DisplayMonitor(BaseModel):
    model_config = ConfigDict(extra="forbid")

    index: int
    primary: bool = False
    physical_size: tuple[int, int]
    logical_size: tuple[int, int]
    scale: float = 1.0
    origin: tuple[int, int] = (0, 0)


class DisplayInfoResponsePayload(_Payload):
    monitors: list[DisplayMonitor]


class WindowListRequestPayload(_Payload):
    app_bundle_id: str | None = None
    include_minimized: bool = False
    include_offscreen: bool = False


class WindowInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    window_id: str
    pid: int
    app_name: str | None = None
    app_bundle_id: str | None = None
    title: str | None = None
    bounds: tuple[int, int, int, int]  # [x1, y1, x2, y2]
    monitor: int = 0
    is_focused: bool = False
    is_minimized: bool = False
    is_fullscreen: bool = False


class WindowListResponsePayload(_Payload):
    windows: list[WindowInfo]
    truncated: bool = False


class WindowFocusPayload(_Payload):
    window_id: str
    raise_: bool = Field(default=True, alias="raise")

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class AppListRequestPayload(_Payload):
    include_background: bool = False


class AppInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pid: int
    name: str
    bundle_id: str | None = None
    executable_path: str | None = None
    is_frontmost: bool = False
    window_count: int = 0


class AppListResponsePayload(_Payload):
    apps: list[AppInfo]


class AppLaunchPayload(_Payload):
    bundle_id: str | None = None
    executable_path: str | None = None
    args: list[str] = Field(default_factory=list)
    activate: bool = True


class ClipboardReadPayload(_Payload):
    format: Literal["text", "image"] = "text"


class ClipboardReadResponsePayload(_Payload):
    format: Literal["text", "image"] = "text"
    content: str
    size_bytes: int


class ClipboardWritePayload(_Payload):
    format: Literal["text", "image"] = "text"
    content: str


class PermissionsCheckRequestPayload(_Payload):
    permissions: list[str]


class PermissionsCheckResponsePayload(_Payload):
    permissions: dict[str, Literal["granted", "denied", "unknown", "not_applicable"]]


class ErrorPayload(_Payload):
    code: ErrorCode | str
    message: str
    fatal: bool = False
    details: dict[str, Any] | None = None


class PingPongPayload(_Payload):
    pass


# ── Session ownership ────────────────────────────────────────────────────────

# Reason values for SESSION_REVOKED. Extending this enum is a forward-compatible
# minor-version change — receivers tolerate unknown reasons and treat them as
# the catch-all "revoked, do not auto-reconnect" case.
SESSION_REVOKED_REASONS = (
    "another_shim_connected",
    "user_revoked",
    "platform_shutdown",
)


class SessionRevokedPayload(_Payload):
    """Platform → shim notification that this session is no longer valid.

    On receipt the shim MUST:
      1. Audit a SESSION_REVOKED record with the carried reason.
      2. Send no further frames on this connection.
      3. Gracefully close its half of the WebSocket.
      4. NOT auto-reconnect to the same session_id.

    `new_shim_machine_id` is set when reason is `another_shim_connected` and
    the platform knows the takeover machine; it's purely informational.
    """

    reason: str
    new_shim_machine_id: str | None = None


# ── Envelopes ────────────────────────────────────────────────────────────────


class _Envelope(BaseModel):
    """Per-type envelope. Subclasses fix `type` and `payload`.

    The `version` field carries the wire-protocol version this sender speaks
    (or, post-HELLO_ACK, the negotiated version). Receivers MUST be lenient:
    if it's missing or differs in minor from the negotiation, treat the
    HELLO-time negotiation as truth. A differing major on a non-HELLO frame
    is a hard error (drop the frame, log loudly).
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    ts: float
    version: str = VERSION


class HelloMessage(_Envelope):
    type: Literal[MessageType.HELLO] = MessageType.HELLO
    payload: HelloPayload


class HelloAckMessage(_Envelope):
    type: Literal[MessageType.HELLO_ACK] = MessageType.HELLO_ACK
    payload: HelloAckPayload


class ExecuteCommandMessage(_Envelope):
    type: Literal[MessageType.EXECUTE_COMMAND] = MessageType.EXECUTE_COMMAND
    payload: ExecuteCommandPayload


class CommandResultMessage(_Envelope):
    type: Literal[MessageType.COMMAND_RESULT] = MessageType.COMMAND_RESULT
    payload: CommandResultPayload


class FileReadMessage(_Envelope):
    type: Literal[MessageType.FILE_READ] = MessageType.FILE_READ
    payload: FileReadPayload


class FileContentsMessage(_Envelope):
    type: Literal[MessageType.FILE_CONTENTS] = MessageType.FILE_CONTENTS
    payload: FileContentsPayload


class FileWriteMessage(_Envelope):
    type: Literal[MessageType.FILE_WRITE] = MessageType.FILE_WRITE
    payload: FileWritePayload


class AckMessage(_Envelope):
    type: Literal[MessageType.ACK] = MessageType.ACK
    payload: AckPayload


class FileStatMessage(_Envelope):
    type: Literal[MessageType.FILE_STAT] = MessageType.FILE_STAT
    payload: FileStatPayload


class FileStatResponseMessage(_Envelope):
    type: Literal[MessageType.FILE_STAT_RESPONSE] = MessageType.FILE_STAT_RESPONSE
    payload: FileStatResponsePayload


class FileListMessage(_Envelope):
    type: Literal[MessageType.FILE_LIST] = MessageType.FILE_LIST
    payload: FileListPayload


class FileListResponseMessage(_Envelope):
    type: Literal[MessageType.FILE_LIST_RESPONSE] = MessageType.FILE_LIST_RESPONSE
    payload: FileListResponsePayload


class FileDeleteMessage(_Envelope):
    type: Literal[MessageType.FILE_DELETE] = MessageType.FILE_DELETE
    payload: FileDeletePayload


class FileMoveMessage(_Envelope):
    type: Literal[MessageType.FILE_MOVE] = MessageType.FILE_MOVE
    payload: FileMovePayload


class ScreenshotRequestMessage(_Envelope):
    type: Literal[MessageType.SCREENSHOT_REQUEST] = MessageType.SCREENSHOT_REQUEST
    payload: ScreenshotRequestPayload


class ScreenshotResponseMessage(_Envelope):
    type: Literal[MessageType.SCREENSHOT_RESPONSE] = MessageType.SCREENSHOT_RESPONSE
    payload: ScreenshotResponsePayload


class InputActionMessage(_Envelope):
    type: Literal[MessageType.INPUT_ACTION] = MessageType.INPUT_ACTION
    payload: InputActionPayload


class CursorPositionRequestMessage(_Envelope):
    type: Literal[MessageType.CURSOR_POSITION_REQUEST] = MessageType.CURSOR_POSITION_REQUEST
    payload: CursorPositionRequestPayload = Field(default_factory=CursorPositionRequestPayload)


class CursorPositionResponseMessage(_Envelope):
    type: Literal[MessageType.CURSOR_POSITION_RESPONSE] = MessageType.CURSOR_POSITION_RESPONSE
    payload: CursorPositionResponsePayload


class DisplayInfoRequestMessage(_Envelope):
    type: Literal[MessageType.DISPLAY_INFO_REQUEST] = MessageType.DISPLAY_INFO_REQUEST
    payload: DisplayInfoRequestPayload = Field(default_factory=DisplayInfoRequestPayload)


class DisplayInfoResponseMessage(_Envelope):
    type: Literal[MessageType.DISPLAY_INFO_RESPONSE] = MessageType.DISPLAY_INFO_RESPONSE
    payload: DisplayInfoResponsePayload


class WindowListRequestMessage(_Envelope):
    type: Literal[MessageType.WINDOW_LIST_REQUEST] = MessageType.WINDOW_LIST_REQUEST
    payload: WindowListRequestPayload = Field(default_factory=WindowListRequestPayload)


class WindowListResponseMessage(_Envelope):
    type: Literal[MessageType.WINDOW_LIST_RESPONSE] = MessageType.WINDOW_LIST_RESPONSE
    payload: WindowListResponsePayload


class WindowFocusMessage(_Envelope):
    type: Literal[MessageType.WINDOW_FOCUS] = MessageType.WINDOW_FOCUS
    payload: WindowFocusPayload


class AppListRequestMessage(_Envelope):
    type: Literal[MessageType.APP_LIST_REQUEST] = MessageType.APP_LIST_REQUEST
    payload: AppListRequestPayload = Field(default_factory=AppListRequestPayload)


class AppListResponseMessage(_Envelope):
    type: Literal[MessageType.APP_LIST_RESPONSE] = MessageType.APP_LIST_RESPONSE
    payload: AppListResponsePayload


class AppLaunchMessage(_Envelope):
    type: Literal[MessageType.APP_LAUNCH] = MessageType.APP_LAUNCH
    payload: AppLaunchPayload


class ClipboardReadMessage(_Envelope):
    type: Literal[MessageType.CLIPBOARD_READ] = MessageType.CLIPBOARD_READ
    payload: ClipboardReadPayload = Field(default_factory=ClipboardReadPayload)


class ClipboardReadResponseMessage(_Envelope):
    type: Literal[MessageType.CLIPBOARD_READ_RESPONSE] = MessageType.CLIPBOARD_READ_RESPONSE
    payload: ClipboardReadResponsePayload


class ClipboardWriteMessage(_Envelope):
    type: Literal[MessageType.CLIPBOARD_WRITE] = MessageType.CLIPBOARD_WRITE
    payload: ClipboardWritePayload


class PermissionsCheckRequestMessage(_Envelope):
    type: Literal[MessageType.PERMISSIONS_CHECK_REQUEST] = MessageType.PERMISSIONS_CHECK_REQUEST
    payload: PermissionsCheckRequestPayload


class PermissionsCheckResponseMessage(_Envelope):
    type: Literal[MessageType.PERMISSIONS_CHECK_RESPONSE] = MessageType.PERMISSIONS_CHECK_RESPONSE
    payload: PermissionsCheckResponsePayload


class ErrorMessage(_Envelope):
    type: Literal[MessageType.ERROR] = MessageType.ERROR
    payload: ErrorPayload


class PingMessage(_Envelope):
    type: Literal[MessageType.PING] = MessageType.PING
    payload: PingPongPayload = Field(default_factory=PingPongPayload)


class PongMessage(_Envelope):
    type: Literal[MessageType.PONG] = MessageType.PONG
    payload: PingPongPayload = Field(default_factory=PingPongPayload)


class SessionRevokedMessage(_Envelope):
    type: Literal[MessageType.SESSION_REVOKED] = MessageType.SESSION_REVOKED
    payload: SessionRevokedPayload


# Discriminated union — used when parsing inbound frames.
Message = Annotated[
    HelloMessage | HelloAckMessage | ExecuteCommandMessage | CommandResultMessage | FileReadMessage | FileContentsMessage | FileWriteMessage | AckMessage | FileStatMessage | FileStatResponseMessage | FileListMessage | FileListResponseMessage | FileDeleteMessage | FileMoveMessage | ScreenshotRequestMessage | ScreenshotResponseMessage | InputActionMessage | CursorPositionRequestMessage | CursorPositionResponseMessage | DisplayInfoRequestMessage | DisplayInfoResponseMessage | WindowListRequestMessage | WindowListResponseMessage | WindowFocusMessage | AppListRequestMessage | AppListResponseMessage | AppLaunchMessage | ClipboardReadMessage | ClipboardReadResponseMessage | ClipboardWriteMessage | PermissionsCheckRequestMessage | PermissionsCheckResponseMessage | ErrorMessage | PingMessage | PongMessage | SessionRevokedMessage,
    Field(discriminator="type"),
]

_MESSAGE_ADAPTER: TypeAdapter[Message] = TypeAdapter(Message)


# ── Public helpers ───────────────────────────────────────────────────────────


def new_id() -> str:
    return str(uuid.uuid4())


def now_ts() -> float:
    return time.time()


def parse_message(raw: str | bytes) -> Any:
    """
    Parse a raw WebSocket frame into a typed message.

    Returns one of the *Message classes from this module. Raises
    ValidationError on malformed/unknown frames.
    """
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    data = json.loads(raw)
    return _MESSAGE_ADAPTER.validate_python(data)


def dump_message(msg: BaseModel) -> str:
    """Serialize a message to a JSON string for sending on the wire."""
    return msg.model_dump_json()


def make_error(
    msg_id: str,
    code: ErrorCode | str,
    message: str,
    fatal: bool = False,
    details: dict[str, Any] | None = None,
) -> ErrorMessage:
    return ErrorMessage(
        id=msg_id,
        ts=now_ts(),
        payload=ErrorPayload(code=code, message=message, fatal=fatal, details=details),
    )


def make_ack(msg_id: str, ok: bool = True) -> AckMessage:
    return AckMessage(id=msg_id, ts=now_ts(), payload=AckPayload(ok=ok))


def make_pong(msg_id: str) -> PongMessage:
    return PongMessage(id=msg_id, ts=now_ts(), payload=PingPongPayload())


__all__ = [
    "VERSION",
    "ProtocolVersionMismatch",
    "negotiate_version",
    "Arch",
    "AckMessage",
    "AckPayload",
    "AppInfo",
    "AppLaunchMessage",
    "AppLaunchPayload",
    "AppListRequestMessage",
    "AppListRequestPayload",
    "AppListResponseMessage",
    "AppListResponsePayload",
    "ClipboardReadMessage",
    "ClipboardReadPayload",
    "ClipboardReadResponseMessage",
    "ClipboardReadResponsePayload",
    "ClipboardWriteMessage",
    "ClipboardWritePayload",
    "CommandResultMessage",
    "CommandResultPayload",
    "CursorPositionRequestMessage",
    "CursorPositionRequestPayload",
    "CursorPositionResponseMessage",
    "CursorPositionResponsePayload",
    "DisplayInfoRequestMessage",
    "DisplayInfoRequestPayload",
    "DisplayInfoResponseMessage",
    "DisplayInfoResponsePayload",
    "DisplayMonitor",
    "Encoding",
    "ErrorCode",
    "ErrorMessage",
    "ErrorPayload",
    "ExecuteCommandMessage",
    "ExecuteCommandPayload",
    "FileContentsMessage",
    "FileContentsPayload",
    "FileDeleteMessage",
    "FileDeletePayload",
    "FileEntry",
    "FileFormat",
    "FileListMessage",
    "FileListPayload",
    "FileListResponseMessage",
    "FileListResponsePayload",
    "FileMoveMessage",
    "FileMovePayload",
    "FileReadMessage",
    "FileReadPayload",
    "FileStatMessage",
    "FileStatPayload",
    "FileStatResponseMessage",
    "FileStatResponsePayload",
    "FileWriteMessage",
    "FileWritePayload",
    "HelloAckMessage",
    "HelloAckPayload",
    "HelloMessage",
    "HelloPayload",
    "InputActionMessage",
    "InputActionPayload",
    "Message",
    "MessageType",
    "PermissionsCheckRequestMessage",
    "PermissionsCheckRequestPayload",
    "PermissionsCheckResponseMessage",
    "PermissionsCheckResponsePayload",
    "PingMessage",
    "PingPongPayload",
    "Platform",
    "PongMessage",
    "ScreenshotRequestMessage",
    "ScreenshotRequestPayload",
    "ScreenshotResponseMessage",
    "ScreenshotResponseMeta",
    "ScreenshotResponsePayload",
    "SESSION_REVOKED_REASONS",
    "SessionRevokedMessage",
    "SessionRevokedPayload",
    "Shell",
    "ValidationError",
    "WindowFocusMessage",
    "WindowFocusPayload",
    "WindowInfo",
    "WindowListRequestMessage",
    "WindowListRequestPayload",
    "WindowListResponseMessage",
    "WindowListResponsePayload",
    "dump_message",
    "make_ack",
    "make_error",
    "make_pong",
    "new_id",
    "now_ts",
    "parse_message",
]
