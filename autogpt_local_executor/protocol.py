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
from typing import Annotated, Any, Literal, Union

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError


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
    ACK = "ACK"
    ERROR = "ERROR"
    PING = "PING"
    PONG = "PONG"


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


class HelloAckPayload(_Payload):
    session_id: str
    granted_capabilities: list[str]
    max_file_size_bytes: int = 10 * 1024 * 1024
    command_timeout_seconds: int = 30
    max_concurrent: int = 4


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


class ScreenshotResponsePayload(_Payload):
    image_base64: str
    mime_type: str = "image/jpeg"
    width: int
    height: int
    monitor: int = 0


class InputActionPayload(_Payload):
    action: Literal[
        "left_click",
        "right_click",
        "double_click",
        "mouse_move",
        "type",
        "key",
        "scroll",
    ]
    coordinate: tuple[int, int] | None = None
    text: str | None = None
    key: str | None = None
    direction: Literal["up", "down"] | None = None
    clicks: int | None = None


class ErrorPayload(_Payload):
    code: ErrorCode | str
    message: str
    fatal: bool = False


class PingPongPayload(_Payload):
    pass


# ── Envelopes ────────────────────────────────────────────────────────────────


class _Envelope(BaseModel):
    """Per-type envelope. Subclasses fix `type` and `payload`."""

    model_config = ConfigDict(extra="forbid")

    id: str
    ts: float


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


class ErrorMessage(_Envelope):
    type: Literal[MessageType.ERROR] = MessageType.ERROR
    payload: ErrorPayload


class PingMessage(_Envelope):
    type: Literal[MessageType.PING] = MessageType.PING
    payload: PingPongPayload = Field(default_factory=PingPongPayload)


class PongMessage(_Envelope):
    type: Literal[MessageType.PONG] = MessageType.PONG
    payload: PingPongPayload = Field(default_factory=PingPongPayload)


# Discriminated union — used when parsing inbound frames.
Message = Annotated[
    Union[
        HelloMessage,
        HelloAckMessage,
        ExecuteCommandMessage,
        CommandResultMessage,
        FileReadMessage,
        FileContentsMessage,
        FileWriteMessage,
        AckMessage,
        FileStatMessage,
        FileStatResponseMessage,
        FileListMessage,
        FileListResponseMessage,
        FileDeleteMessage,
        FileMoveMessage,
        ScreenshotRequestMessage,
        ScreenshotResponseMessage,
        InputActionMessage,
        ErrorMessage,
        PingMessage,
        PongMessage,
    ],
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
) -> ErrorMessage:
    return ErrorMessage(
        id=msg_id,
        ts=now_ts(),
        payload=ErrorPayload(code=code, message=message, fatal=fatal),
    )


def make_ack(msg_id: str, ok: bool = True) -> AckMessage:
    return AckMessage(id=msg_id, ts=now_ts(), payload=AckPayload(ok=ok))


def make_pong(msg_id: str) -> PongMessage:
    return PongMessage(id=msg_id, ts=now_ts(), payload=PingPongPayload())


__all__ = [
    "Arch",
    "AckMessage",
    "AckPayload",
    "CommandResultMessage",
    "CommandResultPayload",
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
    "PingMessage",
    "PingPongPayload",
    "Platform",
    "PongMessage",
    "ScreenshotRequestMessage",
    "ScreenshotRequestPayload",
    "ScreenshotResponseMessage",
    "ScreenshotResponsePayload",
    "Shell",
    "ValidationError",
    "dump_message",
    "make_ack",
    "make_error",
    "make_pong",
    "new_id",
    "now_ts",
    "parse_message",
]
