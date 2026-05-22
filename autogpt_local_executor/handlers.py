"""
Per-message handlers.

Each handler takes a parsed inbound message (one of the *Message types
from `protocol`) and returns the response message — never raises (any
internal error becomes an ERROR message with INTERNAL_ERROR).

Every FILE_* handler MUST call `assert_inside_jail()` before touching
the filesystem.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import io
import logging
import mimetypes
import os
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

from . import platform_info
from .config import ShimConfig
from .path_jail import PathJailError, assert_inside_jail
from .protocol import (
    AckMessage,
    AckPayload,
    CommandResultMessage,
    CommandResultPayload,
    Encoding,
    ErrorCode,
    ErrorMessage,
    ErrorPayload,
    ExecuteCommandMessage,
    FileContentsMessage,
    FileContentsPayload,
    FileDeleteMessage,
    FileEntry,
    FileFormat,
    FileListMessage,
    FileListResponseMessage,
    FileListResponsePayload,
    FileMoveMessage,
    FileReadMessage,
    FileStatMessage,
    FileStatResponseMessage,
    FileStatResponsePayload,
    FileWriteMessage,
    InputActionMessage,
    ScreenshotRequestMessage,
    ScreenshotResponseMessage,
    ScreenshotResponsePayload,
    make_ack,
    make_error,
    now_ts,
)

try:
    import pyautogui as _pyautogui  # type: ignore[import-untyped]
    from PIL import Image as _Image  # type: ignore[import-untyped]
except ImportError:
    _pyautogui = None  # type: ignore[assignment]
    _Image = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)


# ── Helpers ──────────────────────────────────────────────────────────────────


def _jail_error_to_message(msg_id: str, exc: PathJailError) -> ErrorMessage:
    return make_error(msg_id, exc.code, exc.message)


def _safe_env_baseline() -> dict[str, str]:
    """Per CROSS_PLATFORM.md "Environment variables" → safe-env baseline row."""
    plat = platform_info.detect_platform()
    if plat == "windows":
        keep = {
            "USERPROFILE",
            "HOMEDRIVE",
            "HOMEPATH",
            "PATH",
            "SYSTEMROOT",
            "TEMP",
            "TMP",
            "COMSPEC",
            "OS",
            "WINDIR",
            "LOCALAPPDATA",
            "APPDATA",
        }
        # Case-fold on Windows (env names are case-insensitive in Win32).
        out: dict[str, str] = {}
        for k, v in os.environ.items():
            if k.upper() in keep:
                out[k] = v
        return out
    keep = {"HOME", "PATH", "LANG", "TZ", "TMPDIR", "USER", "SHELL"}
    out = {k: v for k, v in os.environ.items() if k in keep or k.startswith("LC_")}
    return out


def _merge_env(base: dict[str, str], extra: dict[str, str]) -> dict[str, str]:
    """Merge wire-supplied env into the safe baseline.

    On Windows, env-var names are case-insensitive: incoming "Path" should
    replace the baseline's "PATH", not coexist. We case-fold names by
    treating uppercase as canonical when there's a collision.
    """
    if platform_info.detect_platform() != "windows":
        return {**base, **extra}
    # Build a case-folded index over the base so we can drop colliding keys.
    folded: dict[str, str] = {k.upper(): k for k in base}
    result = dict(base)
    for k, v in extra.items():
        existing = folded.get(k.upper())
        if existing is not None:
            del result[existing]
        result[k] = v
    return result


# ── EXECUTE_COMMAND ──────────────────────────────────────────────────────────


class CommandHandler:
    def __init__(self, config: ShimConfig) -> None:
        self.config = config

    async def handle(self, msg: ExecuteCommandMessage) -> CommandResultMessage | ErrorMessage:
        payload = msg.payload

        # Validate command vs argv mutual exclusion.
        if (payload.command is None) == (payload.argv is None):
            return make_error(
                msg.id,
                ErrorCode.INTERNAL_ERROR,
                "Exactly one of `command` or `argv` must be set.",
            )

        cwd_str = payload.cwd or str(self.config.allowed_root)
        try:
            cwd = assert_inside_jail(cwd_str, self.config.allowed_root)
        except PathJailError as exc:
            return _jail_error_to_message(msg.id, exc)

        timeout = payload.timeout_seconds or self.config.command_timeout_seconds
        env = _merge_env(_safe_env_baseline(), payload.env or {})
        # Always force UTF-8 on Python subprocess output to keep stdout/stderr decodable.
        env["PYTHONIOENCODING"] = "utf-8"

        plat = platform_info.detect_platform()
        creation_flags = 0
        preexec_fn = None
        if plat == "windows":
            # CREATE_NEW_PROCESS_GROUP so we can deliver CTRL_BREAK_EVENT.
            creation_flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        else:
            # New session = new pgid so we can kill the whole tree.
            preexec_fn = os.setsid  # type: ignore[attr-defined]

        await self._audit_log(payload, cwd)

        start = time.monotonic()
        timed_out = False
        stdout_b: bytes = b""
        stderr_b: bytes = b""
        exit_code = -1

        try:
            if payload.argv is not None:
                proc = await self._spawn_argv(
                    payload.argv,
                    cwd=str(cwd),
                    env=env,
                    creation_flags=creation_flags,
                    preexec_fn=preexec_fn,
                )
            else:
                resolved = platform_info.resolve_shell(payload.shell.value)
                if resolved is None:
                    return make_error(
                        msg.id,
                        ErrorCode.SHELL_NOT_AVAILABLE,
                        f"Shell {payload.shell.value!r} is not available on this OS.",
                    )
                shell_exe, shell_args = resolved
                # On Windows, ensure UTF-8 codepage for the subprocess.
                full_command = payload.command or ""
                if plat == "windows" and shell_exe.lower().endswith("cmd.exe"):
                    full_command = f"chcp 65001 >NUL & {full_command}"
                proc = await self._spawn_argv(
                    [shell_exe, *shell_args, full_command],
                    cwd=str(cwd),
                    env=env,
                    creation_flags=creation_flags,
                    preexec_fn=preexec_fn,
                )
        except FileNotFoundError as exc:
            return make_error(
                msg.id,
                ErrorCode.SHELL_NOT_AVAILABLE,
                f"Executable not found: {exc}",
            )
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("Failed to spawn subprocess")
            return make_error(msg.id, ErrorCode.INTERNAL_ERROR, str(exc))

        try:
            stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            exit_code = proc.returncode if proc.returncode is not None else -1
        except asyncio.TimeoutError:
            timed_out = True
            await self._terminate_tree(proc)
            try:
                # Drain any remaining output without blocking long.
                stdout_b, stderr_b = await asyncio.wait_for(
                    proc.communicate(), timeout=2.0
                )
            except asyncio.TimeoutError:
                pass
            exit_code = proc.returncode if proc.returncode is not None else -1

        duration = time.monotonic() - start

        return CommandResultMessage(
            id=msg.id,
            ts=now_ts(),
            payload=CommandResultPayload(
                stdout=stdout_b.decode("utf-8", errors="replace"),
                stderr=stderr_b.decode("utf-8", errors="replace"),
                exit_code=exit_code,
                timed_out=timed_out,
                duration_seconds=round(duration, 3),
            ),
        )

    @staticmethod
    async def _spawn_argv(
        argv: list[str],
        *,
        cwd: str,
        env: dict[str, str],
        creation_flags: int,
        preexec_fn,
    ) -> asyncio.subprocess.Process:
        return await asyncio.create_subprocess_exec(
            *argv,
            cwd=cwd,
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            creationflags=creation_flags,
            preexec_fn=preexec_fn,
        )

    @staticmethod
    async def _terminate_tree(proc: asyncio.subprocess.Process) -> None:
        """Graceful → forceful kill per CROSS_PLATFORM.md "Process control" row."""
        plat = platform_info.detect_platform()
        try:
            if plat == "windows":
                # CTRL_BREAK to the process group, then TerminateProcess.
                try:
                    proc.send_signal(getattr(__import__("signal"), "CTRL_BREAK_EVENT"))
                except (AttributeError, OSError):
                    pass
                await asyncio.sleep(2.0)
                if proc.returncode is None:
                    proc.kill()
            else:
                import signal

                # Kill the whole process group we created with setsid.
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                except (ProcessLookupError, OSError):
                    pass
                await asyncio.sleep(2.0)
                if proc.returncode is None:
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    except (ProcessLookupError, OSError):
                        pass
        except Exception:  # pragma: no cover - best-effort
            logger.exception("Error terminating subprocess tree")

    async def _audit_log(self, payload, cwd: Path) -> None:
        """Append a single line to the audit log. Best-effort; never fatal."""
        try:
            log_path = Path(self.config.audit_log_path)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            line = (
                f"{now_ts():.3f}\t"
                f"session={self.config.session_id or '-'}\t"
                f"cwd={cwd}\t"
                f"shell={payload.shell.value if payload.command else 'argv'}\t"
                f"cmd={payload.command or payload.argv}\n"
            )
            await asyncio.to_thread(_append_line, log_path, line)
        except Exception:
            logger.debug("Audit log write failed", exc_info=True)


def _append_line(path: Path, line: str) -> None:
    with open(path, "a", encoding="utf-8") as f:
        f.write(line)


# ── FILE_* handlers ──────────────────────────────────────────────────────────


class FileHandler:
    def __init__(self, config: ShimConfig) -> None:
        self.config = config

    # -- FILE_READ -----------------------------------------------------------

    async def handle_read(
        self, msg: FileReadMessage
    ) -> FileContentsMessage | ErrorMessage:
        payload = msg.payload
        try:
            path = assert_inside_jail(payload.path, self.config.allowed_root)
        except PathJailError as exc:
            return _jail_error_to_message(msg.id, exc)

        if not path.exists():
            return make_error(
                msg.id, ErrorCode.PATH_NOT_FOUND, f"{path} does not exist"
            )
        if path.is_dir():
            return make_error(
                msg.id,
                ErrorCode.INTERNAL_ERROR,
                f"{path} is a directory, not a file",
            )

        size = path.stat().st_size
        if size > self.config.max_file_size_bytes:
            return make_error(
                msg.id,
                ErrorCode.FILE_TOO_LARGE,
                f"{size} bytes exceeds limit {self.config.max_file_size_bytes}",
            )

        offset = max(payload.offset, 0)
        length = payload.length
        raw = await asyncio.to_thread(path.read_bytes)
        end = offset + length if length is not None else len(raw)
        chunk = raw[offset:end]
        truncated = length is not None and end < len(raw)

        # encoding ↔ format mapping per PROTOCOL.md FILE_READ table.
        if payload.format == FileFormat.BYTES or payload.encoding == Encoding.BASE64:
            content = base64.b64encode(chunk).decode("ascii")
            wire_encoding = Encoding.BASE64
        else:
            # text mode: decode as UTF-8, do NOT translate CRLF.
            content = chunk.decode("utf-8", errors="replace")
            wire_encoding = Encoding.UTF8

        return FileContentsMessage(
            id=msg.id,
            ts=now_ts(),
            payload=FileContentsPayload(
                content=content,
                encoding=wire_encoding,
                size_bytes=len(chunk),
                truncated=truncated,
            ),
        )

    # -- FILE_WRITE ----------------------------------------------------------

    async def handle_write(
        self, msg: FileWriteMessage
    ) -> AckMessage | ErrorMessage:
        payload = msg.payload
        try:
            path = self._jail_for_write(payload.path, payload.create_parents)
        except PathJailError as exc:
            return _jail_error_to_message(msg.id, exc)

        if payload.encoding == Encoding.BASE64:
            try:
                raw = base64.b64decode(payload.content, validate=True)
            except (ValueError, binascii.Error) as exc:
                return make_error(
                    msg.id, ErrorCode.INTERNAL_ERROR, f"Bad base64: {exc}"
                )
        else:
            raw = payload.content.encode("utf-8")

        if len(raw) > self.config.max_file_size_bytes:
            return make_error(
                msg.id,
                ErrorCode.FILE_TOO_LARGE,
                f"{len(raw)} bytes exceeds limit {self.config.max_file_size_bytes}",
            )

        if payload.create_parents:
            await asyncio.to_thread(lambda: path.parent.mkdir(parents=True, exist_ok=True))

        await asyncio.to_thread(path.write_bytes, raw)
        return make_ack(msg.id)

    def _jail_for_write(self, raw_path: str, create_parents: bool) -> Path:
        """FILE_WRITE may target a not-yet-existing path; jail the *parent*."""
        target = Path(raw_path).expanduser()
        parent = target.parent
        # The parent (which must exist after create_parents) is what we
        # jail-check; we then return the final target path.
        if create_parents:
            # Find the nearest existing ancestor for the jail check.
            probe = parent
            while not probe.exists() and probe != probe.parent:
                probe = probe.parent
            assert_inside_jail(probe, self.config.allowed_root)
            # Also make sure the requested parent itself (once it exists)
            # would be inside the jail.
            if parent.exists():
                assert_inside_jail(parent, self.config.allowed_root)
        else:
            assert_inside_jail(parent, self.config.allowed_root)
        # Re-check the full target via the standard path (catches symlink
        # tricks under the target name).
        # If the file doesn't exist yet, realpath on its parent is enough.
        if target.exists():
            return assert_inside_jail(target, self.config.allowed_root)
        return target

    # -- FILE_STAT -----------------------------------------------------------

    async def handle_stat(
        self, msg: FileStatMessage
    ) -> FileStatResponseMessage | ErrorMessage:
        payload = msg.payload
        try:
            path = assert_inside_jail(payload.path, self.config.allowed_root)
        except PathJailError as exc:
            return _jail_error_to_message(msg.id, exc)

        # Real-resolve here too if follow_symlinks asked (realpath already ran
        # in the jail; path is the resolved form).
        try:
            if payload.follow_symlinks:
                st = await asyncio.to_thread(os.stat, str(path))
            else:
                st = await asyncio.to_thread(os.lstat, str(path))
        except FileNotFoundError:
            return FileStatResponseMessage(
                id=msg.id,
                ts=now_ts(),
                payload=FileStatResponsePayload(exists=False),
            )
        except OSError as exc:
            return make_error(msg.id, ErrorCode.INTERNAL_ERROR, str(exc))

        is_file = stat.S_ISREG(st.st_mode)
        is_dir = stat.S_ISDIR(st.st_mode)
        is_symlink = False
        if not payload.follow_symlinks:
            is_symlink = stat.S_ISLNK(st.st_mode)
        else:
            # Even with follow=True we can report whether the *original*
            # path was a symlink, via a separate lstat.
            try:
                lst = await asyncio.to_thread(os.lstat, payload.path)
                is_symlink = stat.S_ISLNK(lst.st_mode)
            except OSError:
                is_symlink = False

        is_windows = sys.platform == "win32"
        mode_str: str
        if is_windows:
            # Derive a POSIX-flavored mode from FILE_ATTRIBUTE_READONLY.
            ro = bool(st.st_mode & stat.S_IWRITE) is False
            if is_dir:
                mode_str = "0555" if ro else "0755"
            else:
                mode_str = "0444" if ro else "0644"
        else:
            mode_str = f"{stat.S_IMODE(st.st_mode):04o}"

        mime, _ = mimetypes.guess_type(str(path))

        return FileStatResponseMessage(
            id=msg.id,
            ts=now_ts(),
            payload=FileStatResponsePayload(
                exists=True,
                is_file=is_file,
                is_dir=is_dir,
                is_symlink=is_symlink,
                size_bytes=st.st_size,
                mtime=st.st_mtime,
                ctime=st.st_ctime,
                mode=mode_str,
                owner_uid=None if is_windows else st.st_uid,
                owner_gid=None if is_windows else st.st_gid,
                mime_type=mime,
                path=str(path),
            ),
        )

    # -- FILE_LIST -----------------------------------------------------------

    async def handle_list(
        self, msg: FileListMessage
    ) -> FileListResponseMessage | ErrorMessage:
        payload = msg.payload
        try:
            base = assert_inside_jail(payload.path, self.config.allowed_root)
        except PathJailError as exc:
            return _jail_error_to_message(msg.id, exc)

        if not base.exists():
            return make_error(
                msg.id, ErrorCode.PATH_NOT_FOUND, f"{base} does not exist"
            )
        if not base.is_dir():
            return make_error(
                msg.id, ErrorCode.INTERNAL_ERROR, f"{base} is not a directory"
            )

        def _walk() -> tuple[list[FileEntry], bool]:
            entries: list[FileEntry] = []
            truncated = False
            case_fold = platform_info.is_case_insensitive_fs(str(base))
            glob = payload.glob

            def _matches(name: str) -> bool:
                if glob is None:
                    return True
                if case_fold:
                    from fnmatch import fnmatchcase

                    return fnmatchcase(name.lower(), glob.lower())
                from fnmatch import fnmatchcase

                return fnmatchcase(name, glob)

            iterator = base.rglob("*") if payload.recursive else base.iterdir()
            for p in iterator:
                if not payload.include_hidden and p.name.startswith("."):
                    continue
                if not _matches(p.name):
                    continue
                try:
                    st = p.lstat()
                except OSError:
                    continue
                entries.append(
                    FileEntry(
                        name=p.name,
                        path=str(p),
                        is_file=p.is_file(),
                        is_dir=p.is_dir(),
                        is_symlink=p.is_symlink(),
                        size_bytes=st.st_size,
                        mtime=st.st_mtime,
                    )
                )
                if len(entries) >= payload.max_entries:
                    truncated = True
                    break
            return entries, truncated

        entries, truncated = await asyncio.to_thread(_walk)
        return FileListResponseMessage(
            id=msg.id,
            ts=now_ts(),
            payload=FileListResponsePayload(entries=entries, truncated=truncated),
        )

    # -- FILE_DELETE ---------------------------------------------------------

    async def handle_delete(
        self, msg: FileDeleteMessage
    ) -> AckMessage | ErrorMessage:
        payload = msg.payload
        try:
            path = assert_inside_jail(payload.path, self.config.allowed_root)
        except PathJailError as exc:
            return _jail_error_to_message(msg.id, exc)

        if not path.exists():
            if payload.missing_ok:
                return make_ack(msg.id)
            return make_error(
                msg.id, ErrorCode.PATH_NOT_FOUND, f"{path} does not exist"
            )

        try:
            if path.is_dir() and not path.is_symlink():
                if payload.recursive:
                    await asyncio.to_thread(shutil.rmtree, str(path))
                else:
                    try:
                        await asyncio.to_thread(os.rmdir, str(path))
                    except OSError as exc:
                        # Dir not empty.
                        return make_error(
                            msg.id, ErrorCode.PATH_NOT_EMPTY, str(exc)
                        )
            else:
                await asyncio.to_thread(os.unlink, str(path))
        except OSError as exc:
            return make_error(msg.id, ErrorCode.INTERNAL_ERROR, str(exc))

        return make_ack(msg.id)

    # -- FILE_MOVE -----------------------------------------------------------

    async def handle_move(
        self, msg: FileMoveMessage
    ) -> AckMessage | ErrorMessage:
        payload = msg.payload
        try:
            src = assert_inside_jail(payload.src, self.config.allowed_root)
            dst_raw = Path(payload.dst).expanduser()
            if dst_raw.exists():
                dst = assert_inside_jail(dst_raw, self.config.allowed_root)
            else:
                # Jail the destination's parent (it must exist before move).
                assert_inside_jail(dst_raw.parent, self.config.allowed_root)
                dst = dst_raw
        except PathJailError as exc:
            return _jail_error_to_message(msg.id, exc)

        if not src.exists():
            return make_error(
                msg.id, ErrorCode.PATH_NOT_FOUND, f"{src} does not exist"
            )
        if dst.exists() and not payload.overwrite:
            return make_error(
                msg.id, ErrorCode.PATH_EXISTS, f"{dst} already exists"
            )

        try:
            if dst.exists() and payload.overwrite:
                if dst.is_dir() and not dst.is_symlink():
                    await asyncio.to_thread(shutil.rmtree, str(dst))
                else:
                    await asyncio.to_thread(os.unlink, str(dst))
            # shutil.move handles cross-device by falling back to copy+delete.
            await asyncio.to_thread(shutil.move, str(src), str(dst))
        except OSError as exc:
            return make_error(msg.id, ErrorCode.INTERNAL_ERROR, str(exc))

        return make_ack(msg.id)


# ── Computer use ─────────────────────────────────────────────────────────────


class ComputerUseHandler:
    def __init__(self, config: ShimConfig) -> None:
        self.config = config

    async def handle(self, msg) -> ScreenshotResponseMessage | AckMessage | ErrorMessage:
        if not self.config.enable_computer_use:
            return make_error(
                msg.id,
                ErrorCode.CAPABILITY_NOT_GRANTED,
                "Computer use is not enabled on this shim.",
            )
        if isinstance(msg, ScreenshotRequestMessage):
            return await self._screenshot(msg)
        if isinstance(msg, InputActionMessage):
            return await self._execute_action(msg)
        return make_error(
            msg.id, ErrorCode.INTERNAL_ERROR, f"Unknown computer-use message: {type(msg).__name__}"
        )

    async def _screenshot(
        self, msg: ScreenshotRequestMessage
    ) -> ScreenshotResponseMessage | ErrorMessage:
        if _pyautogui is None or _Image is None:
            return make_error(
                msg.id,
                ErrorCode.DEPENDENCY_MISSING,
                "pyautogui/Pillow not installed. pip install autogpt-local-executor[computer-use]",
            )
        quality = msg.payload.quality

        def _capture() -> tuple[bytes, int, int]:
            img = _pyautogui.screenshot()
            buf = io.BytesIO()
            img.convert("RGB").save(buf, format="JPEG", quality=quality)
            return buf.getvalue(), img.width, img.height

        try:
            img_bytes, w, h = await asyncio.to_thread(_capture)
        except Exception as exc:
            return make_error(msg.id, ErrorCode.INTERNAL_ERROR, str(exc))

        return ScreenshotResponseMessage(
            id=msg.id,
            ts=now_ts(),
            payload=ScreenshotResponsePayload(
                image_base64=base64.b64encode(img_bytes).decode("ascii"),
                mime_type="image/jpeg",
                width=w,
                height=h,
                monitor=msg.payload.monitor,
            ),
        )

    async def _execute_action(
        self, msg: InputActionMessage
    ) -> AckMessage | ErrorMessage:
        if _pyautogui is None:
            return make_error(
                msg.id, ErrorCode.DEPENDENCY_MISSING, "pyautogui not installed."
            )

        payload = msg.payload

        def _run() -> None:
            _pyautogui.FAILSAFE = True
            action = payload.action
            coord = payload.coordinate
            if action == "mouse_move" and coord:
                _pyautogui.moveTo(coord[0], coord[1])
            elif action == "left_click" and coord:
                _pyautogui.click(coord[0], coord[1])
            elif action == "right_click" and coord:
                _pyautogui.rightClick(coord[0], coord[1])
            elif action == "double_click" and coord:
                _pyautogui.doubleClick(coord[0], coord[1])
            elif action == "type" and payload.text is not None:
                _pyautogui.write(payload.text, interval=0.02)
            elif action == "key" and payload.key:
                _pyautogui.hotkey(*payload.key.split("+"))
            elif action == "scroll" and coord:
                direction = payload.direction or "down"
                clicks = payload.clicks or 3
                _pyautogui.scroll(
                    clicks if direction == "up" else -clicks,
                    x=coord[0],
                    y=coord[1],
                )
            else:
                raise ValueError(f"Unknown or under-specified action: {action}")

        try:
            await asyncio.to_thread(_run)
        except Exception as exc:
            return make_error(msg.id, ErrorCode.INTERNAL_ERROR, str(exc))

        return make_ack(msg.id)


__all__ = [
    "CommandHandler",
    "ComputerUseHandler",
    "FileHandler",
]
