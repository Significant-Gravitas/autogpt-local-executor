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
from typing import Any

from . import platform_info
from .audit import AuditWriter
from .computer_use import (
    BackendError,
    ComputerUseBackend,
    get_backend,
)
from .config import ShimConfig
from .path_jail import PathJailError, assert_inside_jail
from .protocol import (
    AckMessage,
    AckPayload,
    AppLaunchMessage,
    AppListRequestMessage,
    AppListResponseMessage,
    AppListResponsePayload,
    ClipboardReadMessage,
    ClipboardReadResponseMessage,
    ClipboardReadResponsePayload,
    ClipboardWriteMessage,
    CommandResultMessage,
    CommandResultPayload,
    CursorPositionRequestMessage,
    CursorPositionResponseMessage,
    CursorPositionResponsePayload,
    DisplayInfoRequestMessage,
    DisplayInfoResponseMessage,
    DisplayInfoResponsePayload,
    Encoding,
    ErrorCode,
    ErrorMessage,
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
    PermissionsCheckRequestMessage,
    PermissionsCheckResponseMessage,
    PermissionsCheckResponsePayload,
    ScreenshotRequestMessage,
    ScreenshotResponseMessage,
    ScreenshotResponseMeta,
    ScreenshotResponsePayload,
    WindowFocusMessage,
    WindowListRequestMessage,
    WindowListResponseMessage,
    WindowListResponsePayload,
    make_ack,
    make_error,
    now_ts,
)

# Kept for legacy tests that monkeypatch h_mod._pyautogui / h_mod._Image.
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


def _ok_result(duration_ms: int, *, exit_code: int | None = None) -> dict:
    return {"ok": True, "exit_code": exit_code, "duration_ms": duration_ms, "error_code": None}


def _err_result(duration_ms: int, error_code: str, *, exit_code: int | None = None) -> dict:
    return {
        "ok": False,
        "exit_code": exit_code,
        "duration_ms": duration_ms,
        "error_code": error_code,
    }


def _elapsed_ms(start: float) -> int:
    return int((time.monotonic() - start) * 1000)


async def _audit_jail_violation(
    audit: AuditWriter | None,
    op: str,
    raw_path: str,
    exc: PathJailError,
) -> None:
    """Mirror a path-jail rejection into the audit log as JAIL_VIOLATION."""
    if audit is None:
        return
    try:
        await audit.jail_violation(exc.code, raw_path, op=op)
    except Exception:
        logger.debug("Failed to write JAIL_VIOLATION audit record", exc_info=True)


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
    def __init__(
        self,
        config: ShimConfig,
        audit: AuditWriter | None = None,
    ) -> None:
        self.config = config
        self.audit = audit

    async def handle(self, msg: ExecuteCommandMessage) -> CommandResultMessage | ErrorMessage:
        payload = msg.payload
        start = time.monotonic()

        # Validate command vs argv mutual exclusion.
        if (payload.command is None) == (payload.argv is None):
            err = "Exactly one of `command` or `argv` must be set."
            await self._audit(
                msg.id,
                payload,
                cwd=payload.cwd or str(self.config.allowed_root),
                result=_err_result(_elapsed_ms(start), ErrorCode.INTERNAL_ERROR.value),
            )
            return make_error(msg.id, ErrorCode.INTERNAL_ERROR, err)

        cwd_str = payload.cwd or str(self.config.allowed_root)
        try:
            cwd = assert_inside_jail(cwd_str, self.config.allowed_root)
        except PathJailError as exc:
            await _audit_jail_violation(self.audit, "EXECUTE_COMMAND", cwd_str, exc)
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
                    await self._audit(
                        msg.id,
                        payload,
                        cwd=str(cwd),
                        result=_err_result(_elapsed_ms(start), ErrorCode.SHELL_NOT_AVAILABLE.value),
                    )
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
            await self._audit(
                msg.id,
                payload,
                cwd=str(cwd),
                result=_err_result(_elapsed_ms(start), ErrorCode.SHELL_NOT_AVAILABLE.value),
            )
            return make_error(
                msg.id,
                ErrorCode.SHELL_NOT_AVAILABLE,
                f"Executable not found: {exc}",
            )
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("Failed to spawn subprocess")
            await self._audit(
                msg.id,
                payload,
                cwd=str(cwd),
                result=_err_result(_elapsed_ms(start), ErrorCode.INTERNAL_ERROR.value),
            )
            return make_error(msg.id, ErrorCode.INTERNAL_ERROR, str(exc))

        try:
            stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            exit_code = proc.returncode if proc.returncode is not None else -1
        except TimeoutError:
            timed_out = True
            await self._terminate_tree(proc)
            try:
                # Drain any remaining output without blocking long.
                stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=2.0)
            except TimeoutError:
                pass
            exit_code = proc.returncode if proc.returncode is not None else -1

        elapsed_ms = _elapsed_ms(start)
        duration = elapsed_ms / 1000.0

        if timed_out:
            result = _err_result(elapsed_ms, ErrorCode.COMMAND_TIMEOUT.value, exit_code=exit_code)
        else:
            result = _ok_result(elapsed_ms, exit_code=exit_code)
        await self._audit(msg.id, payload, cwd=str(cwd), result=result, env=env)

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

    async def _audit(
        self,
        request_id: str,
        payload,
        *,
        cwd: str,
        result: dict,
        env: dict[str, str] | None = None,
    ) -> None:
        """Emit an EXECUTE_COMMAND record. Never logs env *values* — only the
        list of keys, per AUDIT_LOG.md "What's NEVER logged"."""
        if self.audit is None:
            return
        # Prefer the merged env if we got that far; otherwise the wire env.
        env_keys = sorted((env or payload.env or {}).keys())
        details = {
            "command": payload.command,
            "argv": payload.argv,
            "shell": payload.shell.value,
            "cwd": cwd,
            "env_keys": env_keys,
            "timeout_seconds": payload.timeout_seconds or self.config.command_timeout_seconds,
        }
        try:
            await self.audit.write(
                "EXECUTE_COMMAND",
                request_id=request_id,
                details=details,
                result=result,
            )
        except Exception:
            logger.debug("Failed to write EXECUTE_COMMAND audit record", exc_info=True)


# ── FILE_* handlers ──────────────────────────────────────────────────────────


class FileHandler:
    def __init__(
        self,
        config: ShimConfig,
        audit: AuditWriter | None = None,
    ) -> None:
        self.config = config
        self.audit = audit

    # -- FILE_READ -----------------------------------------------------------

    async def handle_read(self, msg: FileReadMessage) -> FileContentsMessage | ErrorMessage:
        payload = msg.payload
        start = time.monotonic()
        try:
            path = assert_inside_jail(payload.path, self.config.allowed_root)
        except PathJailError as exc:
            await _audit_jail_violation(self.audit, "FILE_READ", payload.path, exc)
            return _jail_error_to_message(msg.id, exc)

        details_base = {
            "path": str(path),
            "encoding": payload.encoding.value,
            "offset": payload.offset,
            "length": payload.length,
        }

        if not path.exists():
            await self._emit(
                "FILE_READ",
                msg.id,
                {**details_base, "size_bytes_returned": 0},
                _err_result(_elapsed_ms(start), ErrorCode.PATH_NOT_FOUND.value),
            )
            return make_error(msg.id, ErrorCode.PATH_NOT_FOUND, f"{path} does not exist")
        if path.is_dir():
            await self._emit(
                "FILE_READ",
                msg.id,
                {**details_base, "size_bytes_returned": 0},
                _err_result(_elapsed_ms(start), ErrorCode.INTERNAL_ERROR.value),
            )
            return make_error(
                msg.id,
                ErrorCode.INTERNAL_ERROR,
                f"{path} is a directory, not a file",
            )

        size = path.stat().st_size
        if size > self.config.max_file_size_bytes:
            await self._emit(
                "FILE_READ",
                msg.id,
                {**details_base, "size_bytes_returned": 0},
                _err_result(_elapsed_ms(start), ErrorCode.FILE_TOO_LARGE.value),
            )
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

        await self._emit(
            "FILE_READ",
            msg.id,
            {**details_base, "size_bytes_returned": len(chunk)},
            _ok_result(_elapsed_ms(start)),
        )

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

    async def handle_write(self, msg: FileWriteMessage) -> AckMessage | ErrorMessage:
        payload = msg.payload
        start = time.monotonic()
        try:
            path = self._jail_for_write(payload.path, payload.create_parents)
        except PathJailError as exc:
            await _audit_jail_violation(self.audit, "FILE_WRITE", payload.path, exc)
            return _jail_error_to_message(msg.id, exc)

        details_base = {
            "path": str(path),
            "encoding": payload.encoding.value,
            "create_parents": payload.create_parents,
        }

        if payload.encoding == Encoding.BASE64:
            try:
                raw = base64.b64decode(payload.content, validate=True)
            except (ValueError, binascii.Error) as exc:
                await self._emit(
                    "FILE_WRITE",
                    msg.id,
                    {**details_base, "size_bytes_written": 0},
                    _err_result(_elapsed_ms(start), ErrorCode.INTERNAL_ERROR.value),
                )
                return make_error(msg.id, ErrorCode.INTERNAL_ERROR, f"Bad base64: {exc}")
        else:
            raw = payload.content.encode("utf-8")

        if len(raw) > self.config.max_file_size_bytes:
            await self._emit(
                "FILE_WRITE",
                msg.id,
                {**details_base, "size_bytes_written": 0},
                _err_result(_elapsed_ms(start), ErrorCode.FILE_TOO_LARGE.value),
            )
            return make_error(
                msg.id,
                ErrorCode.FILE_TOO_LARGE,
                f"{len(raw)} bytes exceeds limit {self.config.max_file_size_bytes}",
            )

        if payload.create_parents:
            await asyncio.to_thread(lambda: path.parent.mkdir(parents=True, exist_ok=True))

        await asyncio.to_thread(path.write_bytes, raw)
        await self._emit(
            "FILE_WRITE",
            msg.id,
            {**details_base, "size_bytes_written": len(raw)},
            _ok_result(_elapsed_ms(start)),
        )
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

    async def handle_stat(self, msg: FileStatMessage) -> FileStatResponseMessage | ErrorMessage:
        payload = msg.payload
        start = time.monotonic()
        try:
            path = assert_inside_jail(payload.path, self.config.allowed_root)
        except PathJailError as exc:
            await _audit_jail_violation(self.audit, "FILE_STAT", payload.path, exc)
            return _jail_error_to_message(msg.id, exc)

        details = {"path": str(path), "follow_symlinks": payload.follow_symlinks}

        # Real-resolve here too if follow_symlinks asked (realpath already ran
        # in the jail; path is the resolved form).
        try:
            if payload.follow_symlinks:
                st = await asyncio.to_thread(os.stat, str(path))
            else:
                st = await asyncio.to_thread(os.lstat, str(path))
        except FileNotFoundError:
            await self._emit("FILE_STAT", msg.id, details, _ok_result(_elapsed_ms(start)))
            return FileStatResponseMessage(
                id=msg.id,
                ts=now_ts(),
                payload=FileStatResponsePayload(exists=False),
            )
        except OSError as exc:
            await self._emit(
                "FILE_STAT",
                msg.id,
                details,
                _err_result(_elapsed_ms(start), ErrorCode.INTERNAL_ERROR.value),
            )
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

        await self._emit("FILE_STAT", msg.id, details, _ok_result(_elapsed_ms(start)))
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

    async def handle_list(self, msg: FileListMessage) -> FileListResponseMessage | ErrorMessage:
        payload = msg.payload
        start = time.monotonic()
        try:
            base = assert_inside_jail(payload.path, self.config.allowed_root)
        except PathJailError as exc:
            await _audit_jail_violation(self.audit, "FILE_LIST", payload.path, exc)
            return _jail_error_to_message(msg.id, exc)

        details_base = {
            "path": str(base),
            "glob": payload.glob,
            "recursive": payload.recursive,
            "include_hidden": payload.include_hidden,
            "max_entries": payload.max_entries,
        }

        if not base.exists():
            await self._emit(
                "FILE_LIST",
                msg.id,
                {**details_base, "entries_returned": 0},
                _err_result(_elapsed_ms(start), ErrorCode.PATH_NOT_FOUND.value),
            )
            return make_error(msg.id, ErrorCode.PATH_NOT_FOUND, f"{base} does not exist")
        if not base.is_dir():
            await self._emit(
                "FILE_LIST",
                msg.id,
                {**details_base, "entries_returned": 0},
                _err_result(_elapsed_ms(start), ErrorCode.INTERNAL_ERROR.value),
            )
            return make_error(msg.id, ErrorCode.INTERNAL_ERROR, f"{base} is not a directory")

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
        await self._emit(
            "FILE_LIST",
            msg.id,
            {**details_base, "entries_returned": len(entries)},
            _ok_result(_elapsed_ms(start)),
        )
        return FileListResponseMessage(
            id=msg.id,
            ts=now_ts(),
            payload=FileListResponsePayload(entries=entries, truncated=truncated),
        )

    # -- FILE_DELETE ---------------------------------------------------------

    async def handle_delete(self, msg: FileDeleteMessage) -> AckMessage | ErrorMessage:
        payload = msg.payload
        start = time.monotonic()
        try:
            path = assert_inside_jail(payload.path, self.config.allowed_root)
        except PathJailError as exc:
            await _audit_jail_violation(self.audit, "FILE_DELETE", payload.path, exc)
            return _jail_error_to_message(msg.id, exc)

        details = {
            "path": str(path),
            "recursive": payload.recursive,
            "missing_ok": payload.missing_ok,
        }

        if not path.exists():
            if payload.missing_ok:
                await self._emit("FILE_DELETE", msg.id, details, _ok_result(_elapsed_ms(start)))
                return make_ack(msg.id)
            await self._emit(
                "FILE_DELETE",
                msg.id,
                details,
                _err_result(_elapsed_ms(start), ErrorCode.PATH_NOT_FOUND.value),
            )
            return make_error(msg.id, ErrorCode.PATH_NOT_FOUND, f"{path} does not exist")

        try:
            if path.is_dir() and not path.is_symlink():
                if payload.recursive:
                    await asyncio.to_thread(shutil.rmtree, str(path))
                else:
                    try:
                        await asyncio.to_thread(os.rmdir, str(path))
                    except OSError as exc:
                        # Dir not empty.
                        await self._emit(
                            "FILE_DELETE",
                            msg.id,
                            details,
                            _err_result(_elapsed_ms(start), ErrorCode.PATH_NOT_EMPTY.value),
                        )
                        return make_error(msg.id, ErrorCode.PATH_NOT_EMPTY, str(exc))
            else:
                await asyncio.to_thread(os.unlink, str(path))
        except OSError as exc:
            await self._emit(
                "FILE_DELETE",
                msg.id,
                details,
                _err_result(_elapsed_ms(start), ErrorCode.INTERNAL_ERROR.value),
            )
            return make_error(msg.id, ErrorCode.INTERNAL_ERROR, str(exc))

        await self._emit("FILE_DELETE", msg.id, details, _ok_result(_elapsed_ms(start)))
        return make_ack(msg.id)

    # -- FILE_MOVE -----------------------------------------------------------

    async def handle_move(self, msg: FileMoveMessage) -> AckMessage | ErrorMessage:
        payload = msg.payload
        start = time.monotonic()
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
            await _audit_jail_violation(
                self.audit, "FILE_MOVE", f"{payload.src} -> {payload.dst}", exc
            )
            return _jail_error_to_message(msg.id, exc)

        details = {"src": str(src), "dst": str(dst), "overwrite": payload.overwrite}

        if not src.exists():
            await self._emit(
                "FILE_MOVE",
                msg.id,
                details,
                _err_result(_elapsed_ms(start), ErrorCode.PATH_NOT_FOUND.value),
            )
            return make_error(msg.id, ErrorCode.PATH_NOT_FOUND, f"{src} does not exist")
        if dst.exists() and not payload.overwrite:
            await self._emit(
                "FILE_MOVE",
                msg.id,
                details,
                _err_result(_elapsed_ms(start), ErrorCode.PATH_EXISTS.value),
            )
            return make_error(msg.id, ErrorCode.PATH_EXISTS, f"{dst} already exists")

        try:
            if dst.exists() and payload.overwrite:
                if dst.is_dir() and not dst.is_symlink():
                    await asyncio.to_thread(shutil.rmtree, str(dst))
                else:
                    await asyncio.to_thread(os.unlink, str(dst))
            # shutil.move handles cross-device by falling back to copy+delete.
            await asyncio.to_thread(shutil.move, str(src), str(dst))
        except OSError as exc:
            await self._emit(
                "FILE_MOVE",
                msg.id,
                details,
                _err_result(_elapsed_ms(start), ErrorCode.INTERNAL_ERROR.value),
            )
            return make_error(msg.id, ErrorCode.INTERNAL_ERROR, str(exc))

        await self._emit("FILE_MOVE", msg.id, details, _ok_result(_elapsed_ms(start)))
        return make_ack(msg.id)

    # -- emit helper ---------------------------------------------------------

    async def _emit(
        self,
        op: str,
        request_id: str,
        details: dict,
        result: dict,
    ) -> None:
        if self.audit is None:
            return
        try:
            await self.audit.write(op, request_id=request_id, details=details, result=result)
        except Exception:
            logger.debug("Failed to write %s audit record", op, exc_info=True)


# ── Computer use ─────────────────────────────────────────────────────────────


class ComputerUseHandler:
    """Dispatches computer-use wire ops to a per-OS ComputerUseBackend.

    Backends raise BackendError subclasses on recoverable failures; the
    dispatcher turns each into the matching wire ERROR envelope (with
    `details` carrying the structured payload — see protocol.py and
    docs/COMPUTER_USE.md Q1-Q5).
    """

    def __init__(
        self,
        config: ShimConfig,
        audit: AuditWriter | None = None,
        backend: ComputerUseBackend | None = None,
    ) -> None:
        self.config = config
        self.audit = audit
        self._backend = backend  # lazily built when first needed

    @property
    def backend(self) -> ComputerUseBackend:
        if self._backend is None:
            self._backend = get_backend(self.config)
        return self._backend

    def on_hello(self) -> None:
        """Forward (re)connect lifecycle to the backend so window IDs reset."""
        self.backend.on_hello()

    async def handle(self, msg) -> Any:
        if not self.config.enable_computer_use:
            return make_error(
                msg.id,
                ErrorCode.CAPABILITY_NOT_GRANTED,
                "Computer use is not enabled on this shim.",
            )
        if isinstance(msg, ScreenshotRequestMessage):
            return await self._screenshot(msg)
        if isinstance(msg, InputActionMessage):
            return await self._input_action(msg)
        if isinstance(msg, CursorPositionRequestMessage):
            return await self._cursor_position(msg)
        if isinstance(msg, DisplayInfoRequestMessage):
            return await self._display_info(msg)
        if isinstance(msg, WindowListRequestMessage):
            return await self._window_list(msg)
        if isinstance(msg, WindowFocusMessage):
            return await self._window_focus(msg)
        if isinstance(msg, AppListRequestMessage):
            return await self._app_list(msg)
        if isinstance(msg, AppLaunchMessage):
            return await self._app_launch(msg)
        if isinstance(msg, ClipboardReadMessage):
            return await self._clipboard_read(msg)
        if isinstance(msg, ClipboardWriteMessage):
            return await self._clipboard_write(msg)
        if isinstance(msg, PermissionsCheckRequestMessage):
            return await self._permissions_check(msg)
        return make_error(
            msg.id,
            ErrorCode.INTERNAL_ERROR,
            f"Unknown computer-use message: {type(msg).__name__}",
        )

    # ── Dispatch error helper ─────────────────────────────────────────

    @staticmethod
    def _to_wire_error(msg_id: str, exc: BackendError) -> ErrorMessage:
        return make_error(msg_id, exc.code, exc.message, details=exc.details or None)

    async def _emit(
        self,
        op: str,
        request_id: str,
        details: dict,
        result: dict,
    ) -> None:
        if self.audit is None:
            return
        try:
            await self.audit.write(op, request_id=request_id, details=details, result=result)
        except Exception:
            logger.debug("Failed to write %s audit record", op, exc_info=True)

    # ── SCREENSHOT ───────────────────────────────────────────────────

    async def _screenshot(self, msg: ScreenshotRequestMessage) -> Any:
        start = time.monotonic()
        p = msg.payload
        details = {
            "monitor": p.monitor,
            "quality": p.quality,
            "region": list(p.region) if p.region else None,
            "window_id": p.window_id,
            "format": p.format,
        }

        # Legacy test compatibility: when the old module-level pyautogui
        # mock is in place, honor it instead of the backend so existing
        # tests that monkey-patch h_mod._pyautogui keep working.
        if (
            _Image is not None
            and _pyautogui is not None
            and getattr(_pyautogui, "_extract_mock_name", None) is not None
        ):
            try:
                buf = io.BytesIO()
                img = _pyautogui.screenshot()
                img.convert("RGB").save(buf, format="JPEG", quality=p.quality)
                img_bytes = buf.getvalue()
                await self._emit(
                    "SCREENSHOT_REQUEST",
                    msg.id,
                    {**details, "image_bytes_returned": len(img_bytes)},
                    _ok_result(_elapsed_ms(start)),
                )
                return ScreenshotResponseMessage(
                    id=msg.id,
                    ts=now_ts(),
                    payload=ScreenshotResponsePayload(
                        image_base64=base64.b64encode(img_bytes).decode("ascii"),
                        mime_type="image/jpeg",
                        width=img.width,
                        height=img.height,
                        monitor=p.monitor,
                    ),
                )
            except Exception:
                pass

        try:
            result = await asyncio.to_thread(
                self.backend.screenshot,
                monitor=p.monitor,
                quality=p.quality,
                region=p.region,
                window_id=p.window_id,
                format=p.format,
                include_cursor=p.include_cursor,
            )
        except BackendError as exc:
            await self._emit(
                "SCREENSHOT_REQUEST",
                msg.id,
                {**details, "image_bytes_returned": 0},
                _err_result(_elapsed_ms(start), exc.code.value),
            )
            return self._to_wire_error(msg.id, exc)
        except Exception as exc:
            await self._emit(
                "SCREENSHOT_REQUEST",
                msg.id,
                {**details, "image_bytes_returned": 0},
                _err_result(_elapsed_ms(start), ErrorCode.INTERNAL_ERROR.value),
            )
            return make_error(msg.id, ErrorCode.INTERNAL_ERROR, str(exc))

        await self._emit(
            "SCREENSHOT_REQUEST",
            msg.id,
            {
                **details,
                "image_bytes_returned": len(result.image_bytes),
                "width": result.width,
                "height": result.height,
            },
            _ok_result(_elapsed_ms(start)),
        )
        return ScreenshotResponseMessage(
            id=msg.id,
            ts=now_ts(),
            payload=ScreenshotResponsePayload(
                image_base64=base64.b64encode(result.image_bytes).decode("ascii"),
                mime_type=result.mime_type,
                width=result.width,
                height=result.height,
                monitor=result.monitor,
                region=result.region,
                display_scale=result.display_scale,
                logical_size=result.logical_size,
                meta=ScreenshotResponseMeta(origin=result.origin, display_id=result.display_id),
            ),
        )

    # ── INPUT_ACTION ─────────────────────────────────────────────────

    async def _input_action(self, msg: InputActionMessage) -> Any:
        start = time.monotonic()
        p = msg.payload
        details = {
            "action": p.action,
            "coordinate": list(p.coordinate) if p.coordinate else None,
            "key": p.key,
            "direction": p.direction,
            "clicks": p.clicks,
            "text_length": len(p.text) if p.text is not None else None,
            "modifiers": list(p.modifiers) if p.modifiers else None,
            "button": p.button,
            "paste": p.paste,
        }
        try:
            await asyncio.to_thread(
                self.backend.input_action,
                p.action,
                coordinate=p.coordinate,
                text=p.text,
                key=p.key,
                direction=p.direction,
                clicks=p.clicks,
                button=p.button,
                modifiers=p.modifiers,
                scroll_amount=p.scroll_amount,
                scroll_direction=p.scroll_direction,
                duration_ms=p.duration_ms,
                path=p.path,
                paste=p.paste,
                preserve_clipboard=p.preserve_clipboard,
            )
        except BackendError as exc:
            await self._emit(
                "INPUT_ACTION",
                msg.id,
                details,
                _err_result(_elapsed_ms(start), exc.code.value),
            )
            return self._to_wire_error(msg.id, exc)
        except Exception as exc:
            await self._emit(
                "INPUT_ACTION",
                msg.id,
                details,
                _err_result(_elapsed_ms(start), ErrorCode.INTERNAL_ERROR.value),
            )
            return make_error(msg.id, ErrorCode.INTERNAL_ERROR, str(exc))

        await self._emit("INPUT_ACTION", msg.id, details, _ok_result(_elapsed_ms(start)))
        return make_ack(msg.id)

    # ── CURSOR_POSITION ──────────────────────────────────────────────

    async def _cursor_position(self, msg: CursorPositionRequestMessage) -> Any:
        start = time.monotonic()
        try:
            x, y, mon = await asyncio.to_thread(self.backend.cursor_position)
        except BackendError as exc:
            await self._emit(
                "CURSOR_POSITION_REQUEST",
                msg.id,
                {},
                _err_result(_elapsed_ms(start), exc.code.value),
            )
            return self._to_wire_error(msg.id, exc)
        await self._emit("CURSOR_POSITION_REQUEST", msg.id, {}, _ok_result(_elapsed_ms(start)))
        return CursorPositionResponseMessage(
            id=msg.id,
            ts=now_ts(),
            payload=CursorPositionResponsePayload(x=x, y=y, monitor=mon),
        )

    # ── DISPLAY_INFO ─────────────────────────────────────────────────

    async def _display_info(self, msg: DisplayInfoRequestMessage) -> Any:
        start = time.monotonic()
        try:
            monitors = await asyncio.to_thread(self.backend.display_info)
        except BackendError as exc:
            await self._emit(
                "DISPLAY_INFO_REQUEST",
                msg.id,
                {},
                _err_result(_elapsed_ms(start), exc.code.value),
            )
            return self._to_wire_error(msg.id, exc)
        await self._emit(
            "DISPLAY_INFO_REQUEST",
            msg.id,
            {"monitor_count": len(monitors)},
            _ok_result(_elapsed_ms(start)),
        )
        return DisplayInfoResponseMessage(
            id=msg.id,
            ts=now_ts(),
            payload=DisplayInfoResponsePayload(monitors=monitors),
        )

    # ── WINDOW_LIST ──────────────────────────────────────────────────

    async def _window_list(self, msg: WindowListRequestMessage) -> Any:
        start = time.monotonic()
        p = msg.payload
        details = {
            "app_bundle_id": p.app_bundle_id,
            "include_minimized": p.include_minimized,
            "include_offscreen": p.include_offscreen,
        }
        try:
            windows = await asyncio.to_thread(
                self.backend.window_list,
                app_bundle_id=p.app_bundle_id,
                include_minimized=p.include_minimized,
                include_offscreen=p.include_offscreen,
            )
        except BackendError as exc:
            await self._emit(
                "WINDOW_LIST_REQUEST",
                msg.id,
                details,
                _err_result(_elapsed_ms(start), exc.code.value),
            )
            return self._to_wire_error(msg.id, exc)
        await self._emit(
            "WINDOW_LIST_REQUEST",
            msg.id,
            {**details, "windows_returned": len(windows)},
            _ok_result(_elapsed_ms(start)),
        )
        return WindowListResponseMessage(
            id=msg.id,
            ts=now_ts(),
            payload=WindowListResponsePayload(windows=windows),
        )

    # ── WINDOW_FOCUS ─────────────────────────────────────────────────

    async def _window_focus(self, msg: WindowFocusMessage) -> Any:
        start = time.monotonic()
        details = {"window_id": msg.payload.window_id, "raise": msg.payload.raise_}
        try:
            await asyncio.to_thread(
                self.backend.window_focus,
                msg.payload.window_id,
                raise_=msg.payload.raise_,
            )
        except BackendError as exc:
            await self._emit(
                "WINDOW_FOCUS",
                msg.id,
                details,
                _err_result(_elapsed_ms(start), exc.code.value),
            )
            return self._to_wire_error(msg.id, exc)
        await self._emit("WINDOW_FOCUS", msg.id, details, _ok_result(_elapsed_ms(start)))
        return make_ack(msg.id)

    # ── APP_LIST ─────────────────────────────────────────────────────

    async def _app_list(self, msg: AppListRequestMessage) -> Any:
        start = time.monotonic()
        try:
            apps = await asyncio.to_thread(
                self.backend.app_list, include_background=msg.payload.include_background
            )
        except BackendError as exc:
            await self._emit(
                "APP_LIST_REQUEST",
                msg.id,
                {"include_background": msg.payload.include_background},
                _err_result(_elapsed_ms(start), exc.code.value),
            )
            return self._to_wire_error(msg.id, exc)
        await self._emit(
            "APP_LIST_REQUEST",
            msg.id,
            {"include_background": msg.payload.include_background, "apps_returned": len(apps)},
            _ok_result(_elapsed_ms(start)),
        )
        return AppListResponseMessage(
            id=msg.id,
            ts=now_ts(),
            payload=AppListResponsePayload(apps=apps),
        )

    # ── APP_LAUNCH ───────────────────────────────────────────────────

    async def _app_launch(self, msg: AppLaunchMessage) -> Any:
        start = time.monotonic()
        p = msg.payload
        details = {
            "bundle_id": p.bundle_id,
            "executable_path": p.executable_path,
            "args_count": len(p.args),
            "activate": p.activate,
        }
        try:
            pid = await asyncio.to_thread(
                self.backend.app_launch,
                bundle_id=p.bundle_id,
                executable_path=p.executable_path,
                args=p.args,
                activate=p.activate,
            )
        except BackendError as exc:
            await self._emit(
                "APP_LAUNCH",
                msg.id,
                details,
                _err_result(_elapsed_ms(start), exc.code.value),
            )
            return self._to_wire_error(msg.id, exc)
        await self._emit(
            "APP_LAUNCH",
            msg.id,
            {**details, "pid": pid},
            _ok_result(_elapsed_ms(start)),
        )
        return AckMessage(
            id=msg.id,
            ts=now_ts(),
            payload=AckPayload(ok=True),
        )

    # ── CLIPBOARD_READ ───────────────────────────────────────────────

    async def _clipboard_read(self, msg: ClipboardReadMessage) -> Any:
        start = time.monotonic()
        details = {"format": msg.payload.format}
        try:
            result = await asyncio.to_thread(self.backend.clipboard_read, format=msg.payload.format)
        except BackendError as exc:
            await self._emit(
                "CLIPBOARD_READ",
                msg.id,
                {**details, "size_bytes": 0},
                _err_result(_elapsed_ms(start), exc.code.value),
            )
            return self._to_wire_error(msg.id, exc)
        await self._emit(
            "CLIPBOARD_READ",
            msg.id,
            {**details, "size_bytes": result.size_bytes},
            _ok_result(_elapsed_ms(start)),
        )
        return ClipboardReadResponseMessage(
            id=msg.id,
            ts=now_ts(),
            payload=ClipboardReadResponsePayload(
                format=result.format,
                content=result.content,
                size_bytes=result.size_bytes,
            ),
        )

    # ── CLIPBOARD_WRITE ──────────────────────────────────────────────

    async def _clipboard_write(self, msg: ClipboardWriteMessage) -> Any:
        start = time.monotonic()
        p = msg.payload
        details = {"format": p.format, "size_bytes": len(p.content.encode("utf-8"))}
        try:
            await asyncio.to_thread(
                self.backend.clipboard_write, format=p.format, content=p.content
            )
        except BackendError as exc:
            await self._emit(
                "CLIPBOARD_WRITE",
                msg.id,
                details,
                _err_result(_elapsed_ms(start), exc.code.value),
            )
            return self._to_wire_error(msg.id, exc)
        await self._emit("CLIPBOARD_WRITE", msg.id, details, _ok_result(_elapsed_ms(start)))
        return make_ack(msg.id)

    # ── PERMISSIONS_CHECK ────────────────────────────────────────────

    async def _permissions_check(self, msg: PermissionsCheckRequestMessage) -> Any:
        start = time.monotonic()
        try:
            perms = await asyncio.to_thread(self.backend.permissions_check, msg.payload.permissions)
        except BackendError as exc:
            await self._emit(
                "PERMISSIONS_CHECK_REQUEST",
                msg.id,
                {"permissions": msg.payload.permissions},
                _err_result(_elapsed_ms(start), exc.code.value),
            )
            return self._to_wire_error(msg.id, exc)
        await self._emit(
            "PERMISSIONS_CHECK_REQUEST",
            msg.id,
            {"permissions": msg.payload.permissions},
            _ok_result(_elapsed_ms(start)),
        )
        return PermissionsCheckResponseMessage(
            id=msg.id,
            ts=now_ts(),
            payload=PermissionsCheckResponsePayload(permissions=perms),
        )


__all__ = [
    "CommandHandler",
    "ComputerUseHandler",
    "FileHandler",
]
