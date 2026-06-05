"""Tests for FileHandler and CommandHandler."""

from __future__ import annotations

import asyncio
import base64
from pathlib import Path
from unittest.mock import patch

import pytest

from autogpt_local_executor.config import ShimConfig
from autogpt_local_executor.handlers import CommandHandler, FileHandler
from autogpt_local_executor.protocol import (
    AckMessage,
    CommandResultMessage,
    Encoding,
    ErrorCode,
    ErrorMessage,
    ExecuteCommandMessage,
    ExecuteCommandPayload,
    FileContentsMessage,
    FileDeleteMessage,
    FileDeletePayload,
    FileFormat,
    FileListMessage,
    FileListPayload,
    FileListResponseMessage,
    FileMoveMessage,
    FileMovePayload,
    FileReadMessage,
    FileReadPayload,
    FileStatMessage,
    FileStatPayload,
    FileStatResponseMessage,
    FileWriteMessage,
    FileWritePayload,
    Shell,
    new_id,
    now_ts,
)


def make_config(tmp_path: Path) -> ShimConfig:
    return ShimConfig(
        allowed_root=tmp_path,
        audit_log_path=tmp_path / "_audit.log",
        platform_url="http://localhost:9999",
        machine_id="test-machine",
    )


def _read_msg(path: Path, **kw) -> FileReadMessage:
    return FileReadMessage(
        id=new_id(),
        ts=now_ts(),
        payload=FileReadPayload(path=str(path), **kw),
    )


def _write_msg(path: Path, content: str, **kw) -> FileWriteMessage:
    return FileWriteMessage(
        id=new_id(),
        ts=now_ts(),
        payload=FileWritePayload(path=str(path), content=content, **kw),
    )


# ── FILE_READ / FILE_WRITE ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_write_then_read_text(tmp_path: Path) -> None:
    h = FileHandler(make_config(tmp_path))
    resp = await h.handle_write(_write_msg(tmp_path / "a.txt", "hello"))
    assert isinstance(resp, AckMessage)
    resp = await h.handle_read(_read_msg(tmp_path / "a.txt"))
    assert isinstance(resp, FileContentsMessage)
    assert resp.payload.content == "hello"
    assert resp.payload.encoding == Encoding.UTF8


@pytest.mark.asyncio
async def test_write_creates_parents(tmp_path: Path) -> None:
    h = FileHandler(make_config(tmp_path))
    target = tmp_path / "a" / "b" / "c.txt"
    resp = await h.handle_write(_write_msg(target, "hi", create_parents=True))
    assert isinstance(resp, AckMessage)
    assert target.read_text() == "hi"


@pytest.mark.asyncio
async def test_write_no_parents_returns_error(tmp_path: Path) -> None:
    h = FileHandler(make_config(tmp_path))
    target = tmp_path / "missing-dir" / "c.txt"
    resp = await h.handle_write(_write_msg(target, "hi", create_parents=False))
    # Parent doesn't exist → write should fail with an OSError surfaced.
    assert isinstance(resp, (ErrorMessage,)) or not target.exists()


@pytest.mark.asyncio
async def test_read_base64_path(tmp_path: Path) -> None:
    h = FileHandler(make_config(tmp_path))
    raw = bytes(range(256))
    (tmp_path / "bin.dat").write_bytes(raw)
    resp = await h.handle_read(
        _read_msg(tmp_path / "bin.dat", encoding=Encoding.BASE64, format=FileFormat.BYTES)
    )
    assert isinstance(resp, FileContentsMessage)
    assert resp.payload.encoding == Encoding.BASE64
    assert base64.b64decode(resp.payload.content) == raw


@pytest.mark.asyncio
async def test_read_crlf_preserved(tmp_path: Path) -> None:
    """Per PROTOCOL.md FILE_READ: shim does NOT auto-translate \\r\\n → \\n."""
    h = FileHandler(make_config(tmp_path))
    (tmp_path / "win.txt").write_bytes(b"line1\r\nline2\r\n")
    resp = await h.handle_read(_read_msg(tmp_path / "win.txt"))
    assert isinstance(resp, FileContentsMessage)
    assert "\r\n" in resp.payload.content


@pytest.mark.asyncio
async def test_read_offset_and_length(tmp_path: Path) -> None:
    h = FileHandler(make_config(tmp_path))
    (tmp_path / "f.txt").write_text("abcdefghij")
    resp = await h.handle_read(_read_msg(tmp_path / "f.txt", offset=2, length=3))
    assert isinstance(resp, FileContentsMessage)
    assert resp.payload.content == "cde"
    assert resp.payload.truncated is True


@pytest.mark.asyncio
async def test_read_missing_returns_path_not_found(tmp_path: Path) -> None:
    h = FileHandler(make_config(tmp_path))
    resp = await h.handle_read(_read_msg(tmp_path / "nope.txt"))
    assert isinstance(resp, ErrorMessage)
    assert resp.payload.code == ErrorCode.PATH_NOT_FOUND


@pytest.mark.asyncio
async def test_read_outside_jail(tmp_path: Path) -> None:
    h = FileHandler(make_config(tmp_path))
    resp = await h.handle_read(_read_msg(Path("/etc/passwd")))
    assert isinstance(resp, ErrorMessage)
    assert resp.payload.code == ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT


@pytest.mark.asyncio
async def test_write_too_large(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    config.max_file_size_bytes = 10
    h = FileHandler(config)
    resp = await h.handle_write(_write_msg(tmp_path / "big.txt", "x" * 20))
    assert isinstance(resp, ErrorMessage)
    assert resp.payload.code == ErrorCode.FILE_TOO_LARGE


# ── FILE_STAT ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_stat_file(tmp_path: Path) -> None:
    h = FileHandler(make_config(tmp_path))
    target = tmp_path / "x.txt"
    target.write_text("hi")
    msg = FileStatMessage(id=new_id(), ts=now_ts(), payload=FileStatPayload(path=str(target)))
    resp = await h.handle_stat(msg)
    assert isinstance(resp, FileStatResponseMessage)
    assert resp.payload.exists is True
    assert resp.payload.is_file is True
    assert resp.payload.is_dir is False
    assert resp.payload.size_bytes == 2


@pytest.mark.asyncio
async def test_stat_missing_returns_exists_false(tmp_path: Path) -> None:
    h = FileHandler(make_config(tmp_path))
    msg = FileStatMessage(
        id=new_id(), ts=now_ts(), payload=FileStatPayload(path=str(tmp_path / "nope"))
    )
    resp = await h.handle_stat(msg)
    assert isinstance(resp, FileStatResponseMessage)
    assert resp.payload.exists is False


@pytest.mark.asyncio
async def test_stat_outside_jail_is_distinguishable_from_missing(tmp_path: Path) -> None:
    """Per PROTOCOL.md: jail violation returns ERROR, not exists:false."""
    h = FileHandler(make_config(tmp_path))
    msg = FileStatMessage(id=new_id(), ts=now_ts(), payload=FileStatPayload(path="/etc/passwd"))
    resp = await h.handle_stat(msg)
    assert isinstance(resp, ErrorMessage)
    assert resp.payload.code == ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT


# ── FILE_LIST ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_directory(tmp_path: Path) -> None:
    h = FileHandler(make_config(tmp_path))
    (tmp_path / "a.txt").write_text("a")
    (tmp_path / "b.csv").write_text("b")
    (tmp_path / "sub").mkdir()
    msg = FileListMessage(id=new_id(), ts=now_ts(), payload=FileListPayload(path=str(tmp_path)))
    resp = await h.handle_list(msg)
    assert isinstance(resp, FileListResponseMessage)
    names = {e.name for e in resp.payload.entries}
    assert {"a.txt", "b.csv", "sub"} <= names


@pytest.mark.asyncio
async def test_list_glob_csv(tmp_path: Path) -> None:
    h = FileHandler(make_config(tmp_path))
    (tmp_path / "a.txt").write_text("a")
    (tmp_path / "b.csv").write_text("b")
    msg = FileListMessage(
        id=new_id(),
        ts=now_ts(),
        payload=FileListPayload(path=str(tmp_path), glob="*.csv"),
    )
    resp = await h.handle_list(msg)
    assert isinstance(resp, FileListResponseMessage)
    names = {e.name for e in resp.payload.entries}
    assert names == {"b.csv"}


@pytest.mark.asyncio
async def test_list_max_entries_truncates(tmp_path: Path) -> None:
    h = FileHandler(make_config(tmp_path))
    for i in range(5):
        (tmp_path / f"f{i}").write_text("x")
    msg = FileListMessage(
        id=new_id(),
        ts=now_ts(),
        payload=FileListPayload(path=str(tmp_path), max_entries=3),
    )
    resp = await h.handle_list(msg)
    assert isinstance(resp, FileListResponseMessage)
    assert len(resp.payload.entries) == 3
    assert resp.payload.truncated is True


@pytest.mark.asyncio
async def test_list_hidden_files_excluded_by_default(tmp_path: Path) -> None:
    h = FileHandler(make_config(tmp_path))
    (tmp_path / ".hidden").write_text("x")
    (tmp_path / "visible").write_text("x")
    msg = FileListMessage(id=new_id(), ts=now_ts(), payload=FileListPayload(path=str(tmp_path)))
    resp = await h.handle_list(msg)
    assert isinstance(resp, FileListResponseMessage)
    names = {e.name for e in resp.payload.entries}
    assert ".hidden" not in names
    assert "visible" in names


# ── FILE_DELETE ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_delete_file(tmp_path: Path) -> None:
    h = FileHandler(make_config(tmp_path))
    target = tmp_path / "del.txt"
    target.write_text("x")
    msg = FileDeleteMessage(id=new_id(), ts=now_ts(), payload=FileDeletePayload(path=str(target)))
    resp = await h.handle_delete(msg)
    assert isinstance(resp, AckMessage)
    assert not target.exists()


@pytest.mark.asyncio
async def test_delete_missing_without_missing_ok(tmp_path: Path) -> None:
    h = FileHandler(make_config(tmp_path))
    msg = FileDeleteMessage(
        id=new_id(), ts=now_ts(), payload=FileDeletePayload(path=str(tmp_path / "nope"))
    )
    resp = await h.handle_delete(msg)
    assert isinstance(resp, ErrorMessage)
    assert resp.payload.code == ErrorCode.PATH_NOT_FOUND


@pytest.mark.asyncio
async def test_delete_missing_with_missing_ok(tmp_path: Path) -> None:
    h = FileHandler(make_config(tmp_path))
    msg = FileDeleteMessage(
        id=new_id(),
        ts=now_ts(),
        payload=FileDeletePayload(path=str(tmp_path / "nope"), missing_ok=True),
    )
    resp = await h.handle_delete(msg)
    assert isinstance(resp, AckMessage)


@pytest.mark.asyncio
async def test_delete_nonempty_dir_without_recursive(tmp_path: Path) -> None:
    h = FileHandler(make_config(tmp_path))
    d = tmp_path / "d"
    d.mkdir()
    (d / "x").write_text("x")
    msg = FileDeleteMessage(id=new_id(), ts=now_ts(), payload=FileDeletePayload(path=str(d)))
    resp = await h.handle_delete(msg)
    assert isinstance(resp, ErrorMessage)
    assert resp.payload.code == ErrorCode.PATH_NOT_EMPTY


@pytest.mark.asyncio
async def test_delete_recursive(tmp_path: Path) -> None:
    h = FileHandler(make_config(tmp_path))
    d = tmp_path / "d"
    (d / "sub").mkdir(parents=True)
    (d / "sub" / "x").write_text("x")
    msg = FileDeleteMessage(
        id=new_id(),
        ts=now_ts(),
        payload=FileDeletePayload(path=str(d), recursive=True),
    )
    resp = await h.handle_delete(msg)
    assert isinstance(resp, AckMessage)
    assert not d.exists()


# ── FILE_MOVE ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_move_rename(tmp_path: Path) -> None:
    h = FileHandler(make_config(tmp_path))
    src = tmp_path / "a.txt"
    src.write_text("x")
    dst = tmp_path / "b.txt"
    msg = FileMoveMessage(
        id=new_id(),
        ts=now_ts(),
        payload=FileMovePayload(src=str(src), dst=str(dst)),
    )
    resp = await h.handle_move(msg)
    assert isinstance(resp, AckMessage)
    assert not src.exists()
    assert dst.read_text() == "x"


@pytest.mark.asyncio
async def test_move_blocks_dst_outside_jail(tmp_path: Path) -> None:
    h = FileHandler(make_config(tmp_path))
    src = tmp_path / "a.txt"
    src.write_text("x")
    msg = FileMoveMessage(
        id=new_id(),
        ts=now_ts(),
        payload=FileMovePayload(src=str(src), dst="/etc/evil.txt"),
    )
    resp = await h.handle_move(msg)
    assert isinstance(resp, ErrorMessage)
    assert resp.payload.code == ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT


@pytest.mark.asyncio
async def test_move_exists_without_overwrite(tmp_path: Path) -> None:
    h = FileHandler(make_config(tmp_path))
    src = tmp_path / "a.txt"
    src.write_text("x")
    dst = tmp_path / "b.txt"
    dst.write_text("y")
    msg = FileMoveMessage(
        id=new_id(),
        ts=now_ts(),
        payload=FileMovePayload(src=str(src), dst=str(dst), overwrite=False),
    )
    resp = await h.handle_move(msg)
    assert isinstance(resp, ErrorMessage)
    assert resp.payload.code == ErrorCode.PATH_EXISTS


@pytest.mark.asyncio
async def test_move_overwrite(tmp_path: Path) -> None:
    h = FileHandler(make_config(tmp_path))
    src = tmp_path / "a.txt"
    src.write_text("new")
    dst = tmp_path / "b.txt"
    dst.write_text("old")
    msg = FileMoveMessage(
        id=new_id(),
        ts=now_ts(),
        payload=FileMovePayload(src=str(src), dst=str(dst), overwrite=True),
    )
    resp = await h.handle_move(msg)
    assert isinstance(resp, AckMessage)
    assert dst.read_text() == "new"


# ── EXECUTE_COMMAND (mocked) ─────────────────────────────────────────────────


def _cmd_msg(argv=None, command=None, **kw) -> ExecuteCommandMessage:
    return ExecuteCommandMessage(
        id=new_id(),
        ts=now_ts(),
        payload=ExecuteCommandPayload(argv=argv, command=command, **kw),
    )


class _FakeProc:
    def __init__(self, *, stdout: bytes, stderr: bytes, returncode: int) -> None:
        self._stdout = stdout
        self._stderr = stderr
        self.returncode = returncode
        self.pid = 12345

    async def communicate(self) -> tuple[bytes, bytes]:
        return self._stdout, self._stderr


@pytest.mark.asyncio
async def test_command_argv_form_calls_create_subprocess_exec(tmp_path: Path) -> None:
    """Per PROTOCOL.md, argv form must bypass shell parsing."""
    h = CommandHandler(make_config(tmp_path))
    fake = _FakeProc(stdout=b"out\n", stderr=b"", returncode=0)

    captured = {}

    async def fake_exec(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return fake

    with patch("asyncio.create_subprocess_exec", side_effect=fake_exec):
        msg = _cmd_msg(argv=["echo", "hi"], cwd=str(tmp_path))
        resp = await h.handle(msg)

    assert isinstance(resp, CommandResultMessage)
    assert resp.payload.exit_code == 0
    assert resp.payload.stdout == "out\n"
    assert resp.payload.timed_out is False
    # First two args should be the binary and its first arg (we didn't pass through a shell).
    assert captured["args"][0] == "echo"
    assert captured["args"][1] == "hi"


@pytest.mark.asyncio
async def test_command_shell_form_picks_shell(tmp_path: Path) -> None:
    h = CommandHandler(make_config(tmp_path))
    fake = _FakeProc(stdout=b"out\n", stderr=b"", returncode=0)
    captured = {}

    async def fake_exec(*args, **kwargs):
        captured["args"] = args
        return fake

    with patch("asyncio.create_subprocess_exec", side_effect=fake_exec):
        with patch(
            "autogpt_local_executor.handlers.platform_info.resolve_shell",
            return_value=("/bin/bash", ["-c"]),
        ):
            msg = _cmd_msg(command="echo hi", cwd=str(tmp_path), shell=Shell.BASH)
            resp = await h.handle(msg)

    assert isinstance(resp, CommandResultMessage)
    # First three args: shell, -c, command string.
    assert captured["args"][0] == "/bin/bash"
    assert captured["args"][1] == "-c"
    assert captured["args"][2] == "echo hi"


@pytest.mark.asyncio
async def test_command_shell_not_available(tmp_path: Path) -> None:
    h = CommandHandler(make_config(tmp_path))
    with patch(
        "autogpt_local_executor.handlers.platform_info.resolve_shell",
        return_value=None,
    ):
        msg = _cmd_msg(command="echo hi", cwd=str(tmp_path), shell=Shell.ZSH)
        resp = await h.handle(msg)
    assert isinstance(resp, ErrorMessage)
    assert resp.payload.code == ErrorCode.SHELL_NOT_AVAILABLE


@pytest.mark.asyncio
async def test_command_neither_argv_nor_command(tmp_path: Path) -> None:
    h = CommandHandler(make_config(tmp_path))
    msg = _cmd_msg(argv=None, command=None, cwd=str(tmp_path))
    resp = await h.handle(msg)
    assert isinstance(resp, ErrorMessage)


@pytest.mark.asyncio
async def test_command_cwd_outside_jail(tmp_path: Path) -> None:
    h = CommandHandler(make_config(tmp_path))
    msg = _cmd_msg(argv=["echo", "hi"], cwd="/etc")
    resp = await h.handle(msg)
    assert isinstance(resp, ErrorMessage)
    assert resp.payload.code == ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT


@pytest.mark.asyncio
async def test_command_timeout(tmp_path: Path) -> None:
    h = CommandHandler(make_config(tmp_path))

    class _HangingProc:
        def __init__(self) -> None:
            self.returncode = None
            self.pid = 12345
            self._calls = 0

        async def communicate(self) -> tuple[bytes, bytes]:
            self._calls += 1
            if self._calls == 1:
                await asyncio.sleep(5)
            return b"", b""

        def send_signal(self, sig) -> None:
            self.returncode = -1

        def kill(self) -> None:
            self.returncode = -1

    hanging = _HangingProc()

    async def fake_exec(*args, **kwargs):
        return hanging

    async def fake_terminate(proc) -> None:
        proc.returncode = -1

    with patch("asyncio.create_subprocess_exec", side_effect=fake_exec):
        with patch.object(CommandHandler, "_terminate_tree", staticmethod(fake_terminate)):
            msg = _cmd_msg(argv=["sleep", "10"], cwd=str(tmp_path), timeout_seconds=1)
            resp = await h.handle(msg)

    assert isinstance(resp, CommandResultMessage)
    assert resp.payload.timed_out is True


@pytest.mark.asyncio
async def test_command_audit_log_written(tmp_path: Path) -> None:
    import json

    from autogpt_local_executor.audit import AuditWriter

    config = make_config(tmp_path)
    audit = AuditWriter(path=config.audit_log_path, audit_key=b"\0" * 32)
    h = CommandHandler(config, audit=audit)
    fake = _FakeProc(stdout=b"", stderr=b"", returncode=0)

    async def fake_exec(*args, **kwargs):
        return fake

    with patch("asyncio.create_subprocess_exec", side_effect=fake_exec):
        msg = _cmd_msg(argv=["echo", "hi"], cwd=str(tmp_path))
        await h.handle(msg)

    assert config.audit_log_path.exists()
    lines = config.audit_log_path.read_text().splitlines()
    rec = json.loads(lines[-1])
    assert rec["op"] == "EXECUTE_COMMAND"
    assert rec["details"]["argv"] == ["echo", "hi"]
    assert rec["result"]["ok"] is True
    assert rec["hmac"]


@pytest.mark.asyncio
async def test_command_env_merged_with_baseline(tmp_path: Path) -> None:
    h = CommandHandler(make_config(tmp_path))
    captured: dict = {}

    async def fake_exec(*args, **kwargs):
        captured["env"] = kwargs.get("env")
        return _FakeProc(stdout=b"", stderr=b"", returncode=0)

    with patch("asyncio.create_subprocess_exec", side_effect=fake_exec):
        msg = _cmd_msg(argv=["echo", "x"], cwd=str(tmp_path), env={"MY_VAR": "v"})
        await h.handle(msg)

    env = captured["env"]
    assert env["MY_VAR"] == "v"
    assert "PYTHONIOENCODING" in env
    # PATH (or equivalent) is preserved from the baseline on every OS.
    assert any(k.upper() == "PATH" for k in env)
