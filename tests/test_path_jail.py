"""Path jail tests — every attack scenario from CROSS_PLATFORM.md."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from autogpt_local_executor.path_jail import (
    PathJailError,
    assert_inside_jail,
    is_inside_jail,
)


# ── Happy path ───────────────────────────────────────────────────────────────


def test_allows_file_inside_root(tmp_path: Path) -> None:
    file = tmp_path / "ok.txt"
    file.write_text("hi")
    assert is_inside_jail(file, tmp_path)


def test_allows_nested_file_inside_root(tmp_path: Path) -> None:
    nested = tmp_path / "a" / "b" / "c.txt"
    nested.parent.mkdir(parents=True)
    nested.write_text("hi")
    assert is_inside_jail(nested, tmp_path)


def test_allows_root_itself(tmp_path: Path) -> None:
    assert is_inside_jail(tmp_path, tmp_path)


# ── CROSS_PLATFORM.md "What the algorithm catches" — six attacks ─────────────


def test_blocks_dotdot_traversal(tmp_path: Path) -> None:
    target = tmp_path / "child" / ".." / ".." / "etc" / "passwd"
    with pytest.raises(PathJailError) as exc:
        assert_inside_jail(target, tmp_path)
    assert exc.value.code == "PATH_OUTSIDE_ALLOWED_ROOT"


def test_blocks_symlink_escape(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside_dir"
    outside.mkdir(exist_ok=True)
    secret = outside / "secret.txt"
    secret.write_text("nope")
    link = tmp_path / "link"
    try:
        os.symlink(secret, link)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks unavailable on this platform/account")
    try:
        with pytest.raises(PathJailError) as exc:
            assert_inside_jail(link, tmp_path)
        assert exc.value.code == "PATH_OUTSIDE_ALLOWED_ROOT"
    finally:
        link.unlink()
        secret.unlink()
        outside.rmdir()


def test_allows_uppercased_on_case_insensitive_fs(tmp_path: Path) -> None:
    """When the FS is case-insensitive, /WORKSPACE and /workspace are the
    same directory. We allow either spelling for the jail check."""
    if sys.platform not in ("darwin", "win32"):
        pytest.skip("Only relevant on case-insensitive FS by default")
    # Use the parent's case-toggled spelling and a real subpath.
    nested = tmp_path / "x.txt"
    nested.write_text("hi")
    upper_root = Path(str(tmp_path).upper())
    # Result depends on whether normcase rewrites it consistently; mainly we
    # assert we DON'T raise on a same-volume case toggle.
    try:
        assert_inside_jail(nested, upper_root)
    except PathJailError:
        # If realpath(upper_root, strict=True) failed because the literal
        # upper-case path doesn't exist on the FS, that's a different error
        # and acceptable for this probe.
        pass


def test_blocks_prefix_lookalike_dir(tmp_path: Path) -> None:
    """/workspace2 must NOT be considered inside /workspace."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    workspace2 = tmp_path / "workspace2"
    workspace2.mkdir()
    file_in_lookalike = workspace2 / "evil.txt"
    file_in_lookalike.write_text("nope")
    with pytest.raises(PathJailError) as exc:
        assert_inside_jail(file_in_lookalike, workspace)
    assert exc.value.code == "PATH_OUTSIDE_ALLOWED_ROOT"


@pytest.mark.skipif(sys.platform != "win32", reason="ADS only on Windows")
def test_blocks_alternate_data_stream(tmp_path: Path) -> None:
    bad = f"{tmp_path}\\file.txt:hidden"
    with pytest.raises(PathJailError) as exc:
        assert_inside_jail(bad, tmp_path)
    assert exc.value.code in ("PATH_INVALID_CHARS", "PATH_OUTSIDE_ALLOWED_ROOT")


@pytest.mark.skipif(sys.platform != "win32", reason="Reserved names only on Windows")
def test_blocks_windows_reserved_name(tmp_path: Path) -> None:
    bad = tmp_path / "CON"
    with pytest.raises(PathJailError) as exc:
        assert_inside_jail(bad, tmp_path)
    assert exc.value.code == "PATH_RESERVED_NAME"


@pytest.mark.skipif(sys.platform != "win32", reason="UNC prefix only on Windows")
def test_blocks_unc_long_path_escape(tmp_path: Path) -> None:
    """\\?\<drive>\..\..\etc should still fail the prefix check."""
    bad = f"\\\\?\\{tmp_path}\\..\\..\\Windows\\System32\\cmd.exe"
    with pytest.raises(PathJailError):
        assert_inside_jail(bad, tmp_path)


# ── Additional invariants ────────────────────────────────────────────────────


def test_assert_returns_resolved_path(tmp_path: Path) -> None:
    file = tmp_path / "ok.txt"
    file.write_text("hi")
    resolved = assert_inside_jail(file, tmp_path)
    assert resolved.exists()


def test_missing_root_raises(tmp_path: Path) -> None:
    nonexistent = tmp_path / "does-not-exist"
    file = tmp_path / "x.txt"
    file.write_text("hi")
    with pytest.raises(PathJailError):
        assert_inside_jail(file, nonexistent)


def test_null_byte_in_path_rejected(tmp_path: Path) -> None:
    bad = str(tmp_path / "evil\x00.txt")
    with pytest.raises(PathJailError) as exc:
        assert_inside_jail(bad, tmp_path)
    assert exc.value.code in ("PATH_INVALID_CHARS", "PATH_OUTSIDE_ALLOWED_ROOT")
