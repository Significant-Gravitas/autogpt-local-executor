"""
Path jail — the single security-critical primitive that every FILE_*
handler must call before touching the filesystem.

The full algorithm is in docs/CROSS_PLATFORM.md "Path Jail Strategy".
This module is a faithful implementation of it; if you change behavior
here, update the doc first.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path, PurePath

from .platform_info import detect_platform, is_case_insensitive_fs

# Windows reserved device names (case-insensitive, with or without extension).
# Per docs/CROSS_PLATFORM.md → "Reserved filenames" row.
_WINDOWS_RESERVED = {
    "con",
    "prn",
    "aux",
    "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}

# Invalid Windows path chars (per the same table).
_WINDOWS_INVALID_CHARS = re.compile(r'[<>"|?*\x00-\x1f]')

# Per-OS PATH_MAX limits, per CROSS_PLATFORM.md.
_PATH_MAX = {
    "darwin": 1024,
    "linux": 4096,
    "wsl2": 4096,
    "windows": 32767,
}


class PathJailError(Exception):
    """Raised when a path violates the jail.

    `code` is one of the ErrorCode enum values for direct mapping to the
    wire ERROR.code field.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _is_reserved_name(p: PurePath) -> bool:
    if sys.platform != "win32":
        # Only Windows treats these as reserved.
        return False
    # Check every part — reserved names are reserved at every depth.
    for part in p.parts:
        stem = part.split(".", 1)[0].lower() if "." in part else part.lower()
        if stem in _WINDOWS_RESERVED:
            return True
    return False


def _has_alternate_data_stream(raw: str) -> bool:
    """NTFS Alternate Data Streams use `:` after the drive letter.

    On Windows, `C:\\foo\\bar.txt:hidden` is an ADS reference. We reject
    any `:` outside the drive prefix (positions 0-1).
    """
    if sys.platform != "win32":
        return False
    # Strip drive prefix (e.g., "C:") so we don't false-positive on it.
    rest = raw[2:] if len(raw) >= 2 and raw[1] == ":" else raw
    # Also strip UNC `\\?\` prefix.
    if rest.startswith("\\\\?\\"):
        rest = rest[4:]
        # And the next drive letter colon.
        if len(rest) >= 2 and rest[1] == ":":
            rest = rest[2:]
    return ":" in rest


def _has_invalid_chars(raw: str) -> bool:
    if sys.platform != "win32":
        # POSIX: only \x00 is illegal in paths.
        return "\x00" in raw
    # Strip drive letter colon before checking.
    rest = raw[2:] if len(raw) >= 2 and raw[1] == ":" else raw
    return bool(_WINDOWS_INVALID_CHARS.search(rest))


def _exceeds_path_max(raw: str) -> bool:
    limit = _PATH_MAX.get(detect_platform())
    if limit is None:
        return False
    return len(raw) > limit


def _normalize_for_compare(path: str) -> str:
    """Case-fold via os.path.normcase when the FS is case-insensitive."""
    if is_case_insensitive_fs(path):
        return os.path.normcase(path)
    return path


def is_inside_jail(requested_path: str | os.PathLike[str], allowed_root: str | os.PathLike[str]) -> bool:
    """Return True iff `requested_path` resolves inside `allowed_root`.

    Faithful implementation of the algorithm in CROSS_PLATFORM.md "Path
    Jail Strategy". Returns False on any check failure (reserved name,
    ADS, invalid chars, path-max exceeded, realpath OSError, or outside
    the jail). For diagnosable errors, use `assert_inside_jail()`.
    """
    try:
        assert_inside_jail(requested_path, allowed_root)
        return True
    except PathJailError:
        return False


def assert_inside_jail(
    requested_path: str | os.PathLike[str],
    allowed_root: str | os.PathLike[str],
) -> Path:
    """Raise PathJailError if `requested_path` is outside `allowed_root`.

    Returns the resolved Path on success — callers should use this Path
    rather than the original, so they always operate on the canonicalized
    form.
    """
    raw = str(requested_path)

    # 1. Lexical normalize. expanduser handles `~`; we keep the result as a
    #    PurePath for the reserved-name / ADS / invalid-char checks.
    try:
        lex = Path(raw).expanduser()
    except (RuntimeError, OSError) as exc:
        raise PathJailError("PATH_INVALID_CHARS", f"Bad path: {exc}") from exc

    if _exceeds_path_max(str(lex)):
        raise PathJailError(
            "PATH_INVALID_CHARS",
            f"Path exceeds OS PATH_MAX: len={len(str(lex))}",
        )

    if _is_reserved_name(lex):
        raise PathJailError(
            "PATH_RESERVED_NAME",
            f"Path uses a Windows reserved device name: {raw!r}",
        )

    if _has_alternate_data_stream(str(lex)):
        raise PathJailError(
            "PATH_INVALID_CHARS",
            f"Path contains an NTFS alternate data stream: {raw!r}",
        )

    if _has_invalid_chars(str(lex)):
        raise PathJailError(
            "PATH_INVALID_CHARS",
            f"Path contains characters illegal on this OS: {raw!r}",
        )

    # 2. Resolve symlinks, junctions, firmlinks, reparse points.
    #    Use os.path.realpath (Python 3.8+ handles Windows junctions) —
    #    pathlib's resolve() can hang on broken symlinks on some FS.
    try:
        resolved = os.path.realpath(str(lex), strict=False)
    except OSError as exc:
        raise PathJailError(
            "PATH_INVALID_CHARS",
            f"Cannot resolve path {raw!r}: {exc}",
        ) from exc

    try:
        root_resolved = os.path.realpath(str(allowed_root), strict=True)
    except OSError as exc:
        # Treat a missing allowed_root as a config error, not a path error,
        # but still surface it via the jail interface so handlers don't crash.
        raise PathJailError(
            "PATH_OUTSIDE_ALLOWED_ROOT",
            f"allowed_root {str(allowed_root)!r} does not exist: {exc}",
        ) from exc

    # 3. Canonical-form comparison, case-folded only when the FS is
    #    case-insensitive.
    a = _normalize_for_compare(resolved)
    b = _normalize_for_compare(root_resolved)

    # 4. Strict prefix with path separator boundary — append os.sep so that
    #    /workspace doesn't match /workspaceother.
    a_check = a if a.endswith(os.sep) else a + os.sep
    b_check = b if b.endswith(os.sep) else b + os.sep

    if a == b or a_check.startswith(b_check):
        return Path(resolved)

    raise PathJailError(
        "PATH_OUTSIDE_ALLOWED_ROOT",
        f"Path {raw!r} (resolved to {resolved!r}) is outside allowed_root {root_resolved!r}",
    )


__all__ = [
    "PathJailError",
    "assert_inside_jail",
    "is_inside_jail",
]
