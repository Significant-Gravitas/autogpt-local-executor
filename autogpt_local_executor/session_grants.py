"""Tamper-evident grants binding one chat session to one canonical root."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .directory_browser import _is_reparse_point


class RootGrantError(Exception):
    pass


@dataclass(frozen=True)
class RootBinding:
    session_id: str
    allowed_root: Path
    fingerprint: str
    revision: int
    root_grant: str


class RootGrantSigner:
    def __init__(
        self,
        key: bytes,
        machine_id: str,
        *,
        now: Callable[[], float] = time.time,
    ) -> None:
        if len(key) < 16:
            raise ValueError("root grant key must be at least 16 bytes")
        self._key = hmac.new(key, b"autogpt-root-grant-v1", hashlib.sha256).digest()
        self.machine_id = machine_id
        self._now = now

    def issue(self, session_id: str, allowed_root: Path, revision: int) -> RootBinding:
        if revision < 1:
            raise ValueError("revision must be positive")
        root = canonical_directory(allowed_root)
        fingerprint = directory_fingerprint(root)
        claims = {
            "allowed_root": str(root),
            "fingerprint": fingerprint,
            "issued_at": self._now(),
            "machine_id": self.machine_id,
            "revision": revision,
            "session_id": session_id,
        }
        encoded = _b64encode(
            json.dumps(claims, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
        signature = _b64encode(
            hmac.new(self._key, encoded.encode("ascii"), hashlib.sha256).digest()
        )
        grant = f"v1.{encoded}.{signature}"
        return RootBinding(
            session_id=session_id,
            allowed_root=root,
            fingerprint=fingerprint,
            revision=revision,
            root_grant=grant,
        )

    def verify(self, root_grant: str, expected_session_id: str) -> RootBinding:
        try:
            version, encoded, signature = root_grant.split(".", 2)
            if version != "v1":
                raise RootGrantError("Unsupported root grant version")
            expected = _b64encode(
                hmac.new(self._key, encoded.encode("ascii"), hashlib.sha256).digest()
            )
            if not hmac.compare_digest(signature, expected):
                raise RootGrantError("Root grant signature is invalid")
            claims = json.loads(_b64decode(encoded))
            session_id = claims["session_id"]
            machine_id = claims["machine_id"]
            revision = claims["revision"]
            allowed_root = claims["allowed_root"]
            fingerprint = claims["fingerprint"]
            if not isinstance(session_id, str) or session_id != expected_session_id:
                raise RootGrantError("Root grant belongs to another session")
            if not isinstance(machine_id, str) or machine_id != self.machine_id:
                raise RootGrantError("Root grant belongs to another machine")
            if not isinstance(revision, int) or revision < 1:
                raise RootGrantError("Root grant revision is invalid")
            if not isinstance(allowed_root, str) or not isinstance(fingerprint, str):
                raise RootGrantError("Root grant claims are invalid")
            root = canonical_directory(Path(allowed_root))
            if directory_fingerprint(root) != fingerprint:
                raise RootGrantError("The selected directory changed after the grant was issued")
        except RootGrantError:
            raise
        except (KeyError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RootGrantError("Root grant is malformed") from exc
        return RootBinding(
            session_id=session_id,
            allowed_root=root,
            fingerprint=fingerprint,
            revision=revision,
            root_grant=root_grant,
        )


def canonical_directory(path: Path) -> Path:
    try:
        if path.is_symlink() or _is_reparse_point(path):
            raise RootGrantError("Selected root cannot be a symbolic link")
        resolved = Path(os.path.realpath(path, strict=True))
        if not resolved.is_dir() or not os.access(resolved, os.R_OK | os.W_OK | os.X_OK):
            raise RootGrantError("Selected root is unavailable")
        return resolved
    except RootGrantError:
        raise
    except (OSError, RuntimeError) as exc:
        raise RootGrantError("Selected root is unavailable") from exc


def directory_fingerprint(path: Path) -> str:
    root = canonical_directory(path)
    try:
        stat = root.stat(follow_symlinks=False)
    except OSError as exc:
        raise RootGrantError("Selected root is unavailable") from exc
    identity = {
        "device": stat.st_dev,
        "inode": stat.st_ino,
        "path": os.path.normcase(str(root)),
    }
    raw = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> str:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding).decode("utf-8")


__all__ = [
    "RootBinding",
    "RootGrantError",
    "RootGrantSigner",
    "canonical_directory",
    "directory_fingerprint",
]
