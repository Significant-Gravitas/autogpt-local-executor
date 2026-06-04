"""
CLI entry point — `autogpt-shim <command>`

Commands:
    auth       Run the OAuth flow to authenticate with the AutoGPT platform
    start      Start the shim daemon (foreground)
    status     Show connection status
    revoke     Revoke OAuth tokens and disconnect
    install    Register the shim as a per-user autostart entry
    uninstall  Remove the autostart entry
    audit      Read/verify/export/rotate/prune the audit log (see subcommands)
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="autogpt-shim",
        description="EXPERIMENTAL: AutoGPT Local PC Executor shim",
    )
    parser.add_argument(
        "--allowed-root",
        type=Path,
        default=None,
        help="Override the directory that all file ops are jailed to.",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Path to a TOML config file (defaults to per-OS location).",
    )
    parser.add_argument(
        "--platform-url",
        default=None,
        help="Base URL of the AutoGPT platform (default: https://platform.autogpt.net).",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        help="Python logging level (DEBUG/INFO/WARNING/ERROR).",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("auth", help="Authenticate with the AutoGPT platform (OAuth)")
    sub.add_parser("start", help="Start the shim daemon")
    sub.add_parser("status", help="Show connection + autostart status")
    sub.add_parser("revoke", help="Revoke tokens and disconnect")
    install_p = sub.add_parser(
        "install",
        help="Write a per-OS autostart entry (launchd / systemd / Task Scheduler)",
    )
    install_p.add_argument(
        "--at-login",
        action="store_true",
        default=True,
        help="Trigger autostart at login (default; v0 supports no other trigger).",
    )
    sub.add_parser(
        "uninstall",
        help="Remove the autostart entry written by `autogpt-shim install`",
    )

    audit_p = sub.add_parser("audit", help="Inspect / verify the audit log")
    audit_sub = audit_p.add_subparsers(dest="audit_command", required=True)
    audit_sub.add_parser("tail", help="Tail the current audit log (follow appends).")
    show_p = audit_sub.add_parser("show", help="Pretty-print a single record by seq.")
    show_p.add_argument("seq", type=int, help="Record sequence number.")
    audit_sub.add_parser("verify", help="Chain-verify the current audit log.")
    audit_sub.add_parser("verify-all", help="Chain-verify every audit log in the directory.")
    export_p = audit_sub.add_parser(
        "export",
        help="Zip current + rotated logs and sign the manifest for upload.",
    )
    export_p.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output zip path. Defaults to ./audit-export-{timestamp}.zip.",
    )
    audit_sub.add_parser("rotate", help="Explicit rotation; starts a fresh chain.")
    prune_p = audit_sub.add_parser("prune", help="Delete rotated files older than threshold.")
    prune_p.add_argument(
        "--older-than",
        default="90d",
        help="Threshold like `90d` or `30d`. Default 90d.",
    )

    args = parser.parse_args()
    logging.basicConfig(
        level=args.log_level.upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    print("WARNING: This is experimental, untested software.")
    print("   It gives the AutoGPT platform code execution access to this machine.")
    print("   Read docs/SECURITY.md before continuing.\n")

    # install / uninstall don't need a full config load — they only need the
    # config path so the rendered autostart file points at the right file.
    if args.command == "install":
        _cmd_install(args)
        return
    if args.command == "uninstall":
        _cmd_uninstall(args)
        return

    config = _build_config(args)

    if args.command == "auth":
        _cmd_auth(config)
    elif args.command == "start":
        asyncio.run(_cmd_start(config))
    elif args.command == "status":
        _cmd_status(config, args)
    elif args.command == "revoke":
        _cmd_revoke()
    elif args.command == "audit":
        exit_code = _cmd_audit(config, args)
        if exit_code:
            sys.exit(exit_code)
    else:
        parser.print_help()
        sys.exit(1)


def _build_config(args):
    from .config import load_config

    overrides = {}
    if args.allowed_root is not None:
        overrides["allowed_root"] = args.allowed_root
    if args.platform_url is not None:
        overrides["platform_url"] = args.platform_url
    return load_config(config_path=args.config, overrides=overrides)


def _cmd_auth(config) -> None:
    from .auth import KeychainTokenStore, OAuthFlow

    flow = OAuthFlow(config=config, token_store=KeychainTokenStore())
    flow.run()


async def _cmd_start(config) -> None:
    from .auth import KeychainTokenStore
    from .daemon import ShimDaemon

    daemon = ShimDaemon(config=config, token_store=KeychainTokenStore())
    print(f"Starting shim daemon (machine_id={config.machine_id})")
    print(f"Allowed root: {config.allowed_root}")
    print("Press Ctrl+C to stop.\n")
    try:
        await daemon.run()
    except KeyboardInterrupt:
        await daemon.stop()
        print("\nShim stopped.")


def _cmd_status(config, args) -> None:
    # TODO: check pidfile / unix socket for running daemon status.
    print("Status check not yet implemented.")
    print(f"Configured platform: {config.platform_url}")
    print(f"Configured allowed_root: {config.allowed_root}")
    print()
    _print_autostart_status()


def _cmd_revoke() -> None:
    from .auth import KeychainTokenStore

    store = KeychainTokenStore()
    store.clear_tokens()
    print("Tokens revoked. Run `autogpt-shim auth` to re-authenticate.")


def _cmd_install(args) -> None:
    from . import install as _install

    status = _install.install_autostart(
        at_login=args.at_login,
        config_path=args.config,
    )
    print(f"Wrote autostart entry: {status.target_path}")
    print(f"Platform: {status.platform}")
    if status.enable_command:
        print("\nTo activate, run:")
        print(f"  {status.enable_command}")
    if status.disable_command:
        print("\nTo deactivate later, run:")
        print(f"  {status.disable_command}")
    for note in status.notes:
        print(f"\nNote: {note}")


def _cmd_uninstall(args) -> None:
    from . import install as _install

    status = _install.uninstall_autostart()
    if status.installed:
        # Shouldn't happen — uninstall_autostart already removed it.
        print(f"WARNING: autostart entry still present at {status.target_path}")
    else:
        print(f"Removed autostart entry (or it was already absent): {status.target_path}")
    if status.disable_command:
        print("\nIf the OS service manager already registered it, also run:")
        print(f"  {status.disable_command}")


def _print_autostart_status() -> None:
    from . import install as _install

    plat = _install._current_platform_for_install()
    status = _install.status_for(plat)
    marker = "installed" if status.installed else "not installed"
    print(f"Autostart entry ({status.platform}): {marker}")
    print(f"  path: {status.target_path}")
    if status.enable_command:
        print(f"  enable: {status.enable_command}")
    if status.disable_command:
        print(f"  disable: {status.disable_command}")
    for note in status.notes:
        print(f"  note: {note}")


# ── `audit` subcommands ───────────────────────────────────────────────────────


def _cmd_audit(config, args) -> int:
    """Dispatch one of the `audit` subcommands. Returns process exit code."""
    sub = args.audit_command
    if sub == "tail":
        return _audit_tail(config.audit_log_path)
    if sub == "show":
        return _audit_show(config.audit_log_path, args.seq)
    if sub == "verify":
        return _audit_verify(config.audit_log_path)
    if sub == "verify-all":
        return _audit_verify_all(config.audit_log_path)
    if sub == "export":
        return _audit_export(config.audit_log_path, args.output)
    if sub == "rotate":
        return _audit_rotate(config.audit_log_path)
    if sub == "prune":
        return _audit_prune(config.audit_log_path, args.older_than)
    print(f"Unknown audit subcommand: {sub}")
    return 2


def _audit_tail(path: Path) -> int:
    """Print existing records then follow appends. Like `tail -f` for the
    audit log — but we strict-decode each line so a truncated final write
    is visible as a parse error rather than silently garbled output."""
    import time

    if not path.is_file():
        print(f"Audit log not found: {path}")
        return 1
    with open(path, "rb") as f:
        # Print everything that already exists, then poll for appends.
        for line in f:
            _print_record_line(line)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            _print_record_line(line)


def _audit_show(current: Path, seq: int) -> int:
    """Find one record by seq across current + rotated files and pretty-print
    it. Useful for jumping to a specific event referenced in a bug report
    without leaving the terminal."""
    import json

    from .audit import list_rotated_files

    candidates: list[Path] = []
    if current.is_file():
        candidates.append(current)
    candidates.extend(list_rotated_files(current))
    for path in candidates:
        with open(path, "rb") as f:
            for raw in f:
                if not raw.strip():
                    continue
                try:
                    rec = json.loads(raw.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
                if rec.get("seq") == seq:
                    print(f"# from {path.name}")
                    print(json.dumps(rec, indent=2, ensure_ascii=False))
                    return 0
    print(f"No record with seq={seq} in {current} or rotated files.")
    return 1


def _audit_verify(current: Path) -> int:
    from .audit import AuditWriter, get_or_create_audit_key

    if not current.is_file():
        print(f"Audit log not found: {current}")
        return 1
    try:
        key = get_or_create_audit_key()
    except Exception as exc:
        print(f"Could not load audit key: {exc}")
        return 2
    violations = AuditWriter.verify(current, key)
    return _print_violations(current, violations)


def _audit_verify_all(current: Path) -> int:
    from .audit import AuditWriter, get_or_create_audit_key, list_rotated_files

    try:
        key = get_or_create_audit_key()
    except Exception as exc:
        print(f"Could not load audit key: {exc}")
        return 2
    files: list[Path] = []
    if current.is_file():
        files.append(current)
    files.extend(list_rotated_files(current))
    if not files:
        print("No audit logs found.")
        return 0
    failures = 0
    for path in files:
        violations = AuditWriter.verify(path, key)
        if violations:
            failures += 1
        _print_violations(path, violations)
    if failures:
        print(f"\n{failures} of {len(files)} files have violations.")
        return 1
    print(f"\nAll {len(files)} files verified clean.")
    return 0


def _audit_export(current: Path, output: Path | None) -> int:
    """Zip current + rotated files and sign the manifest with the audit key.

    The manifest pins each file's size + SHA-256, and is itself HMACed with
    the audit key. An operator with the key (the user) can prove the bundle
    is intact. We use HMAC (not RSA) because the audit key is symmetric;
    the trust path is "user shares key out-of-band with support"."""
    import datetime
    import hashlib
    import hmac
    import json
    import zipfile

    from .audit import KEYCHAIN_AUDIT_KEY_USERNAME, get_or_create_audit_key, list_rotated_files

    try:
        key = get_or_create_audit_key()
    except Exception as exc:
        print(f"Could not load audit key: {exc}")
        return 2

    files: list[Path] = []
    if current.is_file():
        files.append(current)
    files.extend(list_rotated_files(current))
    if not files:
        print("Nothing to export — no audit logs present.")
        return 1

    if output is None:
        stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        output = Path.cwd() / f"audit-export-{stamp}.zip"

    manifest: dict = {
        "exported_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "files": [],
        "key_username": KEYCHAIN_AUDIT_KEY_USERNAME,
    }
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in files:
            data = path.read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            manifest["files"].append(
                {"name": path.name, "size": len(data), "sha256": digest}
            )
            zf.writestr(path.name, data)
        manifest_bytes = json.dumps(manifest, sort_keys=True).encode("utf-8")
        signature = hmac.new(key, manifest_bytes, hashlib.sha256).hexdigest()
        zf.writestr("manifest.json", manifest_bytes)
        zf.writestr("manifest.sig", signature)
    print(f"Wrote {output}")
    print(f"  files: {len(files)}")
    print(f"  signature (HMAC-SHA256): {signature}")
    return 0


def _audit_rotate(current: Path) -> int:
    from .audit import AuditWriter, get_or_create_audit_key

    if not current.is_file():
        print(f"Audit log not found: {current}")
        return 1
    try:
        key = get_or_create_audit_key()
    except Exception as exc:
        print(f"Could not load audit key: {exc}")
        return 2
    writer = AuditWriter(path=current, audit_key=key)
    rotated = writer.force_rotate()
    if rotated is None:
        print("Audit log was empty; nothing to rotate.")
        return 0
    print(f"Rotated to {rotated}")
    return 0


def _audit_prune(current: Path, older_than: str) -> int:
    """Delete rotated files where the *newest* record is older than `older_than`.

    Threshold parser accepts `Nd` (days), `Nh` (hours), `Nm` (minutes). The
    shim never auto-prunes — this is operator-initiated."""
    import json
    import time

    from .audit import list_rotated_files

    seconds = _parse_duration(older_than)
    if seconds is None:
        print(f"Could not parse duration: {older_than!r}. Use e.g. 90d, 12h, 30m.")
        return 2
    cutoff = time.time() - seconds
    rotated = list_rotated_files(current)
    if not rotated:
        print("No rotated audit files to prune.")
        return 0
    deleted = 0
    for path in rotated:
        try:
            # Newest record sits at the tail; reuse the same window logic
            # as the writer's tail-state recovery (8 KiB is fine for our
            # line sizes).
            with open(path, "rb") as f:
                f.seek(0, 2)
                size = f.tell()
                f.seek(max(0, size - 8192))
                tail = f.read()
            lines = [ln for ln in tail.split(b"\n") if ln.strip()]
            if not lines:
                continue
            newest_ts = float(json.loads(lines[-1]).get("ts", 0))
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        if newest_ts < cutoff:
            try:
                path.unlink()
                deleted += 1
                print(f"Deleted {path.name} (newest_ts={newest_ts:.0f})")
            except OSError as exc:
                print(f"Could not delete {path.name}: {exc}")
    print(f"\nPruned {deleted} of {len(rotated)} rotated files.")
    return 0


def _parse_duration(s: str) -> float | None:
    """Tiny duration parser: `90d`, `12h`, `30m`, `45s`."""
    if not s:
        return None
    units = {"d": 86400, "h": 3600, "m": 60, "s": 1}
    suffix = s[-1].lower()
    if suffix not in units:
        return None
    try:
        n = int(s[:-1])
    except ValueError:
        return None
    return n * units[suffix]


def _print_record_line(raw: bytes) -> None:
    import json

    s = raw.decode("utf-8", errors="replace").rstrip("\n")
    if not s.strip():
        return
    try:
        rec = json.loads(s)
    except json.JSONDecodeError:
        print(f"[unparseable] {s}")
        return
    seq = rec.get("seq", "?")
    op = rec.get("op", "?")
    ok = rec.get("result", {}).get("ok")
    marker = "ok" if ok else f"err:{rec.get('result', {}).get('error_code')}"
    print(f"seq={seq:>5}  {op:<22}  {marker}")


def _print_violations(path: Path, violations: list) -> int:
    """Pretty-print a verify result. Returns shell exit code (0 clean, 1 dirty)."""
    if not violations:
        print(f"{path.name}: OK")
        return 0
    print(f"{path.name}: {len(violations)} violation(s)")
    for v in violations:
        seq_part = f"seq={v.seq}" if v.seq is not None else "seq=?"
        print(f"  [{v.kind}] {seq_part}: {v.message}")
    return 1
