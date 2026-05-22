"""
CLI entry point — `autogpt-shim <command>`

Commands:
    auth       Run the OAuth flow to authenticate with the AutoGPT platform
    start      Start the shim daemon (foreground)
    status     Show connection status
    revoke     Revoke OAuth tokens and disconnect
    install    Register the shim as a per-user autostart entry
    uninstall  Remove the autostart entry
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
