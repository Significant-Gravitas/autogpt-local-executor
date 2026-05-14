"""
OAuth authentication for the shim.

Uses AutoGPT's existing OAuth 2.0 provider with:
- Authorization Code + PKCE flow
- Localhost callback server on port 41899
- Token storage in OS keychain via the `keyring` library
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import secrets
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional

import httpx
import keyring

KEYCHAIN_SERVICE = "autogpt-local-executor"
KEYCHAIN_ACCESS_TOKEN_KEY = "access_token"
KEYCHAIN_REFRESH_TOKEN_KEY = "refresh_token"


class KeychainTokenStore:
    """
    Stores OAuth tokens in the OS keychain using the `keyring` library.

    Backends by platform:
        macOS   → Keychain Services
        Linux   → Secret Service (GNOME Keyring / KWallet)
        Windows → Windows Credential Manager
    """

    async def get_access_token(self) -> Optional[str]:
        """Return the stored access token, or None if not authenticated."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            lambda: keyring.get_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCESS_TOKEN_KEY),
        )

    async def store_tokens(self, access_token: str, refresh_token: str) -> None:
        """Persist both tokens to the OS keychain."""
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None,
            lambda: keyring.set_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCESS_TOKEN_KEY, access_token),
        )
        await loop.run_in_executor(
            None,
            lambda: keyring.set_password(KEYCHAIN_SERVICE, KEYCHAIN_REFRESH_TOKEN_KEY, refresh_token),
        )

    def clear_tokens(self) -> None:
        """Remove all stored tokens (used by `autogpt-shim revoke`)."""
        try:
            keyring.delete_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCESS_TOKEN_KEY)
        except keyring.errors.PasswordDeleteError:
            pass
        try:
            keyring.delete_password(KEYCHAIN_SERVICE, KEYCHAIN_REFRESH_TOKEN_KEY)
        except keyring.errors.PasswordDeleteError:
            pass

    async def get_refresh_token(self) -> Optional[str]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            lambda: keyring.get_password(KEYCHAIN_SERVICE, KEYCHAIN_REFRESH_TOKEN_KEY),
        )


class OAuthFlow:
    """
    Runs the Authorization Code + PKCE flow against the AutoGPT OAuth provider.
    """

    SCOPES = [
        "local_executor:connect",
        "local_executor:shell",
        "local_executor:files",
    ]

    def __init__(self, config: Any, token_store: KeychainTokenStore) -> None:  # noqa: F821
        self.config = config
        self.token_store = token_store

    def run(self) -> None:
        """Execute the full auth flow interactively."""
        code_verifier, code_challenge = self._generate_pkce_pair()
        auth_url = self._build_auth_url(code_challenge)

        print(f"\nOpening browser for AutoGPT authentication...")
        print(f"If it doesn't open automatically, visit:\n  {auth_url}\n")
        webbrowser.open(auth_url)

        auth_code = self._wait_for_callback()
        tokens = asyncio.run(self._exchange_code(auth_code, code_verifier))
        asyncio.run(self.token_store.store_tokens(tokens["access_token"], tokens["refresh_token"]))
        print("Authentication successful. Tokens stored in OS keychain.")

    async def refresh_token(self) -> None:
        """Use the stored refresh token to obtain a new access token."""
        refresh = await self.token_store.get_refresh_token()
        if not refresh:
            raise ValueError("No refresh token stored. Run `autogpt-shim auth` first.")
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self.config.platform_oauth_url}/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": refresh,
                    "client_id": self.config.oauth_client_id,
                },
            )
            resp.raise_for_status()
            tokens = resp.json()
        await self.token_store.store_tokens(
            tokens["access_token"],
            tokens.get("refresh_token", refresh),
        )

    @staticmethod
    def _generate_pkce_pair() -> tuple[str, str]:
        code_verifier = secrets.token_urlsafe(64)
        digest = hashlib.sha256(code_verifier.encode()).digest()
        code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        return code_verifier, code_challenge

    def _build_auth_url(self, code_challenge: str) -> str:
        params = {
            "response_type": "code",
            "client_id": self.config.oauth_client_id,
            "redirect_uri": f"http://localhost:{self.config.oauth_redirect_port}/callback",
            "scope": " ".join(self.SCOPES),
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": secrets.token_urlsafe(16),
        }
        return f"{self.config.platform_oauth_url}/authorize?" + urllib.parse.urlencode(params)

    def _wait_for_callback(self) -> str:
        auth_code: list[str] = []

        class CallbackHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                parsed = urllib.parse.urlparse(self.path)
                params = urllib.parse.parse_qs(parsed.query)
                if "code" in params:
                    auth_code.append(params["code"][0])
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"<h1>Authenticated! You can close this tab.</h1>")

            def log_message(self, *args):
                pass

        server = HTTPServer(("localhost", self.config.oauth_redirect_port), CallbackHandler)
        server.handle_request()
        server.server_close()

        if not auth_code:
            raise ValueError("No authorization code received from OAuth callback")
        return auth_code[0]

    async def _exchange_code(self, auth_code: str, code_verifier: str) -> dict:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self.config.platform_oauth_url}/token",
                data={
                    "grant_type": "authorization_code",
                    "code": auth_code,
                    "redirect_uri": f"http://localhost:{self.config.oauth_redirect_port}/callback",
                    "client_id": self.config.oauth_client_id,
                    "code_verifier": code_verifier,
                },
            )
            resp.raise_for_status()
            return resp.json()
