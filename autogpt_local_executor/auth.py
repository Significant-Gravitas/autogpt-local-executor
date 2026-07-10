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

    async def get_access_token(self) -> str | None:
        """Return the stored access token, or None if not authenticated."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None,
            lambda: keyring.get_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCESS_TOKEN_KEY),
        )

    async def store_tokens(self, access_token: str, refresh_token: str) -> None:
        """Persist both tokens to the OS keychain."""
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None,
            lambda: keyring.set_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCESS_TOKEN_KEY, access_token),
        )
        await loop.run_in_executor(
            None,
            lambda: keyring.set_password(
                KEYCHAIN_SERVICE, KEYCHAIN_REFRESH_TOKEN_KEY, refresh_token
            ),
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

    async def get_refresh_token(self) -> str | None:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None,
            lambda: keyring.get_password(KEYCHAIN_SERVICE, KEYCHAIN_REFRESH_TOKEN_KEY),
        )


class OAuthFlow:
    """
    Runs the Authorization Code + PKCE flow against the AutoGPT OAuth provider.
    """

    SCOPES = ["USE_TOOLS"]

    def __init__(self, config, token_store: KeychainTokenStore) -> None:
        self.config = config
        self.token_store = token_store

    def run(self) -> None:
        """Execute the full auth flow interactively."""
        code_verifier, code_challenge = self._generate_pkce_pair()
        state = secrets.token_urlsafe(32)
        server, auth_code, oauth_error, callback_port = self._bind_callback_server(
            expected_state=state
        )
        auth_url = self._build_auth_url(
            code_challenge,
            state=state,
            redirect_port=callback_port,
        )

        print("\nOpening browser for AutoGPT authentication...")
        print(f"If it doesn't open automatically, visit:\n  {auth_url}\n")
        webbrowser.open(auth_url)

        code = self._wait_for_callback(server, auth_code, oauth_error)
        tokens = asyncio.run(self._exchange_code(code, code_verifier, redirect_port=callback_port))
        asyncio.run(self.token_store.store_tokens(tokens["access_token"], tokens["refresh_token"]))
        print("Authentication successful. Tokens stored in OS keychain.")

    async def refresh_token(self) -> None:
        """Use the stored refresh token to obtain a new access token."""
        refresh = await self.token_store.get_refresh_token()
        if not refresh:
            raise ValueError("No refresh token stored. Run `autogpt-shim auth` first.")
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                self.config.derived_oauth_token_url,
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

    async def revoke_tokens(self) -> None:
        """Revoke both token types remotely before deleting local credentials.

        The desktop shim is a public client, so it sends the well-known client
        id with an empty secret. Any HTTP or keychain read error aborts before
        local deletion, leaving the credentials available for a retry.
        """
        access = await self.token_store.get_access_token()
        refresh = await self.token_store.get_refresh_token()
        tokens = (
            (access, "access_token"),
            (refresh, "refresh_token"),
        )
        async with httpx.AsyncClient() as client:
            for token, token_type_hint in tokens:
                if not token:
                    continue
                resp = await client.post(
                    self.config.derived_oauth_revoke_url,
                    json={
                        "token": token,
                        "token_type_hint": token_type_hint,
                        "client_id": self.config.oauth_client_id,
                        "client_secret": "",
                    },
                )
                resp.raise_for_status()
        self.token_store.clear_tokens()

    @staticmethod
    def _generate_pkce_pair() -> tuple[str, str]:
        code_verifier = secrets.token_urlsafe(64)
        digest = hashlib.sha256(code_verifier.encode()).digest()
        code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        return code_verifier, code_challenge

    def _build_auth_url(
        self,
        code_challenge: str,
        *,
        state: str | None = None,
        redirect_port: int | None = None,
    ) -> str:
        port = redirect_port or self.config.oauth_redirect_port
        params = {
            "response_type": "code",
            "client_id": self.config.oauth_client_id,
            "redirect_uri": f"http://localhost:{port}/callback",
            "scope": " ".join(self.SCOPES),
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": state or secrets.token_urlsafe(32),
        }
        return f"{self.config.derived_oauth_url}/authorize?" + urllib.parse.urlencode(params)

    def _bind_callback_server(
        self, *, expected_state: str
    ) -> tuple[HTTPServer, list[str], list[str], int]:
        auth_code: list[str] = []
        oauth_error: list[str] = []

        class CallbackHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                parsed = urllib.parse.urlparse(self.path)
                params = urllib.parse.parse_qs(parsed.query)
                state = params.get("state", [""])[0]
                if parsed.path != "/callback":
                    self.send_response(404)
                    message = b"Not found"
                elif not secrets.compare_digest(state, expected_state):
                    oauth_error.append("OAuth callback state did not match")
                    self.send_response(400)
                    message = b"Authentication failed: invalid state."
                elif "error" in params:
                    oauth_error.append(params["error"][0])
                    self.send_response(400)
                    message = b"Authentication was denied or failed."
                elif "code" in params and params["code"][0]:
                    auth_code.append(params["code"][0])
                    self.send_response(200)
                    message = b"<h1>Authenticated! You can close this tab.</h1>"
                else:
                    oauth_error.append("No authorization code received")
                    self.send_response(400)
                    message = b"Authentication failed: no authorization code."
                self.end_headers()
                self.wfile.write(message)

            def log_message(self, *args):
                pass

        first_port = self.config.oauth_redirect_port
        for port in range(first_port, first_port + 12):
            try:
                server = HTTPServer(("127.0.0.1", port), CallbackHandler)
                server.timeout = 300
                return server, auth_code, oauth_error, port
            except OSError:
                continue
        raise RuntimeError(f"Could not bind OAuth callback on ports {first_port}-{first_port + 11}")

    @staticmethod
    def _wait_for_callback(server: HTTPServer, auth_code: list[str], oauth_error: list[str]) -> str:
        try:
            server.handle_request()
        finally:
            server.server_close()

        if not auth_code:
            detail = oauth_error[0] if oauth_error else "OAuth callback timed out"
            raise ValueError(detail)
        return auth_code[0]

    async def _exchange_code(
        self,
        auth_code: str,
        code_verifier: str,
        *,
        redirect_port: int | None = None,
    ) -> dict:
        port = redirect_port or self.config.oauth_redirect_port
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                self.config.derived_oauth_token_url,
                data={
                    "grant_type": "authorization_code",
                    "code": auth_code,
                    "redirect_uri": f"http://localhost:{port}/callback",
                    "client_id": self.config.oauth_client_id,
                    "code_verifier": code_verifier,
                },
            )
            resp.raise_for_status()
            return resp.json()
