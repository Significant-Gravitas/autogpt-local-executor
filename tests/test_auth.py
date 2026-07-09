"""OAuth PKCE and localhost callback tests."""

from __future__ import annotations

import socket
import threading
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from autogpt_local_executor.auth import OAuthFlow
from autogpt_local_executor.config import ShimConfig


def _config(tmp_path: Path, *, callback_port: int = 41899) -> ShimConfig:
    return ShimConfig(
        platform_url="https://platform.example.com",
        oauth_redirect_port=callback_port,
        allowed_root=tmp_path,
        audit_log_path=tmp_path / "audit.log",
    )


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def test_authorize_url_uses_supported_scope_and_explicit_state(tmp_path: Path) -> None:
    flow = OAuthFlow(_config(tmp_path), token_store=object())
    url = flow._build_auth_url(
        "challenge",
        state="expected-state",
        redirect_port=41903,
    )
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed.query)

    assert parsed.path == "/auth/authorize"
    assert query["scope"] == ["USE_TOOLS"]
    assert query["state"] == ["expected-state"]
    assert query["redirect_uri"] == ["http://localhost:41903/callback"]


def test_callback_validates_state_before_accepting_code(tmp_path: Path) -> None:
    flow = OAuthFlow(_config(tmp_path, callback_port=_free_port()), token_store=object())
    server, codes, errors, port = flow._bind_callback_server(expected_state="right-state")

    def send_callback() -> None:
        with urllib.request.urlopen(
            f"http://127.0.0.1:{port}/callback?code=the-code&state=right-state",
            timeout=2,
        ):
            pass

    thread = threading.Thread(target=send_callback)
    thread.start()
    assert flow._wait_for_callback(server, codes, errors) == "the-code"
    thread.join(timeout=2)


def test_callback_rejects_state_mismatch(tmp_path: Path) -> None:
    flow = OAuthFlow(_config(tmp_path, callback_port=_free_port()), token_store=object())
    server, codes, errors, port = flow._bind_callback_server(expected_state="right-state")

    def send_callback() -> None:
        try:
            urllib.request.urlopen(
                f"http://127.0.0.1:{port}/callback?code=the-code&state=wrong-state",
                timeout=2,
            )
        except urllib.error.HTTPError:
            pass

    thread = threading.Thread(target=send_callback)
    thread.start()
    with pytest.raises(ValueError, match="state did not match"):
        flow._wait_for_callback(server, codes, errors)
    thread.join(timeout=2)


def test_callback_uses_next_port_when_first_is_busy(tmp_path: Path) -> None:
    blocker = socket.socket()
    blocker.bind(("127.0.0.1", 0))
    first_port = blocker.getsockname()[1]
    flow = OAuthFlow(_config(tmp_path, callback_port=first_port), token_store=object())

    server, _codes, _errors, bound_port = flow._bind_callback_server(expected_state="state")
    try:
        assert bound_port > first_port
        assert bound_port <= first_port + 11
    finally:
        server.server_close()
        blocker.close()


@pytest.mark.asyncio
async def test_code_exchange_posts_form_to_backend_token_endpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, Any] = {}

    class Response:
        def raise_for_status(self) -> None:
            pass

        def json(self) -> dict[str, str]:
            return {"access_token": "access", "refresh_token": "refresh"}

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def post(self, url: str, *, data: dict[str, str]):
            captured["url"] = url
            captured["data"] = data
            return Response()

    monkeypatch.setattr("autogpt_local_executor.auth.httpx.AsyncClient", Client)
    flow = OAuthFlow(_config(tmp_path), token_store=object())

    result = await flow._exchange_code("code", "verifier", redirect_port=41907)

    assert result["access_token"] == "access"
    assert captured["url"] == "https://platform.example.com/api/oauth/token"
    assert captured["data"] == {
        "grant_type": "authorization_code",
        "code": "code",
        "redirect_uri": "http://localhost:41907/callback",
        "client_id": "autogpt-local-executor",
        "code_verifier": "verifier",
    }
