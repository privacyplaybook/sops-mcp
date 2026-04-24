"""Regression tests for the SSE transport's security posture.

These guard two behaviors that exist specifically to defend against the
DNS rebinding advisory and accidental network exposure. Both were verified
manually during the v0.9.1 hardening; these tests keep them green going
forward so a future refactor can't silently undo them.
"""

import asyncio

import pytest
from starlette.testclient import TestClient

from sops_mcp.server import SopsMcpServer, main
from sops_mcp.sops import SopsEncryptor


def test_main_refuses_0000_bind_without_api_token(monkeypatch):
    """Binding the SSE transport to 0.0.0.0 without SOPS_MCP_API_TOKEN must
    fail closed at startup, not silently expose an unauthenticated interface.
    """
    monkeypatch.setenv("SOPS_MCP_TRANSPORT", "sse")
    monkeypatch.setenv("SOPS_MCP_HOST", "0.0.0.0")
    monkeypatch.setenv("SOPS_MCP_AGE_PUBLIC_KEY", "age1dummy")
    monkeypatch.delenv("SOPS_MCP_API_TOKEN", raising=False)

    # If the refusal check is ever removed, main() would reach asyncio.run
    # and try to actually bind 0.0.0.0 — turning a test into a hang or a
    # CI port conflict. Replace asyncio.run with a sentinel so that code
    # path produces a clean, immediate failure instead.
    def _unexpected_asyncio_run(_coro):
        pytest.fail(
            "main() reached asyncio.run despite 0.0.0.0 bind without a "
            "token — the refusal check is missing or bypassed."
        )

    monkeypatch.setattr(asyncio, "run", _unexpected_asyncio_run)

    with pytest.raises(RuntimeError, match="Refusing to bind"):
        main()


def test_sse_endpoint_rejects_bogus_host_header():
    """The SseServerTransport must reject requests whose Host header isn't
    on the allowlist. Without this, a malicious webpage could use DNS
    rebinding to send requests to a local MCP server on the user's behalf.
    """
    srv = SopsMcpServer(SopsEncryptor("age1dummy"))
    app = srv._build_sse_app()  # default: loopback-only allowlist

    with TestClient(app) as client:
        response = client.get("/sse", headers={"Host": "evil.com"})

    assert response.status_code == 421
    assert "Invalid Host" in response.text


def test_sse_endpoint_honors_explicit_allowed_hosts():
    """Custom allowed_hosts passed to _build_sse_app must be honored — and
    hosts outside the custom list still rejected — while /health remains
    outside the SSE security middleware entirely.
    """
    srv = SopsMcpServer(SopsEncryptor("age1dummy"))
    app = srv._build_sse_app(allowed_hosts=["mcp.example.com"])

    with TestClient(app) as client:
        rejected = client.get("/sse", headers={"Host": "127.0.0.1"})
        assert rejected.status_code == 421

        health = client.get("/health", headers={"Host": "anything-at-all"})
        assert health.status_code == 200
        assert health.text == "ok"
