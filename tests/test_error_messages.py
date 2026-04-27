"""Regression test for the call_tool dispatcher's exception handling.

The dispatcher catches `Exception` as a last resort and must NOT echo the
raised exception's text back to the client — a deep failure inside the
encrypt / yaml / subprocess path could in principle carry secret-bearing
context, and the client (an LLM) is treated as untrusted by this server's
threat model.
"""

from mcp.types import CallToolRequest, CallToolRequestParams

from sops_mcp.server import SopsMcpServer
from sops_mcp.sops import SopsEncryptor


async def test_unexpected_exception_returns_generic_message(monkeypatch, caplog):
    srv = SopsMcpServer(SopsEncryptor("age1dummy"))

    sentinel = "SECRET_LEAK_CANARY_zzz9876"

    async def explode(_arguments):
        raise RuntimeError(sentinel)

    monkeypatch.setattr(srv, "_create_secrets", explode)

    handler = srv.server.request_handlers[CallToolRequest]
    # Arguments must satisfy the tool's input schema or MCP rejects the
    # call before reaching our handler. We pass a schema-valid payload
    # and rely on the monkeypatched method to explode at the catch-all.
    request = CallToolRequest(
        params=CallToolRequestParams(
            name="sops_create_secrets",
            arguments={"secrets": []},
        ),
    )

    with caplog.at_level("ERROR"):
        result = await handler(request)

    rendered = result.model_dump_json()
    assert sentinel not in rendered, (
        "Raw exception text leaked to client response — the catch-all must "
        "return a static string, not f'Internal error: {e}'."
    )
    assert "Internal error" in rendered

    # The detail belongs in the server log (so the operator can debug),
    # not in the client-visible response.
    assert any(sentinel in r.getMessage() or sentinel in str(r.exc_info)
               for r in caplog.records), (
        "Exception detail must still reach the server log via "
        "logger.exception so operators can debug."
    )


# ValueError / SopsError carry validation messages and SHOULD be surfaced —
# they're meant for the user (e.g. "Invalid key name FOO_bar"). Lock that
# in so a future overzealous refactor doesn't make all errors generic.
async def test_validation_errors_still_surface_to_client():
    srv = SopsMcpServer(SopsEncryptor("age1dummy"))

    handler = srv.server.request_handlers[CallToolRequest]
    request = CallToolRequest(
        params=CallToolRequestParams(
            name="sops_create_secrets",
            arguments={"secrets": [{"key_name": "bad-name", "source": "external", "value": "x"}]},
        ),
    )

    result = await handler(request)
    rendered = result.model_dump_json()
    assert "bad-name" in rendered or "Invalid key name" in rendered
