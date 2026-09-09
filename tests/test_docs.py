"""Guards against the README drifting away from the code.

Every claim pinned here is one that actually went stale at some point:
the tool table, the environment-variable table and the transforms table
all described a version of this server that no longer existed.

These tests check that things are *mentioned*, not how they are worded.
Prose is free to change; a tool or a variable disappearing from the docs
is not.
"""

import pathlib
import re

import pytest

from sops_mcp.secrets_derive import TRANSFORMS
from tests.helpers import make_server

README = pathlib.Path(__file__).resolve().parents[1] / "README.md"

# Environment variables the server reads as configuration. Every one of
# these must appear in the README's table.
CONFIG_ENV_VARS = {
    "SOPS_MCP_AGE_PUBLIC_KEY",
    "SOPS_AGE_RECIPIENTS",
    "SOPS_AGE_KEY",
    "SOPS_MCP_DOMAINS_FILE",
    "SOPS_MCP_REQUIRE_DOMAIN",
    "SOPS_MCP_SOPS_BINARY",
    "SOPS_MCP_LOG_LEVEL",
    "SOPS_MCP_TRANSPORT",
    "SOPS_MCP_HOST",
    "SOPS_MCP_PORT",
    "SOPS_MCP_ALLOWED_HOSTS",
    "SOPS_MCP_API_TOKEN",
}

# Variables the server scrubs from each sops subprocess rather than reads.
# They are not configuration, so they are not in the README table — but
# they do appear as string literals in the source, so the scan below has
# to account for them.
SCRUBBED_ENV_VARS = {
    "SOPS_AGE_KEY",
    "SOPS_AGE_KEY_FILE",
    "SOPS_AGE_KEY_CMD",
    "SOPS_AGE_SSH_PRIVATE_KEY_FILE",
    "SOPS_AGE_RECIPIENTS",
}

# `sops_mcp` is the package name, from `python -m sops_mcp`, not a tool.
NOT_A_TOOL = {"sops_mcp"}


@pytest.fixture(scope="module")
def readme() -> str:
    return README.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def tool_names() -> set[str]:
    """Every tool the server advertises, straight from list_tools."""
    import asyncio

    from mcp.types import ListToolsRequest

    server = make_server()

    async def _list():
        handler = server.server.request_handlers[ListToolsRequest]
        result = await handler(ListToolsRequest(method="tools/list"))
        return {tool.name for tool in result.root.tools}

    return asyncio.run(_list())


def test_every_tool_is_documented(readme, tool_names):
    """A tool the README never mentions is a tool nobody will use."""
    undocumented = {name for name in tool_names if name not in readme}
    assert not undocumented, (
        f"tools missing from README.md: {sorted(undocumented)}"
    )


def test_readme_documents_no_tool_that_does_not_exist(readme, tool_names):
    """Catches a rename that updated the code but not the docs."""
    mentioned = set(re.findall(r"sops_[a-z0-9_]+", readme)) - NOT_A_TOOL
    stale = mentioned - tool_names
    assert not stale, (
        f"README.md documents tools that do not exist: {sorted(stale)}"
    )


def test_every_config_env_var_is_documented(readme):
    undocumented = {var for var in CONFIG_ENV_VARS if var not in readme}
    assert not undocumented, (
        f"env vars missing from README.md: {sorted(undocumented)}"
    )


def test_env_vars_in_the_source_are_all_classified():
    """A new env var must be either documented or explicitly scrubbed.

    Without this, adding a configuration variable and forgetting the
    README leaves no trace — the other test only checks the ones already
    listed here.
    """
    src = pathlib.Path(__file__).resolve().parents[1] / "src" / "sops_mcp"
    found: set[str] = set()
    for path in src.rglob("*.py"):
        found |= set(
            re.findall(r'"(SOPS_[A-Z0-9_]+)"', path.read_text(encoding="utf-8"))
        )

    unclassified = found - CONFIG_ENV_VARS - SCRUBBED_ENV_VARS
    assert not unclassified, (
        "these env vars appear in the source but are neither documented as "
        f"configuration nor listed as scrubbed: {sorted(unclassified)}"
    )


def test_every_transform_is_documented(readme):
    """The transforms table is part of the tool contract."""
    undocumented = {name for name in TRANSFORMS if name not in readme}
    assert not undocumented, (
        f"transforms missing from README.md: {sorted(undocumented)}"
    )


def test_readme_documents_no_transform_that_does_not_exist(readme):
    table = re.search(
        r"### Transforms.*?\n\n(.*?)\n\n", readme, re.DOTALL
    )
    assert table, "the README no longer has a Transforms section"
    mentioned = set(re.findall(r"`([a-z0-9_]+)`", table.group(1)))
    stale = mentioned - set(TRANSFORMS)
    assert not stale, (
        f"README.md documents transforms that do not exist: {sorted(stale)}"
    )
