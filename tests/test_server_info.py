"""What the server says about itself at MCP initialize."""

from mcp.shared.memory import create_connected_server_and_client_session

import sops_mcp
from sops_mcp.domains import Domain
from sops_mcp.server import SopsMcpServer
from sops_mcp.sops import SopsEncryptor


async def test_initialize_reports_the_sops_mcp_version():
    # Without an explicit version, the SDK reports its own (mcp's) version
    # here, so an operator can't tell which sops-mcp release is running.
    domains = {"default": Domain("default", ("age1placeholder",), ())}
    server = SopsMcpServer(SopsEncryptor(), domains)
    async with create_connected_server_and_client_session(
        server.server
    ) as client:
        result = await client.initialize()
    assert result.serverInfo.name == "sops-mcp"
    assert result.serverInfo.version == sops_mcp.__version__
