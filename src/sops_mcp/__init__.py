"""MCP server for creating and managing SOPS-encrypted secrets."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("sops-mcp")
except PackageNotFoundError:  # running from a source tree without an install
    __version__ = "0.0.0+unknown"
