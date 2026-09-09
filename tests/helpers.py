"""Shared test constructors.

The recipient below is a real age public key generated for the test suite.
It is public key material with no private half retained anywhere, so it is
safe to hard-code; tests that never invoke sops only need it to be well
formed enough to pass domain validation.
"""

from sops_mcp.domains import Domain
from sops_mcp.server import SopsMcpServer
from sops_mcp.sops import SopsEncryptor

DUMMY_RECIPIENT = "age100lh2nut8xdqat8stj7vwf2l220q72l8tupndjr2h8m2qemfuptq3wee69"


def make_domain(name: str = "default", **kwargs) -> Domain:
    """A well-formed encrypt-only domain for tests that never call sops."""
    kwargs.setdefault("recipients", (DUMMY_RECIPIENT,))
    return Domain(name=name, **kwargs)


def make_server(**kwargs) -> SopsMcpServer:
    """A server wired to a single dummy domain."""
    domains = kwargs.pop("domains", None) or {"default": make_domain()}
    return SopsMcpServer(SopsEncryptor(), domains, **kwargs)
