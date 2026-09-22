"""Network device driver package."""

from __future__ import annotations

from netnerd_mcp.drivers.ssh_driver import SSHDriver
from netnerd_mcp.drivers.parser import GenieParser

__all__ = ["SSHDriver", "GenieParser", "get_driver"]


def get_driver() -> SSHDriver:
    """Return an SSH driver bound to the current request context."""
    return SSHDriver()
