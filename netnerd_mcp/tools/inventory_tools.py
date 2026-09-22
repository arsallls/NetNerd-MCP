"""Tool: list_devices."""
from __future__ import annotations

from typing import Any

from netnerd_mcp.inventory import get_inventory


def list_devices() -> dict[str, Any]:
    """List the devices this server is allowed to reach.

    The inventory is an allowlist: a device that is not in this list cannot be
    connected to, even by IP address. Credentials are never returned.
    """
    inventory = get_inventory()
    return {
        "devices": [d.redacted() for d in inventory.all()],
        "total": len(inventory),
        "inventory_file": str(inventory.source) if inventory.source else None,
    }
