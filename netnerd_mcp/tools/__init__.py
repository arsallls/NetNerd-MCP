"""Read-only device tools. Change tools live in netnerd_mcp.changes."""
from netnerd_mcp.tools.inventory_tools import list_devices
from netnerd_mcp.tools.show_tools import get_config, show

__all__ = ["list_devices", "show", "get_config"]
