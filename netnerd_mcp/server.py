"""netnerd-mcp — MCP server giving an agent guarded SSH access to network gear.

Runs as a local subprocess of the MCP client (stdio transport). Nothing is
hosted; device credentials never leave the machine.

Twelve tools: six that read, five that change configuration through a
token-gated plan/apply/confirm loop, and one that closes the session and
writes the report.
Safety is enforced here in server code, not in the client's prompt — the token
gate, the read-only checks and the rollback timer all hold whether or not the
agent follows instructions.
"""
from __future__ import annotations

import logging
import os
import sys
from typing import Any, Callable

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from netnerd_mcp import audit, changes, sessions, topology
from netnerd_mcp.config.settings import settings
from netnerd_mcp.inventory import get_inventory
from netnerd_mcp.tools import get_config, list_devices, show

try:
    from importlib.metadata import version as _pkg_version
    __version__ = _pkg_version("netnerd-mcp")
except Exception:  # running from a source tree without an install
    __version__ = "0.0.0.dev0"

# stdio transport speaks protocol on stdout — logs MUST go to stderr or they
# corrupt the stream.
logging.basicConfig(
    stream=sys.stderr,
    level=os.environ.get("NETNERD_LOG_LEVEL", settings.LOG_LEVEL).upper(),
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger("netnerd_mcp")

INSTRUCTIONS = """\
Tools for operating real network devices over SSH.

Devices are addressed by their inventory name — call list_devices first. An
address that is not in the inventory cannot be reached.

Diagnosing: use `show` for commands and `get_config` for configuration. Read
the device rather than inferring its state from its name or from memory; never
invent interface names, VLAN IDs or addresses.

Topology: discover_topology walks the devices once and stores how they connect;
query_topology then answers neighbour, path and blast-radius questions from
that graph instead of re-reading every device. Ask it what a change would cut
off before applying anything that touches an interface. An empty graph means
nothing has been discovered yet — never that nothing is connected.

Changing configuration:
  1. plan_change  — validates the commands, backs the device up, returns a token
  2. show the operator the exact commands and wait for them to agree
  3. apply_change — pushes them; the change now reverts by itself on a timer
  4. show         — verify on the device that it did what was intended
  5. confirm_change if healthy, rollback if not
  6. save_config  — only once confirmed; changes are not persistent before this

Every tool takes a `reason`. It is written to an audit log the operator can
read, so make it a real explanation, not a restatement of the command.

Call end_session when the work is done: it closes the SSH sessions and writes
the report.
"""


server = MCPServer(name="netnerd", version=__version__, instructions=INSTRUCTIONS)


def _register(fn: Callable[..., Any], *, read_only: bool, destructive: bool = False) -> None:
    server.tool(
        annotations=ToolAnnotations(
            read_only_hint=read_only,
            destructive_hint=destructive,
            open_world_hint=True,  # talks to devices outside the model's context
        )
    )(fn)


# The read/write split is a security boundary, so it is written out explicitly
# rather than inferred from a naming convention — a tool in the wrong list is
# the kind of mistake that should be visible in review.
READ_TOOLS = [
    list_devices,
    show,
    get_config,
    changes.plan_change,      # reads the device and issues a token; sends no config
    topology.discover_topology,  # runs show commands only
    topology.query_topology,
    sessions.get_transcript,
    sessions.end_session,
]

WRITE_TOOLS = [
    changes.apply_change,
    changes.confirm_change,
    changes.rollback,
    changes.save_config,
]

for _t in READ_TOOLS:
    _register(_t, read_only=True)
for _t in WRITE_TOOLS:
    _register(_t, read_only=False, destructive=True)


def main() -> None:
    inventory = get_inventory()
    log = audit.current()
    logger.info(
        "netnerd-mcp %s starting: %d tools, %d device(s) (%d writable), read_only=%s, audit → %s",
        __version__,
        len(READ_TOOLS) + len(WRITE_TOOLS),
        len(inventory),
        sum(1 for d in inventory.all() if d.writable),
        settings.READ_ONLY,
        log.jsonl_path,
    )
    log.event("session_start", version=__version__, read_only=settings.READ_ONLY,
              devices=inventory.names())
    try:
        server.run()
    finally:
        changes.reset()
        sessions.close_all(reason="server shutdown")


if __name__ == "__main__":
    main()
