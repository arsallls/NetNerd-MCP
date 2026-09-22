"""End-to-end through the MCP layer.

Registration, schema and annotations, plus real tool calls that resolve a
device by inventory name and come back with live state off the lab.
"""
from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest

from tests.conftest import requires_lab

# The server module loads the inventory at import time.
os.environ["NETNERD_INVENTORY"] = str(Path(__file__).resolve().parents[2] / "lab" / "lab-inventory.yaml")
os.environ.setdefault("NETNERD_READ_ONLY", "true")

from netnerd_mcp.server import READ_TOOLS, WRITE_TOOLS, server  # noqa: E402

pytestmark = pytest.mark.integration


def _run(coro):
    return asyncio.run(coro)


class TestRegistration:
    def test_the_tool_surface_is_ten_primitives(self):
        tools = _run(server.list_tools())
        assert len(tools) == 10, [t.name for t in tools]

    def test_read_tools_are_annotated_read_only(self):
        by_name = {t.name: t for t in _run(server.list_tools())}
        for fn in READ_TOOLS:
            ann = by_name[fn.__name__].annotations
            assert ann is not None and ann.read_only_hint is True, fn.__name__

    def test_write_tools_are_annotated_destructive(self):
        by_name = {t.name: t for t in _run(server.list_tools())}
        for fn in WRITE_TOOLS:
            ann = by_name[fn.__name__].annotations
            assert ann is not None and ann.destructive_hint is True, fn.__name__
            assert ann.read_only_hint is False, fn.__name__

    def test_every_device_tool_requires_a_reason(self):
        """The reason is what makes the audit log readable — it is not optional."""
        by_name = {t.name: t for t in _run(server.list_tools())}
        for name in ("show", "get_config", "plan_change", "apply_change",
                     "confirm_change", "save_config"):
            schema = by_name[name].input_schema
            assert "reason" in schema["required"], f"{name} does not require a reason"

    def test_schemas_are_derived_from_the_functions(self):
        by_name = {t.name: t for t in _run(server.list_tools())}
        schema = by_name["show"].input_schema
        assert {"device", "command", "reason"} <= set(schema["properties"])


class TestInventoryIsAnAllowlist:
    def test_unknown_device_is_reported_not_raised(self):
        result = _run(server.call_tool("show", {
            "device": "nope-not-here", "command": "show version", "reason": "test",
        }))
        assert "Unknown device" in str(result)

    def test_a_bare_ip_is_not_reachable(self):
        """An address the model saw in output must not become a session."""
        result = _run(server.call_tool("show", {
            "device": "10.9.9.9", "command": "show version", "reason": "test",
        }))
        assert "Unknown device" in str(result)

    def test_list_devices_never_returns_credentials(self):
        result = str(_run(server.call_tool("list_devices", {})))
        assert "netnerd123" not in result
        assert "r1" in result and "writable" in result


@requires_lab
class TestLiveToolCalls:
    def test_show_returns_live_protocol_state(self):
        result = str(_run(server.call_tool("show", {
            "device": "r1",
            "command": "show ip bgp summary",
            "reason": "checking the eBGP session with r2 is established",
        })))
        assert "65002" in result, f"live BGP peer AS missing:\n{result[:800]}"

    def test_show_refuses_a_write_command(self):
        result = str(_run(server.call_tool("show", {
            "device": "r1", "command": "configure terminal", "reason": "test",
        })))
        assert "read-only" in result.lower() or "plan_change" in result

    def test_a_command_the_device_rejects_comes_back_as_an_error(self):
        """FRR answers `show interfaces brief` with "% Unknown command" and
        netmiko raises nothing. A live agent had to spot that in the text to
        know its command had failed — that should not be the caller's job."""
        result = str(_run(server.call_tool("show", {
            "device": "r1",
            "command": "show interfaces brief",
            "reason": "an IOS command FRR does not have",
        })))
        assert "Unknown command" in result
        assert "device_rejected" in result

    def test_get_config_section_filter_trims_the_output(self):
        full = _run(server.call_tool("get_config", {
            "device": "r1", "reason": "baseline",
        }))
        section = _run(server.call_tool("get_config", {
            "device": "r1", "reason": "just the bgp stanza", "section": "router bgp",
        }))
        assert "router bgp" in str(section)
        assert len(str(section)) < len(str(full))
