"""Tools: show, get_config."""
from __future__ import annotations

import time
from typing import Any

from netnerd_mcp import audit, sessions, vendor
from netnerd_mcp.drivers.ssh_driver import _is_write_command
from netnerd_mcp.inventory import InventoryError, get_inventory


def show(device: str, command: str, reason: str) -> dict[str, Any]:
    """Run one read-only command on a device and return its output.

    Use this for everything diagnostic: `show ip bgp summary`,
    `show interfaces`, `ping`, `traceroute`, and the equivalents on other
    platforms. Anything that changes configuration is refused — use
    plan_change for that.

    Parameters
    ----------
    device: inventory name of the target device.
    command: the CLI command to run, exactly as it would be typed.
    reason: why this is being run — recorded in the audit log.
    """
    try:
        target = get_inventory().resolve(device)
    except InventoryError as exc:
        return {"error": str(exc)}

    if _is_write_command(command):
        why = (
            f"'{command.strip()}' changes device state. `show` only runs read-only "
            f"commands. Configuration goes through plan_change — though commands "
            f"that cannot be rolled back, such as reload or erase, are refused "
            f"there too and have to be run by a human."
        )
        audit.current().event("blocked", device=target.name, tool="show",
                              cmd=command, reason=reason, why=why)
        return {"error": why, "device": target.name}

    started = time.monotonic()
    try:
        output = sessions.run_command(target, command, reason=reason, tool="show")
    except PermissionError as exc:
        return {"error": str(exc), "device": target.name}
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}", "device": target.name}

    ms = int((time.monotonic() - started) * 1000)
    result = {
        "device": target.name,
        "command": command,
        "output": audit.mask(output),
        "ms": ms,
        "transcript": sessions.format_result(target, command, reason, output, ms),
    }

    # The device answering "% Unknown command" is not a successful read, and
    # spotting that in the text should not be the caller's job.
    rejected = vendor.device_rejected(output)
    if rejected:
        result["device_rejected"] = audit.mask(rejected)
        result["error"] = (
            f"{target.name} rejected '{command}': {rejected}. The command may not "
            f"exist on this platform ({target.device_type}) — check the syntax for "
            f"the software it actually runs."
        )
    return result


def get_config(device: str, reason: str, section: str = "", startup: bool = False) -> dict[str, Any]:
    """Return a device's configuration, with secrets masked.

    Parameters
    ----------
    device: inventory name of the target device.
    reason: why the config is being read — recorded in the audit log.
    section: optional filter, e.g. "interface GigabitEthernet0/1" or "router bgp".
        Only the matching blocks are returned, which keeps large configs out of
        the context window.
    startup: read the startup config instead of the running config.
    """
    try:
        target = get_inventory().resolve(device)
    except InventoryError as exc:
        return {"error": str(exc)}

    command = (
        vendor.startup_config_command(target.device_type)
        if startup
        else vendor.running_config_command(target.device_type)
    )

    try:
        output = sessions.run_command(target, command, reason=reason, tool="get_config")
    except PermissionError as exc:
        return {"error": str(exc), "device": target.name}
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}", "device": target.name}

    # An empty config is a claim that the device will boot with nothing on it,
    # which is very different from "this platform ignored the command". FRR
    # accepts `show startup-config` and prints nothing at all, so silence is
    # reported as silence rather than as an empty configuration.
    if not output.strip():
        # No "config" key at all. An earlier version returned an error *and*
        # "config": "", and an agent read the empty string as the answer and
        # reported that a saved change had been lost from the startup config —
        # while the file on disk had it. A result that means "I could not read
        # this" must not also hand back something shaped like the answer.
        return {
            "device": target.name,
            "source": "startup" if startup else "running",
            "error": (
                f"COULD NOT READ the {'startup' if startup else 'running'} config: "
                f"'{command}' returned no output on {target.name} (device_type "
                f"{target.device_type}). This platform probably does not support that "
                f"command. This is NOT evidence that the config is empty or that a "
                f"change was lost — verify another way before concluding anything."
            ),
        }

    full_lines = len(output.splitlines())
    if section:
        output = _section(output, section)

    return {
        "device": target.name,
        "source": "startup" if startup else "running",
        "section": section or None,
        "lines": len(output.splitlines()),
        "total_lines": full_lines,
        "config": audit.mask(output),
    }


def _section(config: str, section: str) -> str:
    """Return the top-level blocks whose header contains *section*.

    A block runs from a non-indented line until the next non-indented line, so
    an interface or routing-process stanza comes back with its body attached.
    """
    needle = section.strip().lower()
    kept: list[str] = []
    in_block = False
    for line in config.splitlines():
        if line[:1].strip():  # non-indented: a new top-level block
            in_block = needle in line.lower()
        if in_block:
            kept.append(line)
    return "\n".join(kept)
