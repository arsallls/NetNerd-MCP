"""Turn raw CLI output into something small enough to be worth sending.

A `show ip route` on a real router is thousands of lines. Handing that to a
model burns the context window on text it has to re-parse anyway, so the
parsing happens here instead and only the structured result goes back.

Two parsers, tried in order:

``ntc-templates``
    TextFSM templates covering roughly a thousand command/platform pairs.
    Already installed — netmiko depends on it — so this costs nothing.

``genie``
    Cisco's pyATS parsers, richer on IOS-XE but hundreds of megabytes, so it
    stays an optional extra and is only tried when ntc-templates has no
    template for the command.

Neither is authoritative. When both decline, the raw text goes back unchanged
— capped, and under a key that says it is an excerpt.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from netnerd_mcp.config.settings import settings

logger = logging.getLogger(__name__)

# ntc-templates names platforms the way netmiko does, so the inventory's
# device_type usually passes straight through. These are the exceptions.
_PLATFORM_ALIASES = {
    "cisco_xe": "cisco_ios",
    "cisco_ios_telnet": "cisco_ios",
    "arista_eos_telnet": "arista_eos",
    "juniper": "juniper_junos",
}


def _platform(device_type: str) -> str:
    return _PLATFORM_ALIASES.get(device_type, device_type)


def structured(output: str, command: str, device_type: str) -> Optional[list[dict]]:
    """Parse *output* into rows, or None if no parser understands it.

    Pure function over text that has already been read from the device, so the
    audit trail still records exactly what the device said — parsing never
    happens on the way in.
    """
    if not output or not output.strip():
        return None

    platform = _platform(device_type)

    try:
        from ntc_templates.parse import parse_output

        rows = parse_output(platform=platform, command=command, data=output)
        if rows:
            return rows
    except Exception as exc:
        # No template for this command/platform is the common case and not
        # worth a warning; it is the normal path for FRR and anything exotic.
        logger.debug("ntc-templates declined '%s' on %s: %s", command, platform, exc)

    try:
        from netnerd_mcp.drivers.parser import GenieParser

        parsed = GenieParser().parse(output, command, device_type=platform)
        if isinstance(parsed, dict) and parsed:
            return [parsed]
    except Exception as exc:
        logger.debug("Genie declined '%s' on %s: %s", command, platform, exc)

    return None


def excerpt(text: str, max_lines: Optional[int] = None) -> Optional[dict[str, Any]]:
    """Cap *text* for return to the model, or None if it is already short.

    The result deliberately uses no key named ``output`` or ``config``. An
    earlier version of get_config returned an empty ``config`` alongside a
    warning and an agent reported the empty string as fact; a partial result
    must not be shaped like a complete one.
    """
    limit = settings.MAX_OUTPUT_LINES if max_lines is None else max_lines
    lines = text.splitlines()
    if len(lines) <= limit:
        return None

    head = limit * 2 // 3
    tail = limit - head
    return {
        "truncated": True,
        "total_lines": len(lines),
        "shown_lines": limit,
        "excerpt": "\n".join(lines[:head] + [
            f"... [{len(lines) - limit} lines omitted from the middle] ...",
        ] + lines[-tail:]),
        "note": (
            f"This is an EXCERPT, not the full output ({len(lines)} lines total). "
            f"Do not conclude anything from what is absent here — narrow the "
            f"command or use a section filter to see the rest."
        ),
    }
