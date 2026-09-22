"""
Cisco Genie / pyATS CLI output parser.

Wraps ``genie.libs.parser`` to convert raw IOS-XE show-command output into
structured Python dictionaries.  Falls back gracefully to returning the raw
string when no Genie parser exists for a command, or when the Genie library
is not installed.
"""

from __future__ import annotations

import logging
from typing import Any, Union

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional import – Genie may not be available in all environments.
# ---------------------------------------------------------------------------
try:
    from genie.libs.parser.utils import get_parser
    from genie.conf.base import Device as GenieDevice

    _GENIE_AVAILABLE = True
    logger.debug("Genie library loaded successfully.")
except ImportError:
    _GENIE_AVAILABLE = False
    logger.warning(
        "Genie/pyATS library not found. Parser will fall back to returning "
        "raw CLI strings. Install 'genie' and 'pyats' for structured output."
    )


# ---------------------------------------------------------------------------
# GenieParser
# ---------------------------------------------------------------------------


class GenieParser:
    """
    Parses Cisco CLI output into structured dictionaries using Genie.

    When Genie is unavailable or when no parser exists for a given command,
    the raw string is returned unchanged so callers always receive *something*
    useful.

    Usage
    -----
    .. code-block:: python

        parser = GenieParser()
        result = parser.parse(raw_output, "show interfaces", device_type="iosxe")
        # result is a dict (or the raw string if parsing failed)
    """

    def parse(
        self,
        device_output: str,
        command: str,
        device_type: str = "iosxe",
        hostname: str = "virtual-device",
    ) -> Union[dict[str, Any], str]:
        """
        Parse raw CLI *device_output* for *command* using Genie.

        Parameters
        ----------
        device_output:
            The raw string returned by the device for *command*.
        command:
            The CLI command that produced *device_output* (e.g.
            ``"show interfaces"``).  Used to select the correct Genie parser.
        device_type:
            OS/platform type understood by Genie (default ``"iosxe"``).
            Other valid values: ``"ios"``, ``"nxos"``, ``"iosxr"``, etc.
        hostname:
            Logical name assigned to the virtual device object used
            internally by Genie (does not need to match the real device).

        Returns
        -------
        dict | str
            Parsed output as a dictionary when a Genie parser is available and
            succeeds, otherwise the raw *device_output* string.
        """
        if not device_output or not device_output.strip():
            logger.debug("Empty output for command '%s', returning empty dict.", command)
            return {}

        if not _GENIE_AVAILABLE:
            logger.debug(
                "Genie unavailable; returning raw output for command '%s'.", command
            )
            return device_output

        return self._parse_with_genie(device_output, command, device_type, hostname)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _parse_with_genie(
        self,
        device_output: str,
        command: str,
        device_type: str,
        hostname: str,
    ) -> Union[dict[str, Any], str]:
        """Attempt Genie parsing; fall back to raw string on any error."""
        try:
            # Build a minimal virtual Genie device so we can invoke its parsers.
            device = self._build_virtual_device(hostname, device_type)
            parser_cls = get_parser(command, device)
            parser_instance = parser_cls(device=device)

            # Feed the pre-collected CLI text directly to avoid a real SSH call.
            parsed: dict[str, Any] = parser_instance.parse(output=device_output)
            logger.debug(
                "Genie parsed '%s' successfully (%d top-level keys).",
                command,
                len(parsed),
            )
            return parsed

        except Exception as exc:
            # This covers SchemaEmptyParserError, KeyError, AttributeError, etc.
            logger.info(
                "Genie could not parse command '%s' (%s: %s). Returning raw output.",
                command,
                type(exc).__name__,
                exc,
            )
            return device_output

    @staticmethod
    def _build_virtual_device(hostname: str, os_type: str) -> "GenieDevice":
        """
        Create a minimal ``genie.conf.base.Device`` that points to no real host.

        Genie parsers require a device object to look up platform-specific
        grammar; we provide a lightweight stub instead of a live connection.
        """
        device = GenieDevice(hostname)
        device.os = os_type
        # Prevent Genie from attempting actual connectivity.
        device.custom.setdefault("abstraction", {})["order"] = ["os"]
        return device

    # ------------------------------------------------------------------
    # Convenience helpers for common commands
    # ------------------------------------------------------------------

    def parse_interfaces(
        self, raw_output: str, device_type: str = "iosxe"
    ) -> Union[dict[str, Any], str]:
        """Shortcut for parsing ``show interfaces`` output."""
        return self.parse(raw_output, "show interfaces", device_type=device_type)

    def parse_ip_brief(
        self, raw_output: str, device_type: str = "iosxe"
    ) -> Union[dict[str, Any], str]:
        """Shortcut for parsing ``show ip interface brief`` output."""
        return self.parse(raw_output, "show ip interface brief", device_type=device_type)

    def parse_bgp_summary(
        self, raw_output: str, device_type: str = "iosxe"
    ) -> Union[dict[str, Any], str]:
        """Shortcut for parsing ``show bgp summary`` output."""
        return self.parse(raw_output, "show bgp summary", device_type=device_type)

    def parse_bgp_neighbors(
        self, raw_output: str, device_type: str = "iosxe"
    ) -> Union[dict[str, Any], str]:
        """Shortcut for parsing ``show bgp neighbors`` output."""
        return self.parse(raw_output, "show bgp neighbors", device_type=device_type)
