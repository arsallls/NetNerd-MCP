"""Per-vendor command strings.

Keyed on the netmiko device_type from the inventory, never guessed from a
device's name or prompt.
"""
from __future__ import annotations

import re

_RUNNING = {
    "juniper_junos": "show configuration",
    "juniper": "show configuration",
    "linux": "cat /etc/network/interfaces",
    "vyos": "show configuration commands",
}
_STARTUP = {
    "juniper_junos": "show configuration",
    "juniper": "show configuration",
}
_SAVE = {
    "juniper_junos": "commit",
    "juniper": "commit",
    "arista_eos": "write memory",
    "cisco_nxos": "copy running-config startup-config",
    "cisco_ios": "write memory",
    "cisco_xe": "write memory",
}

# Platforms where netmiko can ask the device itself to revert an unconfirmed
# change. Everything else relies on the server-side rollback timer.
_NATIVE_COMMIT_CONFIRM = {"juniper_junos", "juniper"}


def running_config_command(device_type: str) -> str:
    return _RUNNING.get(device_type, "show running-config")


def startup_config_command(device_type: str) -> str:
    return _STARTUP.get(device_type, "show startup-config")


def save_command(device_type: str) -> str:
    return _SAVE.get(device_type, "write memory")


def supports_native_commit_confirm(device_type: str) -> bool:
    return device_type in _NATIVE_COMMIT_CONFIRM


# Topology discovery. Candidates are tried in order until one is not rejected,
# rather than picked from device_type alone: the lab's FRR routers are typed
# cisco_ios because that is the netmiko driver that speaks vtysh, so the type
# cannot tell real IOS from FRR. A rejected first attempt costs one round trip
# and lands in the audit log, which is what a human would do anyway.
#
# Interface commands are ordered to prefer output carrying a prefix length.
# Without a mask, an interface is still recorded but cannot be used to infer
# which devices share a subnet.
_DISCOVERY = {
    "cisco_ios": {
        "interfaces": ["show interface brief", "show ip interface brief"],
        "lldp": ["show lldp neighbors detail", "show cdp neighbors detail"],
        "bgp": ["show ip bgp summary"],
        "ospf": ["show ip ospf neighbor"],
    },
    "arista_eos": {
        "interfaces": ["show ip interface brief"],
        "lldp": ["show lldp neighbors detail"],
        "bgp": ["show ip bgp summary"],
        "ospf": ["show ip ospf neighbor"],
    },
    "juniper_junos": {
        "interfaces": ["show interfaces terse"],
        "lldp": ["show lldp neighbors"],
        "bgp": ["show bgp summary"],
        "ospf": ["show ospf neighbor"],
    },
    "linux": {
        "interfaces": ["ip address show"],
        "lldp": ["lldpctl"],
        "bgp": [],
        "ospf": [],
    },
}
_DISCOVERY["cisco_xe"] = _DISCOVERY["cisco_ios"]
_DISCOVERY["cisco_nxos"] = _DISCOVERY["cisco_ios"]
_DISCOVERY["juniper"] = _DISCOVERY["juniper_junos"]


def discovery_commands(device_type: str, kind: str) -> list[str]:
    """Candidate commands for one discovery source, best first.

    An unknown platform falls back to the IOS-style set — those commands are
    the most widely imitated, and a rejection is detected rather than guessed.
    """
    table = _DISCOVERY.get(device_type, _DISCOVERY["cisco_ios"])
    return table.get(kind, [])


# A device that refuses a command says so in the output and returns normally —
# netmiko raises nothing. Matching is on specific failure phrasing, not on a
# leading "%": FRR prints "% Can't open configuration file /etc/frr/vtysh.conf"
# and "processing failure: 11" on every successful command in the lab, so
# anything looser reports failure on healthy writes.
_REJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)%\s*configuration write failed"),
    re.compile(r"(?i)read-only file system"),
    re.compile(r"(?i)%\s*(invalid|incomplete|unknown|ambiguous)\s+(input|command)"),
    re.compile(r"(?i)%\s*authorization failed"),
    re.compile(r"(?i)%\s*error:.*(failed|denied|unable)"),
    re.compile(r"(?i)%\s*permission denied"),
]


def device_rejected(output: str) -> str:
    """Return the device's own error lines, or "" if it accepted the command."""
    hits = [
        line.strip()
        for line in output.splitlines()
        if any(pattern.search(line) for pattern in _REJECTION_PATTERNS)
    ]
    return "\n".join(hits)
