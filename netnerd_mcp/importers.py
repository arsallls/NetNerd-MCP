"""Build an inventory from the one the engineer already has.

Nobody hand-types five hundred devices. They are already listed in an Ansible
inventory or an SSH config, and re-typing them into a second file is the step
that stops someone trying this at all.

Two rules hold for everything here, and neither is negotiable:

**Imported devices are read-only.** A bulk import that produced five hundred
writable devices would turn one command into the widest blast radius in the
tool. Writability is granted per device, by hand, afterwards.

**Passwords are never copied.** Ansible inventories often carry
``ansible_password`` inline. Reading it and writing it into a second file
spreads the secret to somewhere its owner is not thinking about. What gets
written is a reference — ``${NET_PASS}``, or a keyring entry — and a count of
what was deliberately left behind.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Optional

import yaml

logger = logging.getLogger(__name__)

# ansible_network_os (long or short form) -> netmiko platform.
_NETWORK_OS = {
    "ios": "cisco_ios", "cisco.ios.ios": "cisco_ios",
    "iosxr": "cisco_xr", "cisco.iosxr.iosxr": "cisco_xr",
    "nxos": "cisco_nxos", "cisco.nxos.nxos": "cisco_nxos",
    "eos": "arista_eos", "arista.eos.eos": "arista_eos",
    "junos": "juniper_junos", "junipernetworks.junos.junos": "juniper_junos",
    "vyos": "vyos", "vyos.vyos.vyos": "vyos",
    "asa": "cisco_asa", "cisco.asa.asa": "cisco_asa",
}

# Keys whose value is a secret. Read to be counted, never written out.
_SECRET_KEYS = ("ansible_password", "ansible_ssh_pass", "ansible_become_pass",
                "ansible_become_password", "ansible_ssh_password")


class ImportError_(Exception):
    """The source could not be read or made sense of."""


def _platform(network_os: Optional[str]) -> tuple[str, bool]:
    """(netmiko platform, was it actually known)."""
    if not network_os:
        return "cisco_ios", False
    key = str(network_os).strip().lower()
    if key in _NETWORK_OS:
        return _NETWORK_OS[key], True
    # `cisco.ios.ios` style collections not in the table: take the last part.
    tail = key.rsplit(".", 1)[-1]
    if tail in _NETWORK_OS:
        return _NETWORK_OS[tail], True
    return "cisco_ios", False


def _walk_ansible(node: Any, inherited: dict, found: dict[str, dict]) -> None:
    """Collect hosts out of an Ansible YAML tree, carrying group vars down."""
    if not isinstance(node, dict):
        return
    here = {**inherited, **(node.get("vars") or {})}

    for name, host_vars in (node.get("hosts") or {}).items():
        merged = {**here, **(host_vars or {})}
        # A host in several groups: first definition wins, but later group
        # vars still fill gaps rather than being dropped.
        found.setdefault(name, {}).update({**merged, **found.get(name, {})})

    for child in (node.get("children") or {}).values():
        _walk_ansible(child, here, found)


def from_ansible(path: Path) -> tuple[list[dict], dict[str, Any]]:
    """Devices from an Ansible inventory. Returns (devices, report)."""
    try:
        text = Path(path).read_text()
    except OSError as exc:
        raise ImportError_(f"Could not read {path}: {exc}") from exc

    hosts: dict[str, dict] = {}
    try:
        tree = yaml.safe_load(text)
    except yaml.YAMLError:
        # An INI inventory is not valid YAML, and that is the common case
        # rather than an error — fall through and parse it as INI.
        tree = None

    if isinstance(tree, dict):
        if "all" in tree:
            _walk_ansible(tree["all"], {}, hosts)
        for key, group in tree.items():
            if key != "all" and isinstance(group, dict):
                _walk_ansible(group, {}, hosts)
    if not hosts:
        hosts = _from_ansible_ini(text)
    if not hosts:
        raise ImportError_(
            f"No hosts found in {path}. Expected an Ansible inventory — a YAML "
            f"tree with 'hosts:' entries, or an INI file with [group] sections.")

    devices, unknown, secrets = [], [], 0
    for name, host_vars in sorted(hosts.items()):
        platform, known = _platform(host_vars.get("ansible_network_os"))
        if not known:
            unknown.append(name)
        secrets += sum(1 for k in _SECRET_KEYS if host_vars.get(k))
        device = {
            "name": name,
            "host": str(host_vars.get("ansible_host") or name),
            "device_type": platform,
        }
        port = host_vars.get("ansible_port")
        if port and str(port) != "22":
            device["port"] = int(port)
        user = host_vars.get("ansible_user")
        if user and not str(user).startswith("{{"):  # skip Jinja templates
            device["username"] = str(user)
        devices.append(device)

    return devices, {"source": str(path), "found": len(devices),
                     "unknown_platform": unknown, "secrets_skipped": secrets}


_INI_HOST = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*(.*)$")


_INI_SECTION = re.compile(r"^\s*\[[^\]]+\]\s*$", re.M)


def _from_ansible_ini(text: str) -> dict[str, dict]:
    """Hosts from an INI-style inventory: `[group]` then `host key=value`.

    Requires at least one `[group]` header before reading anything. Without
    that guard a bare word on a line looks exactly like a hostname, so any
    text file at all would import as a set of devices — and these end up in
    the allowlist, which is the one place invented entries must not appear.
    """
    if not _INI_SECTION.search(text):
        return {}

    hosts: dict[str, dict] = {}
    group_vars: dict[str, dict] = {}
    group = ""
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            group = line[1:-1].strip()
            continue
        if group.endswith(":children"):
            continue
        pairs = dict(
            p.split("=", 1) for p in line.split() if "=" in p and not p.startswith("="))
        if group.endswith(":vars"):
            group_vars.setdefault(group[:-5], {}).update(pairs)
            continue
        match = _INI_HOST.match(line)
        if match and "=" not in match.group(1):
            hosts[match.group(1)] = {"_group": group, **pairs}

    for name, host_vars in hosts.items():
        inherited = group_vars.get(host_vars.pop("_group", ""), {})
        hosts[name] = {**inherited, **host_vars}
    return hosts


def from_ssh_config(path: Optional[Path] = None) -> tuple[list[dict], dict[str, Any]]:
    """Devices from ~/.ssh/config, skipping wildcard patterns."""
    config = Path(path or Path.home() / ".ssh" / "config")
    if not config.is_file():
        raise ImportError_(f"No SSH config at {config}.")

    from paramiko import SSHConfig

    try:
        parsed = SSHConfig.from_path(str(config))
    except Exception as exc:
        raise ImportError_(f"Could not parse {config}: {exc}") from exc

    devices = []
    for name in sorted(parsed.get_hostnames()):
        if "*" in name or "?" in name or name == "default":
            continue
        # ssh_config: true makes the server resolve hostname, user, port and
        # identity file at load time, so none of it is copied here. One source
        # of truth, and an edit to ~/.ssh/config keeps working.
        devices.append({"name": name, "host": name,
                        "device_type": "cisco_ios", "ssh_config": True})
    if not devices:
        raise ImportError_(f"No named hosts in {config} — only wildcard patterns.")
    return devices, {"source": str(config), "found": len(devices),
                     "unknown_platform": [d["name"] for d in devices],
                     "secrets_skipped": 0}


def to_yaml(devices: list[dict], secret_style: str = "env") -> str:
    """Render devices as an inventory, secrets referenced rather than written."""
    out: dict[str, dict] = {}
    for device in devices:
        entry: dict[str, Any] = {k: v for k, v in device.items() if k != "name"}
        # Read-only until someone says otherwise, per device, by hand.
        entry["writable"] = False
        if not entry.get("ssh_config"):
            entry.setdefault("username", "${NET_USER}")
            entry["password"] = ("${NET_PASS}" if secret_style == "env"
                                 else f"keyring:netnerd/{device['name']}")
        out[device["name"]] = entry
    return yaml.safe_dump({"devices": out}, sort_keys=False, default_flow_style=False)


def merge(existing: Optional[str], devices: list[dict],
          secret_style: str = "env") -> tuple[str, list[str], list[str]]:
    """Add *devices* to an existing inventory. Returns (yaml, added, skipped).

    A name already in the file is never overwritten. An import that silently
    replaced a hand-tuned entry — one someone had marked writable, or pointed
    at a jump host — would undo work with no way to notice.
    """
    current = yaml.safe_load(existing or "") or {}
    known = current.get("devices") or {}

    added, skipped = [], []
    fresh = []
    for device in devices:
        (skipped if device["name"] in known else added).append(device["name"])
        if device["name"] not in known:
            fresh.append(device)

    merged = yaml.safe_load(to_yaml(fresh, secret_style))["devices"] if fresh else {}
    current["devices"] = {**known, **merged}
    return yaml.safe_dump(current, sort_keys=False, default_flow_style=False), added, skipped
