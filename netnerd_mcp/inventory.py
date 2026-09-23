"""Device inventory.

A YAML file mapping names to connection details. Secrets are referenced rather
than written down, so the inventory itself is safe to commit.

    devices:
      core-sw1:
        host: 10.0.0.10
        device_type: cisco_ios
        writable: true
        username: ${NET_USER}
        password: ${NET_PASS}

      edge-rtr1:
        host: edge-rtr1            # resolved through ~/.ssh/config
        ssh_config: true
        password: keyring:netnerd/edge-rtr1

Two reference forms are understood:

``${ENV_VAR}``
    Read from the environment — the convention Ansible and Nornir users
    already expect.

``keyring:SERVICE/USERNAME``
    Read from the OS keychain (macOS Keychain, GNOME Secret Service, Windows
    Credential Manager) via the optional ``keyring`` package. This is the
    "encrypted local vault" without inventing a file format: the OS already
    has one, and it is already unlocked by the user's login.

``ssh_config: true`` fills in hostname, user, port and identity file from
``~/.ssh/config`` for hosts already configured there. Anything set explicitly
in the inventory wins over what the SSH config says.

The inventory is also an allowlist: a device that is not listed cannot be
reached, so the model can never open a session to an arbitrary address it read
out of command output. Lookups accept the inventory name or the listed host.
"""
from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import yaml

logger = logging.getLogger(__name__)

_ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
_KEYRING_REF = re.compile(r"^keyring:([^/]+)/(.+)$")

def _default_paths() -> list[Path]:
    paths = []
    if os.environ.get("NETNERD_INVENTORY"):
        paths.append(Path(os.environ["NETNERD_INVENTORY"]))
    paths.append(Path.cwd() / "inventory.yaml")
    paths.append(Path.home() / ".netnerd" / "inventory.yaml")
    return paths


class InventoryError(Exception):
    """Raised when a device cannot be resolved or the inventory is malformed."""


@dataclass(frozen=True)
class Device:
    name: str
    host: str
    device_type: str = "cisco_ios"
    port: int = 22
    username: str = ""
    password: str = ""
    enable_secret: str = ""
    key_file: str = ""
    writable: bool = False

    def redacted(self) -> dict[str, Any]:
        """Safe to log — never includes the password."""
        return {"name": self.name, "host": self.host, "port": self.port,
                "device_type": self.device_type, "username": self.username,
                "writable": self.writable}


def _from_keyring(service: str, username: str) -> str:
    try:
        import keyring
    except ImportError as exc:
        raise InventoryError(
            f"Inventory uses 'keyring:{service}/{username}' but the keyring package "
            f"is not installed. Install it with: pip install 'netnerd-mcp[vault]'"
        ) from exc

    secret = keyring.get_password(service, username)
    if secret is None:
        # Fail closed. Falling through to an empty password would turn a
        # missing secret into an anonymous login attempt against real gear.
        raise InventoryError(
            f"No keychain entry for service '{service}', user '{username}'. "
            f"Add it with: keyring set {service} {username}"
        )
    return secret


def _expand(value: Any) -> Any:
    """Resolve ${ENV_VAR} and keyring:SERVICE/USER references."""
    if not isinstance(value, str):
        return value

    ref = _KEYRING_REF.match(value.strip())
    if ref:
        return _from_keyring(ref.group(1), ref.group(2))

    def sub(m: re.Match) -> str:
        var = m.group(1)
        resolved = os.environ.get(var)
        if resolved is None:
            raise InventoryError(
                f"Inventory references ${{{var}}} but that environment variable is not set."
            )
        return resolved

    return _ENV_REF.sub(sub, value)


def _ssh_config_defaults(host: str) -> dict[str, str]:
    """Look *host* up in ~/.ssh/config, returning only what it defines.

    Paramiko already ships with netmiko, so this costs nothing. Returns an
    empty mapping when there is no config file or no matching stanza.
    """
    path = Path.home() / ".ssh" / "config"
    if not path.is_file():
        return {}

    from paramiko import SSHConfig

    try:
        entry = SSHConfig.from_path(str(path)).lookup(host)
    except Exception as exc:  # a malformed config should not be fatal
        logger.warning("Could not read %s for '%s': %s", path, host, exc)
        return {}

    found: dict[str, str] = {}
    if entry.get("hostname") and entry["hostname"] != host:
        found["host"] = entry["hostname"]
    if entry.get("user"):
        found["username"] = entry["user"]
    if entry.get("port"):
        found["port"] = str(entry["port"])
    identities = entry.get("identityfile") or []
    if identities:
        found["key_file"] = str(Path(identities[0]).expanduser())
    return found


class Inventory:
    def __init__(self, devices: dict[str, Device], source: Optional[Path] = None) -> None:
        self._devices = devices
        self.source = source
        # Secondary index so a bare IP resolves too.
        self._by_host = {d.host: d for d in devices.values()}

    # ------------------------------------------------------------------
    @classmethod
    def load(cls, path: Optional[Path] = None) -> "Inventory":
        candidates = [path] if path else _default_paths()
        for candidate in candidates:
            if candidate and candidate.is_file():
                return cls._from_file(candidate)
        logger.warning(
            "No inventory file found (looked in: %s). No device can be reached "
            "until one exists — the inventory is the allowlist.",
            ", ".join(str(c) for c in candidates if c),
        )
        return cls({}, source=None)

    @classmethod
    def _from_file(cls, path: Path) -> "Inventory":
        raw = yaml.safe_load(path.read_text()) or {}
        entries = raw.get("devices") or {}
        if not isinstance(entries, dict):
            raise InventoryError(f"{path}: 'devices' must be a mapping of name -> settings.")

        devices: dict[str, Device] = {}
        for name, cfg in entries.items():
            if not isinstance(cfg, dict):
                raise InventoryError(f"{path}: device '{name}' must be a mapping.")
            if "host" not in cfg:
                raise InventoryError(f"{path}: device '{name}' is missing 'host'.")

            host = str(_expand(cfg["host"]))
            # An explicit inventory value always wins; the SSH config only
            # fills gaps. Otherwise a stanza in ~/.ssh/config could silently
            # redirect a device the inventory pins to a specific address.
            defaults = _ssh_config_defaults(host) if cfg.get("ssh_config") else {}

            def field(key: str, fallback: str = "") -> str:
                if key in cfg:
                    return str(_expand(cfg[key]))
                return defaults.get(key, fallback)

            devices[name] = Device(
                name=name,
                host=defaults.get("host", host),
                device_type=str(_expand(cfg.get("device_type", "cisco_ios"))),
                port=int(field("port", "22")),
                username=field("username"),
                password=field("password"),
                enable_secret=field("enable_secret"),
                key_file=field("key_file"),
                writable=bool(cfg.get("writable", False)),
            )
        logger.info("Loaded %d device(s) from %s", len(devices), path)
        return cls(devices, source=path)

    # ------------------------------------------------------------------
    def resolve(self, key: str) -> Device:
        """Resolve an inventory name or a listed host to a Device.

        Anything not in the inventory is refused: the inventory is the
        allowlist, so an address the model saw in command output is not
        reachable unless someone put it in the file.
        """
        if key in self._devices:
            return self._devices[key]
        if key in self._by_host:
            return self._by_host[key]

        known = ", ".join(sorted(self._devices)) or "none"
        raise InventoryError(
            f"Unknown device '{key}'. Known devices: {known}. "
            f"Add it to the inventory file to make it reachable."
        )

    def all(self) -> list[Device]:
        return [self._devices[n] for n in sorted(self._devices)]

    def names(self) -> list[str]:
        return sorted(self._devices)

    def __len__(self) -> int:
        return len(self._devices)


_inventory: Optional[Inventory] = None


def get_inventory() -> Inventory:
    """The loaded inventory, read from disk once per process."""
    global _inventory
    if _inventory is None:
        _inventory = Inventory.load()
    return _inventory


def reset_inventory() -> None:
    """Force the next get_inventory() to re-read from disk (tests)."""
    global _inventory
    _inventory = None
