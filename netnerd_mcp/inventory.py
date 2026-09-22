"""Device inventory.

A YAML file mapping names to connection details. Secrets are referenced as
``${ENV_VAR}`` and resolved from the environment, so the inventory itself is
safe to commit — the convention Ansible and Nornir users already expect.

    devices:
      core-sw1:
        host: 10.0.0.10
        device_type: cisco_ios
        writable: true
        username: ${NET_USER}
        password: ${NET_PASS}

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
    writable: bool = False

    def redacted(self) -> dict[str, Any]:
        """Safe to log — never includes the password."""
        return {"name": self.name, "host": self.host, "port": self.port,
                "device_type": self.device_type, "username": self.username,
                "writable": self.writable}


def _expand(value: Any) -> Any:
    """Replace ${VAR} references with environment values."""
    if not isinstance(value, str):
        return value

    def sub(m: re.Match) -> str:
        var = m.group(1)
        resolved = os.environ.get(var)
        if resolved is None:
            raise InventoryError(
                f"Inventory references ${{{var}}} but that environment variable is not set."
            )
        return resolved

    return _ENV_REF.sub(sub, value)


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
            devices[name] = Device(
                name=name,
                host=str(_expand(cfg["host"])),
                device_type=str(_expand(cfg.get("device_type", "cisco_ios"))),
                port=int(_expand(cfg.get("port", 22))),
                username=str(_expand(cfg.get("username", ""))),
                password=str(_expand(cfg.get("password", ""))),
                enable_secret=str(_expand(cfg.get("enable_secret", ""))),
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
