"""Inventory resolution: the allowlist, and where credentials come from.

The inventory is the security boundary — a device that is not in it cannot be
reached — so the failure modes matter more than the happy paths. Every one of
these asserts that a missing secret raises rather than quietly becoming "".
"""
from __future__ import annotations

import sys
import types

import pytest

from netnerd_mcp import inventory
from netnerd_mcp.inventory import Inventory, InventoryError


def _write(tmp_path, body: str):
    path = tmp_path / "inventory.yaml"
    path.write_text(body)
    return path


class TestEnvRefs:
    def test_env_refs_are_resolved(self, tmp_path, monkeypatch):
        monkeypatch.setenv("TEST_USER", "netops")
        monkeypatch.setenv("TEST_PASS", "s3cret")
        path = _write(tmp_path, """
devices:
  r1:
    host: 10.0.0.1
    username: ${TEST_USER}
    password: ${TEST_PASS}
""")
        device = Inventory.load(path).resolve("r1")

        assert device.username == "netops"
        assert device.password == "s3cret"

    def test_a_missing_env_var_raises_rather_than_blanking(self, tmp_path, monkeypatch):
        monkeypatch.delenv("DEFINITELY_NOT_SET", raising=False)
        path = _write(tmp_path, """
devices:
  r1:
    host: 10.0.0.1
    password: ${DEFINITELY_NOT_SET}
""")
        with pytest.raises(InventoryError, match="DEFINITELY_NOT_SET"):
            Inventory.load(path)


class TestKeyringRefs:
    @pytest.fixture
    def fake_keyring(self, monkeypatch):
        store: dict[tuple[str, str], str] = {}
        module = types.ModuleType("keyring")
        module.get_password = lambda service, user: store.get((service, user))
        monkeypatch.setitem(sys.modules, "keyring", module)
        return store

    def test_a_keyring_ref_is_read_from_the_keychain(self, tmp_path, fake_keyring):
        fake_keyring[("netnerd", "r1")] = "from-the-keychain"
        path = _write(tmp_path, """
devices:
  r1:
    host: 10.0.0.1
    password: keyring:netnerd/r1
""")
        assert Inventory.load(path).resolve("r1").password == "from-the-keychain"

    def test_a_missing_keychain_entry_raises(self, tmp_path, fake_keyring):
        """Falling through to "" would turn a missing secret into an anonymous
        login attempt against real gear."""
        path = _write(tmp_path, """
devices:
  r1:
    host: 10.0.0.1
    password: keyring:netnerd/nobody
""")
        with pytest.raises(InventoryError, match="No keychain entry"):
            Inventory.load(path)

    def test_a_missing_keyring_package_says_how_to_install_it(self, tmp_path, monkeypatch):
        monkeypatch.setitem(sys.modules, "keyring", None)  # import raises
        path = _write(tmp_path, """
devices:
  r1:
    host: 10.0.0.1
    password: keyring:netnerd/r1
""")
        with pytest.raises(InventoryError, match=r"netnerd-mcp\[vault\]"):
            Inventory.load(path)


class TestSshConfig:
    @pytest.fixture
    def ssh_config(self, tmp_path, monkeypatch):
        home = tmp_path / "home"
        (home / ".ssh").mkdir(parents=True)
        (home / ".ssh" / "config").write_text("""
Host edge-rtr1
    HostName 192.0.2.50
    User fieldtech
    Port 2022
    IdentityFile ~/.ssh/id_lab
""")
        monkeypatch.setattr(inventory.Path, "home", staticmethod(lambda: home))
        return home

    def test_ssh_config_fills_in_what_the_inventory_omits(self, tmp_path, ssh_config):
        path = _write(tmp_path, """
devices:
  edge1:
    host: edge-rtr1
    ssh_config: true
""")
        device = Inventory.load(path).resolve("edge1")

        assert device.host == "192.0.2.50"
        assert device.username == "fieldtech"
        assert device.port == 2022
        assert device.key_file.endswith("id_lab")

    def test_the_inventory_wins_over_the_ssh_config(self, tmp_path, ssh_config):
        """Otherwise a stanza in ~/.ssh/config could silently redirect a device
        the inventory pins to a specific user."""
        path = _write(tmp_path, """
devices:
  edge1:
    host: edge-rtr1
    ssh_config: true
    username: netnerd
    port: 22
""")
        device = Inventory.load(path).resolve("edge1")

        assert device.username == "netnerd"
        assert device.port == 22
        assert device.host == "192.0.2.50"  # not overridden, so still filled in

    def test_ssh_config_is_not_consulted_unless_asked(self, tmp_path, ssh_config):
        path = _write(tmp_path, """
devices:
  edge1:
    host: edge-rtr1
""")
        device = Inventory.load(path).resolve("edge1")

        assert device.host == "edge-rtr1"
        assert device.username == ""
        assert device.key_file == ""


class TestAllowlist:
    def test_an_unlisted_device_is_refused(self, tmp_path):
        path = _write(tmp_path, "devices:\n  r1:\n    host: 10.0.0.1\n")
        with pytest.raises(InventoryError, match="Unknown device"):
            Inventory.load(path).resolve("10.0.0.99")

    def test_a_listed_host_resolves_as_well_as_its_name(self, tmp_path):
        path = _write(tmp_path, "devices:\n  r1:\n    host: 10.0.0.1\n")
        assert Inventory.load(path).resolve("10.0.0.1").name == "r1"
