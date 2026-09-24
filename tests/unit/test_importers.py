"""Building an inventory from one the engineer already has.

Two properties matter more than the parsing: an import must not copy secrets
into a new file, and it must not produce writable devices. Everything else is
convenience; those two are the reason importing is safe to offer at all.
"""
from __future__ import annotations

import textwrap

import pytest
import yaml

from netnerd_mcp import importers


def _write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(textwrap.dedent(text).lstrip())
    return path


ANSIBLE_YAML = """
    all:
      vars:
        ansible_user: netadmin
      children:
        ios_switches:
          hosts:
            core-sw1:
              ansible_host: 10.0.0.10
            core-sw2:
              ansible_host: 10.0.0.11
              ansible_password: hunter2
          vars:
            ansible_network_os: cisco.ios.ios
        eos_spines:
          hosts:
            spine1: {ansible_host: 10.0.1.1}
          vars:
            ansible_network_os: eos
        oddballs:
          hosts:
            mystery-box: {ansible_host: 10.0.9.9, ansible_port: 2222}
"""


class TestSecretsAreNeverCopied:
    def test_an_inline_ansible_password_does_not_reach_the_new_file(self, tmp_path):
        """Reading a password out of one file and writing it into another
        spreads it somewhere its owner is not thinking about."""
        devices, report = importers.from_ansible(_write(tmp_path, "h.yml", ANSIBLE_YAML))
        rendered = importers.to_yaml(devices)

        assert "hunter2" not in rendered
        assert report["secrets_skipped"] == 1
        assert "${NET_PASS}" in rendered

    def test_the_count_of_skipped_secrets_is_reported(self, tmp_path):
        """Silently dropping them would look like there were none to drop."""
        _, report = importers.from_ansible(_write(tmp_path, "h.yml", ANSIBLE_YAML))
        assert report["secrets_skipped"] == 1

    def test_keyring_style_references_the_keychain_instead(self, tmp_path):
        devices, _ = importers.from_ansible(_write(tmp_path, "h.yml", ANSIBLE_YAML))
        rendered = importers.to_yaml(devices, secret_style="keyring")

        assert "keyring:netnerd/core-sw1" in rendered
        assert "${NET_PASS}" not in rendered


class TestImportsAreReadOnly:
    def test_every_imported_device_is_writable_false(self, tmp_path):
        """A bulk import that produced 500 writable devices would turn one
        command into the widest blast radius in the tool."""
        devices, _ = importers.from_ansible(_write(tmp_path, "h.yml", ANSIBLE_YAML))
        parsed = yaml.safe_load(importers.to_yaml(devices))["devices"]

        assert parsed, "nothing was imported"
        assert all(d["writable"] is False for d in parsed.values())


class TestAnsibleYaml:
    def test_group_vars_reach_the_hosts_under_them(self, tmp_path):
        devices, _ = importers.from_ansible(_write(tmp_path, "h.yml", ANSIBLE_YAML))
        by_name = {d["name"]: d for d in devices}

        assert by_name["core-sw1"]["username"] == "netadmin"   # from all.vars
        assert by_name["core-sw1"]["device_type"] == "cisco_ios"
        assert by_name["spine1"]["device_type"] == "arista_eos"

    def test_ansible_host_wins_over_the_inventory_name(self, tmp_path):
        devices, _ = importers.from_ansible(_write(tmp_path, "h.yml", ANSIBLE_YAML))
        assert {d["name"]: d["host"] for d in devices}["core-sw1"] == "10.0.0.10"

    def test_a_non_default_port_is_kept(self, tmp_path):
        devices, _ = importers.from_ansible(_write(tmp_path, "h.yml", ANSIBLE_YAML))
        assert {d["name"]: d.get("port") for d in devices}["mystery-box"] == 2222

    def test_an_unknown_platform_is_named_not_quietly_guessed(self, tmp_path):
        """It still defaults to cisco_ios, because that is the most widely
        imitated CLI — but the caller is told which devices were guessed at."""
        devices, report = importers.from_ansible(_write(tmp_path, "h.yml", ANSIBLE_YAML))

        assert report["unknown_platform"] == ["mystery-box"]
        assert {d["name"]: d for d in devices}["mystery-box"]["device_type"] == "cisco_ios"

    def test_a_jinja_templated_user_is_not_imported_literally(self, tmp_path):
        path = _write(tmp_path, "h.yml", """
            all:
              hosts:
                sw1:
                  ansible_host: 10.0.0.1
                  ansible_user: "{{ vault_user }}"
        """)
        devices, _ = importers.from_ansible(path)
        assert "username" not in devices[0], "an unrendered template is not a username"

    def test_a_file_with_no_hosts_is_an_error_not_an_empty_import(self, tmp_path):
        """An empty result would read as 'imported successfully, zero devices'."""
        with pytest.raises(importers.ImportError_):
            importers.from_ansible(_write(tmp_path, "h.yml", "some_key: value\n"))


class TestAnsibleIni:
    INI = """
        [ios_switches]
        sw-a ansible_host=10.1.0.1
        sw-b ansible_host=10.1.0.2 ansible_port=2022

        [ios_switches:vars]
        ansible_network_os=ios
        ansible_user=admin

        [junipers]
        edge1 ansible_host=10.2.0.1

        [junipers:vars]
        ansible_network_os=junos
    """

    def test_an_ini_inventory_is_read_when_it_is_not_valid_yaml(self, tmp_path):
        devices, _ = importers.from_ansible(_write(tmp_path, "h.ini", self.INI))
        assert {d["name"] for d in devices} == {"sw-a", "sw-b", "edge1"}

    def test_group_vars_apply_to_their_own_group_only(self, tmp_path):
        devices, _ = importers.from_ansible(_write(tmp_path, "h.ini", self.INI))
        by_name = {d["name"]: d for d in devices}

        assert by_name["sw-a"]["device_type"] == "cisco_ios"
        assert by_name["sw-a"]["username"] == "admin"
        assert by_name["edge1"]["device_type"] == "juniper_junos"
        assert "username" not in by_name["edge1"], "admin belongs to ios_switches"


class TestMerging:
    def test_an_existing_device_is_never_overwritten(self, tmp_path):
        """Someone marked that device writable, or pointed it at a jump host.
        Replacing it from an import would undo the work with nothing to see."""
        existing = yaml.safe_dump({"devices": {"core-sw1": {
            "host": "10.0.0.10", "device_type": "cisco_ios",
            "writable": True, "password": "keyring:netnerd/core-sw1"}}})
        devices, _ = importers.from_ansible(_write(tmp_path, "h.yml", ANSIBLE_YAML))

        merged, added, skipped = importers.merge(existing, devices)
        parsed = yaml.safe_load(merged)["devices"]

        assert skipped == ["core-sw1"]
        assert parsed["core-sw1"]["writable"] is True
        assert parsed["core-sw1"]["password"] == "keyring:netnerd/core-sw1"
        assert set(added) == {"core-sw2", "spine1", "mystery-box"}

    def test_merging_into_nothing_just_writes_the_devices(self, tmp_path):
        devices, _ = importers.from_ansible(_write(tmp_path, "h.yml", ANSIBLE_YAML))
        merged, added, skipped = importers.merge(None, devices)

        assert not skipped and len(added) == 4
        assert len(yaml.safe_load(merged)["devices"]) == 4


class TestSshConfig:
    def test_wildcard_patterns_are_not_devices(self, tmp_path):
        config = _write(tmp_path, "config", """
            Host *
              ServerAliveInterval 60

            Host edge-rtr1
              HostName 10.0.0.1
              User netops
        """)
        devices, _ = importers.from_ssh_config(config)

        assert [d["name"] for d in devices] == ["edge-rtr1"]

    def test_the_ssh_config_stays_the_source_of_truth(self, tmp_path):
        """ssh_config: true makes the server resolve hostname, user, port and
        identity at load time, so an edit to ~/.ssh/config keeps working."""
        config = _write(tmp_path, "config", """
            Host edge-rtr1
              HostName 10.0.0.1
              User netops
        """)
        devices, _ = importers.from_ssh_config(config)

        assert devices[0]["ssh_config"] is True
        assert "password" not in importers.to_yaml(devices).split("edge-rtr1")[1]

    def test_a_config_with_only_wildcards_is_an_error(self, tmp_path):
        config = _write(tmp_path, "config", "Host *\n  ServerAliveInterval 60\n")
        with pytest.raises(importers.ImportError_):
            importers.from_ssh_config(config)
