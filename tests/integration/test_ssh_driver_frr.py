"""Integration tests against the FRR lab (`make lab`).

Real SSH, real routing daemons, real device state — the SSH driver is never
mocked, because what these tests are actually verifying is that commands
survive the round trip to a device and come back parseable.

FRR's vtysh presents an IOS-like CLI, so netmiko's stock ``cisco_ios`` driver
drives it unmodified. These exercise the same code path production does.
"""
from __future__ import annotations

import pytest

from tests.conftest import requires_lab

pytestmark = [pytest.mark.integration, requires_lab]


class TestRealDeviceReads:
    def test_connects_and_returns_live_bgp_state(self, driver, r1):
        with driver.managed_connection(r1["host"], port=r1["port"]) as conn:
            out = driver.run_command(conn, "show ip bgp summary")

        # r1 (AS 65001) peers with r2 (AS 65002) — this is live protocol state,
        # not a fixture.
        assert "65002" in out, out
        assert r1["router_id"] in out, out

    def test_routing_table_reflects_learned_bgp_prefix(self, driver, r1):
        with driver.managed_connection(r1["host"], port=r1["port"]) as conn:
            out = driver.run_command(conn, "show ip route")

        # 10.2.2.2/32 is originated by r2 and learned over the eBGP session.
        assert "10.2.2.2" in out, f"BGP prefix from r2 not in r1's table:\n{out}"

    def test_display_filter_survives_the_round_trip(self, driver, r1):
        with driver.managed_connection(r1["host"], port=r1["port"]) as conn:
            out = driver.run_command(conn, "show ip bgp summary | include 65002")

        assert "65002" in out
        assert "IPv4 Unicast Summary" not in out, "pipe filter was not applied"


class TestReadOnlyEnforcement:
    """Read-only is enforced in the driver, not the tool layer — a tool that
    forgets to check still cannot write."""

    def test_blocks_write_command_against_a_real_device(self, readonly_driver, r1):
        with readonly_driver.managed_connection(r1["host"], port=r1["port"]) as conn:
            with pytest.raises(PermissionError, match="READ_ONLY_MODE"):
                readonly_driver.run_command(conn, "configure terminal")

    def test_blocks_config_set_against_a_real_device(self, readonly_driver, r1):
        with readonly_driver.managed_connection(r1["host"], port=r1["port"]) as conn:
            with pytest.raises(PermissionError, match="READ_ONLY_MODE"):
                readonly_driver.send_config_set_validated(conn, ["interface lo", "description nope"])

    def test_still_allows_reads(self, readonly_driver, r1):
        with readonly_driver.managed_connection(r1["host"], port=r1["port"]) as conn:
            assert "BGP" in readonly_driver.run_command(conn, "show ip bgp summary")


class TestValidatorBlocksBeforeTheWire:
    @pytest.mark.parametrize("cmd", [
        "show ip route; reboot",
        "show ip route && reboot",
        "show running-config | sh",
        "show ip route `whoami`",
    ])
    def test_injection_never_reaches_the_device(self, driver, r1, cmd):
        with driver.managed_connection(r1["host"], port=r1["port"]) as conn:
            with pytest.raises(PermissionError, match="security validator"):
                driver.run_command(conn, cmd)

            # The session is still healthy — nothing was executed.
            assert "BGP" in driver.run_command(conn, "show ip bgp summary")


class TestRealConfigWrite:
    def test_config_change_lands_and_can_be_rolled_back(self, driver, r1, preserve_r1_loopback):
        marker = "netnerd-integration-test"
        with driver.managed_connection(r1["host"], port=r1["port"]) as conn:
            driver.send_config_set_validated(conn, ["interface lo", f"description {marker}"])
            after = driver.run_command(conn, "show running-config")
            assert marker in after, "config change did not land on the device"

            driver.send_config_set_validated(conn, ["interface lo", "no description"])
            rolled_back = driver.run_command(conn, "show running-config")

        assert marker not in rolled_back, "rollback failed — lab left dirty"
