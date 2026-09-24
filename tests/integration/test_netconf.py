"""The NETCONF change loop against a real NETCONF server.

The test that matters here is `test_the_device_reverts_it_without_our_help`.
Every other rollback in this project is a timer on *this* side replaying a
backup, which only works while this process is alive and can still reach the
device — the two things a change bad enough to need a rollback is most likely
to have broken. RFC 6241 confirmed-commit moves that timer onto the device.

Until now there was nothing in the lab that implements it, so it shipped
unverified. netopeer2 does, and this proves it by disarming our own rollback
and letting only the device's countdown run.
"""
from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from tests.conftest import requires_netconf

os.environ["NETNERD_INVENTORY"] = str(
    Path(__file__).resolve().parents[2] / "lab" / "lab-inventory.yaml")
os.environ["NETNERD_READ_ONLY"] = "false"

from netnerd_mcp import audit, changes  # noqa: E402
from netnerd_mcp.config.settings import settings  # noqa: E402
from netnerd_mcp.drivers import transports  # noqa: E402
from netnerd_mcp.drivers.base import CONFIRMED_COMMIT, DeviceRejected  # noqa: E402
from netnerd_mcp.inventory import get_inventory, reset_inventory  # noqa: E402

pytestmark = [pytest.mark.integration, requires_netconf]

MARKER = "netnerd-netconf-test"


def _config(name: str, description: str) -> str:
    return f"""<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <interfaces xmlns="urn:ietf:params:xml:ns:yang:ietf-interfaces">
    <interface>
      <name>{name}</name>
      <description>{description}</description>
      <type xmlns:ianaift="urn:ietf:params:xml:ns:yang:iana-if-type">ianaift:ethernetCsmacd</type>
    </interface>
  </interfaces>
</config>"""


def _remove(name: str) -> str:
    return f"""<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <interfaces xmlns="urn:ietf:params:xml:ns:yang:ietf-interfaces">
    <interface xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" nc:operation="remove">
      <name>{name}</name>
    </interface>
  </interfaces>
</config>"""


@pytest.fixture
def device():
    reset_inventory()
    return get_inventory().resolve("netconf1")


@pytest.fixture
def transport(device):
    return transports.for_device(device)


@pytest.fixture(autouse=True)
def clean_state(tmp_path, monkeypatch, device, transport):
    monkeypatch.setattr(settings, "AUDIT_DIR", str(tmp_path))
    monkeypatch.setattr(settings, "STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setattr(settings, "READ_ONLY", False)
    audit.reset()
    changes.reset()
    yield
    changes.reset()
    # Leave the datastore as it was found, whatever the test did to it.
    for name in ("test0", "ghost0", "reject0"):
        try:
            transport.apply(device, [_remove(name)])
        except Exception:
            pass
    audit.reset()


class TestTransportSelection:
    def test_the_device_gets_the_netconf_transport(self, transport):
        assert transport.name == "netconf"
        assert CONFIRMED_COMMIT in transport.capabilities()

    def test_the_server_advertises_what_the_transport_relies_on(self, device, transport):
        with transport._connect(device) as session:
            caps = transports._capabilities(session)
        assert ":candidate" in caps
        assert ":confirmed-commit" in caps


class TestChangeLoop:
    def test_the_plan_says_the_device_enforces_the_rollback(self, device):
        plan = changes.plan_change(device="netconf1", commands=[_config("test0", MARKER)],
                                   reason="checking the mechanism is the device's own")

        assert plan["applicable"] is True, plan
        assert "confirmed-commit" in plan["rollback"]
        assert "enforced by the device" in plan["rollback"]

    def test_a_change_lands_and_survives_confirmation(self, device, transport):
        plan = changes.plan_change(device="netconf1", commands=[_config("test0", MARKER)],
                                   reason="proving the loop end to end")
        assert MARKER not in transport.get_config(device), "planning must not write"

        applied = changes.apply_change(plan["token"], reason="operator approved")
        assert applied["applied"] is True, applied
        assert MARKER in transport.get_config(device)

        confirmed = changes.confirm_change(
            plan["token"], reason="the interface is present in the running datastore")
        assert confirmed["confirmed"] is True
        assert "confirming commit accepted" in confirmed["device_confirmation"]

        time.sleep(3)
        assert MARKER in transport.get_config(device), \
            "a confirmed commit must not revert"

    def test_the_device_reverts_it_without_our_help(self, device, transport, monkeypatch):
        """The whole point of confirmed-commit.

        Our own rollback timer is cancelled straight after applying, so the
        only thing that can undo this is the device's own countdown. If the
        change is gone at the end, the device did it.
        """
        monkeypatch.setattr(settings, "CONFIRM_TIMEOUT_MIN", 5 / 60)  # 5 seconds

        plan = changes.plan_change(device="netconf1", commands=[_config("ghost0", "should-revert")],
                                   reason="testing the device-side revert")
        changes.apply_change(plan["token"], reason="applying without confirming")
        assert "ghost0" in transport.get_config(device)

        token = changes._tokens[plan["token"]]
        token.timer.cancel()
        token.timer = None

        time.sleep(12)

        assert "ghost0" not in transport.get_config(device), \
            "the device did not revert an unconfirmed commit on its own"

    def test_confirming_is_recorded_with_the_mechanism_that_was_used(self, device):
        plan = changes.plan_change(device="netconf1", commands=[_config("test0", MARKER)],
                                   reason="auditing the mechanism")
        changes.apply_change(plan["token"], reason="operator approved")
        changes.confirm_change(plan["token"], reason="verified in the datastore")

        confirms = [e for e in audit.current().events() if e["event"] == "confirm"]
        assert "confirmed-commit" in confirms[-1]["mechanism"]


class TestRefusalsAreNotFailures:
    def test_a_change_the_device_rejects_leaves_nothing_behind(self, device, transport):
        """A YANG validation error is a complete "no" — the candidate is
        untouched. Reporting it as a dropped connection would send an operator
        looking for damage that was never done."""
        broken = _config("reject0", MARKER).replace(
            "ianaift:ethernetCsmacd", "ianaift:notARealInterfaceType")

        plan = changes.plan_change(device="netconf1", commands=[broken], reason="planning an invalid change")
        applied = changes.apply_change(plan["token"], reason="the device should refuse this")

        assert applied.get("applied") is False, applied
        assert "refused" in applied["error"]
        assert "Nothing was applied" in applied["note"]
        assert "reject0" not in transport.get_config(device)

    def test_a_rejected_change_leaves_no_rollback_armed(self, device):
        broken = _config("reject0", MARKER).replace(
            "ianaift:ethernetCsmacd", "ianaift:notARealInterfaceType")
        plan = changes.plan_change(device="netconf1", commands=[broken], reason="planning an invalid change")
        changes.apply_change(plan["token"], reason="the device should refuse this")

        token = changes._tokens[plan["token"]]
        assert token.state == "pending", "a refused change must not be marked applied"
        assert token.timer is None, "nothing was applied, so nothing needs reverting"

    def test_the_refusal_is_in_the_audit_trail(self, device):
        broken = _config("reject0", MARKER).replace(
            "ianaift:ethernetCsmacd", "ianaift:notARealInterfaceType")
        plan = changes.plan_change(device="netconf1", commands=[broken], reason="planning an invalid change")
        changes.apply_change(plan["token"], reason="the device should refuse this")

        blocked = [e for e in audit.current().events()
                   if e["event"] == "blocked" and e.get("tool") == "apply_change"]
        assert blocked, "a refusal nobody can see in the log is not a record"

    def test_cli_lines_are_refused_before_reaching_the_device(self, device, transport):
        with pytest.raises(Exception, match="XML"):
            transport.apply(device, ["interface test0", "shutdown"])


class TestReads:
    def test_the_running_datastore_comes_back_as_xml(self, device, transport):
        config = transport.get_config(device)
        assert config.strip().startswith("<")
        assert "urn:ietf:params:xml:ns:" in config

    def test_a_plan_backs_up_the_datastore_first(self, device):
        plan = changes.plan_change(device="netconf1", commands=[_config("test0", MARKER)],
                                   reason="checking the backup is taken")
        assert plan["backup_lines"] > 0
        assert changes._tokens[plan["token"]].backup.strip().startswith("<")


class TestTopologySkipsIt:
    def test_discovery_says_why_it_skipped_a_netconf_only_device(self, tmp_path, monkeypatch):
        """Discovery reads neighbours with CLI show commands. A NETCONF-only
        device has no CLI, and appearing in the graph with no neighbours would
        read as a device with nothing attached to it."""
        from netnerd_mcp import topology
        monkeypatch.setattr(settings, "STATE_DIR", str(tmp_path / "topo"))
        topology.reset()

        result = topology.discover_topology(
            reason="checking a netconf-only device is skipped", devices=["netconf1"])

        assert "netconf1" in result.get("failed", {}), result
        assert "not CLI over SSH" in result["failed"]["netconf1"]
        topology.reset()
