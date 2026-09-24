"""Staged fleet rollout against real routers.

The point of staging is that a change which breaks something stops after one
device instead of five hundred, and that what already went out comes back off.
Neither can be shown against a mock: the first needs a device that really does
become unreachable, the second needs real config to restore. So this drives
r1, r3 and r4 over SSH and stops containers mid-rollout.
"""
from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

import pytest

from tests.conftest import FLEET_NODES, requires_fleet, requires_lab

os.environ["NETNERD_INVENTORY"] = str(Path(__file__).resolve().parents[2] / "lab" / "lab-inventory.yaml")
os.environ["NETNERD_READ_ONLY"] = "false"

from netnerd_mcp import audit, changes, fleet, sessions  # noqa: E402
from netnerd_mcp.config.settings import settings  # noqa: E402
from netnerd_mcp.inventory import reset_inventory  # noqa: E402

pytestmark = [pytest.mark.integration, requires_lab, requires_fleet]

FLEET = ["r1", "r3", "r4"]
MARKER = "netnerd-fleet-test"
CHANGE = ["interface lo", f"description {MARKER}"]
PORTS = {"r1": 2211, "r2": 2212, **FLEET_NODES}


def _docker(*args: str) -> str:
    return subprocess.run(["docker", *args], capture_output=True,
                          text=True, timeout=60).stdout


def _vtysh(node: str, *args: str) -> str:
    return _docker("exec", f"netnerd-lab-{node}", "vtysh", *args)


def _has_marker(node: str) -> bool:
    return MARKER in _vtysh(node, "-c", "show running-config")


def _port_open(port: int) -> bool:
    import socket
    try:
        with socket.create_connection(("localhost", port), timeout=2):
            return True
    except OSError:
        return False


def _wait_for(node: str, up: bool = True, limit: int = 90) -> None:
    """Block until *node*'s SSH is up (or gone). FRR needs a moment to boot."""
    deadline = time.monotonic() + limit
    while time.monotonic() < deadline:
        if _port_open(PORTS[node]) is up:
            if up:
                time.sleep(3)  # sshd answers a little before vtysh is ready
            return
        time.sleep(1)
    raise AssertionError(f"{node} did not come {'up' if up else 'down'} in {limit}s")


def _clear_markers() -> None:
    for node in FLEET:
        if _has_marker(node):
            _vtysh(node, "-c", "configure terminal", "-c", "interface lo",
                   "-c", "no description")


@pytest.fixture(autouse=True)
def clean_lab(tmp_path, monkeypatch):
    """Every container running, no leftover descriptions, fresh audit state."""
    monkeypatch.setattr(settings, "AUDIT_DIR", str(tmp_path))
    monkeypatch.setattr(settings, "READ_ONLY", False)
    reset_inventory()
    audit.reset()
    changes.reset()
    fleet.reset()

    for node in PORTS:
        if not _port_open(PORTS[node]):
            _docker("start", f"netnerd-lab-{node}")
            _wait_for(node)
    _clear_markers()

    yield

    changes.reset()
    fleet.reset()
    for node in PORTS:
        if not _port_open(PORTS[node]):
            _docker("start", f"netnerd-lab-{node}")
            _wait_for(node)
    _clear_markers()
    audit.reset()
    sessions.close_all(reason="fleet test finished")


def _plan() -> dict:
    return changes.plan_change(
        devices=FLEET, commands=CHANGE,
        reason="staged rollout of a loopback description across the fleet")


class TestTheHappyPath:
    def test_a_three_stage_rollout_lands_on_every_device_and_confirms(self):
        plan = _plan()
        assert plan["stages"] == [{"stage": 1, "devices": 1},
                                  {"stage": 2, "devices": 1},
                                  {"stage": 3, "devices": 1}], plan
        token = plan["token"]

        for stage in (1, 2, 3):
            result = changes.apply_change(token, reason=f"advancing to stage {stage}")
            assert result.get("healthy") == 1, result
            assert not result.get("failed"), result
            assert not result.get("degraded"), result

        assert all(_has_marker(n) for n in FLEET), "every device should carry it"

        confirmed = changes.confirm_change(token, reason="verified on all three")
        assert confirmed["confirmed"] == 3, confirmed
        assert all(_has_marker(n) for n in FLEET), "confirmed change was reverted"

    def test_a_stage_applies_only_its_own_devices(self):
        """The canary is the whole point: after stage one exactly one device
        is carrying the change."""
        plan = _plan()
        changes.apply_change(plan["token"], reason="canary only")

        assert [_has_marker(n) for n in FLEET] == [True, False, False]


class TestAFailedStageTakesEverythingBackOff:
    def test_a_device_that_dies_mid_rollout_reverts_the_whole_fleet(self):
        """The test this phase exists for. Two stages land, the third device
        is gone, and the rollout does not leave the fleet half-applied."""
        plan = _plan()
        token = plan["token"]

        changes.apply_change(token, reason="stage 1: the canary")
        changes.apply_change(token, reason="stage 2")
        assert _has_marker("r1") and _has_marker("r3")

        _docker("stop", "netnerd-lab-r4")
        _wait_for("r4", up=False)

        result = changes.apply_change(token, reason="stage 3, into a dead device")

        assert result["failed"], result
        assert "r4" in result["failed"]
        assert result["rolled_back"]["rolled_back"] == 2, result["rolled_back"]
        assert not _has_marker("r1"), "r1 kept the change after a failed rollout"
        assert not _has_marker("r3"), "r3 kept the change after a failed rollout"

    def test_the_fleet_rollback_is_recorded_in_the_audit_trail(self):
        plan = _plan()
        changes.apply_change(plan["token"], reason="stage 1")
        changes.apply_change(plan["token"], reason="stage 2")

        _docker("stop", "netnerd-lab-r4")
        _wait_for("r4", up=False)
        changes.apply_change(plan["token"], reason="stage 3 into a dead device")

        events = [e for e in audit.current().events() if e.get("event") == "rollback"]
        assert events, "a fleet rollback has to be auditable"
        assert any(e.get("token") == plan["token"] for e in events), events


class TestALostAdjacencyHalts:
    def test_losing_a_routing_peer_halts_instead_of_reverting(self):
        """A peer going down is the earliest sign a push is breaking the
        network, but it is a weaker signal than a device that will not answer
        — it may have been flapping already. So the rollout stops and hands
        the decision over rather than reverting the fleet on its own."""
        plan = _plan()  # baseline captured while r2 is still up

        _docker("stop", "netnerd-lab-r2")
        # OSPF's dead interval decides this, not us: the neighbour stays listed
        # until it expires, which is exactly why the check reads established
        # sessions rather than whatever addresses appear in the output.
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            if "10.2.2.2" not in fleet._adjacencies("r1", "waiting for the peer to drop"):
                break
            time.sleep(5)
        else:
            pytest.skip("r1 never noticed r2 was gone — OSPF timers too slow here")

        result = changes.apply_change(plan["token"], reason="stage 1 with a dead peer")

        assert result.get("degraded"), result
        assert "r1" in result["degraded"]
        assert fleet.get(plan["token"]).state == "halted"
        assert _has_marker("r1"), "a halted stage must stay applied, not revert"

    def test_a_halted_fleet_refuses_to_advance_without_a_decision(self):
        plan = _plan()
        fleet.get(plan["token"]).state = "halted"

        result = changes.apply_change(plan["token"], reason="pushing on regardless")

        assert "error" in result and "halted" in result["error"]
        assert not _has_marker("r3"), "a halted fleet must not push another stage"


class TestDoingNothingIsSafe:
    def test_an_unconfirmed_fleet_reverts_on_its_own(self, monkeypatch):
        # Real timer, short fuse — the mechanism is under test, not the duration.
        monkeypatch.setattr(settings, "FLEET_TIMEOUT_MIN", 3 / 60)

        plan = _plan()
        changes.apply_change(plan["token"], reason="stage 1, then walk away")
        changes.apply_change(plan["token"], reason="stage 2, then walk away")
        assert _has_marker("r1") and _has_marker("r3")

        time.sleep(10)  # timers fire at 3s; allow for two SSH round trips

        assert not _has_marker("r1"), "an unconfirmed fleet did not revert"
        assert not _has_marker("r3"), "an unconfirmed fleet did not revert"


class TestARefusedPlanLeavesNothingBehind:
    def test_a_non_writable_device_refuses_the_whole_rollout(self):
        result = changes.plan_change(
            devices=["r1", "r2", "r3"], commands=CHANGE,
            reason="r2 is marked writable: false")

        assert "r2" in result["refused"], result
        assert "token" not in result

    def test_a_refused_rollout_leaves_no_tokens_holding_backups(self):
        """plan_change issues a token even for a device it marks inapplicable.
        Left behind, they would let an operator apply half a rollout one token
        at a time — and each one holds a full configuration backup, so five
        hundred refused devices would be five hundred configs in memory."""
        changes.plan_change(devices=["r1", "r2", "r3"], commands=CHANGE,
                            reason="r2 cannot take this")

        assert not changes._tokens, f"tokens left behind: {list(changes._tokens)}"

    def test_the_write_gate_is_checked_before_any_device_is_read(self):
        """Finding out per device would open an SSH session and read a full
        configuration for every device in the fleet before refusing on a
        question that is pure local state."""
        changes.plan_change(devices=["r1", "r2", "r3"], commands=CHANGE,
                            reason="the gate comes first")

        touched = [e for e in audit.current().events()
                   if e.get("event") in ("command", "connect")]
        assert not touched, f"a refusal on local state contacted devices: {touched}"


class TestRollbackTellsTheTruth:
    def test_a_device_it_cannot_reach_is_reported_as_still_changed(self):
        """Some rollbacks fail. Counting an unreachable device as restored
        would be the one lie the single-device rollback already refuses."""
        plan = _plan()
        changes.apply_change(plan["token"], reason="stage 1")
        changes.apply_change(plan["token"], reason="stage 2")

        _docker("stop", "netnerd-lab-r3")
        _wait_for("r3", up=False)

        result = changes.rollback(plan["token"], reason="undoing with r3 unreachable")

        assert result["rolled_back"] == 1, result
        assert "r3" in result.get("still_changed", {}), result
        assert "still carrying the change" in result["note"]
