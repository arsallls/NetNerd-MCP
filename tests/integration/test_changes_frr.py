"""The change loop against a real device.

This is the test that matters: a change that is never confirmed has to come
back off the device on its own. That cannot be proven against a mock, so it
runs against the FRR lab over real SSH.
"""
from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

import pytest

from tests.conftest import requires_lab

os.environ["NETNERD_INVENTORY"] = str(Path(__file__).resolve().parents[2] / "lab" / "lab-inventory.yaml")
os.environ["NETNERD_READ_ONLY"] = "false"

from netnerd_mcp import audit, changes, sessions  # noqa: E402
from netnerd_mcp.config.settings import settings  # noqa: E402
from netnerd_mcp.inventory import get_inventory, reset_inventory  # noqa: E402
from netnerd_mcp.tools.show_tools import get_config, show  # noqa: E402

pytestmark = [pytest.mark.integration, requires_lab]

MARKER = "netnerd-change-test"


def _startup_file() -> str:
    return subprocess.run(
        ["docker", "exec", "netnerd-lab-r1", "cat", "/etc/frr/frr.conf"],
        capture_output=True, text=True, timeout=30,
    ).stdout


@pytest.fixture(autouse=True)
def clean_state(tmp_path, monkeypatch, preserve_r1_loopback):
    monkeypatch.setattr(settings, "AUDIT_DIR", str(tmp_path))
    monkeypatch.setattr(settings, "READ_ONLY", False)
    reset_inventory()
    audit.reset()
    changes.reset()
    yield
    changes.reset()
    audit.reset()


def _running_config() -> str:
    return get_config("r1", reason="verifying change state").get("config", "")


class TestPlanApplyConfirm:
    def test_the_happy_path_lands_and_stays(self):
        plan = changes.plan_change(
            "r1", ["interface lo", f"description {MARKER}"],
            reason="tagging the loopback so the change loop can be verified",
        )
        assert plan["applicable"] is True, plan
        assert MARKER not in _running_config(), "plan_change must not touch the device"

        applied = changes.apply_change(plan["token"], reason="verified plan with operator")
        assert applied["applied"] is True, applied
        assert MARKER in _running_config(), "change did not reach the device"

        confirmed = changes.confirm_change(
            plan["token"], reason="description is present and BGP is still up"
        )
        assert confirmed["confirmed"] is True

        time.sleep(2)
        assert MARKER in _running_config(), "confirmed change was rolled back anyway"

    def test_an_unconfirmed_change_reverts_by_itself(self, monkeypatch):
        # Real timer, short fuse — the mechanism is what's under test, not the duration.
        monkeypatch.setattr(settings, "CONFIRM_TIMEOUT_MIN", 3 / 60)

        plan = changes.plan_change(
            "r1", ["interface lo", f"description {MARKER}"],
            reason="simulating an agent that applies a change and then loses the session",
        )
        changes.apply_change(plan["token"], reason="applying without confirming")
        assert MARKER in _running_config()

        time.sleep(8)  # timer fires at 3s; allow for the SSH round trip

        assert MARKER not in _running_config(), "unconfirmed change did not revert"
        assert changes._tokens[plan["token"]].state == "rolled_back"

    def test_rollback_reports_whether_the_device_matches_its_backup(self):
        plan = changes.plan_change(
            "r1", ["interface lo", f"description {MARKER}"],
            reason="checking rollback verification",
        )
        changes.apply_change(plan["token"], reason="apply then undo")

        result = changes.rollback(plan["token"], reason="operator asked to undo")

        assert result["rolled_back"] is True
        assert result["matches_backup"] is True, result.get("remaining_diff")
        assert MARKER not in _running_config()

    def test_rollback_restores_an_overwritten_value_not_just_the_new_one(self):
        """Undoing has to mean putting back what was there.

        Negating a command only removes it, so overwriting a description that
        already existed and then rolling back used to leave the interface with
        no description at all — near the backup, but not equal to it."""
        device = get_inventory().resolve("r1")
        with sessions.connection(device) as (driver, conn):
            driver.send_config_set_validated(
                conn, ["interface lo", "description original-value"])

        plan = changes.plan_change(
            "r1", ["interface lo", f"description {MARKER}"],
            reason="overwriting a description that already has a value",
        )
        changes.apply_change(plan["token"], reason="apply over the existing value")
        assert MARKER in _running_config()

        result = changes.rollback(plan["token"], reason="undo the overwrite")

        assert result["matches_backup"] is True, result.get("remaining_diff")
        assert "description original-value" in _running_config(), \
            "rollback dropped the value the change had overwritten"


class TestGates:
    def test_a_non_writable_device_is_refused(self):
        plan = changes.plan_change(
            "r2", ["interface lo", "description nope"],
            reason="r2 is marked writable: false in the inventory",
        )
        assert plan["applicable"] is False
        assert "writable: false" in plan["note"]

        applied = changes.apply_change(plan["token"], reason="should not get through")
        assert "error" in applied and "writable" in applied["error"]

    def test_read_only_mode_blocks_apply_even_with_a_valid_token(self, monkeypatch):
        plan = changes.plan_change(
            "r1", ["interface lo", f"description {MARKER}"],
            reason="token issued while writes were allowed",
        )
        monkeypatch.setattr(settings, "READ_ONLY", True)

        applied = changes.apply_change(plan["token"], reason="read-only is on now")

        assert "error" in applied and "Read-only" in applied["error"]
        assert MARKER not in _running_config()

    def test_a_confirmed_change_can_be_saved_and_reaches_startup_config(self):
        """`saved: true` has to mean the change survives a reboot, so this reads
        it back out of the startup config rather than trusting the return value.

        A live session found the opposite bug: the lab could not save at all and
        save_config reported success anyway. The refusal path is covered by the
        verbatim device output in tests/unit/test_changes.py."""
        plan = changes.plan_change(
            "r1", ["interface lo", f"description {MARKER}"],
            reason="checking a confirmed change can be persisted",
        )
        changes.apply_change(plan["token"], reason="applying before save")
        changes.confirm_change(plan["token"], reason="verified on the device")

        result = changes.save_config("r1", reason="persisting the confirmed change")

        assert result["saved"] is True, result

        # Checked out of band, on the file the router actually boots from.
        # Asking the device to confirm its own save would not prove much —
        # and FRR's `show startup-config` prints nothing at all.
        saved = subprocess.run(
            ["docker", "exec", "netnerd-lab-r1", "cat", "/etc/frr/frr.conf"],
            capture_output=True, text=True, timeout=30,
        ).stdout
        assert MARKER in saved, f"save reported success but /etc/frr/frr.conf lacks it:\n{saved}"

    def test_save_config_refuses_an_unconfirmed_change(self):
        plan = changes.plan_change(
            "r1", ["interface lo", f"description {MARKER}"],
            reason="checking save is gated on confirmation",
        )
        changes.apply_change(plan["token"], reason="apply without confirming")

        result = changes.save_config("r1", reason="trying to persist too early")

        assert "error" in result
        assert "not confirmed" in result["error"]
        # A refusal nobody can see is not a guardrail — it has to be in the log
        # next to the successes.
        blocked = [e for e in audit.current().events()
                   if e["event"] == "blocked" and e.get("tool") == "save_config"]
        assert blocked, "the refusal was not recorded in the audit trail"
        assert blocked[-1]["reason"] == "trying to persist too early"


class TestUnreadableConfig:
    def test_an_unreadable_startup_config_is_not_reported_as_empty(self):
        """FRR accepts `show startup-config` and prints nothing at all.

        A live agent read the empty result as fact and told the operator a
        confirmed, saved change had been lost from the startup config — while
        the file on disk still had it. The result must not carry anything that
        can be mistaken for the config itself."""
        result = get_config("r1", reason="reading a config this platform cannot show",
                            startup=True)

        assert "config" not in result, \
            "an unreadable config must not come back with a config field"
        assert "COULD NOT READ" in result["error"]


class TestAuditTrail:
    def test_the_whole_loop_is_recorded_and_verifies(self):
        from netnerd_mcp.audit import verify

        plan = changes.plan_change(
            "r1", ["interface lo", f"description {MARKER}"],
            reason="auditing the change loop end to end",
        )
        changes.apply_change(plan["token"], reason="operator approved")
        changes.confirm_change(plan["token"], reason="verified on the device")

        log = audit.current()
        events = [e["event"] for e in log.events()]
        assert events.count("plan") == 1
        assert events.count("apply") == 1
        assert events.count("confirm") == 1

        ok, message = verify(log.jsonl_path)
        assert ok, message

        report = log.write_report().read_text()
        assert plan["token"] in report
        assert "auditing the change loop end to end" in report


class TestBlastRadiusInThePlan:
    """A plan that would cut a device off has to say so before it is applied.

    These run against a graph discovered from the real lab, so the impact is
    computed from devices rather than from a fixture.
    """

    @pytest.fixture
    def mapped(self, tmp_path, monkeypatch):
        from netnerd_mcp import topology
        monkeypatch.setattr(settings, "STATE_DIR", str(tmp_path / "state"))
        topology.reset()
        topology.discover_topology(reason="mapping the lab before planning a change")
        yield
        topology.reset()

    def test_shutting_the_transit_link_warns_that_r2_is_cut_off(self, mapped):
        plan = changes.plan_change(
            "r1", ["interface eth0", "shutdown"],
            reason="checking the plan reports what this would isolate")

        assert plan["blast_radius"] is not None, plan
        assert plan["blast_radius"]["isolated"] == ["r2"], plan["blast_radius"]
        assert "r2" in plan["blast_radius_note"]
        assert "cut off" in plan["blast_radius_note"]

    def test_the_warning_arrives_before_anything_is_applied(self, mapped):
        """plan_change must not touch the device — the operator gets the
        warning while the interface is still up."""
        plan = changes.plan_change(
            "r1", ["interface eth0", "shutdown"], reason="checking nothing is pushed")

        assert plan["blast_radius"]["isolated"] == ["r2"]
        assert changes._tokens[plan["token"]].state == "pending"

        # Read the interface itself rather than the config: eth0's address
        # comes from the kernel, so FRR's running-config never mentions it.
        brief = show("r1", "show interface brief",
                     reason="confirming planning did not touch the device")
        eth0 = [l for l in brief["output"].splitlines() if l.startswith("eth0")]
        assert eth0 and " up " in eth0[0], eth0

    def test_a_harmless_change_is_not_dressed_up_as_dangerous(self, mapped):
        plan = changes.plan_change(
            "r1", ["interface lo", f"description {MARKER}"],
            reason="a description change takes no link down")

        assert plan["blast_radius"] is None
        assert "no link impact was assessed" in plan["blast_radius_note"]

    def test_what_isolates_a_device_is_recorded_in_the_audit_trail(self, mapped):
        changes.plan_change(
            "r1", ["interface eth0", "shutdown"], reason="auditing the impact finding")

        plans = [e for e in audit.current().events() if e["event"] == "plan"]
        assert plans[-1]["isolates"] == ["r2"]

    def test_an_undiscovered_device_does_not_come_back_as_all_clear(self, tmp_path, monkeypatch):
        """No graph at all is the dangerous case: silence reads as safety."""
        from netnerd_mcp import topology
        monkeypatch.setattr(settings, "STATE_DIR", str(tmp_path / "empty"))
        topology.reset()

        plan = changes.plan_change(
            "r1", ["interface eth0", "shutdown"], reason="planning with no graph")

        assert plan["blast_radius"] is None
        assert "NOT a finding" in plan["blast_radius_note"]
        assert plan["applicable"] is True, "the default must inform, not block"
        topology.reset()

    def test_the_optional_gate_refuses_the_change_outright(self, tmp_path, monkeypatch):
        from netnerd_mcp import topology
        monkeypatch.setattr(settings, "STATE_DIR", str(tmp_path / "empty"))
        monkeypatch.setattr(settings, "REQUIRE_TOPOLOGY_FOR_WRITES", True)
        topology.reset()

        plan = changes.plan_change(
            "r1", ["interface eth0", "shutdown"], reason="gate is on, graph is empty")

        assert plan["applicable"] is False
        assert "discover_topology" in plan["note"]

        applied = changes.apply_change(plan["token"], reason="should not get through")

        # Assert on WHY it was refused. An earlier version of this test only
        # checked that an error came back — and it passed while the change was
        # being pushed, because shutting eth0 killed the SSH session and the
        # resulting connection error looked like a refusal. It took the lab
        # down every run until the assertion was tightened.
        assert "discover_topology" in applied["error"], applied
        assert changes._tokens[plan["token"]].state == "pending", \
            "a refused change must not be marked applied"

        brief = show("r1", "show interface brief", reason="confirming eth0 was untouched")
        eth0 = [l for l in brief["output"].splitlines() if l.startswith("eth0")]
        assert eth0 and " up " in eth0[0], f"the refused change reached the device: {eth0}"
        topology.reset()
