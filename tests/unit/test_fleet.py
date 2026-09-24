"""Fleet staging logic that needs no devices.

Anything that touches a device lives in tests/integration/test_fleet_frr.py —
the rollout behaviour that matters (a stage failing, a fleet coming back off)
cannot be demonstrated without real device state.
"""
from __future__ import annotations

import pytest

from netnerd_mcp import fleet


@pytest.fixture(autouse=True)
def clean_fleets():
    fleet.reset()
    yield
    fleet.reset()


def _token(**kw):
    """A fleet token in whatever state a test needs, with no devices behind it."""
    defaults = dict(
        id="fleet-test01", devices=["a", "b", "c"], commands=["description x"],
        stages=[1, 1, 1], children={n: f"chg-{n}" for n in "abc"}, baseline={},
    )
    token = fleet.FleetToken(**{**defaults, **kw})
    fleet._fleets[token.id] = token
    return token


class TestStageSizes:
    def test_the_ansible_shape_splits_a_big_fleet(self):
        assert fleet.resolve_stages(500) == [1, 50, 449]

    def test_a_percentage_that_rounds_below_one_still_means_some(self):
        """10% of 5 is half a device. Rounding that to zero would produce a
        stage that applies nothing and reports itself healthy — a check that
        cannot fail, sitting between two real stages."""
        assert fleet.resolve_stages(5) == [1, 1, 3]

    def test_a_spec_that_runs_out_does_not_drop_the_rest(self):
        """Whatever the spec leaves over becomes a final stage. Silently
        skipping them would report a clean rollout across devices that were
        never touched."""
        assert fleet.resolve_stages(10, [1]) == [1, 9]
        assert sum(fleet.resolve_stages(10, [1])) == 10

    def test_stages_never_exceed_the_fleet(self):
        assert fleet.resolve_stages(3, [10, 10]) == [3]
        assert fleet.resolve_stages(3) == [1, 1, 1]

    def test_rest_takes_everything_left(self):
        assert fleet.resolve_stages(100, [5, "rest"]) == [5, 95]


class TestStageMembership:
    def test_each_stage_names_its_own_devices(self):
        token = _token(devices=list("abcde"), stages=[1, 2, 2])

        assert token.stage_devices(0) == ["a"]
        assert token.stage_devices(1) == ["b", "c"]
        assert token.stage_devices(2) == ["d", "e"]

    def test_remaining_counts_what_has_not_been_staged(self):
        token = _token(devices=list("abcde"), stages=[1, 2, 2])
        assert token.remaining() == 5
        token.stage_index = 1
        assert token.remaining() == 4
        token.stage_index = 3
        assert token.remaining() == 0


class TestStateMachine:
    def test_a_halted_fleet_will_not_advance_on_its_own(self):
        """Halting is a decision handed to the operator. Advancing past it
        would push a change onto more devices after the network already said
        something was wrong."""
        token = _token(state="halted", applied=["a"])

        result = fleet.advance(token.id, reason="trying to carry on")

        assert "error" in result
        assert "halted" in result["error"]
        assert "rollback" in result["note"] and "confirm_change" in result["note"]

    def test_a_finished_fleet_has_nothing_left_to_apply(self):
        token = _token(stage_index=3, state="staged")
        assert "error" in fleet.advance(token.id, reason="one more")

    def test_an_unknown_token_is_refused(self):
        assert "error" in fleet.advance("fleet-nope", reason="x")
        assert "error" in fleet.confirm_fleet("fleet-nope", reason="x")
        assert "error" in fleet.rollback_fleet("fleet-nope", reason="x")

    def test_confirming_nothing_is_an_error_not_a_success(self):
        """An empty confirm returning 'confirmed: 0' would read as a clean
        rollout to anything counting successes."""
        token = _token(applied=[])
        result = fleet.confirm_fleet(token.id, reason="nothing applied yet")

        assert "error" in result
        assert "confirmed" not in result

    def test_rolling_back_nothing_is_an_error_not_a_success(self):
        token = _token(applied=[])
        assert "error" in fleet.rollback_fleet(token.id, reason="nothing to undo")


class TestPlanGuards:
    def test_a_fleet_of_one_is_refused(self):
        """One device is the single-device path, which gives a better result."""
        result = fleet.plan_fleet(["r1"], ["description x"], reason="too small")

        assert "error" in result
        assert "at least two" in result["error"]

    def test_duplicates_do_not_inflate_the_fleet(self):
        result = fleet.plan_fleet(["r1", "r1"], ["description x"], reason="same device")

        assert "error" in result, "r1 twice is still one device"
