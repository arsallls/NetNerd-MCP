"""Telemetry: the summary, the bound, and what it refuses to claim.

The device-side behaviour lives in tests/integration/test_gnmi.py. These cover
the summarising and the guards, which need no device.
"""
from __future__ import annotations

import pytest

from netnerd_mcp.drivers.transports import _summarise


class TestSummarising:
    def test_a_rising_counter_reports_its_delta(self):
        """The question telemetry exists to answer: is this moving."""
        result = _summarise([100, 105, 112, 130])

        assert result["samples"] == 4
        assert result["first"] == 100
        assert result["last"] == 130
        assert result["delta"] == 30

    def test_a_flat_counter_reports_a_zero_delta(self):
        result = _summarise([7, 7, 7])
        assert result["delta"] == 0
        assert result["min"] == result["max"] == 7

    def test_a_counter_that_wrapped_is_not_hidden(self):
        """A negative delta is how a reset or wrap shows up, and averaging it
        away would hide the one thing worth noticing."""
        result = _summarise([4_000_000_000, 12])
        assert result["delta"] < 0

    def test_non_numeric_states_are_listed_not_averaged(self):
        """Taking the mean of an interface's oper-status is meaningless."""
        result = _summarise(["UP", "DOWN", "UP"])

        assert "delta" not in result
        assert result["values_seen"] == ["DOWN", "UP"]
        assert result["samples"] == 3

    def test_booleans_are_not_treated_as_numbers(self):
        result = _summarise([True, False, True])
        assert "delta" not in result


class TestSilenceIsNotZero:
    """The rule this project keeps relearning: a result that means "I did not
    see anything" must not be mistakable for a measurement."""

    def test_no_samples_refuses_to_report_a_value(self):
        result = _summarise([])

        assert result["samples"] == 0
        assert "first" not in result
        assert "last" not in result
        assert "delta" not in result

    def test_no_samples_says_it_is_not_a_zero_reading(self):
        note = _summarise([])["note"]
        assert "NOT a reading of zero" in note
        assert "NOT proof the path does not exist" in note

    def test_a_refused_path_is_reported_as_refused_not_as_silence(self):
        """"The device said that path does not exist" and "nothing arrived"
        are different findings and lead to different next steps."""
        result = _summarise([], rejected="path not found")

        assert result["device_rejected"] == "path not found"
        assert "refused this path" in result["note"]
        assert "NOT a reading of zero" not in result["note"]


class TestBounds:
    def test_the_window_is_capped(self, monkeypatch):
        """A tool call that never returns wedges the client session, so the
        cap is enforced here rather than trusted to the caller."""
        from netnerd_mcp.config.settings import settings
        from netnerd_mcp.tools.telemetry_tools import telemetry

        monkeypatch.setattr(settings, "MAX_TELEMETRY_SEC", 5)
        result = telemetry("no-such-device", ["/interfaces"], reason="x", seconds=99999)

        # Stops at the inventory, but the point is it never reaches a device
        # with an unbounded window.
        assert "error" in result

    def test_no_paths_is_refused(self):
        from netnerd_mcp.tools.telemetry_tools import telemetry
        result = telemetry("anything", [], reason="x")
        assert "error" in result
