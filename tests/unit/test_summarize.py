"""Parsing and truncation.

The rule these enforce: anything less than the whole answer must not be
reachable under a key that reads like the whole answer. An agent already
mistook an empty `config` for a real one and told the operator a saved change
had been lost.
"""
from __future__ import annotations

import pytest

from netnerd_mcp import summarize
from netnerd_mcp.config.settings import settings


# Real `show ip interface brief` from IOS — ntc-templates has a template.
IOS_IP_INT_BRIEF = """\
Interface                  IP-Address      OK? Method Status                Protocol
GigabitEthernet0/0         10.0.0.1        YES NVRAM  up                    up
GigabitEthernet0/1         unassigned      YES NVRAM  administratively down down
Loopback0                  192.168.1.1     YES NVRAM  up                    up
"""

# FRR's vtysh answering the same question. No template exists for this shape,
# which is the normal case for anything that is not a mainstream vendor.
FRR_INTERFACE = """\
Interface       Status  VRF             Addresses
---------       ------  ---             ---------
eth0            up      default         172.30.0.2/24
lo              up      default         10.0.0.1/32
"""


class TestStructured:
    def test_a_known_command_comes_back_as_rows(self):
        rows = summarize.structured(IOS_IP_INT_BRIEF, "show ip interface brief", "cisco_ios")

        assert rows is not None, "ntc-templates should have a template for this"
        assert len(rows) == 3
        assert {r["interface"] for r in rows} == {
            "GigabitEthernet0/0", "GigabitEthernet0/1", "Loopback0"}

    def test_an_unparseable_platform_declines_rather_than_guessing(self):
        """A wrong parse is worse than no parse — the model would act on it."""
        assert summarize.structured(FRR_INTERFACE, "show interface", "frr_unknown") is None

    def test_empty_output_is_not_a_parse(self):
        assert summarize.structured("", "show version", "cisco_ios") is None
        assert summarize.structured("   \n  ", "show version", "cisco_ios") is None

    def test_an_unknown_command_declines(self):
        assert summarize.structured(
            "some output", "show frobnicate widgets", "cisco_ios") is None

    def test_device_type_aliases_reach_the_same_templates(self):
        rows = summarize.structured(IOS_IP_INT_BRIEF, "show ip interface brief", "cisco_xe")
        assert rows is not None and len(rows) == 3


class TestExcerpt:
    def test_short_output_is_left_alone(self):
        assert summarize.excerpt("one\ntwo\nthree") is None

    def test_output_at_the_limit_is_left_alone(self):
        text = "\n".join(str(i) for i in range(settings.MAX_OUTPUT_LINES))
        assert summarize.excerpt(text) is None

    def test_long_output_is_cut_and_says_so(self):
        text = "\n".join(f"line {i}" for i in range(500))

        result = summarize.excerpt(text, max_lines=100)

        assert result["truncated"] is True
        assert result["total_lines"] == 500
        assert "EXCERPT" in result["note"]

    def test_both_ends_survive_the_cut(self):
        """Errors cluster at the end of output; a head-only excerpt hides them."""
        text = "\n".join(f"line {i}" for i in range(500))

        excerpt = summarize.excerpt(text, max_lines=100)["excerpt"]

        assert "line 0" in excerpt
        assert "line 499" in excerpt
        assert "omitted" in excerpt

    def test_the_excerpt_is_actually_shorter(self):
        text = "\n".join(f"line {i}" for i in range(500))
        result = summarize.excerpt(text, max_lines=100)
        assert len(result["excerpt"].splitlines()) <= 101  # 100 + the marker


class TestResultShape:
    """The keys themselves are the guardrail, so they are asserted directly."""

    @pytest.mark.parametrize("max_lines", [10, 50])
    def test_an_excerpt_never_travels_under_a_complete_sounding_key(self, max_lines):
        text = "\n".join(f"line {i}" for i in range(500))
        result = summarize.excerpt(text, max_lines=max_lines)

        assert "output" not in result
        assert "config" not in result
        assert "excerpt" in result
