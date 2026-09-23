"""Server-side parsing, proven over real SSH rather than in a unit test.

ntc-templates has no FRR coverage, so `r1-shell` — the same container reached
with an ordinary shell instead of vtysh — is what exercises the parsed path.
Both outcomes matter: commands that parse must come back as rows with the raw
text dropped, and commands that do not must fall back cleanly rather than
guessing.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from tests.conftest import requires_lab

os.environ["NETNERD_INVENTORY"] = str(
    Path(__file__).resolve().parents[2] / "lab" / "lab-inventory.yaml")

from netnerd_mcp import audit  # noqa: E402
from netnerd_mcp.config.settings import settings  # noqa: E402
from netnerd_mcp.inventory import reset_inventory  # noqa: E402
from netnerd_mcp.tools.show_tools import get_config, show  # noqa: E402

pytestmark = [pytest.mark.integration, requires_lab]


@pytest.fixture(autouse=True)
def clean_state(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "AUDIT_DIR", str(tmp_path))
    reset_inventory()
    audit.reset()
    yield
    audit.reset()


class TestParsedOutput:
    def test_a_parseable_command_comes_back_as_rows(self):
        result = show("r1-shell", "ip address show", reason="reading interfaces structured")

        assert result["format"] == "parsed"
        assert result["rows"] > 0
        interfaces = {row["interface"] for row in result["parsed"]}
        assert any(i.startswith("eth0") for i in interfaces), interfaces

    def test_the_raw_text_is_dropped_once_it_is_parsed(self):
        """Returning both would be larger than returning raw alone, which is
        the whole reason this exists. The raw text stays in the transcript."""
        result = show("r1-shell", "ip address show", reason="checking raw is not duplicated")

        assert "output" not in result
        assert "output_excerpt" not in result
        assert result["transcript"], "the raw text must still be recorded somewhere"

    def test_the_parsed_rows_carry_the_addresses(self):
        """Phase 2 builds the topology graph out of exactly this."""
        result = show("r1-shell", "ip address show", reason="checking address extraction")

        addresses = {ip for row in result["parsed"] for ip in row.get("ip_addresses", [])}
        assert "10.1.1.1" in addresses, addresses      # r1's loopback
        assert "172.30.0.2" in addresses, addresses    # r1 on labnet


class TestGracefulFallback:
    def test_an_unparseable_platform_returns_raw_rather_than_guessing(self):
        """FRR has no templates at all. A wrong parse would be worse than
        none, because the model would act on it."""
        result = show("r1", "show ip bgp summary", reason="FRR has no ntc template")

        assert result["format"] == "raw"
        assert "output" in result
        assert "65002" in result["output"], "the raw text still has to be usable"

    def test_a_rejected_command_is_still_reported_as_rejected(self):
        """Parsing must not paper over the device refusing the command."""
        result = show("r1", "show frobnicate", reason="checking rejection survives parsing")

        assert "device_rejected" in result
        assert "error" in result


class TestTruncation:
    def test_long_output_comes_back_as_a_labelled_excerpt(self, monkeypatch):
        monkeypatch.setattr(settings, "MAX_OUTPUT_LINES", 5)

        result = show("r1", "show running-config", reason="forcing the cap")

        assert result["truncated"] is True
        assert "output_excerpt" in result
        assert "output" not in result, \
            "a partial result must not be reachable under the key for a whole one"
        assert result["total_lines"] > 5

    def test_a_capped_config_is_not_called_config(self, monkeypatch):
        monkeypatch.setattr(settings, "MAX_OUTPUT_LINES", 5)

        result = get_config("r1", reason="forcing the cap on a config read")

        assert "config" not in result
        assert "config_excerpt" in result
        assert "EXCERPT" in result["note"]

    def test_a_short_config_is_returned_whole(self):
        result = get_config("r1", reason="normal config read")

        assert "config" in result
        assert "config_excerpt" not in result
        assert "truncated" not in result
