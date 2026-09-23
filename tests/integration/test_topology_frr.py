"""Discovery against the real lab.

The unit tests build a graph by hand; these prove one can actually be read off
devices over SSH. FRR has no LLDP daemon, so the sources exercised here are
subnet inference and the BGP and OSPF adjacencies — which is why discovery does
not depend on LLDP being present.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from tests.conftest import requires_lab

os.environ["NETNERD_INVENTORY"] = str(
    Path(__file__).resolve().parents[2] / "lab" / "lab-inventory.yaml")

from netnerd_mcp import audit, topology  # noqa: E402
from netnerd_mcp.config.settings import settings  # noqa: E402
from netnerd_mcp.inventory import reset_inventory  # noqa: E402

pytestmark = [pytest.mark.integration, requires_lab]


@pytest.fixture(autouse=True)
def clean_state(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "STATE_DIR", str(tmp_path))
    monkeypatch.setattr(settings, "AUDIT_DIR", str(tmp_path / "audit"))
    reset_inventory()
    topology.reset()
    audit.reset()
    yield
    topology.reset()
    audit.reset()


@pytest.fixture
def discovered():
    return topology.discover_topology(reason="mapping the lab for the test suite")


class TestDiscovery:
    def test_both_routers_are_found(self, discovered):
        assert discovered["discovered"] >= 2
        assert {"r1", "r2"} <= set(discovered["nodes"])

    def test_the_link_between_them_is_found_by_more_than_one_source(self, discovered):
        """Each source is an independent read of the same physical link, so
        agreement between them is the point — no single one has to be trusted."""
        result = topology.query_topology("neighbors", node="r1", reason="checking the link")

        peers = {n["peer"]: n for n in result["neighbors"]}
        assert "r2" in peers, result
        assert len(peers["r2"]["sources"]) >= 2, peers["r2"]

    def test_the_subnet_and_routing_sources_all_fire(self, discovered):
        by_source = discovered["edges_by_source"]
        assert "subnet" in by_source, by_source
        assert "bgp" in by_source, by_source
        assert "ospf" in by_source, by_source

    def test_addresses_are_read_with_their_masks(self, discovered):
        """Without a prefix length there is no subnet to infer from."""
        rows = list(topology._db().execute(
            "SELECT * FROM interfaces WHERE node='r1' AND ip != ''"))
        addresses = {r["ip"]: r["prefixlen"] for r in rows}

        assert addresses.get("172.30.0.2") == 24
        assert addresses.get("10.1.1.1") == 32

    def test_the_shell_entry_is_merged_into_the_router_it_shares_a_box_with(self, discovered):
        """r1 and r1-shell are one container reached two ways. Treating them as
        neighbours would invent a link, and would make r1 look redundantly
        connected when it is not."""
        assert discovered.get("merged_aliases", {}).get("r1-shell") == "r1"
        assert "r1-shell" not in discovered["nodes"]

    def test_discovery_is_recorded_in_the_audit_trail(self, discovered):
        events = [e for e in audit.current().events() if e["event"] == "discover"]
        assert events, "a walk of every device in the inventory has to be auditable"
        assert events[-1]["nodes"] >= 2

    def test_rediscovery_does_not_duplicate_the_graph(self, discovered):
        before = topology.query_topology("summary", reason="before")
        topology.discover_topology(reason="running discovery a second time")
        after = topology.query_topology("summary", reason="after")

        assert after["nodes"] == before["nodes"]
        assert after["edges"] == before["edges"]


class TestBlastRadiusOnTheLab:
    def test_cutting_r1s_lab_interface_strands_r2(self, discovered):
        """The headline capability, on a real graph read off real devices."""
        result = topology.query_topology(
            "blast_radius", node="r1", interface="eth0",
            reason="checking what shutting the lab link would cost")

        assert result["isolated"] == ["r2"], result
        assert "r2" in result["impact"]

    def test_the_loopback_carries_no_link(self, discovered):
        """lo is a /32 with nothing on the far side — shutting it strands
        nobody, and the graph must not invent an adjacency for it."""
        result = topology.query_topology(
            "blast_radius", node="r1", interface="lo",
            reason="checking a loopback is not treated as a link")

        assert "error" in result, result
        assert "NOT the same as" in result["error"]


class TestFreshness:
    def test_a_freshly_discovered_graph_reports_its_age(self, discovered):
        result = topology.query_topology("summary", reason="checking freshness")

        assert result["discovered"] is True
        assert result["age_minutes"] < 5
        assert "stale" not in result

    def test_querying_before_discovering_refuses_to_answer(self):
        """No discovery has run in this fixture, so there is nothing to say —
        and saying "nothing is connected" would be the dangerous answer."""
        result = topology.query_topology("summary", reason="asking too early")

        assert result["discovered"] is False
        assert result["nodes"] == 0
        assert "warning" in result
