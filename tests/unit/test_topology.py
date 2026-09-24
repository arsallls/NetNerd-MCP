"""The graph, and what it refuses to claim.

Blast radius is the reason this module exists: an answer here decides whether
an operator shuts an interface. So these cover the arithmetic on a known
topology, and — just as hard — that an empty or stale graph says so instead of
answering "nothing breaks".
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from netnerd_mcp import audit, topology
from netnerd_mcp.config.settings import settings


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "STATE_DIR", str(tmp_path))
    monkeypatch.setattr(settings, "AUDIT_DIR", str(tmp_path / "audit"))
    topology.reset()
    audit.reset()
    yield
    topology.reset()
    audit.reset()


def _store(nodes, edges, when=None):
    """Write a graph directly, skipping discovery."""
    stamp = when or topology._now()
    conn = topology._db()
    with conn:
        conn.executemany(
            "INSERT OR REPLACE INTO nodes (name, device_type, host, discovered_at) "
            "VALUES (?,?,?,?)", [(n, "cisco_ios", n, stamp) for n in nodes])
        conn.executemany(
            "INSERT OR REPLACE INTO edges "
            "(a_node, a_if, b_node, b_if, source, discovered_at) VALUES (?,?,?,?,?,?)",
            [(a, a_if, b, b_if, src, stamp) for a, a_if, b, b_if, src in edges])


# core ── edge ── leaf, with core also holding a spur. Cutting `edge` strands
# `leaf`; cutting `spur` strands nothing.
def _chain():
    _store(
        ["core", "edge", "leaf", "spur"],
        [("core", "Gi0/1", "edge", "Gi0/0", "lldp"),
         ("edge", "Gi0/2", "leaf", "Gi0/0", "lldp"),
         ("core", "Gi0/3", "spur", "Gi0/0", "lldp")],
    )


class TestBlastRadius:
    def test_cutting_a_transit_device_strands_what_is_behind_it(self):
        _chain()
        result = topology.query_topology("blast_radius", node="edge", reason="test")

        assert result["isolated"] == ["leaf"]
        assert "leaf" in result["impact"]

    def test_cutting_a_leaf_strands_nothing_else(self):
        _chain()
        result = topology.query_topology("blast_radius", node="spur", reason="test")

        assert result["isolated"] == []
        assert "no other device loses reachability" in result["impact"]

    def test_a_single_interface_can_be_cut_instead_of_the_whole_device(self):
        _chain()
        result = topology.query_topology(
            "blast_radius", node="edge", interface="Gi0/2", reason="test")

        assert result["isolated"] == ["leaf"]
        assert [l["peer"] for l in result["links_lost"]] == ["leaf"]

    def test_cutting_an_uplink_reports_the_split_from_both_sides(self):
        """Cutting edge's link to core leaves {core,spur} and {edge,leaf}. The
        answer cannot depend on which end the command was typed on, so an even
        split is reported as a split rather than as one side being stranded."""
        _chain()
        result = topology.query_topology(
            "blast_radius", node="edge", interface="Gi0/0", reason="test")

        assert result["partitions"] == [["core", "spur"], ["edge", "leaf"]]
        assert "ambiguous_split" in result

    def test_an_unrelated_island_does_not_become_the_surviving_network(self):
        """A graph can hold segments that never touch — two sites, a separate
        lab subnet, gear reached by another path. Measuring the split against
        the whole graph let the biggest island count as "the network", so the
        cut device's own side came back as the stranded one: cutting `edge`
        reported core and spur isolated, and on a two-node segment it named the
        changed device itself."""
        _chain()
        _store(["far-a", "far-b", "far-c"],
               [("far-a", "Gi0/1", "far-b", "Gi0/0", "lldp"),
                ("far-b", "Gi0/2", "far-c", "Gi0/0", "lldp")])

        result = topology.query_topology("blast_radius", node="edge", reason="test")

        assert result["isolated"] == ["leaf"], result
        assert not [n for n in result["isolated"] if n.startswith("far-")]

    def test_an_unknown_interface_is_an_error_not_an_all_clear(self):
        """"No link recorded on that interface" must never read as "nothing
        depends on it" — the graph simply may not know the interface."""
        _chain()
        result = topology.query_topology(
            "blast_radius", node="edge", interface="Gi9/9", reason="test")

        assert "error" in result
        assert "NOT the same as" in result["error"]
        assert "isolated" not in result


class TestEmptyAndStale:
    def test_an_empty_graph_refuses_to_answer(self):
        result = topology.query_topology("blast_radius", node="r1", reason="test")

        assert "error" in result
        assert "isolated" not in result, "an empty graph must not report an all-clear"

    def test_a_summary_of_nothing_says_nothing_was_discovered(self):
        result = topology.query_topology("summary", reason="test")

        assert result["discovered"] is False
        assert "not a finding that the network is empty" in result["warning"]

    def test_an_old_graph_is_flagged_as_stale(self):
        old = (datetime.now(tz=timezone.utc) - timedelta(hours=3)).isoformat(timespec="seconds")
        _store(["a", "b"], [("a", "Gi0/0", "b", "Gi0/0", "lldp")], when=old)

        result = topology.query_topology("blast_radius", node="a", reason="test")

        assert result["stale"] is True
        assert result["age_minutes"] > 60
        assert "warning" in result
        assert "age" in result["impact"], "the caveat has to reach the headline answer"

    def test_a_fresh_graph_is_not_flagged(self):
        _chain()
        result = topology.query_topology("neighbors", node="core", reason="test")

        assert result["discovered"] is True
        assert "stale" not in result


class TestNeighborsAndPath:
    def test_neighbors_lists_the_links_and_how_they_are_known(self):
        _chain()
        result = topology.query_topology("neighbors", node="core", reason="test")

        peers = {n["peer"]: n for n in result["neighbors"]}
        assert set(peers) == {"edge", "spur"}
        assert peers["edge"]["local_interface"] == "Gi0/1"
        assert peers["edge"]["confidence"] == "observed"

    def test_an_inferred_link_is_labelled_inferred(self):
        """A shared subnet is a weaker claim than an LLDP sighting and the
        result has to say which one it is."""
        _store(["a", "b"], [("a", "eth0", "b", "eth0", "subnet")])

        result = topology.query_topology("neighbors", node="a", reason="test")

        assert result["neighbors"][0]["confidence"] == "inferred"
        assert result["neighbors"][0]["sources"] == ["subnet"]

    def test_corroborating_sources_are_all_kept(self):
        _store(["a", "b"], [("a", "eth0", "b", "eth0", "subnet"),
                            ("a", "eth0", "b", "eth0", "bgp"),
                            ("a", "eth0", "b", "eth0", "lldp")])

        result = topology.query_topology("neighbors", node="a", reason="test")

        assert result["neighbors"][0]["sources"] == ["lldp", "bgp", "subnet"]
        assert result["neighbors"][0]["confidence"] == "observed"

    def test_path_walks_the_chain(self):
        _chain()
        result = topology.query_topology("path", node="leaf", to="spur", reason="test")

        assert result["path"] == ["leaf", "edge", "core", "spur"]
        assert result["hops"] == 3

    def test_no_path_is_not_reported_as_disconnected_reality(self):
        """The graph only knows what it walked; unconnected in the graph is not
        the same as unreachable on the network."""
        _store(["a", "b"], [])

        result = topology.query_topology("path", node="a", to="b", reason="test")

        assert result["path"] is None
        assert "only knows what it has walked" in result["note"]

    def test_summary_names_single_points_of_failure(self):
        _chain()
        result = topology.query_topology("summary", reason="test")

        assert result["nodes"] == 4
        assert set(result["single_points_of_failure"]) == {"core", "edge"}


class TestParsing:
    FRR_BRIEF = """\
Interface       Status  VRF             Addresses
---------       ------  ---             ---------
eth0            up      default         172.30.0.2/24
lo              up      default         10.1.1.1/32
sit0            down    default
"""

    IOS_BRIEF = """\
Interface                  IP-Address      OK? Method Status                Protocol
GigabitEthernet0/0         10.0.0.1        YES NVRAM  up                    up
GigabitEthernet0/1         unassigned      YES NVRAM  administratively down down
"""

    def test_an_frr_table_yields_addresses_and_masks(self):
        rows = topology._parse_interfaces(self.FRR_BRIEF, "show interface brief", "cisco_ios")

        by_name = {r["name"]: r for r in rows if r["ip"]}
        assert by_name["eth0"]["ip"] == "172.30.0.2"
        assert by_name["eth0"]["prefixlen"] == 24
        assert by_name["lo"]["prefixlen"] == 32

    def test_an_ios_table_without_masks_still_yields_interfaces(self):
        rows = topology._parse_interfaces(
            self.IOS_BRIEF, "show ip interface brief", "cisco_ios")

        addressed = {r["name"]: r for r in rows if r["ip"]}
        assert addressed["GigabitEthernet0/0"]["ip"] == "10.0.0.1"
        assert addressed["GigabitEthernet0/0"]["prefixlen"] is None

    def test_header_and_separator_lines_are_not_mistaken_for_interfaces(self):
        rows = topology._parse_interfaces(self.FRR_BRIEF, "show interface brief", "cisco_ios")
        assert "Interface" not in {r["name"] for r in rows}
        assert "---------" not in {r["name"] for r in rows}


class TestSubnetInference:
    def _ifs(self, ip, plen=24, name="eth0"):
        return [{"name": name, "ip": ip, "prefixlen": plen, "status": "up"}]

    def test_two_devices_on_one_subnet_are_adjacent(self):
        edges = topology._subnet_edges({
            "a": self._ifs("10.0.0.1"), "b": self._ifs("10.0.0.2")})

        assert len(edges) == 1
        assert {edges[0][0], edges[0][2]} == {"a", "b"}
        assert edges[0][4] == "subnet"

    def test_devices_on_different_subnets_are_not(self):
        edges = topology._subnet_edges({
            "a": self._ifs("10.0.0.1"), "b": self._ifs("10.9.9.2")})
        assert edges == []

    def test_a_crowded_segment_is_not_turned_into_a_mesh(self):
        """Everything on a management VLAN is not adjacent to everything else,
        and pretending otherwise turns a /24 into thousands of edges."""
        seen = {f"sw{i}": self._ifs(f"10.0.0.{i}") for i in range(1, 12)}

        assert topology._subnet_edges(seen) == []

    def test_host_routes_are_not_a_shared_subnet(self):
        edges = topology._subnet_edges({
            "a": self._ifs("10.1.1.1", 32), "b": self._ifs("10.2.2.2", 32)})
        assert edges == []


class TestAliasCollapsing:
    def test_two_entries_for_one_box_are_merged_not_linked(self):
        """The lab reaches one container as both a router and a shell. Left
        alone they become two nodes with a link that does not exist."""
        seen = {
            "r1": [{"name": "eth0", "ip": "172.30.0.2", "prefixlen": 24, "status": "up"}],
            "r1-shell": [{"name": "eth0", "ip": "172.30.0.2", "prefixlen": 24, "status": "up"}],
        }

        aliases = topology._collapse_aliases(seen)

        assert aliases == {"r1-shell": "r1"}
        assert set(seen) == {"r1"}

    def test_genuinely_distinct_devices_are_left_alone(self):
        seen = {
            "r1": [{"name": "eth0", "ip": "172.30.0.2", "prefixlen": 24, "status": "up"}],
            "r2": [{"name": "eth0", "ip": "172.30.0.3", "prefixlen": 24, "status": "up"}],
        }

        assert topology._collapse_aliases(seen) == {}
        assert set(seen) == {"r1", "r2"}
