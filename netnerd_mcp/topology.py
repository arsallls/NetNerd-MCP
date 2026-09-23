"""The network as a graph, kept between sessions.

Two jobs. The obvious one is answering questions a model would otherwise
answer by dumping `show cdp neighbors` on every device and reasoning about the
text — asking the graph costs a few hundred tokens instead of tens of
thousands. The one that matters more is blast radius: knowing, before a change
is applied, which devices fall off the network if an interface goes down.

Storage is SQLite under the state directory; NetworkX is built from it per
call. What is stored is not just the edges but **how each one is known** —
observed over LLDP, or inferred from a shared subnet or a routing adjacency —
because an inferred edge is a weaker claim and results say so.

Every answer carries the age of the data behind it. A graph discovered last
week describes last week's network, and silence about that would be the same
mistake as reporting an unreadable config as an empty one.
"""
from __future__ import annotations

import ipaddress
import logging
import re
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

from netnerd_mcp import audit, sessions, summarize, vendor
from netnerd_mcp.config.settings import settings
from netnerd_mcp.inventory import Device, InventoryError, get_inventory

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS nodes (
    name          TEXT PRIMARY KEY,
    device_type   TEXT,
    host          TEXT,
    discovered_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS interfaces (
    node          TEXT NOT NULL,
    name          TEXT NOT NULL,
    ip            TEXT NOT NULL DEFAULT '',
    prefixlen     INTEGER,
    status        TEXT,
    discovered_at TEXT NOT NULL,
    PRIMARY KEY (node, name, ip)
);
CREATE TABLE IF NOT EXISTS edges (
    a_node        TEXT NOT NULL,
    a_if          TEXT NOT NULL DEFAULT '',
    b_node        TEXT NOT NULL,
    b_if          TEXT NOT NULL DEFAULT '',
    source        TEXT NOT NULL,
    discovered_at TEXT NOT NULL,
    PRIMARY KEY (a_node, a_if, b_node, b_if, source)
);
"""

# How each edge is known, strongest claim first. An edge seen by more than one
# source is stronger than any single one of them, which is why the source is
# stored rather than collapsed away at discovery time.
SOURCE_RANK = {"lldp": 0, "cdp": 1, "ospf": 2, "bgp": 3, "subnet": 4}

# ponytail: an hour. A lab changes by the minute and a data centre by the
# quarter; make it a setting when someone actually needs a different number.
_STALE_AFTER_MIN = 60

# Every device on a shared management VLAN is not "adjacent" to every other in
# any sense useful for blast radius, and treating them that way turns a /24
# with 200 hosts into 19,900 edges. Subnet inference is for point-to-point
# links and small segments; anything wider is left to LLDP.
_MAX_SUBNET_PEERS = 4

_IPV4 = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})(?:/(\d{1,2}))?\b")

_lock = threading.RLock()
_conn: Optional[sqlite3.Connection] = None


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------

def _db() -> sqlite3.Connection:
    global _conn
    with _lock:
        if _conn is None:
            path = Path(settings.STATE_DIR).expanduser() / "topology.db"
            path.parent.mkdir(parents=True, exist_ok=True)
            _conn = sqlite3.connect(path, check_same_thread=False)
            _conn.row_factory = sqlite3.Row
            _conn.executescript(_SCHEMA)
            _conn.commit()
        return _conn


def reset() -> None:
    """Drop the cached connection so the next call re-opens (tests)."""
    global _conn
    with _lock:
        if _conn is not None:
            _conn.close()
        _conn = None


def _now() -> str:
    return datetime.now(tz=timezone.utc).isoformat(timespec="seconds")


def _age_minutes(timestamp: Optional[str]) -> Optional[float]:
    if not timestamp:
        return None
    try:
        then = datetime.fromisoformat(timestamp)
    except ValueError:
        return None
    return round((datetime.now(tz=timezone.utc) - then).total_seconds() / 60, 1)


def _freshness(timestamps: Iterable[Optional[str]]) -> dict[str, Any]:
    """Describe how old the data behind an answer is.

    Attached to every query result. An answer built from a stale graph is not
    wrong so much as out of date, and the caller is the one who can tell the
    difference — but only if told.
    """
    ages = [a for a in (_age_minutes(t) for t in timestamps) if a is not None]
    if not ages:
        return {
            "discovered": False,
            "warning": (
                "There is NO topology data for this. That is not a finding that "
                "the network is empty or that nothing is connected — run "
                "discover_topology first."
            ),
        }
    oldest = max(ages)
    info: dict[str, Any] = {"discovered": True, "age_minutes": oldest}
    if oldest > _STALE_AFTER_MIN:
        info["stale"] = True
        info["warning"] = (
            f"This graph was last discovered {oldest:.0f} minutes ago and may no "
            f"longer match the network. Re-run discover_topology before relying "
            f"on it for a change."
        )
    return info


# ---------------------------------------------------------------------------
# Parsing
#
# These pull out only what the graph needs, and resolve it against the set of
# devices already known. That is what makes them robust across platforms: the
# column an address sits in varies, but an address that matches a known node is
# a match whatever column it came from, and one that matches nothing produces
# no edge rather than a wrong one.
# ---------------------------------------------------------------------------

def _parse_interfaces(output: str, command: str, device_type: str) -> list[dict]:
    """Interface name, address and prefix length, where the platform gives them."""
    rows = summarize.structured(output, command, device_type)
    if rows:
        parsed: list[dict] = []
        for row in rows:
            name = row.get("interface") or row.get("intf") or ""
            if not name:
                continue
            addresses = row.get("ip_addresses") or (
                [row["ip_address"]] if row.get("ip_address") else [])
            masks = row.get("ip_masks") or []
            status = (row.get("status") or row.get("state") or "").lower()
            if not addresses:
                parsed.append({"name": name, "ip": "", "prefixlen": None, "status": status})
            for i, address in enumerate(addresses):
                if not _is_usable(address):
                    continue
                plen = int(masks[i]) if i < len(masks) and str(masks[i]).isdigit() else None
                parsed.append({"name": name, "ip": address, "prefixlen": plen,
                               "status": status})
        if parsed:
            return parsed

    # No template for this platform. Every brief-style interface table shares
    # one shape: the interface is the first token, and any address on the line
    # belongs to it.
    parsed = []
    for line in output.splitlines():
        if not line[:1].strip() or line.lstrip().startswith(("-", "%")):
            continue
        tokens = line.split()
        if len(tokens) < 2 or not _looks_like_interface(tokens[0]):
            continue
        status = "up" if " up" in f" {line.lower()}" else (
            "down" if " down" in f" {line.lower()}" else "")
        found = [m for m in _IPV4.finditer(line) if _is_usable(m.group(1))]
        if not found:
            parsed.append({"name": tokens[0], "ip": "", "prefixlen": None, "status": status})
        for match in found:
            parsed.append({
                "name": tokens[0],
                "ip": match.group(1),
                "prefixlen": int(match.group(2)) if match.group(2) else None,
                "status": status,
            })
    return parsed


def _looks_like_interface(token: str) -> bool:
    return bool(token) and token[0].isalpha() and token.lower() not in {
        "interface", "neighbor", "total", "bgp", "ipv4", "ip", "peers", "rib",
        "note", "building", "current", "configuration", "version", "flags",
    }


def _is_usable(address: str) -> bool:
    """An address that could plausibly identify a device on this network."""
    try:
        ip = ipaddress.IPv4Address(address)
    except ValueError:
        return False
    return not (ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_reserved)


def _candidate_peers(output: str) -> set[str]:
    """Every address in the output that might name a neighbour.

    Deliberately over-inclusive: a router ID, a table version and a real peer
    all look alike here. The caller narrows it by keeping only addresses that
    belong to a *different* known device, so a false candidate produces
    nothing rather than a wrong edge.
    """
    return {m.group(1) for m in _IPV4.finditer(output) if _is_usable(m.group(1))}


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

def _first_accepted(device: Device, kind: str, reason: str) -> tuple[str, str]:
    """Run candidate commands until one is not rejected. Returns (command, output)."""
    for command in vendor.discovery_commands(device.device_type, kind):
        try:
            output = sessions.run_command(
                device, command, reason=reason, tool="discover_topology")
        except Exception as exc:
            logger.debug("%s: %s failed: %s", device.name, command, exc)
            continue
        if output.strip() and not vendor.device_rejected(output):
            return command, output
    return "", ""


def discover_topology(reason: str, devices: Optional[list[str]] = None) -> dict[str, Any]:
    """Walk devices, read their neighbours, and build the topology graph.

    Runs only read-only show commands. Each device is re-read from scratch, so
    an interface that has gone away disappears from the graph rather than
    lingering as a stale edge.

    Parameters
    ----------
    reason: why the network is being mapped — recorded in the audit log.
    devices: inventory names to walk. Omit to walk everything in the inventory.
    """
    inventory = get_inventory()
    try:
        targets = [inventory.resolve(name) for name in devices] if devices else inventory.all()
    except InventoryError as exc:
        return {"error": str(exc)}

    if not targets:
        return {"error": "The inventory is empty — there is nothing to discover."}

    log = audit.current()
    conn = _db()
    now = _now()

    seen: dict[str, list[dict]] = {}
    walked: dict[str, Device] = {}
    failed: dict[str, str] = {}
    lldp_edges: list[tuple[str, str, str, str, str]] = []
    peer_hits: dict[str, dict[str, set[str]]] = {}

    for device in targets:
        # Discovery is built on CLI show commands. Pointing them at a device
        # that speaks only NETCONF would open an SSH session to a NETCONF
        # server and wait for a prompt that never comes, so it is skipped and
        # said out loud rather than appearing as a device with no neighbours.
        if "ssh" not in (device.protocols or ("ssh",)):
            failed[device.name] = (
                f"speaks {'/'.join(device.protocols)}, not CLI over SSH — "
                f"discovery reads neighbours with show commands")
            continue

        command, output = _first_accepted(device, "interfaces", reason)
        if not command:
            failed[device.name] = "no interface command was accepted by this device"
            continue

        interfaces = _parse_interfaces(output, command, device.device_type)
        if not interfaces:
            failed[device.name] = f"could not read any interface from '{command}'"
            continue
        seen[device.name] = interfaces
        walked[device.name] = device

        for kind in ("bgp", "ospf"):
            _, peer_output = _first_accepted(device, kind, reason)
            if peer_output:
                peer_hits.setdefault(device.name, {})[kind] = _candidate_peers(peer_output)

        lldp_command, lldp_output = _first_accepted(device, "lldp", reason)
        if lldp_output:
            lldp_edges.extend(
                _lldp_edges(device, lldp_output, lldp_command, inventory.names()))

    if not seen:
        log.event("discover", reason=reason, nodes=0, edges=0, failed=failed)
        return {"discovered": 0, "failed": failed,
                "error": "No device could be read — nothing was written to the graph."}

    aliases = _collapse_aliases(seen)

    with conn:
        for name, interfaces in seen.items():
            device = walked[name]
            conn.execute(
                "INSERT INTO nodes (name, device_type, host, discovered_at) VALUES (?,?,?,?) "
                "ON CONFLICT(name) DO UPDATE SET device_type=excluded.device_type, "
                "host=excluded.host, discovered_at=excluded.discovered_at",
                (name, device.device_type, device.host, now))
            # Replaced wholesale, not merged: an interface that no longer
            # exists has to leave the graph.
            conn.execute("DELETE FROM interfaces WHERE node = ?", (name,))
            conn.executemany(
                "INSERT OR REPLACE INTO interfaces "
                "(node, name, ip, prefixlen, status, discovered_at) VALUES (?,?,?,?,?,?)",
                [(name, i["name"], i["ip"], i["prefixlen"], i["status"], now)
                 for i in interfaces])
        for alias in aliases:
            conn.execute("DELETE FROM nodes WHERE name = ?", (alias,))
            conn.execute("DELETE FROM interfaces WHERE node = ?", (alias,))
            conn.execute("DELETE FROM edges WHERE a_node = ? OR b_node = ?", (alias, alias))

    # Address -> (node, interface), used to turn a peer address into an edge.
    owner: dict[str, tuple[str, str]] = {
        i["ip"]: (node, i["name"])
        for node, interfaces in seen.items() for i in interfaces if i["ip"]
    }

    edges: list[tuple[str, str, str, str, str]] = list(lldp_edges)
    edges.extend(_subnet_edges(seen))
    for node, kinds in peer_hits.items():
        for kind, addresses in kinds.items():
            for address in addresses:
                match = owner.get(address)
                if not match or match[0] == node:
                    continue  # unknown address, or the device's own
                local = _interface_facing(seen[node], address)
                edges.append((node, local, match[0], match[1], kind))

    written = _store_edges(conn, edges, now, [d.name for d in targets if d.name in seen])

    by_source: dict[str, int] = {}
    for edge in written:
        by_source[edge[4]] = by_source.get(edge[4], 0) + 1

    no_masks = [n for n, ifs in seen.items()
                if any(i["ip"] for i in ifs) and not any(i["prefixlen"] for i in ifs)]

    result: dict[str, Any] = {
        "discovered": len(seen),
        "nodes": sorted(seen),
        "interfaces": sum(len(i) for i in seen.values()),
        "edges": len(written),
        "edges_by_source": by_source,
    }
    if failed:
        result["failed"] = failed
        result["note"] = (
            f"{len(failed)} device(s) could not be read, so any link to them is "
            f"missing from the graph. This is not evidence that they are not "
            f"connected.")
    if aliases:
        result["merged_aliases"] = aliases
        result["alias_note"] = (
            "These inventory entries share an address with another entry, so they "
            "were treated as the same device rather than as neighbours of it. If "
            "they are genuinely different devices, that is a duplicate-address "
            "fault worth investigating.")
    if no_masks:
        result["no_subnet_inference"] = no_masks
        result["subnet_note"] = (
            "These devices reported addresses without a prefix length, so shared "
            "subnets could not be inferred for them. LLDP or CDP would cover it.")

    log.event("discover", reason=reason, nodes=len(seen), edges=len(written),
              by_source=by_source, failed=failed or None)
    return result


def _collapse_aliases(seen: dict[str, list[dict]]) -> dict[str, str]:
    """Drop inventory entries that are really another entry for the same device.

    Two devices cannot hold the same unicast address on a working network, so
    entries sharing one are the same box reached twice — an enable account
    beside a read-only one, or the lab's container reached through both vtysh
    and a shell. Left alone they show up as two nodes with a link between them,
    which is a link that does not exist.

    The surviving name is the first alphabetically; the rest are removed from
    *seen* in place and returned so the caller can report them. A genuine
    duplicate-address fault would also land here, which is why the result names
    the entries it merged instead of merging them quietly.
    """
    holders: dict[str, set[str]] = {}
    for node, interfaces in seen.items():
        for i in interfaces:
            if i["ip"]:
                holders.setdefault(i["ip"], set()).add(node)

    alias_of: dict[str, str] = {}
    for nodes in holders.values():
        if len(nodes) < 2:
            continue
        canonical = min(nodes)
        for node in nodes:
            if node != canonical:
                alias_of[node] = alias_of.get(node, canonical)

    for alias in alias_of:
        seen.pop(alias, None)
    return alias_of


def _interface_facing(interfaces: list[dict], peer: str) -> str:
    """The local interface in the same subnet as *peer*, if one is identifiable."""
    try:
        target = ipaddress.IPv4Address(peer)
    except ValueError:
        return ""
    for i in interfaces:
        if not i["ip"] or not i["prefixlen"]:
            continue
        try:
            net = ipaddress.ip_network(f"{i['ip']}/{i['prefixlen']}", strict=False)
        except ValueError:
            continue
        if target in net:
            return i["name"]
    return ""


def _subnet_edges(seen: dict[str, list[dict]]) -> list[tuple[str, str, str, str, str]]:
    """Devices sharing a small subnet are treated as adjacent."""
    members: dict[Any, list[tuple[str, str]]] = {}
    for node, interfaces in seen.items():
        for i in interfaces:
            if not i["ip"] or not i["prefixlen"] or i["prefixlen"] >= 31:
                continue  # /31 and /32 carry no usable peer set here
            try:
                net = ipaddress.ip_network(f"{i['ip']}/{i['prefixlen']}", strict=False)
            except ValueError:
                continue
            members.setdefault(net, []).append((node, i["name"]))

    edges = []
    for net, attached in members.items():
        nodes = {n for n, _ in attached}
        if len(nodes) < 2 or len(nodes) > _MAX_SUBNET_PEERS:
            continue
        for idx, (a_node, a_if) in enumerate(attached):
            for b_node, b_if in attached[idx + 1:]:
                if a_node != b_node:
                    edges.append((a_node, a_if, b_node, b_if, "subnet"))
    return edges


def _lldp_edges(device: Device, output: str, command: str,
                known: list[str]) -> list[tuple[str, str, str, str, str]]:
    """Edges from LLDP/CDP output, matched to inventory names by hostname.

    Unverified against real hardware — the FRR lab has no LLDP daemon, so this
    path is exercised only by unit tests with recorded output.
    """
    source = "cdp" if "cdp" in command.lower() else "lldp"
    rows = summarize.structured(output, command, device.device_type) or []
    edges = []
    for row in rows:
        peer = (row.get("neighbor") or row.get("destination_host")
                or row.get("neighbor_name") or row.get("device_id") or "")
        peer = peer.split(".")[0].strip()
        match = next((k for k in known if k.split(".")[0].lower() == peer.lower()), None)
        if not match or match == device.name:
            continue
        edges.append((
            device.name,
            row.get("local_interface") or row.get("local_port") or "",
            match,
            row.get("neighbor_interface") or row.get("remote_port") or "",
            source,
        ))
    return edges


def _store_edges(conn: sqlite3.Connection, edges: list[tuple[str, str, str, str, str]],
                 now: str, rediscovered: list[str]) -> list[tuple]:
    """Replace the edges touching *rediscovered* nodes with the ones just found."""
    canonical = []
    for a_node, a_if, b_node, b_if, source in edges:
        if a_node == b_node:
            continue
        if a_node > b_node:  # one row per undirected link, not two
            a_node, a_if, b_node, b_if = b_node, b_if, a_node, a_if
        canonical.append((a_node, a_if, b_node, b_if, source))

    unique = sorted(set(canonical))
    with conn:
        placeholders = ",".join("?" * len(rediscovered))
        conn.execute(
            f"DELETE FROM edges WHERE a_node IN ({placeholders}) "
            f"OR b_node IN ({placeholders})",
            rediscovered * 2)
        conn.executemany(
            "INSERT OR REPLACE INTO edges "
            "(a_node, a_if, b_node, b_if, source, discovered_at) VALUES (?,?,?,?,?,?)",
            [(*edge, now) for edge in unique])
    return unique


# ---------------------------------------------------------------------------
# Graph
# ---------------------------------------------------------------------------

def _graph():
    """Build the NetworkX view of what is stored.

    # ponytail: rebuilt per call rather than cached. It is a handful of SQLite
    # rows and microseconds of work; add a cache when someone points this at
    # thousands of nodes and measures a problem.
    """
    import networkx as nx

    conn = _db()
    graph = nx.Graph()
    for row in conn.execute("SELECT * FROM nodes"):
        graph.add_node(row["name"], device_type=row["device_type"],
                       host=row["host"], discovered_at=row["discovered_at"])

    # Strongest source first, so when sources disagree about which interfaces
    # a link lands on, the most authoritative one is the row that sets them.
    rows = sorted(conn.execute("SELECT * FROM edges"),
                  key=lambda r: SOURCE_RANK.get(r["source"], 99))
    for row in rows:
        a, b = row["a_node"], row["b_node"]
        for name in (a, b):
            if name not in graph:  # a neighbour that was never walked itself
                graph.add_node(name, device_type=None, host=None, discovered_at=None)
        if graph.has_edge(a, b):
            data = graph[a][b]
            data["sources"].add(row["source"])
            data["discovered_at"] = max(data["discovered_at"], row["discovered_at"])
            # Sources disagree on detail: a BGP peering names no local
            # interface, a shared subnet names both. Keep whichever row
            # actually knows, so the link reads as the operator would draw it.
            for side in ("a_if", "b_if"):
                if not data[side] and row[side]:
                    data[side] = row[side]
        else:
            graph.add_edge(a, b, sources={row["source"]},
                           a_if=row["a_if"], b_if=row["b_if"],
                           discovered_at=row["discovered_at"])
    return graph


def _edge_view(graph, a: str, b: str) -> dict[str, Any]:
    data = graph[a][b]
    sources = sorted(data["sources"], key=lambda s: SOURCE_RANK.get(s, 99))
    return {
        "peer": b,
        "local_interface": data["a_if"] if a < b else data["b_if"],
        "peer_interface": data["b_if"] if a < b else data["a_if"],
        "sources": sources,
        "confidence": "observed" if sources[0] in ("lldp", "cdp") else "inferred",
    }


# ---------------------------------------------------------------------------
# Query
# ---------------------------------------------------------------------------

def query_topology(kind: str, reason: str, node: str = "",
                   interface: str = "", to: str = "") -> dict[str, Any]:
    """Ask the stored topology a question instead of re-reading every device.

    Parameters
    ----------
    kind: one of
        "summary"      — what the graph holds and how old it is
        "neighbors"    — what *node* is connected to, and how that is known
        "path"         — the shortest path from *node* to *to*
        "blast_radius" — what is cut off if *node* (or one *interface* on it)
                         goes away
    reason: why this is being asked — recorded in the audit log.
    node: the device the question is about.
    interface: for blast_radius, narrow it to a single link on *node*.
    to: for path, the far end.
    """
    graph = _graph()
    audit.current().event("topology_query", kind=kind, node=node or None,
                          interface=interface or None, to=to or None, reason=reason)

    if kind == "summary":
        return _summary(graph)

    if not node:
        return {"error": f"query_topology kind '{kind}' needs a node."}
    if node not in graph:
        known = ", ".join(sorted(graph.nodes)) or "none"
        return {
            "error": f"'{node}' is not in the topology graph. Known: {known}.",
            **_freshness(n.get("discovered_at") for _, n in graph.nodes(data=True)),
        }

    ages = [graph.nodes[node].get("discovered_at")]
    ages += [graph[node][p]["discovered_at"] for p in graph.neighbors(node)]

    if kind == "neighbors":
        return {
            "node": node,
            "neighbors": [_edge_view(graph, node, p) for p in sorted(graph.neighbors(node))],
            **_freshness(ages),
        }

    if kind == "path":
        return _path(graph, node, to, ages)

    if kind == "blast_radius":
        return _blast_radius(graph, node, interface, ages)

    return {"error": f"Unknown kind '{kind}'. Use summary, neighbors, path or blast_radius."}


def _summary(graph) -> dict[str, Any]:
    import networkx as nx

    timestamps = [n.get("discovered_at") for _, n in graph.nodes(data=True)]
    result: dict[str, Any] = {
        "nodes": graph.number_of_nodes(),
        "edges": graph.number_of_edges(),
        "devices": sorted(graph.nodes),
        **_freshness(timestamps),
    }
    if graph.number_of_nodes():
        components = list(nx.connected_components(graph))
        result["connected_components"] = len(components)
        if len(components) > 1:
            result["islands"] = [sorted(c) for c in components]
        # The devices that would partition the network if they went away.
        cut_vertices = sorted(nx.articulation_points(graph))
        if cut_vertices:
            result["single_points_of_failure"] = cut_vertices
    return result


def _path(graph, node: str, to: str, ages: list) -> dict[str, Any]:
    import networkx as nx

    if not to:
        return {"error": "path needs both 'node' and 'to'."}
    if to not in graph:
        return {"error": f"'{to}' is not in the topology graph."}
    try:
        hops = nx.shortest_path(graph, node, to)
    except nx.NetworkXNoPath:
        return {
            "from": node, "to": to, "path": None,
            "note": (f"No path between {node} and {to} in the graph. They may still "
                     f"reach each other through devices that are not in the "
                     f"inventory — the graph only knows what it has walked."),
            **_freshness(ages),
        }
    return {
        "from": node,
        "to": to,
        "hops": len(hops) - 1,
        "path": hops,
        "links": [_edge_view(graph, a, b) for a, b in zip(hops, hops[1:])],
        **_freshness(ages),
    }


def _blast_radius(graph, node: str, interface: str, ages: list) -> dict[str, Any]:
    """What loses reachability if *node*, or one link on it, goes away."""
    import networkx as nx

    working = graph.copy()
    if interface:
        cut = [p for p in graph.neighbors(node)
               if interface.lower() in (
                   (graph[node][p]["a_if"] if node < p else graph[node][p]["b_if"]) or ""
               ).lower()]
        if not cut:
            return {
                "node": node,
                "interface": interface,
                "error": (f"No link on {node} is recorded against interface "
                          f"'{interface}'. The graph may not have that interface, "
                          f"which is NOT the same as the interface carrying no "
                          f"traffic — check `show` on the device."),
                **_freshness(ages),
            }
        working.remove_edges_from([(node, p) for p in cut])
        removed = [{"peer": p, **_edge_view(graph, node, p)} for p in cut]
    else:
        working.remove_node(node)
        removed = [{"peer": p, **_edge_view(graph, node, p)} for p in graph.neighbors(node)]

    # What is left over, measured against the largest surviving island rather
    # than from the changed device's own point of view — cutting an uplink
    # separates two groups, and which of them counts as "cut off" is a fact
    # about the network, not about which end the command was typed on.
    islands = sorted((sorted(c) for c in nx.connected_components(working)),
                     key=lambda c: (-len(c), c[0] if c else ""))
    isolated = sorted(n for island in islands[1:] for n in island)

    result: dict[str, Any] = {
        "node": node,
        "interface": interface or None,
        "links_lost": removed,
        "isolated": isolated,
        "impact": (
            "no other device loses reachability" if not isolated
            else f"{len(isolated)} device(s) lose reachability: {', '.join(isolated)}"
        ),
        **_freshness(ages),
    }
    if len(islands) > 1:
        result["partitions"] = islands
        if len(islands[0]) == len(islands[1]):
            result["ambiguous_split"] = (
                "The network splits into evenly sized halves, so neither side is "
                "obviously the one left stranded. Which half matters depends on "
                "where the rest of the network attaches — read 'partitions' rather "
                "than 'isolated' here."
            )
    if not result.get("discovered", True) or result.get("stale"):
        result["impact"] += " — but see the warning about this graph's age."
    return result
