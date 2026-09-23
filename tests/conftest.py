"""Shared test fixtures.

Integration tests drive the FRR lab (`make lab`) over real SSH — the project
convention is not to mock the SSH driver, because real device state matters.
"""
from __future__ import annotations

import socket
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Lab topology — see lab/docker-compose.yml
LAB_NODES = {
    "r1": {"host": "localhost", "port": 2211, "router_id": "10.1.1.1", "asn": 65001},
    "r2": {"host": "localhost", "port": 2212, "router_id": "10.2.2.2", "asn": 65002},
}
LAB_USER = "netnerd"
LAB_PASS = "netnerd123"


def _port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _lab_is_up() -> bool:
    return all(_port_open(n["host"], n["port"]) for n in LAB_NODES.values())


requires_lab = pytest.mark.skipif(
    not _lab_is_up(),
    reason="FRR lab not running — start it with `make lab`",
)


@pytest.fixture(autouse=True)
def close_pooled_connections():
    """Hand back every SSH session a test opened.

    Connections are pooled per audit session, and the fixtures that reset the
    audit log between tests change the session id — which orphans the pooled
    connections rather than closing them. Left alone they accumulate until
    sshd's MaxStartups refuses the lab entirely, and the whole suite fails with
    "Error reading SSH protocol banner" on tests that have nothing wrong with
    them. Production closes these through end_session and the idle timer; tests
    have to do it themselves.
    """
    yield
    from netnerd_mcp import sessions
    try:
        sessions.close_all(reason="test finished")
    except Exception:  # a teardown failure must not mask the test's own result
        pass


@pytest.fixture(scope="session")
def r1() -> dict:
    return LAB_NODES["r1"]


@pytest.fixture
def driver():
    """A real SSHDriver pointed at the lab, read-only OFF."""
    from netnerd_mcp.drivers.ssh_driver import SSHDriver
    return SSHDriver(username=LAB_USER, password=LAB_PASS, read_only_mode=False)


@pytest.fixture
def readonly_driver():
    """A real SSHDriver pointed at the lab, read-only ON."""
    from netnerd_mcp.drivers.ssh_driver import SSHDriver
    return SSHDriver(username=LAB_USER, password=LAB_PASS, read_only_mode=True)


def _vtysh(*args: str) -> str:
    return subprocess.run(
        ["docker", "exec", "netnerd-lab-r1", "vtysh", *args],
        capture_output=True, text=True, timeout=30,
    ).stdout


def r1_loopback_description() -> str:
    """The description on r1's lo right now, or "" if it has none."""
    in_lo = False
    for line in _vtysh("-c", "show running-config").splitlines():
        if line[:1].strip():
            in_lo = line.strip().lower() == "interface lo"
        elif in_lo and line.strip().lower().startswith("description "):
            return line.strip()[len("description "):]
    return ""


@pytest.fixture
def preserve_r1_loopback():
    """Put back whatever description r1's lo had.

    Several tests borrow that one interface, and the lab is shared with whoever
    is using it by hand — a test run once destroyed a description someone had
    just saved and persisted the removal to startup. Tests may do what they like
    to lo as long as they hand it back.
    """
    running = r1_loopback_description()
    startup = "description" in subprocess.run(
        ["docker", "exec", "netnerd-lab-r1", "grep", "-A2", "interface lo", "/etc/frr/frr.conf"],
        capture_output=True, text=True, timeout=30,
    ).stdout

    yield

    if r1_loopback_description() != running:
        _vtysh("-c", "configure terminal", "-c", "interface lo",
               "-c", f"description {running}" if running else "no description")
    if startup:
        _vtysh("-c", "write memory")
