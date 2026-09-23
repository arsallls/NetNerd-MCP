"""gNMI against a real target.

google/gnxi is the reference implementation from the gNMI authors, so passing
here means the transport speaks the protocol rather than one vendor's reading
of it.

The target serves a static config, so counters do not move. That is fine for
what these prove: that a bounded subscription collects samples, summarises
them, and — the part that matters — *ends*. An unbounded subscription would
hang the tool call and wedge the client session.
"""
from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from tests.conftest import requires_gnmi

os.environ["NETNERD_INVENTORY"] = str(
    Path(__file__).resolve().parents[2] / "lab" / "lab-inventory.yaml")

from netnerd_mcp import audit  # noqa: E402
from netnerd_mcp.config.settings import settings  # noqa: E402
from netnerd_mcp.drivers import transports  # noqa: E402
from netnerd_mcp.drivers.base import STRUCTURED, TELEMETRY, TransportError  # noqa: E402
from netnerd_mcp.inventory import get_inventory, reset_inventory  # noqa: E402
from netnerd_mcp.tools import telemetry  # noqa: E402

pytestmark = [
    pytest.mark.integration,
    requires_gnmi,
    # Closing the channel is how a bounded subscription ends, and pygnmi's
    # internal reader thread sees that as a CANCELLED rpc. It is the expected
    # path, not a swallowed failure — and a suite that warns on every normal
    # run teaches people to stop reading warnings.
    pytest.mark.filterwarnings("ignore::pytest.PytestUnhandledThreadExceptionWarning"),
]

MTU_PATH = "/interfaces/interface[name=eth0]/config/mtu"


@pytest.fixture
def device():
    reset_inventory()
    return get_inventory().resolve("gnmi1")


@pytest.fixture(autouse=True)
def clean_state(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "AUDIT_DIR", str(tmp_path))
    monkeypatch.setattr(settings, "STATE_DIR", str(tmp_path / "state"))
    audit.reset()
    yield
    audit.reset()


class TestTransport:
    def test_the_device_gets_the_gnmi_transport(self, device):
        transport = transports.for_device(device)
        assert transport.name == "gnmi"
        assert {STRUCTURED, TELEMETRY} <= transport.capabilities()

    def test_a_get_returns_the_openconfig_tree(self, device):
        config = transports.for_device(device).get_config(device)
        assert "openconfig-interfaces:interfaces" in config
        assert "eth0" in config

    def test_there_is_no_startup_datastore_to_read(self, device):
        """gNMI reads operational and intended state, not a boot config."""
        with pytest.raises(TransportError, match="NOT a finding"):
            transports.for_device(device).get_config(device, startup=True)


class TestBoundedSubscription:
    def test_a_window_collects_samples_and_ends(self, device):
        started = time.monotonic()
        result = telemetry("gnmi1", [MTU_PATH], reason="watching a live counter", seconds=3)
        elapsed = time.monotonic() - started

        assert result["samples"] > 0, result
        assert result["paths"][MTU_PATH]["last"] == 1500
        assert elapsed < 20, f"a 3s window took {elapsed:.0f}s — it is not bounded"

    def test_a_path_the_device_never_reports_still_returns(self, device):
        """The failure this guards against: iterating a subscription blocks
        until an update arrives, so a silent path would hang forever and take
        the client session with it."""
        started = time.monotonic()
        result = telemetry("gnmi1", ["/interfaces/interface[name=nope99]/state/counters/in-errors"],
                           reason="watching a path that does not exist", seconds=3)
        elapsed = time.monotonic() - started

        assert elapsed < 20, f"a silent path took {elapsed:.0f}s — it is not bounded"
        assert result["samples"] == 0

    def test_silence_is_never_reported_as_a_zero_reading(self, device):
        result = telemetry("gnmi1", ["/interfaces/interface[name=nope99]/state/counters/in-errors"],
                           reason="checking silence is not a measurement", seconds=3)

        summary = result["paths"]["/interfaces/interface[name=nope99]/state/counters/in-errors"]
        assert "last" not in summary, "an absent counter must not come back with a value"
        assert "NOT a reading of zero" in summary["note"]

    def test_several_paths_are_summarised_separately(self, device):
        paths = [MTU_PATH, "/interfaces/interface[name=eth1]/config/mtu"]
        result = telemetry("gnmi1", paths, reason="watching two interfaces", seconds=3)

        assert set(result["paths"]) == set(paths)
        assert all(result["paths"][p]["samples"] > 0 for p in paths), result["paths"]


class TestGuards:
    def test_the_window_is_capped(self, device, monkeypatch):
        monkeypatch.setattr(settings, "MAX_TELEMETRY_SEC", 2)

        result = telemetry("gnmi1", [MTU_PATH], reason="asking for far too long", seconds=600)

        assert result["seconds"] == 2
        assert "MAX_TELEMETRY_SEC" in result["note"]

    def test_a_device_that_cannot_stream_says_so_clearly(self):
        """And says it is not a finding that the counters are idle."""
        result = telemetry("r1", ["/interfaces"], reason="r1 speaks CLI only", seconds=3)

        assert "error" in result
        assert "gNMI" in result["error"]
        assert "NOT a finding" in result["error"]

    def test_the_refusal_is_audited(self):
        telemetry("r1", ["/interfaces"], reason="r1 speaks CLI only", seconds=3)

        blocked = [e for e in audit.current().events()
                   if e["event"] == "blocked" and e.get("tool") == "telemetry"]
        assert blocked, "a refusal nobody can see in the log is not a record"


class TestAudit:
    def test_a_sample_is_recorded_with_its_paths(self, device):
        telemetry("gnmi1", [MTU_PATH], reason="checking the audit trail", seconds=3)

        events = [e for e in audit.current().events() if e.get("tool") == "telemetry"]
        assert events, "watching a device has to be auditable like any other read"
        assert MTU_PATH in events[-1]["paths"]
        assert events[-1]["reason"] == "checking the audit trail"
