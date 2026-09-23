"""Transport selection and the guards that run before a device is contacted.

The device-side behaviour lives in tests/integration/test_netconf.py; these
cover the decisions made without a connection — which transport a device gets,
and what it refuses to send.
"""
from __future__ import annotations

import pytest

from netnerd_mcp.drivers import transports
from netnerd_mcp.drivers.base import (
    CONFIRMED_COMMIT, INTERACTIVE, STRUCTURED, DeviceRejected, TransportError)
from netnerd_mcp.inventory import Device

# The protocol extras are optional by design, so a core install has none of
# this. Tests that need a transport to actually construct are skipped rather
# than installed around — CI runs the suite both ways.
requires_ncclient = pytest.mark.skipif(
    not transports._available("netconf"),
    reason="ncclient not installed (pip install 'netnerd-mcp[netconf]')")
requires_httpx = pytest.mark.skipif(
    not transports._available("restconf"),
    reason="httpx not installed (pip install 'netnerd-mcp[netconf]')")


def _device(**overrides) -> Device:
    return Device(name=overrides.pop("name", "d1"),
                  host=overrides.pop("host", "10.0.0.1"), **overrides)


class TestSelection:
    def test_a_device_with_no_protocols_gets_ssh(self):
        """Brownfield default: everything speaks CLI over SSH."""
        assert transports.for_device(_device()).name == "ssh"

    @requires_ncclient
    def test_a_netconf_device_gets_netconf(self):
        assert transports.for_device(
            _device(protocols=("netconf",))).name == "netconf"

    @requires_ncclient
    def test_the_first_listed_protocol_wins(self):
        assert transports.for_device(
            _device(protocols=("netconf", "ssh"))).name == "netconf"
        assert transports.for_device(
            _device(protocols=("ssh", "netconf"))).name == "ssh"

    def test_an_unknown_protocol_is_skipped_rather_than_fatal(self):
        assert transports.for_device(
            _device(protocols=("carrier-pigeon", "ssh"))).name == "ssh"

    @requires_ncclient
    def test_requiring_confirmed_commit_skips_ssh(self):
        transport = transports.for_device(
            _device(protocols=("ssh", "netconf")), require=CONFIRMED_COMMIT)
        assert transport.name == "netconf"

    def test_requiring_something_nothing_provides_raises(self):
        with pytest.raises(TransportError, match="confirmed_commit"):
            transports.for_device(_device(protocols=("ssh",)), require=CONFIRMED_COMMIT)


class TestNoSilentDowngrade:
    """A device declared NETCONF-only must never be reached over CLI.

    Falling back to SSH would open a netmiko session against port 830 and push
    configuration commands into a NETCONF server. CI caught this: it installs
    without the protocol extras, and selection quietly returned SSH for a
    netconf-only device.
    """

    def test_an_unusable_listed_protocol_raises_rather_than_falling_back(self, monkeypatch):
        monkeypatch.setattr(transports, "_BY_NAME", {"ssh": transports.SSHTransport})

        with pytest.raises(TransportError) as raised:
            transports.for_device(_device(protocols=("netconf",)))

        assert "No usable transport" in str(raised.value)
        assert "netconf" in str(raised.value)

    def test_the_error_says_what_is_missing(self):
        """A missing optional dependency should read as an install hint, not
        as a device problem."""
        if transports._available("netconf"):
            pytest.skip("ncclient is installed, so there is nothing missing")

        with pytest.raises(TransportError, match=r"netnerd-mcp\[netconf\]"):
            transports.for_device(_device(protocols=("netconf",)))

    def test_a_device_listing_ssh_as_a_fallback_still_gets_it(self, monkeypatch):
        monkeypatch.setattr(transports, "_BY_NAME", {"ssh": transports.SSHTransport})

        assert transports.for_device(
            _device(protocols=("netconf", "ssh"))).name == "ssh"


@requires_ncclient
class TestCapabilities:
    def test_only_netconf_claims_the_device_can_revert_itself(self):
        """This drives which rollback mechanism a change gets, so a wrong
        answer here would promise a safety net that does not exist."""
        assert CONFIRMED_COMMIT in transports.NetconfTransport().capabilities()
        assert CONFIRMED_COMMIT not in transports.SSHTransport().capabilities()
        assert CONFIRMED_COMMIT not in transports.RestconfTransport().capabilities()

    def test_only_ssh_runs_arbitrary_commands(self):
        assert INTERACTIVE in transports.SSHTransport().capabilities()
        assert INTERACTIVE not in transports.NetconfTransport().capabilities()

    def test_the_model_driven_transports_say_so(self):
        assert STRUCTURED in transports.NetconfTransport().capabilities()
        assert STRUCTURED in transports.RestconfTransport().capabilities()


class TestConfigLanguage:
    def test_the_inventory_says_what_a_change_must_be_written_in(self):
        assert _device().config_language == "cli"
        assert _device(protocols=("netconf",)).config_language == "xml"
        assert _device(protocols=("restconf",)).config_language == "json"

    def test_list_devices_surfaces_it(self):
        """An agent cannot write a valid change without knowing this."""
        redacted = _device(protocols=("netconf",)).redacted()
        assert redacted["config_language"] == "xml"
        assert redacted["protocols"] == ["netconf"]
        assert "password" not in redacted


@requires_ncclient
class TestWrongLanguageIsRefusedBeforeSending:
    """CLI lines sent to a NETCONF device would be a malformed RPC. Catching
    it here gives the caller a usable message instead of a parser error."""

    def test_cli_lines_to_a_netconf_device_are_refused(self):
        with pytest.raises(TransportError, match="XML"):
            transports.NetconfTransport().apply(
                _device(protocols=("netconf",)), ["interface lo", "shutdown"])

    def test_the_message_names_what_was_received(self):
        with pytest.raises(TransportError, match="interface lo"):
            transports.NetconfTransport().apply(
                _device(protocols=("netconf",)), ["interface lo"])

    @requires_httpx
    def test_cli_lines_to_a_restconf_device_are_refused(self):
        with pytest.raises(TransportError, match="JSON"):
            transports.RestconfTransport().apply(
                _device(protocols=("restconf",)), ["interface lo", "shutdown"])

    def test_an_empty_change_is_refused(self):
        with pytest.raises(TransportError):
            transports.NetconfTransport().apply(_device(protocols=("netconf",)), [])


class TestUnsupportedOperations:
    def test_ssh_has_no_confirmed_commit_to_confirm(self):
        with pytest.raises(TransportError, match="server-side timer"):
            transports.SSHTransport().confirm(_device())

    @requires_httpx
    def test_restconf_has_no_startup_datastore(self):
        """RFC 8040 has only running. Saying that beats returning the running
        config under a label claiming it is the startup one."""
        with pytest.raises(TransportError, match="not a finding"):
            transports.RestconfTransport().get_config(
                _device(protocols=("restconf",)), startup=True)


class TestRejectionIsDistinctFromFailure:
    def test_a_rejection_is_a_kind_of_transport_error(self):
        assert issubclass(DeviceRejected, TransportError)

    def test_but_the_two_can_be_told_apart(self):
        """They mean opposite things about the device: a rejection is a known
        'nothing happened', a transport error is 'state unknown'. The change
        loop arms or disarms a rollback on the difference."""
        assert not isinstance(TransportError("dropped"), DeviceRejected)


class TestPersistId:
    def test_a_confirmed_commit_is_persisted_per_device(self):
        """Without <persist> a confirmed commit dies with the session that
        made it — and these sessions close straight after committing, so every
        change would silently undo itself seconds later."""
        assert transports._persist_id(_device(name="core-sw1")) == "netnerd-core-sw1"
        assert transports._persist_id(_device(name="a")) != transports._persist_id(
            _device(name="b"))
