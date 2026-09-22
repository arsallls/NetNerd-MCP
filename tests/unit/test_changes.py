"""The change token is the gate. These cover the paths that refuse before any
SSH connection is attempted — the device-side behaviour lives in the lab tests.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from netnerd_mcp import audit, changes
from netnerd_mcp.changes import ChangeToken, _hash_commands, _inverse_commands
from netnerd_mcp.vendor import device_rejected as _device_rejected
from netnerd_mcp.config.settings import settings
from netnerd_mcp.security.command_validator import validate_config_change


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "AUDIT_DIR", str(tmp_path))
    audit.reset()
    changes.reset()
    yield
    changes.reset()
    audit.reset()


def _token(**overrides) -> ChangeToken:
    commands = overrides.pop("commands", ["interface lo", "description test"])
    token = ChangeToken(
        id=overrides.pop("id", "chg-test01"),
        device=overrides.pop("device", "r1"),
        commands=commands,
        command_hash=_hash_commands(commands),
        backup=overrides.pop("backup", "hostname r1\n"),
        expires_at=overrides.pop(
            "expires_at", datetime.now(tz=timezone.utc) + timedelta(minutes=10)
        ),
        mechanism="server-side rollback timer (5 min)",
        **overrides,
    )
    changes._tokens[token.id] = token
    return token


class TestTokenGate:
    def test_unknown_token_is_refused(self):
        result = changes.apply_change("chg-nope", reason="test")
        assert "Unknown change token" in result["error"]

    def test_a_token_cannot_be_used_twice(self):
        token = _token(state="applied")
        result = changes.apply_change(token.id, reason="replay")
        assert "already used" in result["error"]

    def test_an_expired_token_is_refused(self):
        token = _token(expires_at=datetime.now(tz=timezone.utc) - timedelta(seconds=1))
        result = changes.apply_change(token.id, reason="late")
        assert "expired" in result["error"]
        assert changes._tokens[token.id].state == "expired"

    def test_commands_swapped_after_issue_are_refused(self):
        token = _token()
        token.commands = ["interface lo", "shutdown"]  # tampered after issue
        result = changes.apply_change(token.id, reason="swap")
        assert "does not match its commands" in result["error"]

    def test_confirm_requires_an_applied_change(self):
        token = _token()  # still pending
        assert "not applied" in changes.confirm_change(token.id, reason="x")["error"]

    def test_confirm_cancels_the_rollback_timer(self):
        token = _token(state="applied")
        changes._arm_rollback(token)
        assert token.timer is not None and token.timer.is_alive()

        result = changes.confirm_change(token.id, reason="interface came back up, BGP still established")

        assert result["confirmed"] is True
        assert token.state == "confirmed"
        assert token.timer is None

    def test_confirming_records_why_the_rollback_was_switched_off(self):
        token = _token(state="applied")
        changes.confirm_change(token.id, reason="verified the peer re-established")

        confirms = [e for e in audit.current().events() if e["event"] == "confirm"]
        assert confirms[-1]["reason"] == "verified the peer re-established"

    def test_rollback_needs_something_to_undo(self):
        token = _token()  # pending, never applied
        assert "nothing to roll back" in changes.rollback(token.id)["error"]


class TestDestructiveCommandsAreRefused:
    @pytest.mark.parametrize("command", [
        "reload",
        "write erase",
        "erase startup-config",
        "crypto key zeroize rsa",
        "no username admin",
        "boot system flash:other.bin",
        "config-register 0x2142",
    ])
    def test_refused_before_a_token_is_ever_issued(self, command):
        result = validate_config_change(["interface lo", command])
        assert not result.safe, command

    def test_ordinary_config_passes(self):
        result = validate_config_change(
            ["interface lo", "description peering link", "ip address 10.0.0.1 255.255.255.0"]
        )
        assert result.safe, result.reason


class TestDeviceRejection:
    """A device that refuses a command says so in the output and returns
    normally. Netmiko raises nothing, so the output is the only signal."""

    # Verbatim from the FRR lab: `write memory` with a read-only /etc/frr.
    FAILED_SAVE = """write memory
Note: this version of vtysh never writes vtysh.conf
% Can't open configuration file /etc/frr/vtysh.conf due to 'No such file or directory'.
Configuration file[/etc/frr/frr.conf] processing failure: 11
Building Configuration...
Error renaming /etc/frr/frr.conf to /etc/frr/frr.conf.sav: Resource busy
% Error: failed to open configuration file /etc/frr/frr.conf: Read-only file system
% Configuration write failed.
"""

    # Verbatim from the same lab on a command that SUCCEEDED. Note it also
    # carries a '%' line and the word 'failure' — which is why the detector
    # matches specific phrasing rather than either of those.
    SUCCESSFUL_CONFIG = """% Can't open configuration file /etc/frr/vtysh.conf due to 'No such file or directory'.
Configuration file[/etc/frr/frr.conf] processing failure: 11
"""

    def test_a_failed_save_is_detected(self):
        assert "Configuration write failed" in _device_rejected(self.FAILED_SAVE)

    def test_successful_output_is_not_flagged(self):
        assert _device_rejected(self.SUCCESSFUL_CONFIG) == ""

    def test_ordinary_show_output_is_not_flagged(self):
        assert _device_rejected("Neighbor  AS  Up/Down  State\n172.30.0.3 65002 00:05:10 1") == ""

    @pytest.mark.parametrize("line", [
        "% Invalid input detected at '^' marker.",
        "% Incomplete command.",
        "% Unknown command: frobnicate",
        "% Authorization failed.",
        "% Permission denied",
    ])
    def test_common_cli_rejections_are_detected(self, line):
        assert _device_rejected(line)


class TestInverseCommands:
    def test_free_text_values_are_not_repeated_in_the_negation(self):
        """`no description <text>` is rejected outright by FRR, so repeating the
        text guarantees a failed command in every rollback transcript. IOS is
        happy with the bare form too."""
        assert _inverse_commands(["interface lo", "description test"]) == [
            "interface lo",
            "no description",
        ]

    def test_an_identifier_value_is_kept(self):
        """Unlike free text, these are not optional — `no ntp server` would
        remove every server, not the one that was added."""
        assert _inverse_commands(["ntp server 10.0.0.5"]) == ["no ntp server 10.0.0.5"]

    def test_a_negation_is_inverted_back(self):
        assert _inverse_commands(["interface lo", "no shutdown"]) == [
            "interface lo",
            "shutdown",
        ]

    def test_routing_process_context_is_preserved(self):
        assert _inverse_commands(["router bgp 65001", "neighbor 10.0.0.2 remote-as 65002"]) == [
            "router bgp 65001",
            "no neighbor 10.0.0.2 remote-as 65002",
        ]

    def test_comments_and_blanks_are_dropped(self):
        assert _inverse_commands(["!", "", "ntp server 10.0.0.5"]) == ["no ntp server 10.0.0.5"]

    def test_keyword_only_form_shortens_the_negation(self):
        """FRR rejects `no description <text>`; it only takes `no description`."""
        assert _inverse_commands(
            ["interface lo", "description some text"], keyword_only=True
        ) == ["interface lo", "no description"]
