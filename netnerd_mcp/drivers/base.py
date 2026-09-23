"""What every way of talking to a device has to provide.

The change loop — plan, apply, verify, confirm — does not care whether a
device is driven over SSH, NETCONF or RESTCONF. It cares about two things:
can this transport read and write configuration, and can the *device* revert
an unconfirmed change by itself.

That second question is the reason this abstraction exists at all. Over SSH
the server has to hold a timer and replay a backup, which only works while the
server is alive and can still reach the device. NETCONF has confirmed-commit
in the protocol (RFC 6241 §8.4): the device starts its own timer and rolls
back on its own if nothing confirms. That is strictly stronger, and it is what
the change loop should use wherever it is available.

Transports advertise that with `capabilities()` rather than being asked what
they are, so adding one later does not mean editing the change loop.
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from netnerd_mcp.inventory import Device

# Capability names a transport may advertise.
CONFIRMED_COMMIT = "confirmed_commit"  # the device reverts itself on a timer
STRUCTURED = "structured"              # config is data, not screen-scraped text
INTERACTIVE = "interactive"            # arbitrary CLI commands can be run
TELEMETRY = "telemetry"                # counters can be sampled over time


class TransportError(RuntimeError):
    """The transport could not do what was asked.

    Says nothing about whether the device changed. A connection that dies
    part-way through a push raises this, and the caller must treat the device
    as being in an unknown state.
    """


class DeviceRejected(TransportError):
    """The device refused the change outright, and nothing was applied.

    The distinction from a plain TransportError matters: a YANG validation
    error or an rpc-error is a complete, definitive "no" — the candidate
    datastore is untouched and there is nothing to roll back. Reporting that
    as "the connection dropped, state unknown" would send an operator looking
    for damage that does not exist, and would leave a rollback armed against
    a device that never changed.
    """


@runtime_checkable
class Transport(Protocol):
    """One way of reaching a device.

    Implementations are per-call, not long-lived: the SSH transport reuses the
    session's pooled connection, and the others open and close around each
    operation. Nothing here holds state that outlives a call.
    """

    name: str

    def capabilities(self) -> set[str]:
        """What this transport can do, from the constants above."""
        ...

    def get_config(self, device: Device, startup: bool = False) -> str:
        """The device's configuration as text."""
        ...

    def apply(self, device: Device, commands: list[str], confirm_timeout_min: int = 0) -> str:
        """Push *commands*, returning whatever the device said.

        When the transport advertises CONFIRMED_COMMIT and
        *confirm_timeout_min* is non-zero, the change must be committed such
        that the **device** reverts it after that many minutes unless
        `confirm()` arrives. The caller still arms its own timer as a backstop;
        both firing is harmless, because a rollback to the same backup twice
        is the same rollback.
        """
        ...

    def confirm(self, device: Device) -> str:
        """Make a confirmed-commit permanent. Only for CONFIRMED_COMMIT."""
        ...
