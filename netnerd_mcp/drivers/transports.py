"""The ways of reaching a device, and how one gets chosen.

Three transports, all satisfying `base.Transport`:

``ssh``
    The original. Wraps the existing SSHDriver and the session connection
    pool without changing either. Rollback is a server-side timer replaying a
    backup.

``netconf``
    RFC 6241. Configuration is XML against the candidate datastore, and a
    commit can be *confirmed*: the device starts its own timer and reverts on
    its own if nothing confirms. That is strictly stronger than replaying a
    backup, because it survives the server dying or the network to the device
    going away — the two situations a rollback is most needed in.

``restconf``
    RFC 8040. HTTP against the same YANG models. No confirmed-commit exists
    in RESTCONF, so it keeps the server-side timer.

Which one is used is a property of the device, not a choice the model makes:
`for_device` picks the first protocol in the inventory entry that is both
implemented and installed. A model asking to change a device does not need to
know how the change gets there.
"""
from __future__ import annotations

import logging
from typing import Optional

from netnerd_mcp import sessions
from netnerd_mcp.drivers.base import (
    CONFIRMED_COMMIT, INTERACTIVE, STRUCTURED, DeviceRejected, Transport,
    TransportError)
from netnerd_mcp.inventory import Device

logger = logging.getLogger(__name__)

NETCONF_PORT = 830
RESTCONF_PORT = 443


class SSHTransport:
    """CLI over SSH, through the session's pooled connection."""

    name = "ssh"

    def capabilities(self) -> set[str]:
        return {INTERACTIVE}

    def get_config(self, device: Device, startup: bool = False) -> str:
        from netnerd_mcp import vendor
        command = (vendor.startup_config_command(device.device_type) if startup
                   else vendor.running_config_command(device.device_type))
        return sessions.run_command(device, command, reason="reading config",
                                    tool="get_config")

    def apply(self, device: Device, commands: list[str],
              confirm_timeout_min: int = 0) -> str:
        with sessions.connection(device) as (driver, conn):
            return driver.send_config_set_validated(conn, commands)

    def confirm(self, device: Device) -> str:
        raise TransportError(
            "SSH has no confirmed-commit to confirm — the rollback is a "
            "server-side timer, cancelled by confirm_change.")


class NetconfTransport:
    """NETCONF over SSH (RFC 6241), using the candidate datastore.

    Sessions are per-operation rather than held open, which is why the
    confirmed commit uses ``<persist>``. Without it a confirmed commit is tied
    to the session that made it and the device reverts the moment that session
    closes — which, for a transport that connects and disconnects around each
    call, would mean every change silently undoing itself seconds later.
    Persisting it hands the confirmation a token that a *later* session can
    present, which is exactly the shape of the change token this server
    already issues.
    """

    name = "netconf"

    def __init__(self) -> None:
        try:
            from ncclient import manager  # noqa: F401
        except ImportError as exc:
            raise TransportError(
                "NETCONF needs the ncclient package: pip install 'netnerd-mcp[netconf]'"
            ) from exc

    def capabilities(self) -> set[str]:
        return {CONFIRMED_COMMIT, STRUCTURED}

    def _connect(self, device: Device):
        from ncclient import manager
        return manager.connect(
            host=device.host,
            port=device.port if device.port != 22 else NETCONF_PORT,
            username=device.username,
            password=device.password,
            key_filename=device.key_file or None,
            hostkey_verify=False,  # lab and brownfield gear; the inventory is the allowlist
            allow_agent=False,
            look_for_keys=False,
            device_params={"name": "default"},
            timeout=30,
        )

    def get_config(self, device: Device, startup: bool = False) -> str:
        from netnerd_mcp import audit
        source = "startup" if startup else "running"
        log = audit.current()
        try:
            with self._connect(device) as session:
                if source == "startup" and ":startup" not in _capabilities(session):
                    # Saying so beats returning the running config under a
                    # label that claims it is the startup one.
                    raise TransportError(
                        f"{device.name} does not advertise the NETCONF :startup "
                        f"capability, so it has no startup datastore to read.")
                reply = session.get_config(source=source)
        except TransportError:
            raise
        except Exception as exc:
            log.event("error", device=device.name, tool="get_config",
                      cmd=f"netconf get-config {source}",
                      reason="reading config", error=f"{type(exc).__name__}: {exc}")
            raise TransportError(f"NETCONF get-config failed on {device.name}: {exc}") from exc

        text = reply.data_xml if hasattr(reply, "data_xml") else str(reply)
        log.event("command", device=device.name, tool="get_config",
                  cmd=f"netconf get-config {source}", reason="reading config",
                  bytes=len(text))
        return text

    def apply(self, device: Device, commands: list[str],
              confirm_timeout_min: int = 0) -> str:
        """Edit the candidate datastore and commit it.

        *commands* is one XML config document — NETCONF is model-driven, so a
        change is data rather than a list of CLI lines. Several entries are
        joined, which lets a caller pass it either way.
        """
        from netnerd_mcp import audit
        config = "\n".join(commands).strip()
        if not config.startswith("<"):
            raise TransportError(
                f"{device.name} is a NETCONF device, so a change must be an XML "
                f"<config> document rather than CLI lines. Received: "
                f"{config.splitlines()[0][:80] if config else '(empty)'}")

        log = audit.current()
        try:
            with self._connect(device) as session:
                caps = _capabilities(session)
                if ":candidate" not in caps:
                    raise TransportError(
                        f"{device.name} does not support the NETCONF :candidate "
                        f"datastore, which this transport edits.")
                session.edit_config(target="candidate", config=config)

                if confirm_timeout_min and CONFIRMED_COMMIT in self.capabilities() \
                        and ":confirmed-commit" in caps:
                    session.commit(
                        confirmed=True,
                        timeout=str(int(confirm_timeout_min * 60)),
                        persist=_persist_id(device),
                    )
                    outcome = (f"committed with confirmed-commit; {device.name} will "
                               f"revert in {confirm_timeout_min} min unless confirmed")
                else:
                    session.commit()
                    outcome = "committed (no confirmed-commit available)"
        except TransportError:
            raise
        except Exception as exc:
            # An rpc-error means the device validated the change and said no.
            # The candidate datastore is untouched, so this is a refusal with a
            # known outcome, not a push of unknown result.
            from ncclient.operations import RPCError
            rejected = isinstance(exc, RPCError)
            log.event("blocked" if rejected else "error",
                      device=device.name, tool="apply_change",
                      cmd="netconf edit-config", reason="applying change",
                      **({"why": str(exc)} if rejected
                         else {"error": f"{type(exc).__name__}: {exc}"}))
            if rejected:
                raise DeviceRejected(
                    f"{device.name} refused the change: {exc}. Nothing was "
                    f"applied — the candidate datastore is unchanged."
                ) from exc
            raise TransportError(f"NETCONF edit-config failed on {device.name}: {exc}") from exc

        log.event("command", device=device.name, tool="apply_change",
                  cmd="netconf edit-config + commit", reason="applying change",
                  outcome=outcome)
        return outcome

    def confirm(self, device: Device) -> str:
        """Present the persist-id so the device keeps the change."""
        from netnerd_mcp import audit
        try:
            with self._connect(device) as session:
                session.commit(persist_id=_persist_id(device))
        except Exception as exc:
            raise TransportError(
                f"NETCONF confirming commit failed on {device.name}: {exc}. The "
                f"device's own timer is still running, so the change will revert "
                f"on its own unless this succeeds."
            ) from exc
        audit.current().event("command", device=device.name, tool="confirm_change",
                              cmd="netconf commit (confirming)",
                              reason="making a confirmed commit permanent")
        return "confirming commit accepted; the change is permanent"


class RestconfTransport:
    """RESTCONF (RFC 8040). Reads and writes YANG data over HTTPS.

    No confirmed-commit exists in RESTCONF, so a change made this way still
    relies on the server-side rollback timer.
    """

    name = "restconf"

    def __init__(self) -> None:
        try:
            import httpx  # noqa: F401
        except ImportError as exc:
            raise TransportError(
                "RESTCONF needs httpx: pip install 'netnerd-mcp[netconf]'") from exc

    def capabilities(self) -> set[str]:
        return {STRUCTURED}

    def _client(self, device: Device):
        import httpx
        port = device.port if device.port not in (22, 830) else RESTCONF_PORT
        return httpx.Client(
            base_url=f"https://{device.host}:{port}/restconf",
            auth=(device.username, device.password),
            headers={"Accept": "application/yang-data+json",
                     "Content-Type": "application/yang-data+json"},
            verify=False,  # brownfield gear ships self-signed certs
            timeout=30.0,
        )

    def get_config(self, device: Device, startup: bool = False) -> str:
        from netnerd_mcp import audit
        if startup:
            raise TransportError(
                "RESTCONF exposes no startup datastore (RFC 8040 has only "
                "running), so there is nothing to read — this is not a finding "
                "that the startup config is empty.")
        try:
            with self._client(device) as client:
                response = client.get("/data")
                response.raise_for_status()
                text = response.text
        except Exception as exc:
            raise TransportError(f"RESTCONF GET failed on {device.name}: {exc}") from exc
        audit.current().event("command", device=device.name, tool="get_config",
                              cmd="restconf GET /data", reason="reading config",
                              bytes=len(text))
        return text

    def apply(self, device: Device, commands: list[str],
              confirm_timeout_min: int = 0) -> str:
        from netnerd_mcp import audit
        payload = "\n".join(commands).strip()
        if not payload.startswith("{"):
            raise TransportError(
                f"{device.name} is a RESTCONF device, so a change must be a JSON "
                f"yang-data document rather than CLI lines.")
        try:
            with self._client(device) as client:
                response = client.patch("/data", content=payload)
                response.raise_for_status()
        except Exception as exc:
            raise TransportError(f"RESTCONF PATCH failed on {device.name}: {exc}") from exc
        audit.current().event("command", device=device.name, tool="apply_change",
                              cmd="restconf PATCH /data", reason="applying change")
        return "applied over RESTCONF (server-side rollback timer, no confirmed-commit)"

    def confirm(self, device: Device) -> str:
        raise TransportError(
            "RESTCONF has no confirmed-commit; the rollback is a server-side timer.")


# ---------------------------------------------------------------------------
# Selection
# ---------------------------------------------------------------------------

_BY_NAME = {
    "ssh": SSHTransport,
    "netconf": NetconfTransport,
    "restconf": RestconfTransport,
}


def _capabilities(session) -> set[str]:
    """Server capabilities, as bare names like ':candidate'."""
    found = set()
    for capability in session.server_capabilities:
        text = str(capability)
        if "netconf:capability:" in text:
            found.add(":" + text.split("netconf:capability:")[1].split(":")[0])
    return found


def _persist_id(device: Device) -> str:
    """The id a confirmed commit is persisted under.

    Per device rather than per change: only one confirmed commit can be
    outstanding on a device at a time, and the change loop already refuses a
    second change while one is unconfirmed.
    """
    return f"netnerd-{device.name}"


def for_device(device: Device, require: Optional[str] = None) -> Transport:
    """The transport to use for *device*.

    Tries the inventory's `protocols` in order, skipping any whose package is
    not installed, and falls back to SSH. With *require*, only a transport
    advertising that capability is returned.
    """
    for name in (device.protocols or ["ssh"]):
        factory = _BY_NAME.get(name)
        if factory is None:
            logger.warning("%s lists unknown protocol '%s' — ignoring", device.name, name)
            continue
        try:
            transport = factory()
        except TransportError as exc:
            logger.info("%s: %s unavailable (%s)", device.name, name, exc)
            continue
        if require and require not in transport.capabilities():
            continue
        return transport

    if require:
        raise TransportError(
            f"No transport for {device.name} provides '{require}'. Listed "
            f"protocols: {device.protocols or ['ssh']}.")
    return SSHTransport()
