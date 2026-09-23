"""
SSH driver wrapping Netmiko for Cisco IOS-XE (and other) devices.

Features
--------
* Context-manager support for automatic resource cleanup.
* READ_ONLY_MODE enforcement: write-class commands raise ``PermissionError``
  before any bytes are sent to the device.
* Structured logging throughout.
"""

from __future__ import annotations

import logging
import re
import socket
import threading
from contextlib import contextmanager
from typing import Generator, Optional

from netmiko import ConnectHandler, BaseConnection
from netmiko.exceptions import (
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
    NetMikoTimeoutException,
)

from netnerd_mcp.security.command_validator import validate_network_command

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Per-session SSH connection pool
# ---------------------------------------------------------------------------
# Keyed by "session_id:device" → active BaseConnection.
# Connections are reused across tool calls within the same agent turn/session
# instead of reconnecting for every command, dramatically cutting latency.

_pool: dict[str, BaseConnection] = {}
_pool_lock = threading.RLock()


def _get_session_id() -> Optional[str]:
    try:
        from netnerd_mcp.config.request_context import get_request_session_id
        return get_request_session_id()
    except Exception:
        return None


def _pool_key(session_id: str, device_ip: str, port: Optional[int] = None) -> str:
    """Identify a pooled connection by the inventory entry, not the address.

    Two entries can name the same host with different credentials, ports or
    device types — a read-only account and an enable account on one switch is
    an ordinary setup, and the lab reaches one container through both vtysh and
    a shell. Keying on the address alone made the second entry silently reuse
    the first's session, so commands ran as the wrong user against the wrong
    CLI. The inventory name is unique by construction and maps one-to-one to a
    credential set; the address is only a fallback for direct driver use with
    no inventory behind it.
    """
    try:
        from netnerd_mcp.config.request_context import get_request_device_name
        name = get_request_device_name()
    except Exception:
        name = None
    return f"{session_id}:{name or f'{device_ip}:{port or 22}'}"


def _connection_alive(conn: BaseConnection) -> bool:
    """Non-blocking check — uses Paramiko transport state, no round-trip."""
    try:
        transport = conn.remote_conn.get_transport() if conn.remote_conn else None
        return transport is not None and transport.is_active()
    except Exception:
        return False


def close_session_connections(session_id: str) -> None:
    """Close all pooled SSH connections for a session.

    Called by end_session and by the idle timeout.
    """
    with _pool_lock:
        keys = [k for k in list(_pool) if k.startswith(f"{session_id}:")]
        for key in keys:
            conn = _pool.pop(key, None)
            if conn:
                try:
                    conn.disconnect()
                    logger.info("Pool: closed connection for %s", key)
                except Exception as exc:
                    logger.debug("Pool: error closing %s: %s", key, exc)


def _is_tcp_reachable(host: str, port: int = 22, timeout: float = 3.0) -> bool:
    """Quick TCP check to see if a host is reachable on the given port."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Command classification helpers
# ---------------------------------------------------------------------------

# Patterns that indicate a command will mutate device state.
_WRITE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bwrite\b", re.IGNORECASE),
    re.compile(r"\bcopy\s+run", re.IGNORECASE),
    re.compile(r"\bconfigure\s+terminal\b", re.IGNORECASE),
    re.compile(r"\bconf\s+t\b", re.IGNORECASE),
    re.compile(r"^no\s+", re.IGNORECASE),
    re.compile(r"\bshutdown\b", re.IGNORECASE),
    re.compile(r"\berase\b", re.IGNORECASE),
    re.compile(r"\breload\b", re.IGNORECASE),
    re.compile(r"\bdelete\b", re.IGNORECASE),
]


def _is_write_command(command: str) -> bool:
    """Return True if *command* is classified as a state-mutating (write) command."""
    stripped = command.strip()
    return any(pattern.search(stripped) for pattern in _WRITE_PATTERNS)


# ---------------------------------------------------------------------------
# SSHDriver
# ---------------------------------------------------------------------------


class SSHDriver:
    """
    Thin wrapper around Netmiko's ``ConnectHandler``.

    Usage – explicit lifecycle
    --------------------------
    .. code-block:: python

        driver = SSHDriver()
        conn = driver.connect("192.168.1.1")
        output = driver.run_command(conn, "show interfaces")
        driver.disconnect(conn)

    Usage – context manager
    -----------------------
    .. code-block:: python

        driver = SSHDriver()
        with driver.managed_connection("192.168.1.1") as conn:
            output = driver.run_command(conn, "show ip interface brief")
    """

    def __init__(
        self,
        username: Optional[str] = None,
        password: Optional[str] = None,
        enable_secret: Optional[str] = None,
        read_only_mode: Optional[bool] = None,
    ) -> None:
        """Initialise the driver.

        Credentials come from the per-call context (set by the server from the
        inventory) unless passed explicitly, which is what tests do.
        """
        from netnerd_mcp.config.request_context import (
            get_request_enable_secret, get_request_password,
            get_request_username, is_read_only,
        )

        self.username = username or get_request_username() or ""
        self.password = password or get_request_password() or ""
        self.enable_secret = enable_secret or get_request_enable_secret() or ""
        self.read_only_mode = is_read_only() if read_only_mode is None else read_only_mode

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def connect(
        self,
        device_ip: str,
        device_type: str = "cisco_ios",
        port: Optional[int] = None,
        timeout: int = 30,
        session_log: Optional[str] = None,
    ) -> BaseConnection:
        """
        Establish an SSH session to *device_ip*.

        Parameters
        ----------
        device_ip:
            IPv4/IPv6 address or hostname of the target device.
        device_type:
            Netmiko device type string (default ``"cisco_ios"`` which covers
            IOS-XE as well).
        port:
            SSH port (default 22).
        timeout:
            TCP connection timeout in seconds (default 30).
        session_log:
            Path to the raw session transcript. Defaults to the current
            session's transcript so every byte exchanged is captured.

        Returns
        -------
        BaseConnection
            An active Netmiko connection object ready for command execution.

        Raises
        ------
        NetmikoAuthenticationException
            If authentication fails.
        NetmikoTimeoutException / NetMikoTimeoutException
            If the connection times out.
        ConnectionError
            For other connection-level problems.
        """
        from netnerd_mcp.config.request_context import (
            get_request_key_file, get_request_port, get_request_session_log,
        )

        if port is None:
            port = get_request_port() or 22
        if session_log is None:
            session_log = get_request_session_log()
        key_file = get_request_key_file()

        logger.info(
            "Connecting to %s (type=%s, port=%d, read_only=%s)",
            device_ip,
            device_type,
            port,
            self.read_only_mode,
        )

        device_params: dict = {
            "device_type": device_type,
            "host": device_ip,
            "username": self.username,
            "password": self.password,
            "port": port,
            "timeout": timeout,
            "session_log": session_log,
            "session_log_record_writes": True,
        }

        if self.enable_secret:
            device_params["secret"] = self.enable_secret

        if key_file:
            # Key auth from ~/.ssh/config. The password stays set: netmiko uses
            # it as the key passphrase, and devices that want both get both.
            device_params["use_keys"] = True
            device_params["key_file"] = key_file

        try:
            connection = ConnectHandler(**device_params)
            # Enter enable mode if a secret is available.
            if self.enable_secret:
                connection.enable()
            logger.info("Connected to %s successfully.", device_ip)
            return connection
        except NetmikoAuthenticationException as exc:
            logger.error("Authentication failed for %s: %s", device_ip, exc)
            raise
        except (NetmikoTimeoutException, NetMikoTimeoutException) as exc:
            logger.error("Connection timed out for %s: %s", device_ip, exc)
            raise
        except Exception as exc:
            logger.error("Unexpected error connecting to %s: %s", device_ip, exc)
            raise ConnectionError(f"Failed to connect to {device_ip}: {exc}") from exc

    def run_command(
        self,
        connection: BaseConnection,
        command: str,
        expect_string: Optional[str] = None,
        read_timeout: float = 30.0,
    ) -> str:
        """
        Execute a single CLI command and return its output.

        Parameters
        ----------
        connection:
            Active Netmiko connection (obtained from :meth:`connect`).
        command:
            The CLI command to execute.
        expect_string:
            Optional regex/string that Netmiko waits for before returning.
        read_timeout:
            Seconds to wait for the command to complete (default 30).

        Returns
        -------
        str
            Raw CLI output from the device.

        Raises
        ------
        PermissionError
            If *command* is classified as a write command and
            ``READ_ONLY_MODE`` is ``True``.
        RuntimeError
            If command execution fails unexpectedly.
        """
        # Security: validate command before sending to device
        from netnerd_mcp.config.request_context import get_request_device_type
        _vr = validate_network_command(
            command, device_type=get_request_device_type() or "cisco_ios"
        )
        if not _vr.safe:
            raise PermissionError(f"Command blocked by security validator: {_vr.reason}")
        command = _vr.sanitized  # use the sanitized version

        if self.read_only_mode and _is_write_command(command):
            raise PermissionError(
                f"READ_ONLY_MODE is enabled. Blocked write command: '{command}'"
            )

        logger.debug("Running command on %s: %s", connection.host, command)

        try:
            kwargs: dict = {"command_string": command, "read_timeout": read_timeout}
            if expect_string is not None:
                kwargs["expect_string"] = expect_string
            output = connection.send_command(**kwargs)
            logger.debug(
                "Command '%s' returned %d chars.", command, len(output)
            )
            return output
        except Exception as exc:
            logger.error("Error running command '%s': %s", command, exc)
            raise RuntimeError(
                f"Command execution failed for '{command}': {exc}"
            ) from exc

    def send_config_set_validated(
        self,
        connection: BaseConnection,
        commands: list[str],
        device_type: Optional[str] = None,
    ) -> str:
        """
        Validate each config command through the security validator, then push
        to the device via ``send_config_set``.

        This is the safe replacement for calling ``conn.send_config_set()`` directly,
        which bypasses the command validator entirely.

        Raises
        ------
        PermissionError
            If read-only mode is enabled, or any command fails validation.
        """
        from netnerd_mcp.config.request_context import get_request_device_type

        device_type = device_type or get_request_device_type() or "cisco_ios"

        if self.read_only_mode:
            raise PermissionError(
                "READ_ONLY_MODE is enabled. Configuration changes are blocked."
            )

        validated: list[str] = []
        for cmd in commands:
            vr = validate_network_command(cmd, device_type=device_type)
            if not vr.safe:
                raise PermissionError(
                    f"Config command blocked by security validator: {vr.reason} (command: '{cmd}')"
                )
            validated.append(vr.sanitized)

        logger.info(
            "send_config_set_validated: pushing %d command(s) to %s",
            len(validated), getattr(connection, "host", "unknown"),
        )
        return connection.send_config_set(validated)

    def disconnect(self, connection: BaseConnection) -> None:
        """
        Gracefully close the SSH session.

        Parameters
        ----------
        connection:
            Active Netmiko connection to tear down.
        """
        try:
            host = getattr(connection, "host", "unknown")
            connection.disconnect()
            logger.info("Disconnected from %s.", host)
        except Exception as exc:
            logger.warning("Error during disconnect: %s", exc)

    @contextmanager
    def managed_connection(
        self,
        device_ip: str,
        device_type: str = "cisco_ios",
        port: Optional[int] = None,
        timeout: int = 30,
    ) -> Generator[BaseConnection, None, None]:
        """
        Context manager that opens a connection, yields it, then disconnects.

        Within a session the connection is pooled and stays open between tool
        calls; ``end_session`` (or the idle timeout) closes it.

        Yields
        ------
        BaseConnection
            Active Netmiko connection object.

        Example
        -------
        .. code-block:: python

            driver = SSHDriver()
            with driver.managed_connection("10.0.0.1") as conn:
                output = driver.run_command(conn, "show version")
        """
        session_id = _get_session_id()
        use_pool = bool(session_id)
        key = _pool_key(session_id, device_ip, port) if use_pool else None

        if use_pool:
            with _pool_lock:
                existing = _pool.get(key)
                if existing and _connection_alive(existing):
                    logger.debug("Pool hit: reusing connection for %s", key)
                    try:
                        yield existing
                        return
                    except Exception:
                        # Connection went bad mid-use — evict and fall through
                        logger.warning("Pool: stale connection for %s, reconnecting", key)
                        _pool.pop(key, None)
                        try:
                            existing.disconnect()
                        except Exception:
                            pass
                elif existing:
                    # Dead connection in pool — evict it
                    _pool.pop(key, None)
                    try:
                        existing.disconnect()
                    except Exception:
                        pass

        # Establish a new connection
        connection = self.connect(
            device_ip,
            device_type=device_type,
            port=port,
            timeout=timeout,
        )

        if use_pool:
            with _pool_lock:
                _pool[key] = connection
            logger.debug("Pool: cached new connection for %s", key)
            try:
                yield connection
            except Exception:
                # On error evict from pool so next call gets a fresh connection
                with _pool_lock:
                    _pool.pop(key, None)
                self.disconnect(connection)
                raise
            # Success — leave in pool, don't disconnect
        else:
            try:
                yield connection
            finally:
                self.disconnect(connection)
