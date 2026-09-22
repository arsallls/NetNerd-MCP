"""Device session lifecycle: connections, audit events, idle timeout.

One MCP server process serves one client session. Within it, each device gets
a pooled SSH connection that stays open between tool calls and closes on
``end_session`` or after the idle timeout.
"""
from __future__ import annotations

import logging
import threading
import time
from contextlib import contextmanager
from typing import Any, Generator

from netmiko import BaseConnection

from netnerd_mcp import audit, vendor
from netnerd_mcp.config.request_context import set_request_context
from netnerd_mcp.config.settings import settings
from netnerd_mcp.drivers.ssh_driver import SSHDriver, close_session_connections
from netnerd_mcp.inventory import Device

logger = logging.getLogger(__name__)

_connected: set[str] = set()
_lock = threading.RLock()
_idle_timer: threading.Timer | None = None


def _touch() -> None:
    """Restart the idle countdown after any device activity."""
    global _idle_timer
    with _lock:
        if _idle_timer is not None:
            _idle_timer.cancel()
        _idle_timer = threading.Timer(settings.IDLE_TIMEOUT_MIN * 60, _close_idle)
        _idle_timer.daemon = True
        _idle_timer.start()


def _close_idle() -> None:
    logger.info("Idle timeout reached — closing device connections")
    close_all(reason=f"idle for {settings.IDLE_TIMEOUT_MIN} minutes")


def close_all(reason: str = "") -> dict[str, Any]:
    """Close every pooled connection and record the disconnects."""
    global _idle_timer
    log = audit.current()
    with _lock:
        if _idle_timer is not None:
            _idle_timer.cancel()
            _idle_timer = None
        devices = sorted(_connected)
        _connected.clear()

    close_session_connections(log.session_id)
    for name in devices:
        log.event("disconnect", device=name, why=reason or "end_session")
    return {"closed": devices}


@contextmanager
def connection(device: Device) -> Generator[tuple[SSHDriver, BaseConnection], None, None]:
    """Open (or reuse) this session's connection to *device*.

    Pushes the device's credentials into the call context first, so the driver
    and the command validator both see the right device type and secrets.
    """
    log = audit.current()
    set_request_context(
        device_name=device.name,
        username=device.username,
        password=device.password,
        enable_secret=device.enable_secret,
        device_type=device.device_type,
        port=device.port,
        session_id=log.session_id,
        session_log=str(log.transcript_path),
    )

    driver = SSHDriver()
    is_new = device.name not in _connected

    with driver.managed_connection(
        device.host, device_type=device.device_type, port=device.port
    ) as conn:
        if is_new:
            with _lock:
                _connected.add(device.name)
            log.event(
                "connect",
                device=device.name,
                host=device.host,
                port=device.port,
                device_type=device.device_type,
                writable=device.writable,
            )
        _touch()
        yield driver, conn


def run_command(device: Device, command: str, reason: str, tool: str) -> str:
    """Run one command against *device*, audited either way.

    A command the validator or read-only mode refuses is recorded as a
    ``blocked`` event before the error is raised, so the audit trail shows the
    attempt, not just the successes.
    """
    log = audit.current()
    started = time.monotonic()
    try:
        with connection(device) as (driver, conn):
            output = driver.run_command(conn, command)
    except PermissionError as exc:
        log.event("blocked", device=device.name, tool=tool, cmd=command,
                  reason=reason, why=str(exc))
        raise
    except Exception as exc:
        log.event("error", device=device.name, tool=tool, cmd=command,
                  reason=reason, error=f"{type(exc).__name__}: {exc}")
        raise

    # A command the device refused comes back as ordinary output, so without
    # this the log would record "% Unknown command" as a command that ran.
    log.event(
        "command",
        device=device.name,
        tool=tool,
        cmd=command,
        reason=reason,
        ms=int((time.monotonic() - started) * 1000),
        bytes=len(output),
        rejected=vendor.device_rejected(output) or None,
    )
    return output


def format_result(device: Device, command: str, reason: str, output: str, ms: int | None = None) -> str:
    """The transcript block a tool result shows the operator."""
    log = audit.current()
    header = f"── netnerd · {device.name} ({device.host}) · session {log.session_id} ──"
    footer = f"── logged → {log.jsonl_path} ──" if ms is None else \
        f"── {ms} ms · logged → {log.jsonl_path} ──"
    return "\n".join([
        header,
        f"reason: {reason}",
        "",
        f"{device.name}# {command}",
        audit.mask(output),
        "",
        footer,
    ])


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


def get_transcript(tail_chars: int = 20000) -> dict[str, Any]:
    """Return this session's audit trail so far.

    The raw SSH transcript plus the structured event list — the same record the
    operator sees, so there is no version of events only the agent can see.
    """
    log = audit.current()
    return {
        "session": log.session_id,
        "events": log.events(),
        "transcript": log.transcript(tail_chars=tail_chars),
        "log_file": str(log.jsonl_path),
    }


def end_session(reason: str = "") -> dict[str, Any]:
    """Close all device connections and write the end-of-session report.

    Call this when the work is done. Returns the path to the markdown report.
    """
    log = audit.current()
    closed = close_all(reason=reason or "end_session")
    events = log.events()
    report = log.write_report()
    return {
        "session": log.session_id,
        "report": str(report),
        "transcript": str(log.transcript_path),
        "log_file": str(log.jsonl_path),
        "devices_closed": closed["closed"],
        "commands": sum(1 for e in events if e["event"] == "command"),
        "changes_applied": sum(1 for e in events if e["event"] == "apply"),
        "changes_rolled_back": sum(1 for e in events if e["event"] == "rollback"),
    }
