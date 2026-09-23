"""Per-call context for the device a tool is currently talking to.

The MCP server resolves a device name against the inventory and pushes the
connection details here; the SSH driver reads them back. ContextVars rather
than a module global because netmiko calls run in worker threads — contextvars
are copied into the thread, so each call keeps its own device and credentials.
"""
from __future__ import annotations

from contextvars import ContextVar
from typing import Optional

_ctx_device_name: ContextVar[Optional[str]] = ContextVar("device_name", default=None)
_ctx_username: ContextVar[Optional[str]] = ContextVar("device_username", default=None)
_ctx_password: ContextVar[Optional[str]] = ContextVar("device_password", default=None)
_ctx_enable_secret: ContextVar[Optional[str]] = ContextVar("device_enable_secret", default=None)
_ctx_read_only: ContextVar[Optional[bool]] = ContextVar("read_only_mode", default=None)
_ctx_device_type: ContextVar[Optional[str]] = ContextVar("device_type", default=None)
_ctx_session_id: ContextVar[Optional[str]] = ContextVar("session_id", default=None)
_ctx_port: ContextVar[Optional[int]] = ContextVar("device_port", default=None)
_ctx_session_log: ContextVar[Optional[str]] = ContextVar("session_log", default=None)
_ctx_key_file: ContextVar[Optional[str]] = ContextVar("key_file", default=None)


def set_request_context(
    device_name: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    enable_secret: Optional[str] = None,
    read_only_mode: Optional[bool] = None,
    device_type: Optional[str] = None,
    session_id: Optional[str] = None,
    port: Optional[int] = None,
    session_log: Optional[str] = None,
    key_file: Optional[str] = None,
) -> None:
    """Set the device details for the current call."""
    for var, value in (
        (_ctx_device_name, device_name),
        (_ctx_username, username),
        (_ctx_password, password),
        (_ctx_enable_secret, enable_secret),
        (_ctx_read_only, read_only_mode),
        (_ctx_device_type, device_type),
        (_ctx_session_id, session_id),
        (_ctx_port, port),
        (_ctx_session_log, session_log),
        (_ctx_key_file, key_file),
    ):
        if value is not None:
            var.set(value)


def get_request_device_name() -> Optional[str]:
    return _ctx_device_name.get()


def get_request_username() -> Optional[str]:
    return _ctx_username.get()


def get_request_password() -> Optional[str]:
    return _ctx_password.get()


def get_request_enable_secret() -> Optional[str]:
    return _ctx_enable_secret.get()


def get_request_device_type() -> Optional[str]:
    return _ctx_device_type.get()


def get_request_session_id() -> Optional[str]:
    return _ctx_session_id.get()


def get_request_port() -> Optional[int]:
    return _ctx_port.get()


def get_request_session_log() -> Optional[str]:
    return _ctx_session_log.get()


def get_request_key_file() -> Optional[str]:
    return _ctx_key_file.get()


def is_read_only() -> bool:
    """Effective read-only mode: per-call value wins over the server default."""
    from netnerd_mcp.config.settings import settings

    value = _ctx_read_only.get()
    return settings.READ_ONLY if value is None else value
