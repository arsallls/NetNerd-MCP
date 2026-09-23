"""Tool: telemetry."""
from __future__ import annotations

from typing import Any

from netnerd_mcp import audit
from netnerd_mcp.config.settings import settings
from netnerd_mcp.drivers import transports
from netnerd_mcp.drivers.base import TELEMETRY, TransportError
from netnerd_mcp.inventory import InventoryError, get_inventory


def telemetry(device: str, paths: list[str], reason: str, seconds: int = 10) -> dict[str, Any]:
    """Watch counters on a device for a few seconds and report what they did.

    Answers questions a single reading cannot: whether an interface is
    dropping packets *now*, whether errors are climbing, whether a counter is
    moving at all. Returns first/last/min/max/delta per path and a sample
    count — never the raw update stream, which is unbounded.

    Only devices whose inventory entry lists a streaming-telemetry protocol
    (gNMI) can be watched this way. Use `show` or `get_config` for everything
    else.

    Parameters
    ----------
    device: inventory name of the target device.
    paths: OpenConfig paths to watch, e.g.
        "/interfaces/interface[name=eth0]/state/counters/in-errors".
    reason: why this is being watched — recorded in the audit log.
    seconds: how long to sample for. Capped by NETNERD_MAX_TELEMETRY_SEC so a
        call cannot hold the session open indefinitely.
    """
    try:
        target = get_inventory().resolve(device)
    except InventoryError as exc:
        return {"error": str(exc)}

    if not paths:
        return {"error": "telemetry needs at least one path to watch.",
                "device": target.name}

    capped = max(1, min(int(seconds), settings.MAX_TELEMETRY_SEC))

    try:
        transport = transports.for_device(target, require=TELEMETRY)
    except TransportError as exc:
        audit.current().event("blocked", device=target.name, tool="telemetry",
                              reason=reason, why=str(exc))
        return {
            "error": (
                f"{target.name} cannot be watched over time: {exc} Streaming "
                f"telemetry needs a device whose inventory entry lists gNMI. "
                f"This is NOT a finding that its counters are idle — read them "
                f"with `show` instead."
            ),
            "device": target.name,
        }

    try:
        result = transport.sample(target, list(paths), capped, reason)
    except TransportError as exc:
        return {"error": str(exc), "device": target.name}

    result["device"] = target.name
    if capped != seconds:
        result["note"] = (
            f"Sampled for {capped}s rather than the {seconds}s requested "
            f"(NETNERD_MAX_TELEMETRY_SEC={settings.MAX_TELEMETRY_SEC})."
        )
    return result
