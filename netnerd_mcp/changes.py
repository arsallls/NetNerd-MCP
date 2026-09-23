"""Guarded configuration changes: plan → apply → verify → confirm.

The gate is a change token, not a prompt. ``plan_change`` validates the
commands, backs up the running config and issues a token bound to that exact
command list; ``apply_change`` refuses anything else. Once applied, the change
reverts by itself unless ``confirm_change`` arrives in time — so an agent that
breaks a device and loses access does not leave it broken.
"""
from __future__ import annotations

import difflib
import hashlib
import logging
import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from netnerd_mcp import audit, sessions, topology, vendor
from netnerd_mcp.config.request_context import is_read_only
from netnerd_mcp.config.settings import settings
from netnerd_mcp.inventory import Device, InventoryError, get_inventory
from netnerd_mcp.security.command_validator import validate_config_change

logger = logging.getLogger(__name__)


def _hash_commands(commands: list[str]) -> str:
    return hashlib.sha256("\n".join(commands).encode()).hexdigest()[:16]


@dataclass
class ChangeToken:
    id: str
    device: str
    commands: list[str]
    command_hash: str
    backup: str
    expires_at: datetime
    mechanism: str
    state: str = "pending"  # pending → applied → confirmed | rolled_back | expired
    timer: Optional[threading.Timer] = field(default=None, repr=False)
    # Why planning refused this, if it did. Carried on the token because
    # apply_change must reach the same verdict plan_change showed the
    # operator — a plan marked not applicable that applies anyway is not a
    # gate, and the operator agreed to what the plan said.
    blocked_reason: Optional[str] = None

    def expired(self) -> bool:
        return datetime.now(tz=timezone.utc) > self.expires_at


# ponytail: in-memory token store. One long-lived process per client session is
# exactly how stdio MCP runs, so tokens never need to outlive it. Swap for a
# file store only if the server starts restarting mid-change.
_tokens: dict[str, ChangeToken] = {}
_last_applied: dict[str, str] = {}
_lock = threading.RLock()


def _resolve(name: str) -> Device:
    return get_inventory().resolve(name)


# Commands that take an interface out of service. Deliberately short: a
# command that is merely *suspicious* would produce warnings nobody reads, and
# the value of this is that it fires only when a link really does go away.
# `no shutdown` must not match, which is why this anchors rather than searches.
_TAKES_A_LINK_DOWN = re.compile(
    r"^(shutdown|no\s+ip\s+address|no\s+ipv6\s+address|no\s+switchport)\b", re.I)

# Top-level keywords that end an interface block, so a `shutdown` under
# `router bgp` is not blamed on the interface configured three lines earlier.
_LEAVES_INTERFACE = ("router ", "line ", "vlan ", "vrf ", "ip route", "exit",
                     "end", "policy-map", "class-map", "route-map")


def _interfaces_taken_down(commands: list[str]) -> list[str]:
    """Interfaces this command list would take out of service."""
    at_risk: list[str] = []
    context = ""
    for raw in commands:
        line = raw.strip()
        if not line or line.startswith("!"):
            continue
        low = line.lower()
        if low.startswith("no interface "):
            at_risk.append(line[len("no interface "):].strip())
            context = ""
        elif low.startswith("interface "):
            context = line[len("interface "):].strip()
        elif low.startswith(_LEAVES_INTERFACE):
            context = ""
        elif context and _TAKES_A_LINK_DOWN.match(line):
            at_risk.append(context)
    return sorted(set(at_risk))


def _link_impact(device: str, commands: list[str], reason: str) -> dict[str, Any]:
    """What this change would cut off, according to the topology graph.

    Always returns a note, including when it has nothing to say. A plan that
    simply omitted the question would read as a plan that had asked it and
    found nothing — which is the failure this whole module exists to avoid.
    """
    interfaces = _interfaces_taken_down(commands)
    if not interfaces:
        return {
            "blast_radius": None,
            "blast_radius_note": (
                "No command here shuts or removes an interface, so no link impact "
                "was assessed. Other kinds of breakage are not covered by this."
            ),
        }

    isolated: set[str] = set()
    assessed: list[dict[str, Any]] = []
    unknown: list[str] = []
    stale = False

    for name in interfaces:
        result = topology.query_topology(
            "blast_radius", node=device, interface=name,
            reason=f"pre-change impact check: {reason}")
        if "error" in result:
            unknown.append(name)
            continue
        stale = stale or bool(result.get("stale"))
        isolated.update(result.get("isolated") or [])
        assessed.append({
            "interface": name,
            "isolated": result.get("isolated"),
            "links_lost": [l["peer"] for l in result.get("links_lost", [])],
            **({"partitions": result["partitions"]} if "partitions" in result else {}),
        })

    if not assessed:
        return {
            "blast_radius": None,
            "blast_radius_note": (
                f"This change takes {', '.join(interfaces)} out of service on "
                f"{device}, but the topology graph has nothing recorded for "
                f"{'that interface' if len(interfaces) == 1 else 'those interfaces'}. "
                f"That is NOT a finding that nothing depends on them — it means "
                f"the graph does not know. Run discover_topology, or check the "
                f"device directly, before applying this."
            ),
        }

    impact: dict[str, Any] = {
        "blast_radius": {
            "interfaces": interfaces,
            "assessed": assessed,
            "isolated": sorted(isolated),
        },
    }
    if isolated:
        impact["blast_radius_note"] = (
            f"Applying this would cut off {', '.join(sorted(isolated))} from the "
            f"rest of the network. Confirm that is intended before proceeding."
        )
    else:
        impact["blast_radius_note"] = (
            "No device loses reachability according to the graph, which only "
            "covers links it has discovered."
        )
    if unknown:
        impact["blast_radius"]["not_assessed"] = unknown
        impact["blast_radius_note"] += (
            f" No link is recorded on {', '.join(unknown)}, so nothing could be "
            f"said about {'it' if len(unknown) == 1 else 'them'}."
        )
    if stale:
        impact["blast_radius_note"] += (
            " The graph is stale — re-run discover_topology before relying on this."
        )
    return impact


def _writable(device: Device) -> Optional[str]:
    """Return the reason writes are refused, or None if they're allowed."""
    if is_read_only():
        return (
            "Read-only mode is on. Start the server with NETNERD_READ_ONLY=false "
            "to allow configuration changes."
        )
    if not device.writable:
        return (
            f"Device '{device.name}' is marked writable: false in the inventory. "
            f"Change the inventory to allow writes to it."
        )
    return None


def _read_running_config(device: Device, reason: str) -> str:
    return sessions.run_command(
        device,
        vendor.running_config_command(device.device_type),
        reason=reason,
        tool="plan_change",
    )


_CONTEXT_PREFIXES = (
    "interface", "router ", "line ", "vrf ", "address-family",
    "class-map", "policy-map", "route-map", "ip access-list",
)

# Leaf commands whose value is free text rather than an identifier. Their
# negation never repeats the text: IOS accepts `no description` and FRR accepts
# only that, so repeating it is a command guaranteed to fail on FRR and to show
# up as an error in every rollback transcript.
_FREE_TEXT_LEAVES = ("description", "remark", "banner", "name")


def _is_context(command: str) -> bool:
    stripped = command.strip().lower()
    return not command[:1].isspace() and any(
        stripped.startswith(prefix) for prefix in _CONTEXT_PREFIXES
    )


def _inverse_commands(commands: list[str], keyword_only: bool = False) -> list[str]:
    """Best-effort undo for a set of config commands.

    Context lines (``interface Gi0/1``, ``router bgp 65001``) are kept so the
    negations land in the right place; leaf lines are negated.

    Vendors disagree about how much of a line a negation must repeat: IOS takes
    ``no description some text``, FRR only takes ``no description``. So there
    are two forms — the full one first, and with *keyword_only* the shortened
    one, which rollback falls back to when the device still does not match its
    backup. Neither is trusted: rollback verifies against the backup either way.
    """
    inverse: list[str] = []
    for raw in commands:
        command = raw.rstrip()
        stripped = command.strip()
        if not stripped or stripped.startswith("!"):
            continue
        if _is_context(command):
            inverse.append(stripped)
        elif stripped.lower().startswith("no "):
            inverse.append(stripped[3:])
        elif keyword_only or stripped.split()[0].lower() in _FREE_TEXT_LEAVES:
            inverse.append(f"no {stripped.split()[0]}")
        else:
            inverse.append(f"no {stripped}")
    return inverse


def _touched_contexts(commands: list[str]) -> list[str]:
    """The top-level config blocks a change wrote into, e.g. ``interface lo``."""
    return [c.strip() for c in commands if _is_context(c)]


def _restore_blocks(backup: str, commands: list[str]) -> list[str]:
    """The backup's own version of every block the change touched.

    Negating a command removes it; it cannot bring back the value it replaced.
    Setting a description on an interface that already had one, then rolling
    back, leaves the interface with no description at all — close to the backup
    but not equal to it. Re-applying the backup's copy of just those blocks
    restores the original values without touching the rest of the device.
    """
    contexts = {c.lower() for c in _touched_contexts(commands)}
    if not contexts:
        return []

    restore: list[str] = []
    keeping = False
    for line in backup.splitlines():
        stripped = line.strip()
        if line[:1].strip():  # a new top-level block
            keeping = stripped.lower() in contexts
            if keeping:
                restore.append(stripped)
        elif keeping and stripped and not stripped.startswith("!"):
            if stripped.lower() == "exit":
                keeping = False
                continue
            restore.append(stripped)
    return restore


def _diff(before: str, after: str) -> str:
    return "\n".join(
        difflib.unified_diff(
            before.splitlines(), after.splitlines(),
            fromfile="before", tofile="after", lineterm="", n=1,
        )
    )


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


def plan_change(device: str, commands: list[str], reason: str) -> dict[str, Any]:
    """Validate a configuration change, back up the device, and issue a token.

    Nothing is sent to the device except the reads needed to take the backup.
    The returned token is the only way to apply this exact command list, and it
    expires. Show the operator the commands before applying them.

    Parameters
    ----------
    device: inventory name of the target device.
    commands: configuration commands, without 'configure terminal' or 'end'.
    reason: why this change is being made — recorded in the audit log.
    """
    try:
        target = _resolve(device)
    except InventoryError as exc:
        return {"error": str(exc)}

    log = audit.current()
    result = validate_config_change(commands, device_type=target.device_type)
    if not result.safe:
        log.event("blocked", device=target.name, tool="plan_change",
                  cmd="; ".join(commands)[:500], reason=reason, why=result.reason)
        return {"error": result.reason, "device": target.name}

    cleaned = result.sanitized.splitlines()
    blocked_reason = _writable(target)

    impact = _link_impact(target.name, cleaned, reason)
    if (blocked_reason is None
            and settings.REQUIRE_TOPOLOGY_FOR_WRITES
            and impact["blast_radius"] is None
            and _interfaces_taken_down(cleaned)):
        blocked_reason = (
            "NETNERD_REQUIRE_TOPOLOGY_FOR_WRITES is on and this change takes an "
            "interface down with no topology data to say what depends on it. Run "
            "discover_topology first."
        )

    try:
        backup = _read_running_config(target, reason=f"pre-change backup: {reason}")
    except Exception as exc:
        return {"error": f"Could not back up {target.name}: {exc}", "device": target.name}

    mechanism = (
        "native commit-confirmed"
        if vendor.supports_native_commit_confirm(target.device_type)
        else f"server-side rollback timer ({settings.CONFIRM_TIMEOUT_MIN} min)"
    )
    token = ChangeToken(
        id="chg-" + secrets.token_hex(3),
        device=target.name,
        commands=cleaned,
        command_hash=_hash_commands(cleaned),
        backup=backup,
        expires_at=datetime.now(tz=timezone.utc) + timedelta(minutes=settings.TOKEN_TTL_MIN),
        mechanism=mechanism,
        blocked_reason=blocked_reason,
    )
    with _lock:
        _tokens[token.id] = token

    log.event("plan", device=target.name, token=token.id, commands=cleaned,
              reason=reason, mechanism=mechanism,
              isolates=(impact["blast_radius"] or {}).get("isolated") or None)

    return {
        "device": target.name,
        "token": token.id,
        "commands": cleaned,
        "expires_at": token.expires_at.isoformat(timespec="seconds"),
        "rollback": mechanism,
        "backup_lines": len(backup.splitlines()),
        **impact,
        "applicable": blocked_reason is None,
        "note": blocked_reason or (
            f"Apply with apply_change('{token.id}'). The change reverts by itself "
            f"unless confirm_change('{token.id}') is called within "
            f"{settings.CONFIRM_TIMEOUT_MIN} minutes."
        ),
    }


def apply_change(token: str, reason: str) -> dict[str, Any]:
    """Push a planned change to the device and arm the rollback.

    Only a token from plan_change is accepted, once, before it expires. After
    this returns, verify the device with `show` and then call confirm_change —
    an unconfirmed change reverts on its own.
    """
    with _lock:
        change = _tokens.get(token)
    if change is None:
        return {"error": f"Unknown change token '{token}'. Call plan_change first."}
    if change.state != "pending":
        return {"error": f"Token '{token}' was already used (state: {change.state}). "
                         f"Call plan_change again to make a new one."}
    if change.expired():
        change.state = "expired"
        return {"error": f"Token '{token}' expired. Call plan_change again."}
    if change.command_hash != _hash_commands(change.commands):
        return {"error": f"Token '{token}' does not match its commands — refusing."}

    # The plan's own verdict, before anything else happens. The operator agreed
    # to what the plan said; a plan marked not applicable that applies anyway
    # is not a gate.
    if change.blocked_reason:
        audit.current().event("blocked", device=change.device, tool="apply_change",
                              token=token, reason=reason, why=change.blocked_reason)
        return {"error": change.blocked_reason, "device": change.device}

    try:
        target = _resolve(change.device)
    except InventoryError as exc:
        return {"error": str(exc)}

    # Re-checked rather than taken from the token: read-only can be switched
    # on after a token is issued.
    blocked = _writable(target)
    if blocked:
        audit.current().event("blocked", device=target.name, tool="apply_change",
                              token=token, reason=reason, why=blocked)
        return {"error": blocked, "device": target.name}

    log = audit.current()
    started = time.monotonic()

    # Armed before the push, not after. A change that breaks the path to the
    # device — shutting the interface the session runs over is the obvious one
    # — kills the connection mid-command, and arming afterwards means that
    # exact case, the one that most needs an automatic revert, never gets one.
    change.state = "applied"
    with _lock:
        _last_applied[target.name] = token
    _arm_rollback(change)

    try:
        with sessions.connection(target) as (driver, conn):
            output = driver.send_config_set_validated(conn, change.commands)
    except PermissionError as exc:
        # The validator refused before anything reached the wire, so nothing
        # landed and there is nothing to revert.
        _cancel_rollback(change)
        change.state = "pending"
        with _lock:
            _last_applied.pop(target.name, None)
        log.event("blocked", device=target.name, tool="apply_change", token=token,
                  reason=reason, why=str(exc))
        return {"error": str(exc), "device": target.name}
    except Exception as exc:
        # The connection died part-way. Some commands may have landed, so the
        # rollback timer stays armed rather than being cancelled on the
        # assumption that nothing happened.
        log.event("error", device=target.name, tool="apply_change", token=token,
                  reason=reason, error=f"{type(exc).__name__}: {exc}",
                  rollback_armed=True)
        return {
            "error": f"Apply failed part-way: {exc}",
            "device": target.name,
            "rollback_armed": True,
            "note": (
                f"The connection dropped during the push, so it is NOT known "
                f"whether the commands landed. The rollback is armed and will "
                f"restore the backup in {settings.CONFIRM_TIMEOUT_MIN} minutes "
                f"unless confirm_change is called. If the change broke the path "
                f"to {target.name}, the rollback will not reach it either — check "
                f"the device out of band."
            ),
        }

    rejected = vendor.device_rejected(output)
    log.event("apply", device=target.name, token=token, commands=change.commands,
              reason=reason, mechanism=change.mechanism, rejected=rejected or None,
              ms=int((time.monotonic() - started) * 1000))

    result = {
        "device": target.name,
        "token": token,
        "applied": True,
        "output": audit.mask(output),
        "rollback": change.mechanism,
        "confirm_within_min": settings.CONFIRM_TIMEOUT_MIN,
        "next": (
            f"Verify the device with `show`, then call confirm_change('{token}'). "
            f"If you do nothing, the change reverts in {settings.CONFIRM_TIMEOUT_MIN} minutes."
        ),
    }
    if rejected:
        # The commands went out and some may have landed, so the rollback stays
        # armed — but "applied" must not read as "accepted".
        result["applied"] = False
        result["device_rejected"] = audit.mask(rejected)
        result["next"] = (
            f"The device rejected part of this change: {rejected}. Read the device "
            f"with `show` to find out what actually landed, then either fix it with a "
            f"new plan_change or call rollback('{token}'). Do not confirm it."
        )
    return result


def _arm_rollback(change: ChangeToken) -> None:
    """Start the countdown that reverts an unconfirmed change."""
    timer = threading.Timer(
        settings.CONFIRM_TIMEOUT_MIN * 60, _auto_rollback, args=(change.id,)
    )
    timer.daemon = True
    change.timer = timer
    timer.start()


def _cancel_rollback(change: ChangeToken) -> None:
    """Stop the countdown — only when it is certain nothing was applied."""
    if change.timer is not None:
        change.timer.cancel()
        change.timer = None


def _auto_rollback(token: str) -> None:
    with _lock:
        change = _tokens.get(token)
    if change is None or change.state != "applied":
        return
    logger.warning("Change %s was never confirmed — rolling back", token)
    rollback(token, reason="not confirmed before the timer expired")


def confirm_change(token: str, reason: str) -> dict[str, Any]:
    """Keep an applied change: cancels the automatic rollback.

    Call this only after verifying on the device that the change did what it
    was meant to do. The change is still not persistent — use save_config.

    Parameters
    ----------
    token: the change token returned by plan_change.
    reason: what you checked on the device that shows the change is good.
        This is the one call that switches off the automatic rollback, so the
        audit log records why it was switched off.
    """
    with _lock:
        change = _tokens.get(token)
    if change is None:
        return {"error": f"Unknown change token '{token}'."}
    if change.state != "applied":
        return {"error": f"Token '{token}' is {change.state}, not applied — nothing to confirm."}

    if change.timer is not None:
        change.timer.cancel()
        change.timer = None
    change.state = "confirmed"
    audit.current().event("confirm", device=change.device, token=token, reason=reason)

    return {
        "device": change.device,
        "token": token,
        "confirmed": True,
        "note": "Change kept, rollback cancelled. It is not persistent yet — "
                "call save_config to survive a reboot.",
    }


def rollback(token: str, reason: str = "") -> dict[str, Any]:
    """Undo an applied change and report whether the device matches its backup.

    Fires automatically when a change is never confirmed. The result says
    whether the post-rollback config matches the pre-change backup — if it does
    not, the diff shows exactly what is still different rather than claiming
    success.
    """
    with _lock:
        change = _tokens.get(token)
    if change is None:
        return {"error": f"Unknown change token '{token}'."}
    if change.state not in ("applied", "confirmed"):
        return {"error": f"Token '{token}' is {change.state} — nothing to roll back."}

    try:
        target = _resolve(change.device)
    except InventoryError as exc:
        return {"error": str(exc)}

    if change.timer is not None:
        change.timer.cancel()
        change.timer = None

    log = audit.current()
    show_config = vendor.running_config_command(target.device_type)
    undo = _inverse_commands(change.commands)
    try:
        with sessions.connection(target) as (driver, conn):
            output = driver.send_config_set_validated(conn, undo)
            after = driver.run_command(conn, show_config)

            # A device that rejected the negation looks exactly like one that
            # accepted it — vtysh and IOS both just print and carry on. The
            # config comparison is what actually tells us, so if it still does
            # not match, try the shorter negation form before giving up.
            if _diff(change.backup, after):
                retry = _inverse_commands(change.commands, keyword_only=True)
                if retry != undo:
                    output += "\n" + driver.send_config_set_validated(conn, retry)
                    after = driver.run_command(conn, show_config)
                    undo = retry

            # Still different: the change overwrote a value rather than adding
            # one, so negating it was never going to be enough. Put the backup's
            # own copy of the affected blocks back.
            if _diff(change.backup, after):
                restore = _restore_blocks(change.backup, change.commands)
                if restore:
                    output += "\n" + driver.send_config_set_validated(conn, restore)
                    after = driver.run_command(conn, show_config)
                    undo = undo + restore
    except Exception as exc:
        log.event("error", device=target.name, tool="rollback", token=token,
                  error=f"{type(exc).__name__}: {exc}")
        return {
            "error": f"Rollback failed: {exc}",
            "device": target.name,
            "manual_restore": audit.mask(change.backup),
        }

    change.state = "rolled_back"
    with _lock:
        if _last_applied.get(target.name) == token:
            _last_applied.pop(target.name)

    drift = _diff(change.backup, after)
    log.event("rollback", device=target.name, token=token, commands=undo,
              reason=reason or "manual", restored=not drift)

    return {
        "device": target.name,
        "token": token,
        "rolled_back": True,
        "matches_backup": not drift,
        "commands": undo,
        "output": audit.mask(output),
        "remaining_diff": audit.mask(drift) if drift else "",
        "note": "Device matches its pre-change backup." if not drift else
                "Device does not fully match the backup — the diff above is what "
                "still differs. Review it before walking away.",
    }


def save_config(device: str, reason: str) -> dict[str, Any]:
    """Write the running configuration to startup so it survives a reboot.

    Refuses unless the last change applied to this device was confirmed —
    saving an unverified change would outlive the rollback that protects it.
    """
    try:
        target = _resolve(device)
    except InventoryError as exc:
        return {"error": str(exc)}

    log = audit.current()
    blocked = _writable(target)
    if blocked:
        log.event("blocked", device=target.name, tool="save_config",
                  reason=reason, why=blocked)
        return {"error": blocked, "device": target.name}

    with _lock:
        pending_token = _last_applied.get(target.name)
    if pending_token:
        change = _tokens.get(pending_token)
        if change and change.state == "applied":
            why = (
                f"Change {pending_token} on {target.name} is applied but not confirmed. "
                f"Verify it and call confirm_change('{pending_token}') first — saving now "
                f"would make an unverified change permanent."
            )
            log.event("blocked", device=target.name, tool="save_config",
                      token=pending_token, reason=reason, why=why)
            return {"error": why, "device": target.name}

    command = vendor.save_command(target.device_type)
    try:
        with sessions.connection(target) as (driver, conn):
            output = driver.run_command(conn, command)
    except PermissionError as exc:
        log.event("blocked", device=target.name, tool="save_config", cmd=command,
                  reason=reason, why=str(exc))
        return {"error": str(exc), "device": target.name}
    except Exception as exc:
        log.event("error", device=target.name, tool="save_config", cmd=command,
                  reason=reason, error=f"{type(exc).__name__}: {exc}")
        return {"error": f"Save failed: {exc}", "device": target.name}

    # A refused save comes back as ordinary output, not an exception — reporting
    # success here would tell the operator a change survives a reboot when it
    # does not.
    rejected = vendor.device_rejected(output)
    if rejected:
        log.event("error", device=target.name, tool="save_config", cmd=command,
                  reason=reason, error=rejected)
        return {
            "device": target.name,
            "saved": False,
            "command": command,
            "error": f"The device refused the save: {rejected}",
            "output": audit.mask(output),
            "note": "The running config still has the change; it will be lost on reboot.",
        }

    log.event("save", device=target.name, cmd=command, reason=reason)
    return {"device": target.name, "saved": True, "command": command,
            "output": audit.mask(output)}


def reset() -> None:
    """Drop all tokens and cancel their timers (tests, and end_session)."""
    with _lock:
        for change in _tokens.values():
            if change.timer is not None:
                change.timer.cancel()
        _tokens.clear()
        _last_applied.clear()
