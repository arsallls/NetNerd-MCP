"""Staged fleet rollout with automatic rollback.

Ansible batches a rollout with ``serial:`` and cannot undo one. A playbook
that half-applies and breaks reachability leaves you half-applied, and the
operator finds out from the monitoring system. Everything needed to undo a
change is already here, per device: a token, a pre-change backup, a timer that
fires if nobody confirms, and a three-pass restore that reports drift rather
than claiming success. This stages that across a fleet.

Apply to one device, check it is healthy, then a tenth, then the rest. If a
stage fails its check, every stage applied so far comes back off.

Two things shape the design:

**A stage per call.** ``apply_change`` advances one stage and returns. A
500-device rollout as one blocking call would hold the client session open for
twenty minutes — the same bug as an unbounded telemetry subscription — and it
would leave no point between stages at which anything could be checked.

**Per-device tokens, not a fleet-wide one.** A ``FleetToken`` holds the
``ChangeToken`` for each device rather than replacing them, so every device
keeps its own backup, its own rollback mechanism (an SSH timer here, the
device's own confirmed-commit there) and its own state. Fleet rollback is then
the existing per-device rollback run in reverse stage order, which is code
that already reports honestly when it fails.
"""
from __future__ import annotations

import contextvars
import logging
import re
import secrets
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Optional

from netnerd_mcp import audit, changes, sessions, topology, vendor
from netnerd_mcp.config.settings import settings
from netnerd_mcp.inventory import InventoryError, get_inventory

logger = logging.getLogger(__name__)

# Ansible's `serial:` shape, because that is the vocabulary this audience
# already has: one canary, then a tenth, then everything left.
DEFAULT_STAGES: list[Any] = [1, "10%", "rest"]


@dataclass
class FleetToken:
    id: str
    devices: list[str]                       # in stage order
    commands: list[str]
    stages: list[int]                        # resolved device counts
    children: dict[str, str]                 # device -> ChangeToken.id
    baseline: dict[str, set[str]]            # device -> adjacencies at plan time
    stage_index: int = 0
    state: str = "pending"  # pending → staged → halted → confirmed | rolled_back
    applied: list[str] = field(default_factory=list)   # devices, in apply order
    health: list[dict] = field(default_factory=list)   # one entry per stage

    def stage_devices(self, index: int) -> list[str]:
        start = sum(self.stages[:index])
        return self.devices[start:start + self.stages[index]]

    def remaining(self) -> int:
        return len(self.devices) - sum(self.stages[:self.stage_index])


_fleets: dict[str, FleetToken] = {}
_lock = threading.RLock()


def resolve_stages(total: int, spec: Optional[list[Any]] = None) -> list[int]:
    """Turn an Ansible-style ``serial:`` spec into device counts.

    ``[1, "10%", "rest"]`` over 500 devices is ``[1, 50, 449]``.

    A percentage that rounds below one device still means "some", not "none" —
    10% of 5 is a stage of one, not a stage that silently does nothing. And
    whatever the spec leaves over becomes a final stage rather than being
    dropped: a rollout that quietly skipped devices would report success over
    a fleet it never touched.
    """
    spec = spec or DEFAULT_STAGES
    stages: list[int] = []
    remaining = total

    for item in spec:
        if remaining <= 0:
            break
        if isinstance(item, str) and item.strip().lower() == "rest":
            size = remaining
        elif isinstance(item, str) and item.strip().endswith("%"):
            size = max(1, int(total * float(item.strip().rstrip("%")) / 100))
        else:
            size = int(item)
        size = min(max(size, 0), remaining)
        if size:
            stages.append(size)
            remaining -= size

    if remaining > 0:
        stages.append(remaining)
    return stages


def _in_parallel(names: list[str], work, limit: Optional[int] = None) -> dict[str, Any]:
    """Run *work* over *names* at once, returning {name: result or Exception}.

    Each task runs in a copy of the calling context. A worker thread otherwise
    starts with an empty one, losing the per-call device context the SSH driver
    reads — and a copy per task rather than a shared one keeps each device's
    credentials from leaking into its siblings.
    """
    width = min(limit or settings.FLEET_MAX_PARALLEL, len(names)) or 1
    results: dict[str, Any] = {}
    with ThreadPoolExecutor(max_workers=width) as pool:
        futures = {}
        for name in names:
            ctx = contextvars.copy_context()
            futures[pool.submit(ctx.run, work, name)] = name
        for future, name in futures.items():
            try:
                results[name] = future.result()
            except Exception as exc:  # reported per device, never fatal here
                results[name] = exc
    return results


# States that mean a neighbour is listed but not actually peering. A dead BGP
# peer keeps its line in `show ip bgp summary` and just changes this column, so
# counting addresses in the output would report a lost session as healthy —
# the check would never fire, which is worse than not having it.
_NOT_ESTABLISHED = re.compile(
    r"\b(idle|active|connect|opensent|openconfirm|down|attempt|init|exstart|loading)\b",
    re.I)


def _adjacencies(device_name: str, reason: str) -> set[str]:
    """Addresses this device is currently peering with, over BGP and OSPF.

    Only established neighbours. Addresses are read with the discovery parser
    rather than a second one, then any line whose state column says the
    session is down is dropped.

    Over-inclusive in the harmless direction: a router ID on a header line
    looks like a peer and gets counted. It appears in the baseline and in the
    later reading alike, so it cancels out — the check compares the set
    against itself, and only an address that *disappears* means anything.
    """
    try:
        device = get_inventory().resolve(device_name)
    except InventoryError:
        return set()

    seen: set[str] = set()
    for kind in ("bgp", "ospf"):
        try:
            _, output = topology._first_accepted(device, kind, reason)
        except Exception as exc:
            logger.debug("%s: %s adjacency read failed: %s", device_name, kind, exc)
            continue
        for line in output.splitlines():
            if _NOT_ESTABLISHED.search(line):
                continue
            seen |= topology._candidate_peers(line)
    return seen


def _change_landed(device_name: str, commands: list[str], reason: str) -> Optional[bool]:
    """Is the change actually in the running config?

    None when the device could not be read at all — which is not the same as
    the change being absent, and must not be reported as though it were.
    """
    try:
        device = get_inventory().resolve(device_name)
        running = sessions.run_command(
            device, vendor.running_config_command(device.device_type),
            reason=reason, tool="apply_change")
    except Exception as exc:
        logger.debug("%s: could not re-read config: %s", device_name, exc)
        return None

    present = {line.strip().lower() for line in running.splitlines()}
    wanted = [c.strip().lower() for c in commands
              if c.strip() and not changes._is_context(c)]
    if not wanted:  # nothing but context lines — nothing to look for
        return True
    return any(w in present for w in wanted)


# ---------------------------------------------------------------------------
# Plan
# ---------------------------------------------------------------------------

def _preflight(names: list[str]) -> dict[str, str]:
    """Refusals that can be found without contacting a device."""
    blocked: dict[str, str] = {}
    inventory = get_inventory()
    for name in names:
        try:
            device = inventory.resolve(name)
        except InventoryError as exc:
            blocked[name] = str(exc)
            continue
        why = changes._writable(device)
        if why:
            blocked[name] = why
    return blocked


def _refuse(log, names: list[str], refused: dict[str, str], reason: str,
            issued: list[str]) -> dict[str, Any]:
    """Refuse the rollout and leave nothing behind.

    Every token issued along the way is dropped, including the ones for
    devices that planned fine and the ones plan_change issued already marked
    blocked. Left in place they would let an operator apply half a rollout one
    token at a time, which is the state staging exists to prevent — and each
    one holds a full configuration backup.
    """
    for token in issued:
        changes.expire(token)
    log.event("blocked", tool="plan_change", reason=reason, devices=names,
              why=f"{len(refused)} device(s) cannot take this change")
    return {
        "error": (f"{len(refused)} of {len(names)} device(s) cannot take this "
                  f"change, so the rollout was not planned."),
        "refused": refused,
        "note": ("Fix or drop those devices and plan again. Nothing was applied, "
                 "and no tokens were left behind."),
    }


def plan_fleet(devices: list[str], commands: list[str], reason: str,
               stages: Optional[list[Any]] = None) -> dict[str, Any]:
    """Plan one change across several devices and issue a fleet token.

    Every device is planned through the ordinary single-device gate, so each
    one is validated, backed up and blast-radius checked exactly as it would
    be on its own. If any device cannot be planned the whole fleet is refused:
    a rollout that quietly skipped the devices it could not handle would
    report success over a fleet it never fully touched.
    """
    names = list(dict.fromkeys(devices))  # de-duplicate, keep order
    if len(names) < 2:
        return {"error": "A fleet needs at least two devices. Use 'device' for one."}

    log = audit.current()

    # Before touching anything. plan_change reads a full configuration for the
    # backup before it reports that a device is not writable, so discovering
    # this one device at a time would open five hundred SSH sessions and hold
    # five hundred configurations in memory to answer a question that is pure
    # local state.
    refused = _preflight(names)
    if refused:
        return _refuse(log, names, refused, reason, [])

    plans: dict[str, dict] = {}
    issued: list[str] = []

    for name in names:
        plan = changes.plan_change(device=name, commands=commands, reason=reason)
        if plan.get("token"):
            issued.append(plan["token"])
        if "error" in plan:
            refused[name] = plan["error"]
        elif not plan.get("applicable", False):
            refused[name] = plan.get("note") or "not applicable"
        else:
            plans[name] = plan

    if refused:
        return _refuse(log, names, refused, reason, issued)

    # Every device gets the fleet window rather than the single-change one:
    # stage one's rollback must not fire while stage three is still going out.
    for plan in plans.values():
        changes.set_timeout(plan["token"], settings.FLEET_TIMEOUT_MIN)

    baseline = _in_parallel(
        names, lambda n: _adjacencies(n, f"fleet adjacency baseline: {reason}"))

    isolated: set[str] = set()
    for plan in plans.values():
        isolated.update((plan.get("blast_radius") or {}).get("isolated") or [])

    token = FleetToken(
        id="fleet-" + secrets.token_hex(3),
        devices=names,
        commands=plans[names[0]]["commands"],
        stages=resolve_stages(len(names), stages),
        children={n: p["token"] for n, p in plans.items()},
        baseline={n: (b if isinstance(b, set) else set()) for n, b in baseline.items()},
    )
    with _lock:
        _fleets[token.id] = token

    log.event("plan", tool="plan_change", token=token.id, devices=names,
              commands=token.commands, reason=reason, stages=token.stages,
              isolates=sorted(isolated) or None)

    result: dict[str, Any] = {
        "token": token.id,
        "devices": names,
        "commands": token.commands,
        "stages": [{"stage": i + 1, "devices": n} for i, n in enumerate(token.stages)],
        "rollback": (f"every device reverts within {settings.FLEET_TIMEOUT_MIN} "
                     f"minutes unless confirm_change is called"),
        "applicable": True,
        "next": (f"apply_change('{token.id}') applies stage 1 "
                 f"({token.stages[0]} device(s)) and checks it before stopping."),
    }
    if isolated:
        result["blast_radius"] = {"isolated": sorted(isolated)}
        result["blast_radius_note"] = (
            f"Applied across the whole fleet this would cut off "
            f"{', '.join(sorted(isolated))}. That is the total across every "
            f"device, computed before any of them is touched.")
    else:
        result["blast_radius_note"] = (
            "No device loses reachability according to the graph, which only "
            "covers links it has discovered.")
    return result


# ---------------------------------------------------------------------------
# Advance one stage
# ---------------------------------------------------------------------------

def advance(token: str, reason: str) -> dict[str, Any]:
    """Apply the next stage, check it, and stop.

    Returns counts rather than per-device output: 500 device results do not
    fit in a context window, and only the ones that went wrong need naming.
    """
    with _lock:
        fleet = _fleets.get(token)
    if fleet is None:
        return {"error": f"Unknown fleet token '{token}'."}
    if fleet.state == "halted":
        return {
            "error": f"Fleet '{token}' is halted after a degraded stage.",
            "health": fleet.health[-1] if fleet.health else None,
            "note": ("Decide explicitly: rollback('" + token + "') to undo every "
                     "applied stage, or confirm_change('" + token + "') to keep "
                     "them. Doing nothing reverts the whole fleet when the timer "
                     "expires."),
        }
    if fleet.state not in ("pending", "staged"):
        return {"error": f"Fleet '{token}' is {fleet.state} — nothing left to apply."}
    if fleet.stage_index >= len(fleet.stages):
        return {"error": f"Every stage of '{token}' is already applied. "
                         f"Call confirm_change('{token}') to keep it."}

    index = fleet.stage_index
    names = fleet.stage_devices(index)
    log = audit.current()

    applied = _in_parallel(
        names, lambda n: changes.apply_change(fleet.children[n], reason))

    failed: dict[str, str] = {}
    for name, outcome in applied.items():
        if isinstance(outcome, Exception):
            failed[name] = f"{type(outcome).__name__}: {outcome}"
        elif outcome.get("device_rejected"):
            failed[name] = f"device rejected the change: {outcome['device_rejected']}"
        elif not outcome.get("applied"):
            failed[name] = outcome.get("error", "the change did not apply")
        else:
            fleet.applied.append(name)

    health = _check_stage(fleet, [n for n in names if n not in failed], reason)
    health.update({"stage": index + 1, "of": len(fleet.stages), "devices": len(names)})
    if failed:
        health["failed"] = {**failed, **health.get("failed", {})}
    fleet.health.append(health)
    fleet.stage_index = index + 1

    hard_failures = health.get("failed") or {}
    degraded = health.get("degraded") or {}

    log.event("apply", tool="apply_change", token=token, devices=names,
              reason=reason, stage=index + 1, healthy=len(health.get("healthy", [])),
              failed=sorted(hard_failures) or None, degraded=sorted(degraded) or None)

    if hard_failures:
        # The change is broken, so the rollout is one decision and it is off.
        undo = rollback_fleet(
            token, reason=f"stage {index + 1} failed: {'; '.join(sorted(hard_failures))}")
        return {
            "stage": f"{index + 1} of {len(fleet.stages)}",
            "devices": len(names),
            "failed": hard_failures,
            "rolled_back": undo,
            "note": (f"Stage {index + 1} failed on {len(hard_failures)} device(s), so "
                     f"every stage applied so far was rolled back. The fleet is not "
                     f"carrying this change."),
        }

    if degraded:
        fleet.state = "halted"
        return {
            "stage": f"{index + 1} of {len(fleet.stages)}",
            "devices": len(names),
            "healthy": len(health.get("healthy", [])),
            "degraded": degraded,
            "note": (
                f"Stage {index + 1} applied, but {len(degraded)} device(s) lost a "
                f"routing adjacency. The rollout is halted rather than rolled back: "
                f"a peer may have been down already, and that is a judgement call. "
                f"Every applied device is still armed, so doing nothing reverts the "
                f"whole fleet in {settings.FLEET_TIMEOUT_MIN} minutes. Decide with "
                f"rollback('{token}') or confirm_change('{token}')."),
        }

    fleet.state = "staged"
    done = fleet.stage_index >= len(fleet.stages)
    result = {
        "stage": f"{index + 1} of {len(fleet.stages)}",
        "devices": len(names),
        "healthy": len(health.get("healthy", [])),
        "failed": {},
        "degraded": {},
    }
    if done:
        result["note"] = (
            f"Every stage applied and healthy across {len(fleet.applied)} device(s). "
            f"Verify, then confirm_change('{token}') — otherwise the whole fleet "
            f"reverts in {settings.FLEET_TIMEOUT_MIN} minutes.")
    else:
        result["next"] = (
            f"apply_change('{token}') advances to stage {fleet.stage_index + 1} "
            f"({fleet.stages[fleet.stage_index]} device(s), {fleet.remaining()} left).")
    return result


def _check_stage(fleet: FleetToken, names: list[str], reason: str) -> dict[str, Any]:
    """Health of the devices a stage just landed on.

    Three outcomes, and the difference between them is the whole point:
    a device that cannot be reached or did not take the change is a hard
    failure and the fleet comes back off; a device that took the change but
    lost a routing adjacency halts the rollout for a human to judge.
    """
    if not names:
        return {"healthy": [], "failed": {}, "degraded": {}}

    def check(name: str) -> dict[str, Any]:
        landed = _change_landed(name, fleet.commands, f"fleet health check: {reason}")
        if landed is None:
            return {"fail": "unreachable after the change"}
        if landed is False:
            return {"fail": "the change is not in the running config"}
        lost = fleet.baseline.get(name, set()) - _adjacencies(
            name, f"fleet adjacency check: {reason}")
        if lost:
            return {"degrade": f"lost {len(lost)} routing adjacency/ies: "
                               f"{', '.join(sorted(lost))}"}
        return {"ok": True}

    healthy, failed, degraded = [], {}, {}
    for name, outcome in _in_parallel(names, check).items():
        if isinstance(outcome, Exception):
            failed[name] = f"health check failed: {type(outcome).__name__}: {outcome}"
        elif "fail" in outcome:
            failed[name] = outcome["fail"]
        elif "degrade" in outcome:
            degraded[name] = outcome["degrade"]
        else:
            healthy.append(name)
    return {"healthy": sorted(healthy), "failed": failed, "degraded": degraded}


# ---------------------------------------------------------------------------
# Finish: keep it or take it all back off
# ---------------------------------------------------------------------------

def confirm_fleet(token: str, reason: str) -> dict[str, Any]:
    """Keep every applied stage, cancelling the rollback on each device."""
    with _lock:
        fleet = _fleets.get(token)
    if fleet is None:
        return {"error": f"Unknown fleet token '{token}'."}
    if not fleet.applied:
        return {"error": f"Fleet '{token}' has nothing applied to confirm."}
    if fleet.state in ("confirmed", "rolled_back"):
        return {"error": f"Fleet '{token}' is already {fleet.state}."}

    pending = fleet.remaining()
    outcomes = _in_parallel(
        fleet.applied, lambda n: changes.confirm_change(fleet.children[n], reason))

    confirmed, stuck = [], {}
    for name, outcome in outcomes.items():
        if isinstance(outcome, Exception):
            stuck[name] = f"{type(outcome).__name__}: {outcome}"
        elif outcome.get("confirmed"):
            confirmed.append(name)
        else:
            stuck[name] = outcome.get("error", "not confirmed")

    fleet.state = "confirmed" if not stuck else "staged"
    audit.current().event("confirm", tool="confirm_change", token=token,
                          reason=reason, devices=sorted(confirmed),
                          not_confirmed=sorted(stuck) or None)

    result: dict[str, Any] = {"token": token, "confirmed": len(confirmed)}
    if stuck:
        # Their timers are still running, so this is not a partial success to
        # be noted in passing — those devices revert unless someone acts.
        result["not_confirmed"] = stuck
        result["note"] = (
            f"{len(stuck)} device(s) could not be confirmed and are still armed — "
            f"they will revert within {settings.FLEET_TIMEOUT_MIN} minutes of being "
            f"applied unless that is fixed. The other {len(confirmed)} are kept.")
    elif pending:
        result["note"] = (
            f"{len(confirmed)} device(s) kept. {pending} device(s) were never "
            f"applied, so the fleet is only partly carrying this change.")
    else:
        result["note"] = (
            f"All {len(confirmed)} device(s) kept and their rollbacks cancelled. "
            f"The change is not persistent — call save_config per device.")
    return result


def rollback_fleet(token: str, reason: str) -> dict[str, Any]:
    """Take the change back off every device that has it, newest stage first.

    Reverse stage order because the canary went out first and should come back
    last: if a rollback is itself going to break something, it breaks on the
    device that has already been carrying the change longest.

    Some rollbacks will fail. That is reality on a fleet, and the result says
    which devices are still carrying the change rather than reporting a clean
    number that hides them.
    """
    with _lock:
        fleet = _fleets.get(token)
    if fleet is None:
        return {"error": f"Unknown fleet token '{token}'."}
    if not fleet.applied:
        return {"error": f"Fleet '{token}' has nothing applied to roll back."}

    order = list(reversed(fleet.applied))
    outcomes = _in_parallel(order, lambda n: changes.rollback(fleet.children[n], reason))

    restored, still_changed, drifted = [], {}, []
    for name, outcome in outcomes.items():
        if isinstance(outcome, Exception):
            still_changed[name] = f"{type(outcome).__name__}: {outcome}"
        elif not outcome.get("rolled_back"):
            still_changed[name] = outcome.get("error", "rollback failed")
        else:
            restored.append(name)
            if not outcome.get("matches_backup", True):
                drifted.append(name)

    fleet.state = "rolled_back" if not still_changed else "halted"
    log = audit.current()
    log.event("rollback", tool="rollback", token=token, reason=reason,
              devices=sorted(restored), still_changed=sorted(still_changed) or None,
              drifted=sorted(drifted) or None)

    result: dict[str, Any] = {"token": token, "rolled_back": len(restored)}
    if still_changed:
        result["still_changed"] = still_changed
        result["note"] = (
            f"{len(still_changed)} device(s) could not be restored and are still "
            f"carrying the change. Each one's pre-change configuration is in the "
            f"audit report at {log.report_path if hasattr(log, 'report_path') else '~/.netnerd/audit'}.")
    else:
        result["note"] = f"All {len(restored)} device(s) restored to their backups."
    if drifted:
        # Rolled back, but not all the way. Counting these as restored would be
        # the exact lie the single-device rollback already refuses to tell.
        result["restored_with_drift"] = drifted
        result["note"] += (
            f" {len(drifted)} of them do not fully match their backup — check the "
            f"per-device rollback entries in the audit log for the remaining diff.")
    return result


def get(token: str) -> Optional[FleetToken]:
    """The fleet behind a token, or None. Used by changes.py to dispatch."""
    with _lock:
        return _fleets.get(token)


def reset() -> None:
    """Drop every fleet token (tests, and end_session)."""
    with _lock:
        _fleets.clear()
