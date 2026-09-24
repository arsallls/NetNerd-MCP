"""Append-only, hash-chained audit trail.

Every tool call writes one JSON line to ``<audit-dir>/<date>/<session>.jsonl``.
Each line carries the previous line's hash, so removing or editing an event
breaks the chain and ``verify()`` says where. Alongside it, netmiko writes the
raw SSH transcript to ``<session>.log`` — every byte sent and received, with
the login password and enable secret filtered out by netmiko itself.

``end_session`` renders ``<session>.md``: the human-readable record of what the
agent did, which is the artifact the operator actually reads.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

GENESIS = "0" * 64

# Secrets that can appear in config output. Netmiko already filters the login
# password and enable secret out of the raw transcript; these cover what shows
# up in `show running-config` and friends.
_SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)\b(password|secret)\s+(?:\d\s+)?(\S+)"),
    re.compile(r"(?i)\b(snmp-server\s+community)\s+(\S+)"),
    re.compile(r"(?i)\b(pre-shared-key)\s+(\S+)"),
    # Digest keywords run before the generic key rule so that
    # "authentication-key 1 md5 <secret>" redacts the secret, not the keyword.
    re.compile(r"(?i)\b(md5|hmac-sha1-96|sha256)\s+(\S+)"),
    re.compile(r"(?i)(?<![-\w])(key-string|key)\s+(?:\d\s+)?(\S+)"),
]

_MASK = "********"


def _private_dir(path: Path) -> None:
    """Create a directory only this user can enter.

    What lands in here is the raw SSH transcript of every device touched —
    running configurations, ACLs, addressing, routing adjacencies. Netmiko
    filters the login password and enable secret out of it, so it holds no
    credentials, but it is a complete record of the network. The default 755
    hands that to every other account on the machine, which on a shared jump
    host is everyone.
    """
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        path.chmod(0o700)  # exist_ok=True leaves an existing dir's mode alone
    except OSError:  # someone else owns it; the write will fail loudly anyway
        pass


def _private_file(path: Path) -> None:
    """Restrict a freshly created audit file to its owner."""
    try:
        path.chmod(0o600)
    except OSError:
        pass


def mask(text: str) -> str:
    """Redact credential-shaped content before it reaches a result or report."""
    if not text:
        return text
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub(lambda m: f"{m.group(1)} {_MASK}", text)
    return text


def _now() -> str:
    return datetime.now(tz=timezone.utc).isoformat(timespec="seconds")


def _hash(prev_hash: str, record: dict[str, Any]) -> str:
    payload = prev_hash + json.dumps(record, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


class AuditError(RuntimeError):
    """The audit trail could not be written — the caller must not proceed."""


class AuditLog:
    """One audit trail per session. Writes are fail-closed by design."""

    def __init__(self, session_id: str, base_dir: Path) -> None:
        self.session_id = session_id
        self.dir = base_dir / datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")
        self.jsonl_path = self.dir / f"{session_id}.jsonl"
        self.transcript_path = self.dir / f"{session_id}.log"
        self.report_path = self.dir / f"{session_id}.md"

        self._lock = threading.RLock()
        self._seq = 0
        self._prev_hash = GENESIS
        self._events: list[dict[str, Any]] = []

        try:
            _private_dir(base_dir)
            _private_dir(self.dir)
            # netmiko opens the transcript itself, and whatever mode it uses
            # is applied when the file is created. Creating it here first means
            # the SSH session log is owner-only from its first byte.
            self.transcript_path.touch(mode=0o600, exist_ok=True)
            _private_file(self.transcript_path)
        except OSError as exc:
            raise AuditError(f"Cannot create audit directory {self.dir}: {exc}") from exc

    def event(self, event: str, **fields: Any) -> dict[str, Any]:
        """Append one event. Raises AuditError rather than losing the record."""
        with self._lock:
            self._seq += 1
            record: dict[str, Any] = {
                "seq": self._seq,
                "ts": _now(),
                "session": self.session_id,
                "event": event,
                **fields,
            }
            record["prev_hash"] = self._prev_hash
            record["hash"] = _hash(self._prev_hash, record)

            line = json.dumps(record) + "\n"
            try:
                self._append(line)
            except FileNotFoundError:
                # The directory was removed underneath us — log rotation, a
                # cleanup script, someone tidying up. Recreate it and carry on
                # rather than refusing every command for the rest of the
                # session. Tampering is caught by verify(), not by this.
                logger.warning("Audit directory %s disappeared — recreating it", self.dir)
                try:
                    _private_dir(self.dir)
                    self._append(line)
                except OSError as exc:
                    self._seq -= 1
                    raise AuditError(
                        f"Cannot write audit log {self.jsonl_path}: {exc}"
                    ) from exc
            except OSError as exc:
                self._seq -= 1
                raise AuditError(f"Cannot write audit log {self.jsonl_path}: {exc}") from exc

            self._prev_hash = record["hash"]
            self._events.append(record)
            return record

    def _append(self, line: str) -> None:
        first = not self.jsonl_path.exists()
        with self.jsonl_path.open("a", encoding="utf-8") as fh:
            fh.write(line)
        if first:
            _private_file(self.jsonl_path)

    def events(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._events)

    def transcript(self, tail_chars: int = 20000) -> str:
        """The raw SSH transcript so far, masked, newest content kept."""
        try:
            text = self.transcript_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""
        if len(text) > tail_chars:
            text = "... [earlier output truncated] ...\n" + text[-tail_chars:]
        return mask(text)

    # ------------------------------------------------------------------
    def write_report(self) -> Path:
        """Render the end-of-session markdown report."""
        events = self.events()
        devices = sorted({e["device"] for e in events if e.get("device")})
        commands = [e for e in events if e["event"] == "command"]
        blocked = [e for e in events if e["event"] == "blocked"]
        changes = [e for e in events if e["event"] in ("plan", "apply", "confirm", "rollback", "save")]

        lines = [
            f"# NetNerd session {self.session_id}",
            "",
            f"- Started: {events[0]['ts'] if events else 'n/a'}",
            f"- Ended: {_now()}",
            f"- Devices: {', '.join(devices) or 'none'}",
            f"- Commands run: {len(commands)} · blocked: {len(blocked)} · change events: {len(changes)}",
            f"- Raw transcript: `{self.transcript_path.name}`",
            f"- Event log: `{self.jsonl_path.name}`",
            "",
            "## Timeline",
            "",
            "| # | Time | Device | Event | Detail |",
            "|---|------|--------|-------|--------|",
        ]
        for e in events:
            detail = (
                e.get("cmd")
                or e.get("why")
                or e.get("token")
                or e.get("error")
                or e.get("host")
                or ""
            )
            detail = mask(str(detail)).replace("|", "\\|")
            if len(detail) > 90:
                detail = detail[:87] + "..."
            lines.append(
                f"| {e['seq']} | {e['ts'][11:19]} | {e.get('device', '')} | {e['event']} | {detail} |"
            )

        if commands:
            lines += ["", "## Commands", ""]
            for e in commands:
                lines += [
                    f"**{e.get('device', '?')}** · `{mask(str(e.get('cmd', '')))}`",
                    f"reason: {e.get('reason', '—')}",
                    "",
                ]

        if changes:
            lines += ["", "## Changes", ""]
            for e in changes:
                lines.append(f"- `{e['event']}` {e.get('token', '')} on **{e.get('device', '?')}** — {e.get('reason') or e.get('why') or ''}")
                for cmd in e.get("commands", []) or []:
                    lines.append(f"  - `{mask(str(cmd))}`")

        if blocked:
            lines += ["", "## Blocked", ""]
            for e in blocked:
                lines.append(f"- `{mask(str(e.get('cmd', '')))}` — {e.get('why', '')}")

        lines.append("")
        report = "\n".join(lines)
        try:
            self.report_path.write_text(report, encoding="utf-8")
            _private_file(self.report_path)
        except OSError as exc:
            raise AuditError(f"Cannot write report {self.report_path}: {exc}") from exc
        return self.report_path


def verify(jsonl_path: Path) -> tuple[bool, str]:
    """Re-walk a JSONL audit log and check the hash chain.

    Returns (ok, message). Used by tests and `netnerd-mcp verify-log`.
    """
    prev = GENESIS
    seq = 0
    try:
        lines = jsonl_path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return False, f"cannot read {jsonl_path}: {exc}"

    for lineno, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            return False, f"line {lineno}: not valid JSON ({exc})"

        seq += 1
        if record.get("seq") != seq:
            return False, f"line {lineno}: expected seq {seq}, found {record.get('seq')}"
        if record.get("prev_hash") != prev:
            return False, f"line {lineno}: broken chain — a previous line was altered or removed"

        claimed = record.pop("hash", None)
        if _hash(prev, record) != claimed:
            return False, f"line {lineno}: hash mismatch — this line was altered"
        prev = claimed

    return True, f"{seq} event(s) verified"


_session_log: Optional[AuditLog] = None
_session_lock = threading.RLock()


def current() -> AuditLog:
    """The audit log for this server process's session, created on first use."""
    global _session_log
    with _session_lock:
        if _session_log is None:
            from netnerd_mcp.config.settings import settings

            _session_log = AuditLog(
                session_id="s-" + hashlib.sha256(str(datetime.now()).encode()).hexdigest()[:6],
                base_dir=Path(settings.AUDIT_DIR),
            )
        return _session_log


def reset() -> None:
    """Drop the current session log so the next call starts a new one."""
    global _session_log
    with _session_lock:
        _session_log = None
