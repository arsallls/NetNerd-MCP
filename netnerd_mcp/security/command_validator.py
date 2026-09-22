"""
Command injection prevention for NetNerd.

Validates every command before it reaches an SSH session.
Three layers of protection:
  1. Structural sanitisation — strips null bytes, control chars, excessive length
  2. Injection pattern detection — blocks shell escapes and dangerous constructs
  3. Prompt injection detection — detects LLM hijack attempts in user messages
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class ValidationResult:
    safe: bool
    reason: str
    sanitized: str  # cleaned command (may differ from input)


# ── Dangerous patterns ─────────────────────────────────────────────────────────

# Patterns that are never valid in a network device CLI command
_INJECTION_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'\x00'), "null byte"),
    (re.compile(r'`'), "backtick execution"),
    (re.compile(r'\$\('), "shell substitution $()"),
    (re.compile(r'\$\{'), "shell substitution ${}"),
    (re.compile(r';\s*\w'), "command separator ;"),
    (re.compile(r'\|\|'), "logical OR ||"),
    (re.compile(r'&&'), "logical AND &&"),
    (re.compile(r'>>\s*/'), "append redirect >>"),
    (re.compile(r'>\s*/'), "write redirect >"),
    (re.compile(r'<\('), "process substitution <()"),
]

# Linux-specific dangerous commands (for run_linux_command tool)
_LINUX_DANGEROUS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'\brm\s+-[rf]', re.IGNORECASE), "rm -rf"),
    (re.compile(r'\bmkfs\b', re.IGNORECASE), "mkfs (disk format)"),
    (re.compile(r'\bdd\b.*\bif=', re.IGNORECASE), "dd with if= (disk write)"),
    (re.compile(r':\(\)\s*\{', re.IGNORECASE), "fork bomb"),
    (re.compile(r'\bshutdown\b', re.IGNORECASE), "shutdown"),
    (re.compile(r'\breboot\b', re.IGNORECASE), "reboot"),
    (re.compile(r'\bpoweroff\b', re.IGNORECASE), "poweroff"),
    (re.compile(r'\biptables\s+-[FXZ]\b', re.IGNORECASE), "iptables flush/delete"),
    (re.compile(r'\bip\s+route\s+(del|flush)\b', re.IGNORECASE), "ip route delete/flush"),
    (re.compile(r'\bpasswd\b', re.IGNORECASE), "passwd (credential change)"),
    (re.compile(r'\bcrontab\s+-r\b', re.IGNORECASE), "crontab -r (delete cron)"),
    # Malware delivery patterns — commonly used to install malware on routers
    (re.compile(r'\bwget\b.*\|\s*(sh|bash)', re.IGNORECASE), "wget pipe to shell (malware dropper)"),
    (re.compile(r'\bcurl\b.*\|\s*(sh|bash)', re.IGNORECASE), "curl pipe to shell (malware dropper)"),
    (re.compile(r'\bwget\b.*/tmp/', re.IGNORECASE), "wget download to /tmp (malware staging)"),
    (re.compile(r'\bcurl\b.*/tmp/', re.IGNORECASE), "curl download to /tmp (malware staging)"),
    (re.compile(r'\bchmod\s+\+x\s+/tmp/', re.IGNORECASE), "chmod +x in /tmp (malware execution)"),
    (re.compile(r'\bchmod\s+\+x\s+/dev/shm/', re.IGNORECASE), "chmod +x in /dev/shm (malware execution)"),
    (re.compile(r'\bbase64\b.*-d.*\|\s*(sh|bash|python)', re.IGNORECASE), "base64 decode pipe to shell (obfuscated dropper)"),
    (re.compile(r'\becho\b.*\|\s*base64\s+-d\s*\|', re.IGNORECASE), "encoded payload execution"),
    (re.compile(r'\bnohup\b.*/tmp/', re.IGNORECASE), "nohup execution from /tmp (malware persistence)"),
    (re.compile(r'\bcrontab\b.*-[li].*http', re.IGNORECASE), "cron job with HTTP download"),
    (re.compile(r'\buserdel\b|\buseradd\b|\badduser\b', re.IGNORECASE), "user account modification"),
    (re.compile(r'>\s*/etc/passwd', re.IGNORECASE), "overwriting /etc/passwd"),
    (re.compile(r'>\s*/etc/shadow', re.IGNORECASE), "overwriting /etc/shadow"),
    (re.compile(r'\binsmod\b|\bmodprobe\b', re.IGNORECASE), "kernel module loading (rootkit risk)"),
    # Catch-all for piping arbitrary content into an interpreter, whatever the
    # source — the wget/curl/base64 entries above only cover known droppers.
    (re.compile(r'\|\s*(sh|bash|zsh|ksh|python\d?|perl|ruby|node)\b', re.IGNORECASE), "pipe to interpreter"),
]

# Device types whose CLI is a real shell, where pipes are legitimate.
_LINUX_DEVICE_TYPES = ("linux", "vyos", "ubuntu_linux")

# Valid Cisco IOS pipe filter keywords (pipe is only valid with these)
_IOS_PIPE_ALLOWED = re.compile(
    r'\|\s*(include|exclude|begin|section|count|no-more|append|redirect|tee)\b',
    re.IGNORECASE,
)

# Prompt injection patterns in user-facing text
_PROMPT_INJECTION_PATTERNS: list[re.Pattern] = [
    re.compile(r'ignore\s+(previous|prior|above|all)\s+(instructions?|prompt|rules?)', re.IGNORECASE),
    re.compile(r'forget\s+(your\s+)?(instructions?|prompt|rules?|training)', re.IGNORECASE),
    re.compile(r'disregard\s+(all|previous|prior|your)', re.IGNORECASE),
    re.compile(r'you\s+are\s+now\s+a?\s*\w+', re.IGNORECASE),
    re.compile(r'act\s+as\s+(if\s+you\s+are|a)\s+\w+', re.IGNORECASE),
    re.compile(r'new\s+(persona|role|instructions?|system\s+prompt)', re.IGNORECASE),
    re.compile(r'jailbreak', re.IGNORECASE),
    re.compile(r'DAN\s+mode', re.IGNORECASE),
    re.compile(r'pretend\s+(you\s+are|to\s+be)', re.IGNORECASE),
    re.compile(r'override\s+(your\s+)?(safety|guidelines?|restrictions?|rules?)', re.IGNORECASE),
    # Device output injection — a device returning instructions to the LLM
    re.compile(r'SYSTEM:\s*(ignore|forget|you are)', re.IGNORECASE),
    re.compile(r'\[INST\]', re.IGNORECASE),
]

_MAX_COMMAND_LENGTH = 1000

# Config commands that are refused outright: they either drop the device off the
# network, destroy state that cannot be rolled back, or lock the operator out.
# An agent that wants one of these has to ask a human to type it.
_DESTRUCTIVE_CONFIG: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\breload\b", re.IGNORECASE), "device reload"),
    (re.compile(r"\berase\s+(startup|nvram|flash)", re.IGNORECASE), "erase persistent storage"),
    (re.compile(r"\bwrite\s+erase\b", re.IGNORECASE), "erase startup config"),
    (re.compile(r"\bformat\b", re.IGNORECASE), "format filesystem"),
    (re.compile(r"\bdelete\s+(flash|bootflash|nvram)", re.IGNORECASE), "delete from flash"),
    (re.compile(r"crypto\s+key\s+zeroize", re.IGNORECASE), "zeroize crypto keys"),
    (re.compile(r"\bboot\s+system\b", re.IGNORECASE), "change boot image"),
    (re.compile(r"\bconfig-register\b", re.IGNORECASE), "change config register"),
    (re.compile(r"^\s*no\s+(username|aaa)\b", re.IGNORECASE), "remove login access"),
    (re.compile(r"\btransport\s+input\s+none\b", re.IGNORECASE), "disable remote access"),
]


# ── Public API ─────────────────────────────────────────────────────────────────


def validate_network_command(command: str, device_type: str = "cisco_ios") -> ValidationResult:
    """
    Validate a CLI command before sending it to a network device via SSH.

    Parameters
    ----------
    command:
        The CLI command string.
    device_type:
        Netmiko device type — used to apply device-specific rules.

    Returns
    -------
    ValidationResult
        safe=True if the command is allowed, False otherwise.
    """
    # Step 1: Basic sanitisation
    sanitized = command.strip()

    # Remove null bytes and control characters (except tab/newline which Netmiko handles)
    sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', sanitized)

    if not sanitized:
        return ValidationResult(safe=False, reason="Empty command after sanitisation.", sanitized="")

    if len(sanitized) > _MAX_COMMAND_LENGTH:
        return ValidationResult(
            safe=False,
            reason=f"Command exceeds maximum length ({len(sanitized)} > {_MAX_COMMAND_LENGTH} chars).",
            sanitized=sanitized,
        )

    # Step 2: Universal injection checks
    for pattern, label in _INJECTION_PATTERNS:
        if pattern.search(sanitized):
            return ValidationResult(
                safe=False,
                reason=f"Blocked: detected {label} in command.",
                sanitized=sanitized,
            )

    is_linux = device_type in _LINUX_DEVICE_TYPES

    # Step 2b: Pipe discipline on network CLIs.
    # On a network device the pipe is only a display filter; anything else is a
    # reach for a shell. This check is deliberately NOT nested inside the loop
    # above — when it was, a bare `show run | sh` matched no injection pattern,
    # so the loop body never ran and the allowlist was never consulted.
    if "|" in sanitized and not is_linux and not _IOS_PIPE_ALLOWED.search(sanitized):
        return ValidationResult(
            safe=False,
            reason=(
                "Invalid pipe usage. Only 'include', 'exclude', 'begin', "
                "'section', 'count' and similar display filters may follow '|'."
            ),
            sanitized=sanitized,
        )

    # Step 3: Linux-specific checks
    if is_linux:
        for pattern, label in _LINUX_DANGEROUS:
            if pattern.search(sanitized):
                return ValidationResult(
                    safe=False,
                    reason=f"Blocked dangerous Linux command: {label}.",
                    sanitized=sanitized,
                )

    return ValidationResult(safe=True, reason="OK", sanitized=sanitized)


def validate_config_change(commands: list[str], device_type: str = "cisco_ios") -> ValidationResult:
    """Validate a whole set of configuration commands before it is planned.

    Applies the same injection checks as a single command, plus a refusal list
    for changes that are destructive or would cut off access — those cannot be
    rolled back by a timer, so the guardrail is to never send them.

    ``sanitized`` holds the cleaned commands joined by newlines.
    """
    cleaned: list[str] = []
    for command in commands:
        result = validate_network_command(command, device_type=device_type)
        if not result.safe:
            return ValidationResult(
                safe=False,
                reason=f"{result.reason} (command: '{command.strip()}')",
                sanitized="\n".join(cleaned),
            )
        for pattern, label in _DESTRUCTIVE_CONFIG:
            if pattern.search(result.sanitized):
                return ValidationResult(
                    safe=False,
                    reason=(
                        f"Refused: '{result.sanitized}' is a {label} command. "
                        f"This cannot be rolled back automatically — a human has to run it."
                    ),
                    sanitized="\n".join(cleaned),
                )
        cleaned.append(result.sanitized)

    if not cleaned:
        return ValidationResult(safe=False, reason="No commands given.", sanitized="")

    return ValidationResult(safe=True, reason="OK", sanitized="\n".join(cleaned))


def check_prompt_injection(text: str) -> tuple[bool, str]:
    """
    Check if user input or device output contains a prompt injection attempt.

    Returns (is_injection, reason). Call this on user messages before passing
    to the agent, and on device output before feeding back into context.
    """
    for pattern in _PROMPT_INJECTION_PATTERNS:
        m = pattern.search(text)
        if m:
            return True, f"Possible prompt injection detected: '{m.group(0)}'"
    return False, ""
