"""Command-line helpers that are deliberately not MCP tools.

Adding a device widens what this server is allowed to reach. The inventory is
the allowlist, and it is the reason a model cannot connect to an address it
read out of command output. A tool that let the model add entries would hand
it the ability to expand its own reach, so importing is a thing a human runs
in a shell — and the result is printed for review before anything is written.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from netnerd_mcp import importers


def _private(path: Path) -> None:
    """Owner-only. An inventory names every device this operator can reach."""
    try:
        path.chmod(0o600)
    except OSError:
        pass


def _target(explicit: str | None) -> Path:
    if explicit:
        return Path(explicit).expanduser()
    if os.environ.get("NETNERD_INVENTORY"):
        return Path(os.environ["NETNERD_INVENTORY"]).expanduser()
    return Path.home() / ".netnerd" / "inventory.yaml"


def _import(args: argparse.Namespace) -> int:
    try:
        if args.from_ansible:
            devices, report = importers.from_ansible(Path(args.from_ansible).expanduser())
        else:
            path = None if args.from_ssh_config is True else args.from_ssh_config
            devices, report = importers.from_ssh_config(Path(path).expanduser() if path else None)
    except importers.ImportError_ as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    style = "keyring" if args.keyring else "env"
    target = _target(args.output)
    existing = target.read_text() if target.is_file() else None
    merged, added, skipped = importers.merge(existing, devices, style)

    print(f"Read {report['found']} host(s) from {report['source']}.", file=sys.stderr)
    if report["unknown_platform"]:
        names = report["unknown_platform"]
        shown = ", ".join(names[:6]) + (f" and {len(names) - 6} more" if len(names) > 6 else "")
        print(f"  {len(names)} had no recognisable platform and defaulted to "
              f"cisco_ios — check these: {shown}", file=sys.stderr)
    if report["secrets_skipped"]:
        print(f"  {report['secrets_skipped']} inline password(s) NOT copied. The "
              f"inventory references them instead.", file=sys.stderr)
    if skipped:
        print(f"  {len(skipped)} already in {target}, left untouched: "
              f"{', '.join(skipped[:6])}", file=sys.stderr)
    print(f"  {len(added)} new device(s), all writable: false.", file=sys.stderr)

    if not args.write:
        print(f"\n--- dry run; re-run with --write to merge into {target} ---\n",
              file=sys.stderr)
        sys.stdout.write(merged)
        return 0

    if not added:
        print("Nothing new to write.", file=sys.stderr)
        return 0

    target.parent.mkdir(parents=True, exist_ok=True)
    if existing is not None:
        # The backup mirrors whatever was already there, which may include a
        # password someone typed in directly against the project's advice.
        backup = target.with_suffix(target.suffix + ".bak")
        backup.write_text(existing)
        _private(backup)
        print(f"Previous inventory saved to {backup}", file=sys.stderr)
    target.write_text(merged)
    _private(target)
    print(f"Wrote {len(added)} device(s) to {target}.", file=sys.stderr)
    print("Every one is read-only. Grant writes per device with "
          "'writable: true'.", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="netnerd-mcp",
        description="Run the MCP server, or build an inventory from one you already have.")
    sub = parser.add_subparsers(dest="command")

    imp = sub.add_parser(
        "import", help="build an inventory from an Ansible inventory or SSH config")
    source = imp.add_mutually_exclusive_group(required=True)
    source.add_argument("--from-ansible", metavar="FILE",
                        help="an Ansible inventory, YAML or INI")
    source.add_argument("--from-ssh-config", nargs="?", const=True, metavar="FILE",
                        help="an SSH config (default: ~/.ssh/config)")
    imp.add_argument("--keyring", action="store_true",
                     help="reference the OS keychain instead of ${NET_PASS}")
    imp.add_argument("--output", metavar="PATH", help="inventory to merge into")
    imp.add_argument("--write", action="store_true",
                     help="actually write; without it this is a dry run")
    imp.set_defaults(func=_import)

    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help(sys.stderr)
        return 2
    return args.func(args)
