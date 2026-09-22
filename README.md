# NetNerd-MCP

An MCP server that gives an LLM real hands on network gear: SSH into switches and
routers, run show commands, and make configuration changes that undo themselves
if nobody confirms them.

Models already know networking. They can explain BGP path selection, read a
spanning-tree topology, and spot a duplex mismatch. What they can't do is reach
your equipment. This closes that gap — without handing an agent an unguarded
enable prompt.

It runs **locally, as a subprocess of your MCP client** — nothing is hosted, no
credentials leave your machine, and device access uses whatever network path you
already have.

## Install

Not on PyPI yet. For now:

```bash
git clone https://github.com/arsallls/NetNerd-MCP && cd NetNerd-MCP && pip install -e .
```

Register it with Claude Code:

```bash
claude mcp add netnerd -- netnerd-mcp
```

## Inventory

The inventory is also the allowlist: a device that isn't listed can't be reached,
even by IP address. Secrets come from the environment — never commit them:

```yaml
devices:
  core-sw1:
    host: 10.0.0.10
    device_type: cisco_ios
    writable: true            # default false — read-only unless you say otherwise
    username: ${NET_USER}
    password: ${NET_PASS}
    enable_secret: ${NET_ENABLE}

  edge-fw1:
    host: 10.0.9.1
    device_type: juniper_junos
    username: ${NET_USER}
    password: ${NET_PASS}
```

`device_type` is any [netmiko platform](https://github.com/ktbyers/netmiko/blob/develop/PLATFORMS.md).

Looked up in order: `$NETNERD_INVENTORY`, `./inventory.yaml`,
`~/.netnerd/inventory.yaml`.

## Tools

Ten primitives, not a tool per feature — the model already knows the CLI, so it
writes the commands and the server decides whether they're allowed to run.

| Tool | | |
|---|---|---|
| `list_devices` | read | What this server may reach. Never returns credentials. |
| `show` | read | One read-only command. Write commands are refused. |
| `get_config` | read | Running or startup config, `section=` filter, secrets masked. |
| `plan_change` | read | Validates commands, backs up the device, returns a change token. |
| `apply_change` | write | Pushes a planned change by token, and arms the rollback. |
| `confirm_change` | write | Keeps the change. Without this it reverts. |
| `rollback` | write | Undoes it now, and says whether the device matches its backup. |
| `save_config` | write | Persists — refused until the change is confirmed. |
| `get_transcript` | read | This session's audit trail so far. |
| `end_session` | read | Closes the SSH sessions, writes the report. |

Every tool takes a `reason`, which lands in the audit log.

## Safety

Read-only mode is **on by default**. Turn it off deliberately:

```bash
export NETNERD_READ_ONLY=false
```

The guarantees are enforced in server code, not in the model's prompt — they
hold whether or not the agent cooperates:

1. **Two gates on any write** — `NETNERD_READ_ONLY=false` *and* `writable: true`
   on that specific device.
2. **Change tokens.** `apply_change` only accepts a token from `plan_change`,
   once, before it expires, and only for the exact command list that was
   planned. "Ask the user first" is a mechanism here, not a sentence in a prompt.
3. **Unconfirmed changes revert.** `apply_change` starts a timer; if
   `confirm_change` never arrives — the agent got it wrong, lost the session, or
   simply stopped — the change comes back off the device.
4. **Rollback tells the truth.** After undoing a change the server re-reads the
   config and compares it to the pre-change backup. If they don't match, you get
   the remaining diff, not a success message.
5. **Destructive commands are refused outright** — `reload`, `write erase`,
   `no username`, `config-register` and friends can't be rolled back by a timer,
   so a human types those.
6. **Command validator** blocks shell injection, enforces the Cisco pipe
   allowlist, and rejects dangerous Linux commands before anything is sent.
7. **Read-only enforcement lives in the SSH driver**, not the tool layer — a tool
   that forgets to check still can't write.

## Audit trail

Everything from SSH login to logout is recorded, in a form the agent can't
summarize away. Per session, under `./netnerd-audit/<date>/`:

- `<session>.log` — the raw SSH transcript, every byte sent and received.
  Netmiko filters the login password and enable secret out of it.
- `<session>.jsonl` — one hash-chained event per action: connects, commands with
  their reasons, blocked attempts, plans, applies, confirms and rollbacks.
  Editing or deleting a line breaks the chain and is detectable.
- `<session>.md` — the end-of-session report: timeline, commands with reasons,
  and every change with what was pushed and whether it stuck.

## Development

A two-node FRR lab with an established eBGP session, reachable over real SSH:

```bash
make lab              # build + start, ~30s
make test-unit        # safety gates, audit chain, token logic — no lab needed
make test-integration # drives the lab over real SSH, including the rollback timer
make lab-down
```

The lab exists because mocking an SSH driver proves nothing — real device state
is the whole point. An unconfirmed change reverting is not something a mock can
demonstrate. FRR's `vtysh` presents an IOS-like CLI, so netmiko's stock
`cisco_ios` driver talks to it unmodified.

## Status

Alpha. Honest state of vendor support:

| Platform | Status |
|---|---|
| FRR | verified in CI via the lab: reads, writes, timer rollback, audit chain |
| Cisco IOS / IOS-XE | written against it, needs hardware validation |
| Arista EOS, NX-OS, VyOS | netmiko supports them; command strings untested |
| Juniper JunOS | untested; `commit confirmed` is detected but not yet used |

Known gaps:

- Rollback undoes a change by negating what was applied, then verifying against
  the backup. It reliably undoes *added* configuration. A command that changed an
  existing value may leave drift — which the rollback result reports rather than
  hides. Native `configure replace` / `commit confirmed` are not wired up yet.
- No jump-host (`via:`) support, no streamable-HTTP transport, no multi-engineer
  auth. Single operator, local machine.
- Structured parsing needs the optional `[parsing]` extra; without it tools
  return raw CLI, which models read fine.

Issues and PRs welcome.

## License

MIT
