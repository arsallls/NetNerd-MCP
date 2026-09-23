# NetNerd-MCP

An MCP server that gives an LLM real hands on network gear: SSH into switches and
routers, run show commands, map how they connect, and make configuration changes
that undo themselves if nobody confirms them.

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

A core install speaks CLI over SSH and parses command output. Everything else is
an optional extra:

| Extra | Adds |
|---|---|
| `netconf` | NETCONF and RESTCONF — and with NETCONF, rollback the device enforces itself |
| `gnmi` | gNMI reads and streaming telemetry |
| `vault` | device passwords from the OS keychain |
| `parsing` | Genie/pyATS parsers for extra IOS-XE coverage (large — see [Parsing](#parsing)) |

```bash
pip install -e ".[netconf,gnmi,vault]"
```

## Inventory

The inventory is also the allowlist: a device that isn't listed can't be reached,
even by IP address. Secrets are referenced, never written down:

```yaml
devices:
  core-sw1:
    host: 10.0.0.10
    device_type: cisco_ios
    writable: true            # default false — read-only unless you say otherwise
    username: ${NET_USER}
    password: ${NET_PASS}
    enable_secret: ${NET_ENABLE}

  edge-rtr1:
    host: edge-rtr1           # hostname, user, port and key from ~/.ssh/config
    ssh_config: true
    password: keyring:netnerd/edge-rtr1

  dc-spine1:
    host: 10.0.1.1
    device_type: cisco_xe
    protocols: [netconf, ssh] # NETCONF preferred: the device holds the rollback
    writable: true
    username: ${NET_USER}
    password: ${NET_PASS}
```

Three ways to supply a secret:

- `${ENV_VAR}` — from the environment, the convention Ansible and Nornir use.
- `keyring:SERVICE/USER` — from the OS keychain (macOS Keychain, GNOME Secret
  Service, Windows Credential Manager). Needs the `vault` extra.
- `ssh_config: true` — hostname, user, port and identity file from
  `~/.ssh/config`. Anything set explicitly in the inventory wins.

A missing secret is an error, never an empty password.

`device_type` is any [netmiko platform](https://github.com/ktbyers/netmiko/blob/develop/PLATFORMS.md).
`protocols` defaults to `[ssh]`; see [Protocols](#protocols).

Looked up in order: `$NETNERD_INVENTORY`, `./inventory.yaml`,
`~/.netnerd/inventory.yaml`.

## Tools

Thirteen primitives, not a tool per feature — the model already knows the CLI, so
it writes the commands and the server decides whether they're allowed to run.

| Tool | | |
|---|---|---|
| `list_devices` | read | What this server may reach. Never returns credentials. |
| `show` | read | One read-only command, parsed to rows where possible. Write commands are refused. |
| `get_config` | read | Running or startup config, `section=` filter, secrets masked. |
| `discover_topology` | read | Walks the devices and records how they connect. |
| `query_topology` | read | Neighbours, paths, and what a change would cut off. |
| `telemetry` | read | Watches counters for a few seconds and reports what they did. |
| `plan_change` | read | Validates commands, backs up the device, returns a change token. |
| `apply_change` | write | Pushes a planned change by token, and arms the rollback. |
| `confirm_change` | write | Keeps the change. Without this it reverts. |
| `rollback` | write | Undoes it now, and says whether the device matches its backup. |
| `save_config` | write | Persists — refused until the change is confirmed. |
| `get_transcript` | read | This session's audit trail so far. |
| `end_session` | read | Closes the sessions, writes the report. |

Every tool takes a `reason`, which lands in the audit log.

## Protocols

How a device is reached is a property of the device, not a choice the model
makes. List them in the inventory, best first:

| Protocol | Reads | Writes | Rollback |
|---|---|---|---|
| `ssh` | CLI, parsed where a template exists | CLI config | server-side timer replaying a backup |
| `netconf` | XML from the candidate/running datastore | XML `edit-config` | **the device's own confirmed-commit** |
| `restconf` | JSON over HTTPS | JSON `PATCH` | server-side timer |
| `gnmi` | OpenConfig paths, plus telemetry | — | — |

The one that matters is NETCONF. RFC 6241 confirmed-commit puts the rollback
timer **on the device**: if this server dies, or the change breaks the path back
to the device, it still reverts. A server-side timer can do neither, and those
are exactly the situations a rollback is for.

gNMI is read-only here on purpose. It has no confirmed-commit, so a change made
over gNMI could only be undone by replaying a backup — the weakest option — and
devices that speak gNMI almost always speak NETCONF too.

A device that lists a protocol whose package isn't installed is **refused**, not
quietly downgraded: sending CLI to port 830 is not a reasonable fallback.

## Topology

`discover_topology` walks the inventory, reads each device's interfaces and
neighbours, and stores a graph in SQLite under `~/.netnerd/`. `query_topology`
then answers from the graph instead of re-reading every device.

Edges record **how they are known** — observed over LLDP/CDP, or inferred from a
shared subnet or a routing adjacency — and an inferred edge is labelled as such.
Every answer carries the age of the data behind it.

The point of it is `blast_radius`:

```
query_topology(kind="blast_radius", node="core-sw1", interface="Gi0/1")
→ isolated: ["access-sw4"]
```

`plan_change` runs this automatically for any change that shuts or removes an
interface, so a plan that would cut devices off says so before anything is
applied. When the graph has nothing to say it says *that* — explicitly, rather
than returning an empty result that reads like an all-clear.

## Parsing

`show` parses output into rows where a template exists, and returns the
structured result instead of the raw text. ntc-templates ships with netmiko, so
this works out of the box across roughly a thousand command/platform pairs. The
`parsing` extra adds Genie/pyATS for extra IOS-XE coverage and pulls in several
hundred megabytes — most people don't need it.

Output nothing can parse comes back raw, capped at `NETNERD_MAX_OUTPUT_LINES`
(200). Past that it is returned as `output_excerpt`, never `output` — a partial
result doesn't get to be shaped like a whole one.

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
   A plan that refused itself stays refused at apply time.
3. **Unconfirmed changes revert.** `apply_change` arms the rollback *before*
   pushing, so a change that breaks the path to the device — the case that most
   needs an automatic revert — still gets one. On NETCONF the device runs that
   timer itself.
4. **Rollback tells the truth.** After undoing a change the server re-reads the
   config and compares it to the pre-change backup. If they don't match, you get
   the remaining diff, not a success message.
5. **Blast radius before the push.** A change that shuts an interface reports
   which devices lose reachability, from the topology graph, at plan time.
6. **Destructive commands are refused outright** — `reload`, `write erase`,
   `no username`, `config-register` and friends can't be rolled back by a timer,
   so a human types those.
7. **Command validator** blocks shell injection, enforces the Cisco pipe
   allowlist, and rejects dangerous Linux commands before anything is sent.
8. **Read-only enforcement lives in the SSH driver**, not the tool layer — a tool
   that forgets to check still can't write.

A device refusing a change and a connection dying mid-push are reported as
different things, because they are: one means nothing happened, the other means
the state is unknown.

## Audit trail

Everything from login to logout is recorded, in a form the agent can't summarize
away. Per session, under `~/.netnerd/audit/<date>/`:

- `<session>.log` — the raw SSH transcript, every byte sent and received.
  Netmiko filters the login password and enable secret out of it.
- `<session>.jsonl` — one hash-chained event per action: connects, commands with
  their reasons, blocked attempts, plans, applies, confirms and rollbacks.
  Editing or deleting a line breaks the chain and is detectable.
- `<session>.md` — the end-of-session report: timeline, commands with reasons,
  and every change with what was pushed and whether it stuck.

Set `NETNERD_AUDIT_DIR` to put it somewhere else.

## Development

An FRR lab with an established eBGP session, reachable over real SSH:

```bash
make lab              # two FRR routers, ~30s
make test-unit        # safety gates, audit chain, token logic — no lab needed
make test-integration # drives the lab over real SSH, including the rollback timer
make lab-down
```

`make lab-full` adds two more nodes behind a compose profile: a
[netopeer2](https://github.com/CESNET/netopeer2) NETCONF server and a
[gnxi](https://github.com/google/gnxi) gNMI target, both built from source. They
take a few minutes the first time and are only needed for the NETCONF and gNMI
tests.

The lab exists because mocking an SSH driver proves nothing — real device state
is the whole point. An unconfirmed change reverting is not something a mock can
demonstrate. FRR's `vtysh` presents an IOS-like CLI, so netmiko's stock
`cisco_ios` driver talks to it unmodified.

CI runs the unit suite twice — once on a core install, once with every extra — so
optional dependencies are proven genuinely optional, then runs both labs.

## Status

Alpha. What has been run, and against what:

| | Verified against | Notes |
|---|---|---|
| SSH + CLI | FRR, in CI | reads, writes, timer rollback, audit chain |
| NETCONF | netopeer2, in CI | including confirmed-commit the device enforces itself |
| Topology discovery | FRR, in CI | via shared subnet and BGP/OSPF adjacency |
| gNMI | gnxi target, in CI | Get and bounded telemetry |
| RESTCONF | not yet | written to RFC 8040 |
| Cisco IOS / IOS-XE | not yet | written against it, needs hardware |
| Arista EOS, NX-OS, VyOS | not yet | netmiko supports them; command strings untested |
| Juniper JunOS | not yet | would use NETCONF confirmed-commit |

The lab proves the mechanisms; it can't prove every vendor's interpretation of
them. Two things worth knowing before you lean on them:

- **RESTCONF has not been run against a device.** Nothing in the lab speaks it.
- **gNMI telemetry has not seen a counter move.** The sampling and summarising
  are proven; a moving counter hasn't been observed.

Single operator, one device at a time. Staged fleet rollout, jump hosts,
streamable-HTTP transport and per-engineer auth are next.

Issues and PRs welcome.

## License

MIT
