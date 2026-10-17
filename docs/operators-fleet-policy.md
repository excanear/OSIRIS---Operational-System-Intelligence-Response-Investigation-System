# Operator guide: fleet policy distribution (Phase 9d-3)

An operator attaches a policy to a host group. The Server resolves, for every
host, the effective policy from all the groups the host belongs to, sends it to
the Agent as a signed `ApplyPolicy` command over the control channel (see
`operators-response-actions.md`), and the Agent applies it live, persists it,
and reports what it runs in every heartbeat.

Policy distribution needs the control channel (`control:` in `server.yaml`
and `control:` in `agent.yaml`). Without it nothing is sent.

## 1. Policy fields

| Field | Meaning |
|---|---|
| `telemetry_level` | `MINIMAL`, `STANDARD`, `DETAILED` or `FORENSIC`. Events outside the level are dropped on the Agent before they reach the bus (counted in `events_dropped_by_policy`). Unset = no filtering (today's behaviour). |
| `sensors` | Map of sensor name to `true`/`false`. `false` stops the sensor; `true` (re)starts it. Known names: `container`, `filesystem`, `identity`, `network`, `persistence`, `process_exec`, `systemd`. An unknown name is rejected (`unknown sensor: <name>`). |
| `heartbeat_interval_secs` | Interval of the Agent's `AGENT_HEALTH` heartbeat, `10..=3600`. Unset = `fleet.health_interval_secs` from `agent.yaml`. |
| `priority` | Integer, default 0. Higher wins when groups conflict (see precedence). |

A policy with no field set is valid but does nothing; use `clear` to remove a
policy.

A sensor only runs if `agent.yaml` configures it. A policy that enables a
sensor `agent.yaml` does not configure is not an error: the sensor simply stays
unavailable. A policy can switch off a configured sensor, never add one.

## 2. Telemetry levels

Levels are cumulative. `AgentHealth`, `SensorHealth`, `AgentStart` and
`AgentStop` are always allowed at every level and are never filtered.

- **Minimal:** `ProcessExec`, `ProcessExit`, `PrivilegeUidChange`, `PrivilegeGidChange`, `PrivilegeCapabilityChange`, `PrivilegeSudo`, `PrivilegeSetuid`, `SessionLogin`, `SessionLogout`, `PersistenceCreated`, `PersistenceModified`, `PersistenceRemoved`, `ServiceCreate`, `ServiceModify`, `ServiceDelete`, `ModuleLoad`, `ModuleUnload`, `ContainerCreate`, `ContainerStart`, `ContainerStop`, `ContainerDestroy`, `LsmDenial`.
- **Standard:** Minimal + `ProcessFork`, `SessionCreate`, `SessionTerminate`, `ServiceStart`, `ServiceStop`, `TimerCreate`, `TimerModify`, `NetworkConnect`, `NetworkAccept`, `NetworkClose`, `DnsQuery`, `FileCreate`, `FileDelete`, `FileRename`, `FileMove`, `FileExecute`, `FilePermissionChange`, `FileOwnerChange`.
- **Detailed:** Standard + `FileModify`, `FileWrite`, `FileAttributeChange`, `SocketCreate`, `SocketBind`, `SocketListen`, `CapabilityUse`.
- **Forensic:** every event type.

Fields follow the same ladder: a process's argv (`process.cmdline`) is
Standard data, so at Minimal a `ProcessExec` event is still sent but with an
empty `cmdline`. The Agent keeps at most 128 arguments and 16 KiB of argv
per exec (a longer argv is cut to that prefix).

With no `telemetry_level` set, the Agent sends the full argv (the filter is off, so
argv is included). Argv can contain secrets, such as passwords or tokens passed on a
command line, and the Agent does no redaction. Set the level to `MINIMAL` to stop
argv from leaving the host.

Lowering the level or switching a sensor off reduces visibility: detections
that depend on the dropped events stop firing for those hosts.

## 3. Precedence

A host can be in several groups. The effective policy is resolved like this:

1. Tenant groups whose tenant differs from the host's current tenant are
   ignored (stale membership after a host was reassigned). Platform groups
   always count.
2. Groups are ordered platform tier first, then tenant tier (a platform policy
   always beats a tenant policy). Within a tier, higher `priority` first, then
   lower `group_id` as the tie-break.
3. Each field is resolved independently: the level, each sensor name, and the
   heartbeat each take the value from the first group in that order that
   defines it.

`osiris hosts policy <host_id>` (and `GET /api/v1/hosts/:host_id/policy`) shows
the winning value and its source group for every field. Tenant callers see a
platform source only as `{"tier": "PLATFORM"}`, without the group id or name.

## 4. Status

| Status | Meaning |
|---|---|
| `IN_SYNC` | The hash the Agent reported in its last heartbeat equals the desired hash. A heartbeat with no policy hash means "no policy" (the empty-policy hash), so a host with no policy is `IN_SYNC` too. |
| `PENDING` | The Agent runs something else and no failed delivery is recorded for the current desired policy; the Server sends it (on policy change, membership change, or the next heartbeat). Resends of the same policy to one host are at least 60 s apart. |
| `FAILED` | The last delivery of the current desired policy was refused or failed on the Agent; the error is in `last_delivery`. |
| `UNMANAGED` | The Server has no control channel configured (no `control:` in `server.yaml`), so it sends nothing. This is a server-side condition: every host reads `UNMANAGED`. |

An Agent without `control:` in `agent.yaml`, under a Server that has the control
channel, never receives or applies the policy. Its heartbeats keep reporting no
policy hash, so it shows `PENDING` for as long as a policy is desired for it
(not `UNMANAGED`). Add the `control:` section to the Agent to fix it.

Agents older than 9d-3 cannot decode a policy command, and receiving one would
drop their control connection. They do not send a policy hash in their
heartbeat, and the Server never sends them a policy. Such a host shows
`PENDING`, with no delivery recorded, for as long as a policy is desired for it.
It shows `IN_SYNC` when no policy applies. Upgrade the Agent to apply the policy.

The applied hash is only learned from the next heartbeat, so `IN_SYNC` appears
after up to one heartbeat interval. A policy that sets
`heartbeat_interval_secs: 10` is therefore confirmed within about 10 s.

## 5. Agent overlay file

The Agent stores the policy it was last sent in `{spool_path}.policy.json`
(next to the spool, mode 0600 on Unix, written atomically). It is loaded before
any sensor starts, so a restarted Agent enforces its policy immediately, even
while the Server is unreachable. An empty policy deletes the file.

Deleting the file by hand is safe: the Agent then runs on `agent.yaml` alone,
reports "no policy" in its next heartbeat, the Server sees the mismatch and
re-sends the policy. A corrupt file is logged as an error, ignored, and treated
the same way.

## 6. CLI

```
osiris groups policy show <group_id>
osiris groups policy set <group_id> --level minimal --sensor network=off --heartbeat 30
osiris groups policy set <group_id> --level standard --sensor filesystem=on --sensor network=off --priority 5
osiris groups policy clear <group_id>
osiris hosts policy <host_id>
```

`set` replaces the whole policy: fields not given become unset. Setting and
clearing a policy require the Admin role and are audited (`group_policy_set`,
`group_policy_clear`); viewing needs Viewer. The Console offers the same under
a group's Policy section and a host's policy view.
