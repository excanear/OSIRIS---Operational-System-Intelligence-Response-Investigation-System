# Operator guide: response actions (Phase 9c-1)

The Server can make an enrolled Agent terminate a process or quarantine (and
restore) a file. Commands are signed by the Server, travel over a dedicated
mTLS control connection that the Agent dials, and are verified by the Agent
before anything is executed. Every attempt is audited.

## 1. Enabling

1. Create the PKI (`osiris pki init-ca`, `issue-server`, `issue-agent <host_id>`).
2. Create the command signing key pair on the **Server** host:

   ```
   osiris pki init-command-key --dir pki --name command
   ```

   This writes `pki/command.key` (private) and `pki/command.pub` (public) and
   prints the agent config line `command_public_key: pki/command.pub`.
3. Server `server.yaml`:

   ```yaml
   control:
     listen_addr: 0.0.0.0:7443
     cert: pki/server.pem
     key: pki/server.key
     client_ca: pki/ca.pem
     command_signing_key: pki/command.key
     command_timeout_secs: 30      # 1..=110
     revoked_hosts: []             # host ids refused on the control channel
   ```
4. Agent `agent.yaml` (copy only `command.pub` to the Agent):

   ```yaml
   control:
     server_addr: server.example:7443
     server_name: server.example
     ca: pki/ca.pem
     cert: pki/agent-<host_id>.pem
     key: pki/agent-<host_id>.key
     command_public_key: pki/command.pub
     vault_dir: /var/lib/osiris/vault
   ```

If either side omits `control`, the feature is disabled there. If the Agent
cannot load `command_public_key` it fails closed and does not connect.

### The private key

The private signing key lives **only on the Server** and must never be copied
to an Agent. It is written mode 0600 on Linux. On Windows it inherits the
directory ACL and no warning is shown: restrict the directory yourself.

## 2. Actions

Run with a session of role RESPONSE_OPERATOR or higher
(`osiris auth login <user>` first). `--reason` is mandatory. `--dry-run`
validates without acting.

```
osiris response terminate-process --pid-target <process_key_hex> --reason "..." [--dry-run]
osiris response quarantine-file   --file <inode>:<device_id>:<host_uuid> --reason "..." [--dry-run]
osiris response restore-file      --host <host_uuid> --quarantine-id <uuid> --reason "..." [--dry-run]
```

* **terminate-process**: the Server resolves the process from stored events
  and sends pid, exe path and observation time. The Agent confirms
  `/proc/<pid>/exe` matches and the process did not start after the
  observation (pid-reuse defence), then sends SIGKILL. **Termination is
  irreversible.**
* **quarantine-file**: moves the file into the Agent's vault and reports a
  `quarantine_id`. Keep it; it is required to restore.
* **restore-file**: takes `--host` and `--quarantine-id` only (a target is
  rejected with 422). To restore: find the quarantine id in the audit log or
  the quarantine command output, then run `restore-file` for that host.

### Protected targets (built in, not configurable)

pid 1, the Agent's own pid and its ancestors, the quarantine vault, and
kernel threads are refused. Refusals return 422.

### Dry-run

A dry-run burns the command id (ids are single use, enforced by the Agent's
replay store even for dry-runs). To perform the real action after a dry-run
you must issue a fresh command; the CLI does this automatically since each
invocation creates a new command. With the Agent offline or control disabled,
a dry-run returns a server-side preview with `agent_validated: false` (HTTP
200, not 409): it did not check the target on the Agent.

## 3. Offline behaviour

There is no queueing. If the target Agent is not connected the API answers 409
(`agent_offline`, or `control_disabled`) and nothing is sent. Retry when the
Agent is back.

## 4. Status codes

| Code | Meaning |
|------|---------|
| 200  | Executed (`ok: true`), or the Agent tried and failed (`ok: false` with a `code`), or a dry-run result |
| 409  | Agent offline or control channel disabled (nothing sent) |
| 422  | Invalid request, protected target, unresolved target, or Agent refused verification |
| 502  | Dispatch error (could not hand the command to the control hub) |
| 504  | Timed out waiting for the Agent (see below) |
| 401/403/404 | Not authenticated / role too low / tenant scoping (unknown or foreign target) |

### 504 never means "not executed"

The command's validity window is the timeout plus 5 s, the Agent may still
execute it after the Server gave up, Agent clock skew extends the validity,
and the real staleness window can reach 120 s. **Verify the state on the host
(process gone? file quarantined?) before retrying.** The audit entry records
the outcome as unknown.

## 5. Limits and caveats

* `control.max_connections` and `control.max_connections_per_ip` are
  **RESERVED**: accepted and validated but not enforced. The control listener
  applies fixed caps of 1024 connections and 16 per IP. (The `api_tls` fields
  with the same names are enforced.)
* A symlinked `vault_dir` is refused; the control channel is not started for
  that deployment. Use a real directory.
* `revoked_hosts` is a bind-time snapshot: revoking a host does not kill its
  live control connections. Restart the Server (or wait for the Agent to
  reconnect) for it to take effect.
* The Linux executor code has not yet been compiled or tested on real Linux
  (development was on Windows, where a stub runs). Validate on a Linux test
  host before relying on it.
