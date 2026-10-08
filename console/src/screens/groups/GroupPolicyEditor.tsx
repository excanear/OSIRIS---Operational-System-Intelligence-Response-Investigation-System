import { useState } from "react";
import { ApiError } from "../../api/client";
import { useClearGroupPolicy, useGroupPolicy, useSaveGroupPolicy } from "../../api/hooks";
import { KNOWN_SENSORS, type GroupPolicy, type TelemetryLevel } from "../../api/types";
import { useAuthStore } from "../../store/authStore";

const LEVELS: TelemetryLevel[] = ["MINIMAL", "STANDARD", "DETAILED", "FORENSIC"];

type SensorChoice = "" | "on" | "off";

function errorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    // The client prefixes "PUT /groups/<id>/policy failed with status 400: ";
    // the operator only needs the server's own message.
    if (error.status === 400) return error.message.replace(/^[A-Z]+ \S+ failed with status 400: /, "");
    if (error.status === 403) return "You do not have permission to change policies.";
    if (error.status === 404) return "Group not found.";
  }
  return error instanceof Error ? error.message : "Request failed.";
}

function PolicySummary({ policy }: { policy: GroupPolicy | null }) {
  if (!policy) return <p>No policy</p>;
  return (
    <dl>
      <dt>Telemetry level</dt>
      <dd>{policy.telemetry_level ?? "Not set"}</dd>
      {KNOWN_SENSORS.map((name) => (
        <div key={name}>
          <dt>Sensor {name}</dt>
          <dd>{name in policy.sensors ? (policy.sensors[name] ? "On" : "Off") : "Not set"}</dd>
        </div>
      ))}
      <dt>Heartbeat (seconds)</dt>
      <dd>{policy.heartbeat_interval_secs ?? "Not set"}</dd>
      <dt>Priority</dt>
      <dd>{policy.priority}</dd>
    </dl>
  );
}

function PolicyForm({
  groupId,
  memberCount,
  policy,
}: {
  groupId: string;
  memberCount: number;
  policy: GroupPolicy | null;
}) {
  const save = useSaveGroupPolicy(groupId);
  const clear = useClearGroupPolicy(groupId);
  const [level, setLevel] = useState<string>(policy?.telemetry_level ?? "");
  const [sensors, setSensors] = useState<Record<string, SensorChoice>>(() =>
    Object.fromEntries(
      KNOWN_SENSORS.map((n) => [
        n,
        policy && n in policy.sensors ? (policy.sensors[n] ? "on" : "off") : "",
      ])
    )
  );
  const [heartbeat, setHeartbeat] = useState(policy?.heartbeat_interval_secs?.toString() ?? "");
  const [priority, setPriority] = useState((policy?.priority ?? 0).toString());
  const [confirming, setConfirming] = useState(false);

  const build = (): GroupPolicy => {
    const out: GroupPolicy = { sensors: {}, priority: Number(priority) || 0 };
    if (level) out.telemetry_level = level as TelemetryLevel;
    for (const [name, choice] of Object.entries(sensors)) {
      if (choice) out.sensors[name] = choice === "on";
    }
    if (heartbeat.trim() !== "") out.heartbeat_interval_secs = Number(heartbeat);
    return out;
  };
  const reducesVisibility = (p: GroupPolicy) =>
    p.telemetry_level === "MINIMAL" || Object.values(p.sensors).some((enabled) => !enabled);

  const submit = (confirmed: boolean) => {
    const next = build();
    if (!confirmed && reducesVisibility(next)) {
      setConfirming(true);
      return;
    }
    clear.reset();
    save.mutate(next, { onSuccess: () => setConfirming(false) });
  };
  const error = save.error ?? clear.error;

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        submit(false);
      }}
    >
      <label>
        Telemetry level
        <select aria-label="Telemetry level" value={level} onChange={(e) => setLevel(e.target.value)}>
          <option value="">Not set</option>
          {LEVELS.map((l) => (
            <option key={l} value={l}>
              {l}
            </option>
          ))}
        </select>
      </label>
      {KNOWN_SENSORS.map((name) => (
        <label key={name}>
          {name}
          <select
            aria-label={`Sensor ${name}`}
            value={sensors[name]}
            onChange={(e) => setSensors({ ...sensors, [name]: e.target.value as SensorChoice })}
          >
            <option value="">Not set</option>
            <option value="on">On</option>
            <option value="off">Off</option>
          </select>
        </label>
      ))}
      <label>
        Heartbeat
        <input
          aria-label="Heartbeat (seconds)"
          type="number"
          value={heartbeat}
          onChange={(e) => setHeartbeat(e.target.value)}
        />
      </label>
      <label>
        Priority
        <input
          aria-label="Priority"
          type="number"
          value={priority}
          onChange={(e) => setPriority(e.target.value)}
        />
      </label>
      {confirming ? (
        <div>
          <p>This reduces visibility on {memberCount} hosts.</p>
          <button type="button" onClick={() => submit(true)}>
            Confirm save
          </button>
          <button type="button" onClick={() => setConfirming(false)}>
            Cancel
          </button>
        </div>
      ) : (
        <button type="submit">Save policy</button>
      )}
      <button
        type="button"
        onClick={() => {
          save.reset();
          setConfirming(false);
          clear.mutate();
        }}
      >
        Remove policy
      </button>
      {error && <p role="alert">{errorMessage(error)}</p>}
    </form>
  );
}

export function GroupPolicyEditor({ groupId, memberCount }: { groupId: string; memberCount: number }) {
  const isAdmin = useAuthStore((s) => s.role) === "ADMIN";
  const query = useGroupPolicy(groupId);
  const policy = query.data?.policy ?? null;

  let body;
  if (query.isLoading) body = <p>Loading policy…</p>;
  else if (query.isError) body = <p role="alert">{errorMessage(query.error)}</p>;
  else if (isAdmin)
    // Re-key on the stored value so the form resets after a save or removal.
    body = (
      <PolicyForm
        key={JSON.stringify(policy)}
        groupId={groupId}
        memberCount={memberCount}
        policy={policy}
      />
    );
  else body = <PolicySummary policy={policy} />;

  return (
    <section>
      <h2>Policy</h2>
      {body}
    </section>
  );
}
