import { useState } from "react";
import { Link } from "react-router-dom";
import { useCreateGroup, useGroups } from "../../api/hooks";
import { useAuthStore } from "../../store/authStore";
import { groupErrorMessage } from "./groupErrors";

export function GroupList() {
  const groups = useGroups();
  const create = useCreateGroup();
  const isAdmin = useAuthStore((s) => s.role) === "ADMIN";
  const isPlatform = useAuthStore((s) => s.tenantId) === null;
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState("");
  const rows = groups.data ?? [];

  return (
    <div>
      <h1>Groups</h1>
      {isAdmin && !creating && (
        <button type="button" onClick={() => setCreating(true)}>
          New group
        </button>
      )}
      {isAdmin && creating && (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            create.mutate(name, {
              onSuccess: () => {
                setName("");
                setCreating(false);
              },
            });
          }}
        >
          <label>
            Name
            <input value={name} onChange={(e) => setName(e.target.value)} />
          </label>
          <button type="submit" disabled={create.isPending}>
            Create
          </button>
          <button type="button" onClick={() => setCreating(false)}>
            Cancel
          </button>
          {create.isError && <p role="alert">{groupErrorMessage(create.error)}</p>}
        </form>
      )}
      {groups.isLoading && <p>Loading groups…</p>}
      {groups.isError && <p role="alert">Failed to load groups: {groupErrorMessage(groups.error)}</p>}
      {!groups.isLoading && !groups.isError && rows.length === 0 && <p>No groups yet.</p>}
      {rows.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Name</th>
              {isPlatform && <th>Tenant</th>}
              <th>Members</th>
              <th>Created</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((g) => (
              <tr key={g.group_id}>
                <td>
                  <Link to={`/groups/${encodeURIComponent(g.group_id)}`}>{g.name}</Link>
                </td>
                {isPlatform && <td>{g.tenant_id ?? "platform"}</td>}
                <td>{g.member_count}</td>
                <td>{new Date(g.created_at / 1_000_000).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
