import { useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import {
  useAddGroupMember,
  useDeleteGroup,
  useGroup,
  useHosts,
  useRemoveGroupMember,
  useRenameGroup,
} from "../../api/hooks";
import { ApiError } from "../../api/client";
import { useAuthStore } from "../../store/authStore";
import { groupErrorMessage } from "./groupErrors";

export function GroupDetail() {
  const { groupId = "" } = useParams();
  const navigate = useNavigate();
  const group = useGroup(groupId);
  const hosts = useHosts();
  const rename = useRenameGroup(groupId);
  const del = useDeleteGroup(groupId);
  const add = useAddGroupMember(groupId);
  const remove = useRemoveGroupMember(groupId);
  const isAdmin = useAuthStore((s) => s.role) === "ADMIN";
  const [editing, setEditing] = useState(false);
  const [newName, setNewName] = useState("");
  const [confirmingDelete, setConfirmingDelete] = useState(false);
  const [hostToAdd, setHostToAdd] = useState("");

  if (group.isLoading) return <p>Loading group…</p>;
  if (group.isError) {
    const notFound = group.error instanceof ApiError && group.error.status === 404;
    return <p role="alert">{notFound ? "Group not found." : groupErrorMessage(group.error)}</p>;
  }
  const g = group.data;
  if (!g) return null;
  const memberIds = new Set(g.members.map((m) => m.host_id));
  const candidates = (hosts.data ?? []).filter((h) => !memberIds.has(h.host_id));
  const mutationError = rename.error ?? del.error ?? add.error ?? remove.error;

  return (
    <div>
      {!editing && <h1>{g.name}</h1>}
      {isAdmin && !editing && (
        <button
          type="button"
          onClick={() => {
            setNewName(g.name);
            setEditing(true);
          }}
        >
          Rename
        </button>
      )}
      {editing && (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            rename.mutate(newName, { onSuccess: () => setEditing(false) });
          }}
        >
          <label>
            Name
            <input value={newName} onChange={(e) => setNewName(e.target.value)} />
          </label>
          <button type="submit">Save</button>
          <button type="button" onClick={() => setEditing(false)}>
            Cancel
          </button>
        </form>
      )}
      {isAdmin && !confirmingDelete && (
        <button type="button" onClick={() => setConfirmingDelete(true)}>
          Delete
        </button>
      )}
      {isAdmin && confirmingDelete && (
        <div>
          <p>Delete group {g.name}?</p>
          <button type="button" onClick={() => del.mutate(undefined, { onSuccess: () => navigate("/groups") })}>
            Confirm delete
          </button>
          <button type="button" onClick={() => setConfirmingDelete(false)}>
            Cancel
          </button>
        </div>
      )}
      {mutationError && <p role="alert">{groupErrorMessage(mutationError)}</p>}

      <h2>Members ({g.member_count})</h2>
      {g.members.length === 0 && <p>No members.</p>}
      {g.members.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Hostname</th>
              <th>Status</th>
              <th>Agent version</th>
              <th>Last Seen</th>
              {isAdmin && <th />}
            </tr>
          </thead>
          <tbody>
            {g.members.map((m) => (
              <tr key={m.host_id}>
                <td>{m.hostname}</td>
                <td>{m.status}</td>
                <td>{m.agent_version}</td>
                <td>{new Date(m.last_seen / 1_000_000).toLocaleString()}</td>
                {isAdmin && (
                  <td>
                    <button type="button" onClick={() => remove.mutate(m.host_id)}>
                      Remove
                    </button>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {isAdmin && (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (hostToAdd) add.mutate(hostToAdd, { onSuccess: () => setHostToAdd("") });
          }}
        >
          <label>
            Add host
            <select value={hostToAdd} onChange={(e) => setHostToAdd(e.target.value)}>
              <option value="">Select a host…</option>
              {candidates.map((h) => (
                <option key={h.host_id} value={h.host_id}>
                  {h.hostname}
                </option>
              ))}
            </select>
          </label>
          <button type="submit" disabled={!hostToAdd}>
            Add
          </button>
        </form>
      )}
    </div>
  );
}
