import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import * as hooks from "../../api/hooks";
import { ApiError } from "../../api/client";
import { useAuthStore } from "../../store/authStore";
import { GroupDetail } from "./GroupDetail";

vi.mock("../../api/hooks");

function query(overrides: Record<string, unknown>) {
  return { data: undefined, isLoading: false, isError: false, error: null, ...overrides } as never;
}

function mutation() {
  return { mutate: vi.fn(), reset: vi.fn(), isPending: false, isError: false, error: null };
}

const detail = {
  group_id: "g1",
  name: "web",
  tenant_id: null,
  created_at: 1,
  member_count: 1,
  members: [
    { host_id: "h1", hostname: "web-1", status: "ONLINE", agent_version: "0.1.0", last_seen: 1_000_000 },
  ],
};

const host = (host_id: string, hostname: string) => ({
  host_id,
  hostname,
  distro: "d",
  kernel_version: "k",
  agent_version: "0.1.0",
  enrolled_at: 1,
  last_seen: 1,
  status: "ONLINE",
  cloud_provider: null,
  cloud_instance_id: null,
  cloud_region: null,
  groups: [],
});

function setup(role: "ADMIN" | "VIEWER" = "ADMIN", groupResult = query({ data: detail })) {
  useAuthStore.setState({ role, tenantId: null });
  const m = { rename: mutation(), del: mutation(), add: mutation(), remove: mutation() };
  vi.mocked(hooks.useGroup).mockReturnValue(groupResult);
  vi.mocked(hooks.useHosts).mockReturnValue(query({ data: [host("h1", "web-1"), host("h2", "db-1")] }));
  vi.mocked(hooks.useRenameGroup).mockReturnValue(m.rename as never);
  vi.mocked(hooks.useDeleteGroup).mockReturnValue(m.del as never);
  vi.mocked(hooks.useAddGroupMember).mockReturnValue(m.add as never);
  vi.mocked(hooks.useRemoveGroupMember).mockReturnValue(m.remove as never);
  render(
    <MemoryRouter initialEntries={["/groups/g1"]}>
      <Routes>
        <Route path="/groups/:groupId" element={<GroupDetail />} />
      </Routes>
    </MemoryRouter>
  );
  return m;
}

describe("GroupDetail", () => {
  it("shows Group not found on a 404", () => {
    setup("ADMIN", query({ isError: true, error: new ApiError(404, "x") }));
    expect(screen.getByRole("alert")).toHaveTextContent("Group not found.");
  });

  it("lists members and lets an Admin remove one", () => {
    const m = setup();
    expect(screen.getByText("web-1")).toBeInTheDocument();
    expect(screen.getByText("ONLINE")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Remove" }));
    expect(m.remove.mutate).toHaveBeenCalledWith("h1");
  });

  it("offers only non-members in Add host", () => {
    const m = setup();
    expect(screen.getByRole("option", { name: "db-1" })).toBeInTheDocument();
    expect(screen.queryByRole("option", { name: "web-1" })).not.toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Add host"), { target: { value: "h2" } });
    fireEvent.click(screen.getByRole("button", { name: "Add" }));
    expect(m.add.mutate).toHaveBeenCalledWith("h2", expect.anything());
  });

  it("renames", () => {
    const m = setup();
    fireEvent.click(screen.getByRole("button", { name: "Rename" }));
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "frontend" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(m.rename.mutate).toHaveBeenCalledWith("frontend", expect.anything());
  });

  it("asks for confirmation before deleting", () => {
    const m = setup();
    fireEvent.click(screen.getByRole("button", { name: "Delete" }));
    expect(m.del.mutate).not.toHaveBeenCalled();
    expect(screen.getByText("Delete group web?")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Confirm delete" }));
    expect(m.del.mutate).toHaveBeenCalled();
  });

  it("resets other mutations' errors when a new mutation starts, so a stale error banner does not persist", () => {
    const m = setup();
    // Simulate Add having already failed (its `error` sticks around until
    // it is reset or run again).
    m.add.error = new ApiError(422, "unknown host") as never;
    fireEvent.click(screen.getByRole("button", { name: "Remove" }));
    expect(m.add.reset).toHaveBeenCalled();
    expect(m.del.reset).toHaveBeenCalled();
    expect(m.rename.reset).toHaveBeenCalled();
    expect(m.remove.reset).not.toHaveBeenCalled();
  });

  it("is read-only for non-Admins", () => {
    setup("VIEWER");
    for (const name of ["Rename", "Delete", "Remove", "Add"]) {
      expect(screen.queryByRole("button", { name })).not.toBeInTheDocument();
    }
    expect(screen.queryByLabelText("Add host")).not.toBeInTheDocument();
  });
});
