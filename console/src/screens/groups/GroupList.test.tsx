import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import * as hooks from "../../api/hooks";
import { ApiError } from "../../api/client";
import { useAuthStore } from "../../store/authStore";
import { GroupList } from "./GroupList";

vi.mock("../../api/hooks");

function query(overrides: Record<string, unknown>) {
  return { data: undefined, isLoading: false, isError: false, error: null, ...overrides } as never;
}

function mutation(overrides: Record<string, unknown> = {}) {
  return { mutate: vi.fn(), isPending: false, isError: false, error: null, ...overrides };
}

const group = { group_id: "g1", name: "web", tenant_id: null, created_at: 1_000_000, member_count: 2 };

function renderList() {
  return render(
    <MemoryRouter>
      <GroupList />
    </MemoryRouter>
  );
}

describe("GroupList", () => {
  beforeEach(() => {
    useAuthStore.setState({ role: "ADMIN", tenantId: null });
    vi.mocked(hooks.useCreateGroup).mockReturnValue(mutation() as never);
  });

  it("shows a loading state", () => {
    vi.mocked(hooks.useGroups).mockReturnValue(query({ isLoading: true }));
    renderList();
    expect(screen.getByText("Loading groups…")).toBeInTheDocument();
  });

  it("shows an error state", () => {
    vi.mocked(hooks.useGroups).mockReturnValue(query({ isError: true, error: new Error("boom") }));
    renderList();
    expect(screen.getByRole("alert")).toHaveTextContent("boom");
  });

  it("shows an empty state", () => {
    vi.mocked(hooks.useGroups).mockReturnValue(query({ data: [] }));
    renderList();
    expect(screen.getByText("No groups yet.")).toBeInTheDocument();
  });

  it("links each group to its detail and shows a Tenant column to platform users", () => {
    vi.mocked(hooks.useGroups).mockReturnValue(query({ data: [group] }));
    renderList();
    expect(screen.getByRole("link", { name: "web" })).toHaveAttribute("href", "/groups/g1");
    expect(screen.getByRole("columnheader", { name: "Tenant" })).toBeInTheDocument();
    expect(screen.getByText("platform")).toBeInTheDocument();
    expect(screen.getByText("2")).toBeInTheDocument();
  });

  it("hides the Tenant column from tenant users", () => {
    useAuthStore.setState({ role: "ADMIN", tenantId: "t1" });
    vi.mocked(hooks.useGroups).mockReturnValue(query({ data: [group] }));
    renderList();
    expect(screen.queryByRole("columnheader", { name: "Tenant" })).not.toBeInTheDocument();
  });

  it("lets an Admin create a group", () => {
    const create = mutation();
    vi.mocked(hooks.useCreateGroup).mockReturnValue(create as never);
    vi.mocked(hooks.useGroups).mockReturnValue(query({ data: [] }));
    renderList();
    fireEvent.click(screen.getByRole("button", { name: "New group" }));
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "db" } });
    fireEvent.click(screen.getByRole("button", { name: "Create" }));
    expect(create.mutate).toHaveBeenCalledWith("db", expect.anything());
  });

  it("shows the duplicate-name message on a 409", () => {
    vi.mocked(hooks.useCreateGroup).mockReturnValue(
      mutation({ isError: true, error: new ApiError(409, "x") }) as never
    );
    vi.mocked(hooks.useGroups).mockReturnValue(query({ data: [] }));
    renderList();
    fireEvent.click(screen.getByRole("button", { name: "New group" }));
    expect(screen.getByRole("alert")).toHaveTextContent("A group with this name already exists.");
  });

  it("hides New group from non-Admins", () => {
    useAuthStore.setState({ role: "VIEWER", tenantId: null });
    vi.mocked(hooks.useGroups).mockReturnValue(query({ data: [] }));
    renderList();
    expect(screen.queryByRole("button", { name: "New group" })).not.toBeInTheDocument();
  });
});
