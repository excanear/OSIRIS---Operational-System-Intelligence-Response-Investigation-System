import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import * as hooks from "../../api/hooks";
import { IncidentList } from "./IncidentList";

vi.mock("../../api/hooks");

function mockQueryResult(overrides: Record<string, unknown>) {
  return {
    data: undefined,
    isLoading: false,
    isError: false,
    error: null,
    ...overrides,
  } as ReturnType<typeof hooks.useIncidents>;
}

function mockMutationResult(overrides: Record<string, unknown>) {
  return {
    mutateAsync: vi.fn(),
    isPending: false,
    isError: false,
    error: null,
    ...overrides,
  } as unknown as ReturnType<typeof hooks.useCreateIncident>;
}

function renderWithRouter() {
  return render(
    <MemoryRouter>
      <IncidentList />
    </MemoryRouter>
  );
}

describe("IncidentList", () => {
  it("shows a loading state", () => {
    vi.mocked(hooks.useIncidents).mockReturnValue(mockQueryResult({ isLoading: true }));
    vi.mocked(hooks.useCreateIncident).mockReturnValue(mockMutationResult({}));
    renderWithRouter();
    expect(screen.getByText("Loading incidents…")).toBeInTheDocument();
  });

  it("shows an empty state", () => {
    vi.mocked(hooks.useIncidents).mockReturnValue(mockQueryResult({ data: [] }));
    vi.mocked(hooks.useCreateIncident).mockReturnValue(mockMutationResult({}));
    renderWithRouter();
    expect(screen.getByText("No incidents found.")).toBeInTheDocument();
  });

  it("renders a row per incident, linking to its detail route", () => {
    vi.mocked(hooks.useIncidents).mockReturnValue(
      mockQueryResult({
        data: [{ incident_id: "i1", status: "NEW", entities: [{ kind: "IP", addr: "1.2.3.4" }], alert_ids: [], notes: [] }],
      })
    );
    vi.mocked(hooks.useCreateIncident).mockReturnValue(mockMutationResult({}));
    renderWithRouter();

    const link = screen.getByRole("link", { name: "NEW" });
    expect(link).toHaveAttribute("href", "/incidents/i1");
  });

  it("submits the entity rows via useCreateIncident.mutateAsync", async () => {
    vi.mocked(hooks.useIncidents).mockReturnValue(mockQueryResult({ data: [] }));
    const mutateAsync = vi.fn().mockResolvedValue({ incident_id: "i1", status: "NEW", entities: [], alert_ids: [], notes: [] });
    vi.mocked(hooks.useCreateIncident).mockReturnValue(mockMutationResult({ mutateAsync }));
    renderWithRouter();

    fireEvent.change(screen.getByLabelText("Entity 1 value"), { target: { value: "203.0.113.10" } });
    screen.getByText("Create incident").click();

    await vi.waitFor(() => expect(mutateAsync).toHaveBeenCalledWith([{ kind: "IP", addr: "203.0.113.10" }]));
  });

  it("disables the submit button when all entity rows are blank, enabling once a row has a value", () => {
    vi.mocked(hooks.useIncidents).mockReturnValue(mockQueryResult({ data: [] }));
    vi.mocked(hooks.useCreateIncident).mockReturnValue(mockMutationResult({}));
    renderWithRouter();

    const submitButton = screen.getByText("Create incident");
    expect(submitButton).toBeDisabled();

    fireEvent.change(screen.getByLabelText("Entity 1 value"), { target: { value: "203.0.113.10" } });

    expect(submitButton).not.toBeDisabled();
  });
});
