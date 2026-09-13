import { fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import * as hooks from "../../api/hooks";
import { IncidentDetailScreen } from "./IncidentDetailScreen";

vi.mock("../../api/hooks");

function mockQueryResult(overrides: Record<string, unknown>) {
  return {
    data: undefined,
    isLoading: false,
    isError: false,
    error: null,
    ...overrides,
  };
}

function mockMutationResult(overrides: Record<string, unknown>) {
  return {
    mutateAsync: vi.fn(),
    isPending: false,
    isError: false,
    error: null,
    ...overrides,
  };
}

function renderAt(incidentId: string) {
  return render(
    <MemoryRouter initialEntries={[`/incidents/${incidentId}`]}>
      <Routes>
        <Route path="/incidents/:incidentId" element={<IncidentDetailScreen />} />
      </Routes>
    </MemoryRouter>
  );
}

describe("IncidentDetailScreen", () => {
  it("shows loading states for incident and evidence", () => {
    vi.mocked(hooks.useIncident).mockReturnValue(mockQueryResult({ isLoading: true }) as ReturnType<typeof hooks.useIncident>);
    vi.mocked(hooks.useEvidence).mockReturnValue(mockQueryResult({ isLoading: true }) as ReturnType<typeof hooks.useEvidence>);
    vi.mocked(hooks.usePatchIncidentStatus).mockReturnValue(mockMutationResult({}) as unknown as ReturnType<typeof hooks.usePatchIncidentStatus>);
    vi.mocked(hooks.useCreateEvidence).mockReturnValue(mockMutationResult({}) as unknown as ReturnType<typeof hooks.useCreateEvidence>);
    renderAt("i1");
    expect(screen.getByText("Loading incident…")).toBeInTheDocument();
    expect(screen.getByText("Loading evidence…")).toBeInTheDocument();
  });

  it("shows the incident's status, entity/alert counts, notes, and evidence once loaded", () => {
    vi.mocked(hooks.useIncident).mockReturnValue(
      mockQueryResult({
        data: {
          incident_id: "i1",
          status: "NEW",
          entities: [{ kind: "IP", addr: "1.2.3.4" }],
          alert_ids: ["a1"],
          notes: ["initial triage note"],
        },
      }) as ReturnType<typeof hooks.useIncident>
    );
    vi.mocked(hooks.useEvidence).mockReturnValue(
      mockQueryResult({
        data: [
          {
            evidence_id: "e1",
            source: "MANUAL_UPLOAD",
            timestamp: 1000,
            integrity: { hash: "abc123", immutable_since: 1000 },
            relationships: [],
            supersedes: null,
          },
        ],
      }) as ReturnType<typeof hooks.useEvidence>
    );
    vi.mocked(hooks.usePatchIncidentStatus).mockReturnValue(mockMutationResult({}) as unknown as ReturnType<typeof hooks.usePatchIncidentStatus>);
    vi.mocked(hooks.useCreateEvidence).mockReturnValue(mockMutationResult({}) as unknown as ReturnType<typeof hooks.useCreateEvidence>);
    renderAt("i1");

    const detail = screen.getByRole("region", { name: "incident detail" });
    expect(within(detail).getByText("NEW")).toBeInTheDocument();
    expect(screen.getByText("initial triage note")).toBeInTheDocument();
    expect(screen.getByText("MANUAL_UPLOAD — abc123")).toBeInTheDocument();
  });

  it("submits a status transition via usePatchIncidentStatus.mutateAsync", async () => {
    vi.mocked(hooks.useIncident).mockReturnValue(
      mockQueryResult({
        data: { incident_id: "i1", status: "NEW", entities: [], alert_ids: [], notes: [] },
      }) as ReturnType<typeof hooks.useIncident>
    );
    vi.mocked(hooks.useEvidence).mockReturnValue(mockQueryResult({ data: [] }) as ReturnType<typeof hooks.useEvidence>);
    const mutateAsync = vi.fn().mockResolvedValue({});
    vi.mocked(hooks.usePatchIncidentStatus).mockReturnValue(
      mockMutationResult({ mutateAsync }) as unknown as ReturnType<typeof hooks.usePatchIncidentStatus>
    );
    vi.mocked(hooks.useCreateEvidence).mockReturnValue(mockMutationResult({}) as unknown as ReturnType<typeof hooks.useCreateEvidence>);
    renderAt("i1");

    screen.getByText("Update status").click();

    await vi.waitFor(() =>
      expect(mutateAsync).toHaveBeenCalledWith({ status: "INVESTIGATING", why: undefined })
    );
  });

  it("submits new evidence via useCreateEvidence.mutateAsync", async () => {
    vi.mocked(hooks.useIncident).mockReturnValue(
      mockQueryResult({
        data: { incident_id: "i1", status: "NEW", entities: [], alert_ids: [], notes: [] },
      }) as ReturnType<typeof hooks.useIncident>
    );
    vi.mocked(hooks.useEvidence).mockReturnValue(mockQueryResult({ data: [] }) as ReturnType<typeof hooks.useEvidence>);
    vi.mocked(hooks.usePatchIncidentStatus).mockReturnValue(mockMutationResult({}) as unknown as ReturnType<typeof hooks.usePatchIncidentStatus>);
    const mutateAsync = vi.fn().mockResolvedValue({});
    vi.mocked(hooks.useCreateEvidence).mockReturnValue(
      mockMutationResult({ mutateAsync }) as unknown as ReturnType<typeof hooks.useCreateEvidence>
    );
    renderAt("i1");

    fireEvent.change(screen.getByLabelText("Evidence hash"), { target: { value: "abc123" } });
    screen.getByText("Add evidence").click();

    await vi.waitFor(() =>
      expect(mutateAsync).toHaveBeenCalledWith(
        expect.objectContaining({ source: "MANUAL_UPLOAD", hash: "abc123", relationships: [], supersedes: null })
      )
    );
  });
});
