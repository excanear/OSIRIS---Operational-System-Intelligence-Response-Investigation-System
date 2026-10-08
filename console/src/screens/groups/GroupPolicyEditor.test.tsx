import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import * as hooks from "../../api/hooks";
import { ApiError } from "../../api/client";
import type { GroupPolicy } from "../../api/types";
import { useAuthStore } from "../../store/authStore";
import { GroupPolicyEditor } from "./GroupPolicyEditor";

vi.mock("../../api/hooks");

function mutation() {
  return { mutate: vi.fn(), reset: vi.fn(), isPending: false, isError: false, error: null as unknown };
}

function setup(
  role: "ADMIN" | "VIEWER",
  policy: GroupPolicy | null,
  opts: { saveError?: unknown } = {}
) {
  useAuthStore.setState({ role, tenantId: null });
  const save = mutation();
  save.error = opts.saveError ?? null;
  const clear = mutation();
  vi.mocked(hooks.useGroupPolicy).mockReturnValue({
    data: { policy },
    isLoading: false,
    isError: false,
    error: null,
  } as never);
  vi.mocked(hooks.useSaveGroupPolicy).mockReturnValue(save as never);
  vi.mocked(hooks.useClearGroupPolicy).mockReturnValue(clear as never);
  render(<GroupPolicyEditor groupId="g1" memberCount={3} />);
  return { save, clear };
}

describe("GroupPolicyEditor", () => {
  it("renders existing policy values into the controls", () => {
    setup("ADMIN", {
      telemetry_level: "DETAILED",
      sensors: { network: false, process_exec: true },
      heartbeat_interval_secs: 30,
      priority: 5,
    });
    expect(screen.getByLabelText("Telemetry level")).toHaveValue("DETAILED");
    expect(screen.getByLabelText("Sensor network")).toHaveValue("off");
    expect(screen.getByLabelText("Sensor process_exec")).toHaveValue("on");
    expect(screen.getByLabelText("Sensor systemd")).toHaveValue("");
    expect(screen.getByLabelText("Heartbeat (seconds)")).toHaveValue(30);
    expect(screen.getByLabelText("Priority")).toHaveValue(5);
  });

  it("saves a Standard-level policy immediately", () => {
    const m = setup("ADMIN", null);
    fireEvent.change(screen.getByLabelText("Telemetry level"), { target: { value: "STANDARD" } });
    fireEvent.click(screen.getByRole("button", { name: "Save policy" }));
    expect(m.save.mutate).toHaveBeenCalledWith(
      { telemetry_level: "STANDARD", sensors: {}, priority: 0 },
      expect.anything()
    );
  });

  it("warns before turning a sensor off and saves only on Confirm save", () => {
    const m = setup("ADMIN", null);
    fireEvent.change(screen.getByLabelText("Sensor network"), { target: { value: "off" } });
    fireEvent.click(screen.getByRole("button", { name: "Save policy" }));
    expect(screen.getByText("This reduces visibility on 3 hosts.")).toBeInTheDocument();
    expect(m.save.mutate).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Confirm save" }));
    expect(m.save.mutate).toHaveBeenCalledWith(
      { sensors: { network: false }, priority: 0 },
      expect.anything()
    );
  });

  it("warns before setting the level to MINIMAL, and Cancel aborts", () => {
    const m = setup("ADMIN", null);
    fireEvent.change(screen.getByLabelText("Telemetry level"), { target: { value: "MINIMAL" } });
    fireEvent.click(screen.getByRole("button", { name: "Save policy" }));
    expect(screen.getByText("This reduces visibility on 3 hosts.")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(m.save.mutate).not.toHaveBeenCalled();
    expect(screen.queryByText(/reduces visibility/)).not.toBeInTheDocument();
  });

  it("Remove policy calls the clear mutation", () => {
    const m = setup("ADMIN", { sensors: {}, priority: 0, telemetry_level: "STANDARD" });
    fireEvent.click(screen.getByRole("button", { name: "Remove policy" }));
    expect(m.clear.mutate).toHaveBeenCalled();
  });

  it("is read-only for a Viewer, with No policy when none is set", () => {
    setup("VIEWER", null);
    expect(screen.getByText("No policy")).toBeInTheDocument();
    expect(screen.queryByRole("combobox")).not.toBeInTheDocument();
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });

  it("shows a Viewer the existing policy as text", () => {
    setup("VIEWER", { telemetry_level: "FORENSIC", sensors: { network: true }, priority: 2 });
    expect(screen.getByText("FORENSIC")).toBeInTheDocument();
    expect(screen.getByText("On")).toBeInTheDocument();
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });

  it("shows a 400 as the server message without the client prefix", () => {
    setup("ADMIN", null, {
      saveError: new ApiError(
        400,
        "PUT /groups/g1/policy failed with status 400: unknown sensor: gpu"
      ),
    });
    expect(screen.getByRole("alert")).toHaveTextContent(/^unknown sensor: gpu$/);
  });
});
