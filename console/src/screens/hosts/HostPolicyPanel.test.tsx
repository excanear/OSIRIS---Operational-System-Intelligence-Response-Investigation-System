import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import * as hooks from "../../api/hooks";
import type { HostPolicyView } from "../../api/types";
import { HostPolicyPanel } from "./HostPolicyPanel";

vi.mock("../../api/hooks");

const view = (over: Partial<HostPolicyView>): HostPolicyView => ({
  host_id: "h1",
  effective: { telemetry_level: "STANDARD", sensors: { network: false }, heartbeat_interval_secs: null },
  sources: {
    telemetry_level: { tier: "PLATFORM" },
    sensors: { network: { tier: "TENANT", group_id: "g1", group_name: "web" } },
  },
  desired_hash: "a",
  applied_hash: "a",
  status: "IN_SYNC",
  last_delivery: null,
  ...over,
});

function show(v: HostPolicyView) {
  vi.mocked(hooks.useHostPolicy).mockReturnValue({
    data: v,
    isLoading: false,
    isError: false,
    error: null,
  } as never);
  render(<HostPolicyPanel hostId="h1" />);
}

describe("HostPolicyPanel", () => {
  it("labels a platform-opaque source and a tenant source", () => {
    show(view({}));
    expect(screen.getByText(/Telemetry level: STANDARD \(Platform policy\)/)).toBeInTheDocument();
    expect(screen.getByText(/Sensor network: Off \(Group web\)/)).toBeInTheDocument();
    expect(screen.getByText("Status: IN_SYNC")).toBeInTheDocument();
  });

  it("shows the delivery error when FAILED", () => {
    show(
      view({
        status: "FAILED",
        last_delivery: { sent_at: 1_000_000, result: "REFUSED", error: "signature rejected" },
      })
    );
    expect(screen.getByText("Status: FAILED")).toBeInTheDocument();
    expect(screen.getByText(/REFUSED/)).toHaveTextContent("signature rejected");
  });
});
