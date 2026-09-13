import { beforeEach, describe, expect, it } from "vitest";
import { useUiStore } from "./uiStore";

const initialState = useUiStore.getState();

beforeEach(() => {
  useUiStore.setState(initialState, true);
});

describe("useUiStore", () => {
  it("starts with no selection, no time range, and no filters", () => {
    const state = useUiStore.getState();
    expect(state.selectedEntity).toBeNull();
    expect(state.timeRange).toEqual({ since: null, until: null });
    expect(state.activeFilters).toEqual({});
  });

  it("selectEntity sets and clears the selected entity", () => {
    useUiStore.getState().selectEntity("process:abc123");
    expect(useUiStore.getState().selectedEntity).toBe("process:abc123");

    useUiStore.getState().selectEntity(null);
    expect(useUiStore.getState().selectedEntity).toBeNull();
  });

  it("setTimeRange replaces the active time range", () => {
    useUiStore.getState().setTimeRange({ since: 1000, until: 2000 });
    expect(useUiStore.getState().timeRange).toEqual({ since: 1000, until: 2000 });
  });

  it("setFilter adds a filter without disturbing existing ones", () => {
    useUiStore.getState().setFilter("host", "web-01");
    useUiStore.getState().setFilter("severity", "high");
    expect(useUiStore.getState().activeFilters).toEqual({
      host: "web-01",
      severity: "high",
    });
  });

  it("clearFilter removes only the named filter", () => {
    useUiStore.getState().setFilter("host", "web-01");
    useUiStore.getState().setFilter("severity", "high");
    useUiStore.getState().clearFilter("host");
    expect(useUiStore.getState().activeFilters).toEqual({ severity: "high" });
  });
});
