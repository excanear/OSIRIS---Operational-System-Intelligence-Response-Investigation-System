import { create } from "zustand";

export interface TimeRange {
  since: number | null;
  until: number | null;
}

export interface UiState {
  selectedEntity: string | null;
  timeRange: TimeRange;
  activeFilters: Record<string, string>;
  selectEntity: (entityId: string | null) => void;
  setTimeRange: (range: TimeRange) => void;
  setFilter: (key: string, value: string) => void;
  clearFilter: (key: string) => void;
}

export const useUiStore = create<UiState>((set) => ({
  selectedEntity: null,
  timeRange: { since: null, until: null },
  activeFilters: {},
  selectEntity: (entityId) => set({ selectedEntity: entityId }),
  setTimeRange: (range) => set({ timeRange: range }),
  setFilter: (key, value) =>
    set((state) => ({ activeFilters: { ...state.activeFilters, [key]: value } })),
  clearFilter: (key) =>
    set((state) => {
      const next = { ...state.activeFilters };
      delete next[key];
      return { activeFilters: next };
    }),
}));
