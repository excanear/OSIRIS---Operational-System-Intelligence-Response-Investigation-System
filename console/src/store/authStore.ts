import { create } from "zustand";

export type Role = "VIEWER" | "ANALYST" | "RESPONSE_OPERATOR" | "ADMIN";

interface StoredSession {
  token: string;
  role: Role;
  username: string;
  tenantId?: string | null;
  tenantName?: string | null;
}

const STORAGE_KEY = "osiris.session";

function readStoredSession(): StoredSession | null {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    return raw ? (JSON.parse(raw) as StoredSession) : null;
  } catch {
    return null;
  }
}

function writeStoredSession(session: StoredSession | null): void {
  try {
    if (session) {
      sessionStorage.setItem(STORAGE_KEY, JSON.stringify(session));
    } else {
      sessionStorage.removeItem(STORAGE_KEY);
    }
  } catch {
    // sessionStorage unavailable (e.g. a private browsing mode) — the
    // session still works for this tab's lifetime via in-memory state.
  }
}

export interface AuthState {
  token: string | null;
  role: Role | null;
  username: string | null;
  tenantId: string | null;
  tenantName: string | null;
  setSession: (session: StoredSession) => void;
  clearSession: () => void;
}

const initial = readStoredSession();

export const useAuthStore = create<AuthState>((set) => ({
  token: initial?.token ?? null,
  role: initial?.role ?? null,
  username: initial?.username ?? null,
  tenantId: initial?.tenantId ?? null,
  tenantName: initial?.tenantName ?? null,
  setSession: (session) => {
    writeStoredSession(session);
    set({
      token: session.token,
      role: session.role,
      username: session.username,
      tenantId: session.tenantId ?? null,
      tenantName: session.tenantName ?? null,
    });
  },
  clearSession: () => {
    writeStoredSession(null);
    set({ token: null, role: null, username: null, tenantId: null, tenantName: null });
  },
}));
