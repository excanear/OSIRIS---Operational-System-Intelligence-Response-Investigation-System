import { beforeEach, describe, expect, it } from "vitest";
import { useAuthStore } from "./authStore";

describe("authStore", () => {
  beforeEach(() => {
    sessionStorage.clear();
    useAuthStore.getState().clearSession();
  });

  it("starts with no session", () => {
    expect(useAuthStore.getState().token).toBeNull();
    expect(useAuthStore.getState().role).toBeNull();
  });

  it("setSession stores the session and persists it to sessionStorage", () => {
    useAuthStore.getState().setSession({ token: "abc", role: "ADMIN", username: "alice" });

    expect(useAuthStore.getState().token).toBe("abc");
    expect(useAuthStore.getState().role).toBe("ADMIN");
    expect(JSON.parse(sessionStorage.getItem("osiris.session")!)).toEqual({
      token: "abc",
      role: "ADMIN",
      username: "alice",
    });
  });

  it("clearSession removes the session from state and sessionStorage", () => {
    useAuthStore.getState().setSession({ token: "abc", role: "ADMIN", username: "alice" });

    useAuthStore.getState().clearSession();

    expect(useAuthStore.getState().token).toBeNull();
    expect(sessionStorage.getItem("osiris.session")).toBeNull();
  });
});
