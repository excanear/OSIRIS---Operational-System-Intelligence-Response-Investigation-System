import { describe, expect, it } from "vitest";
import { describeEntityRef, entityRefToStorageKey, isValidEntityKey } from "./entityKey";
import type { EntityRef } from "./types";

describe("entityRefToStorageKey", () => {
  it("formats a PROCESS entity", () => {
    const entity: EntityRef = { kind: "PROCESS", process_key: "abc123" };
    expect(entityRefToStorageKey(entity)).toBe("PROCESS:abc123");
  });

  it("formats a FILE entity", () => {
    const entity: EntityRef = { kind: "FILE", host_id: "h1", inode: 42, device_id: 7 };
    expect(entityRefToStorageKey(entity)).toBe("FILE:h1:42:7");
  });

  it("formats an IP entity", () => {
    const entity: EntityRef = { kind: "IP", addr: "203.0.113.10" };
    expect(entityRefToStorageKey(entity)).toBe("IP:203.0.113.10");
  });

  it("formats a DOMAIN entity", () => {
    const entity: EntityRef = { kind: "DOMAIN", name: "example.com" };
    expect(entityRefToStorageKey(entity)).toBe("DOMAIN:example.com");
  });

  it("formats a USER entity", () => {
    const entity: EntityRef = { kind: "USER", host_id: "h1", uid: 1000 };
    expect(entityRefToStorageKey(entity)).toBe("USER:h1:1000");
  });

  it("formats a CONTAINER entity", () => {
    const entity: EntityRef = { kind: "CONTAINER", container_id: "c1" };
    expect(entityRefToStorageKey(entity)).toBe("CONTAINER:c1");
  });

  it("formats a SESSION entity", () => {
    const entity: EntityRef = { kind: "SESSION", session_id: "s1" };
    expect(entityRefToStorageKey(entity)).toBe("SESSION:s1");
  });
});

describe("describeEntityRef", () => {
  it("describes an IP entity readably", () => {
    const entity: EntityRef = { kind: "IP", addr: "203.0.113.10" };
    expect(describeEntityRef(entity)).toBe("IP 203.0.113.10");
  });
});

describe("isValidEntityKey", () => {
  it("accepts a known-kind key with a non-empty value", () => {
    expect(isValidEntityKey("IP:203.0.113.10")).toBe(true);
    expect(isValidEntityKey("PROCESS:abc123")).toBe(true);
  });

  it("rejects an unknown kind prefix", () => {
    expect(isValidEntityKey("BOGUS:value")).toBe(false);
  });

  it("rejects a key with no colon", () => {
    expect(isValidEntityKey("IP203.0.113.10")).toBe(false);
  });

  it("rejects a key with an empty value", () => {
    expect(isValidEntityKey("IP:")).toBe(false);
  });

  it("accepts a value that itself contains colons (e.g. FILE)", () => {
    expect(isValidEntityKey("FILE:h1:42:7")).toBe(true);
  });
});
