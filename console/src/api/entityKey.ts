import type { EntityRef } from "./types";

export const KNOWN_ENTITY_KINDS = ["PROCESS", "FILE", "IP", "DOMAIN", "USER", "CONTAINER", "SESSION"] as const;

export function entityRefToStorageKey(entity: EntityRef): string {
  switch (entity.kind) {
    case "PROCESS":
      return `PROCESS:${entity.process_key}`;
    case "FILE":
      return `FILE:${entity.host_id}:${entity.inode}:${entity.device_id}`;
    case "IP":
      return `IP:${entity.addr}`;
    case "DOMAIN":
      return `DOMAIN:${entity.name}`;
    case "USER":
      return `USER:${entity.host_id}:${entity.uid}`;
    case "CONTAINER":
      return `CONTAINER:${entity.container_id}`;
    case "SESSION":
      return `SESSION:${entity.session_id}`;
  }
}

export function describeEntityRef(entity: EntityRef): string {
  switch (entity.kind) {
    case "PROCESS":
      return `Process ${entity.process_key}`;
    case "FILE":
      return `File ${entity.host_id}:${entity.inode}`;
    case "IP":
      return `IP ${entity.addr}`;
    case "DOMAIN":
      return `Domain ${entity.name}`;
    case "USER":
      return `User ${entity.host_id}:${entity.uid}`;
    case "CONTAINER":
      return `Container ${entity.container_id}`;
    case "SESSION":
      return `Session ${entity.session_id}`;
  }
}

export function isValidEntityKey(key: string): boolean {
  const separatorIndex = key.indexOf(":");
  if (separatorIndex === -1) {
    return false;
  }
  const kind = key.slice(0, separatorIndex);
  const value = key.slice(separatorIndex + 1);
  return (KNOWN_ENTITY_KINDS as readonly string[]).includes(kind) && value.length > 0;
}
