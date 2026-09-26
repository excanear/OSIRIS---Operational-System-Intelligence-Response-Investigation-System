import { ApiError } from "../../api/client";

export function groupErrorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 409) return "A group with this name already exists.";
    if (error.status === 422) return "Unknown host.";
    if (error.status === 404) return "Group not found.";
    if (error.status === 403) return "You do not have permission to change groups.";
    if (error.status === 400) return error.message;
  }
  return error instanceof Error ? error.message : "Request failed.";
}
