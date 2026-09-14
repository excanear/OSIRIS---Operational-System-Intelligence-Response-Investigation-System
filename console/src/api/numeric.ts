export function parseOptionalNumber(text: string): number | undefined {
  if (text.trim() === "") {
    return undefined;
  }
  const parsed = Number(text);
  return Number.isFinite(parsed) ? parsed : undefined;
}
