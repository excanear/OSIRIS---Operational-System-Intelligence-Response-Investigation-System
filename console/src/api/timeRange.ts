/** Optional nanosecond window accepted by the rolled-up list endpoints. */
export interface TimeRange {
  since?: number;
  until?: number;
}

/** `?since=..&until=..` (empty string when neither is set). */
export function timeRangeQuery(range?: TimeRange): string {
  const search = new URLSearchParams();
  if (range?.since !== undefined) search.set("since", String(range.since));
  if (range?.until !== undefined) search.set("until", String(range.until));
  const query = search.toString();
  return query ? `?${query}` : "";
}
