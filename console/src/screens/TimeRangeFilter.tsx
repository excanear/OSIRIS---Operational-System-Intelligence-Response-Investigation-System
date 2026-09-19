import { useState } from "react";
import { parseOptionalNumber } from "../api/numeric";
import type { TimeRange } from "../api/timeRange";

/**
 * Two free-text nanosecond inputs (same convention as Timeline). Reports the
 * parsed window on every change; an unparsable entry counts as "not set".
 */
export function TimeRangeFilter({ onChange }: { onChange: (range: TimeRange) => void }) {
  const [since, setSince] = useState("");
  const [until, setUntil] = useState("");

  const emit = (nextSince: string, nextUntil: string) =>
    onChange({ since: parseOptionalNumber(nextSince), until: parseOptionalNumber(nextUntil) });

  return (
    <span>
      <input
        type="text"
        placeholder="Since (ns)"
        aria-label="Since"
        value={since}
        onChange={(event) => {
          setSince(event.target.value);
          emit(event.target.value, until);
        }}
      />
      <input
        type="text"
        placeholder="Until (ns)"
        aria-label="Until"
        value={until}
        onChange={(event) => {
          setUntil(event.target.value);
          emit(since, event.target.value);
        }}
      />
    </span>
  );
}
