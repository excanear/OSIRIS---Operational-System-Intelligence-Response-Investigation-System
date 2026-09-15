import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useLiveEvents } from "./liveEvents";
import type { CanonicalEvent } from "./types";

class MockWebSocket {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;
  static instances: MockWebSocket[] = [];

  url: string;
  readyState = MockWebSocket.CONNECTING;
  onopen: (() => void) | null = null;
  onmessage: ((event: { data: string }) => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;

  constructor(url: string) {
    this.url = url;
    MockWebSocket.instances.push(this);
  }

  close() {
    this.readyState = MockWebSocket.CLOSED;
    this.onclose?.();
  }

  simulateOpen() {
    this.readyState = MockWebSocket.OPEN;
    this.onopen?.();
  }

  simulateMessage(data: unknown) {
    this.onmessage?.({ data: JSON.stringify(data) });
  }
}

function makeEvent(eventId: string): CanonicalEvent {
  return {
    event_id: eventId,
    event_type: "PROCESS_EXEC",
    timestamp: 1000,
    host: { host_id: "h1", hostname: "host-one" },
    event_data: {},
  };
}

describe("useLiveEvents", () => {
  beforeEach(() => {
    MockWebSocket.instances = [];
    vi.stubGlobal("WebSocket", MockWebSocket);
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("opens a socket and transitions to live on open", () => {
    const { result } = renderHook(() => useLiveEvents());
    expect(result.current.connectionState).toBe("connecting");

    act(() => MockWebSocket.instances[0].simulateOpen());

    expect(result.current.connectionState).toBe("live");
  });

  it("adds received events newest-first", () => {
    const { result } = renderHook(() => useLiveEvents());
    act(() => MockWebSocket.instances[0].simulateOpen());

    act(() => MockWebSocket.instances[0].simulateMessage(makeEvent("a")));
    act(() => MockWebSocket.instances[0].simulateMessage(makeEvent("b")));

    expect(result.current.events.map((e) => e.event_id)).toEqual(["b", "a"]);
  });

  it("caps the buffer at 500 events", () => {
    const { result } = renderHook(() => useLiveEvents());
    act(() => MockWebSocket.instances[0].simulateOpen());

    act(() => {
      for (let i = 0; i < 501; i++) {
        MockWebSocket.instances[0].simulateMessage(makeEvent(String(i)));
      }
    });

    expect(result.current.events).toHaveLength(500);
    expect(result.current.events[0].event_id).toBe("500");
  });

  it("pause freezes the rendered list; resume flushes the latest buffer", () => {
    const { result } = renderHook(() => useLiveEvents());
    act(() => MockWebSocket.instances[0].simulateOpen());
    act(() => MockWebSocket.instances[0].simulateMessage(makeEvent("a")));

    act(() => result.current.setPaused(true));
    act(() => MockWebSocket.instances[0].simulateMessage(makeEvent("b")));

    expect(result.current.events.map((e) => e.event_id)).toEqual(["a"]);

    act(() => result.current.setPaused(false));

    expect(result.current.events.map((e) => e.event_id)).toEqual(["b", "a"]);
  });

  it("clear empties both the rendered list and the buffer", () => {
    const { result } = renderHook(() => useLiveEvents());
    act(() => MockWebSocket.instances[0].simulateOpen());
    act(() => MockWebSocket.instances[0].simulateMessage(makeEvent("a")));

    act(() => result.current.clear());

    expect(result.current.events).toEqual([]);
  });

  it("reconnects with exponential backoff after the socket closes", () => {
    renderHook(() => useLiveEvents());
    act(() => MockWebSocket.instances[0].simulateOpen());

    act(() => MockWebSocket.instances[0].close());
    expect(MockWebSocket.instances).toHaveLength(1);

    act(() => vi.advanceTimersByTime(1000));
    expect(MockWebSocket.instances).toHaveLength(2);

    act(() => MockWebSocket.instances[1].close());
    act(() => vi.advanceTimersByTime(1999));
    expect(MockWebSocket.instances).toHaveLength(2);
    act(() => vi.advanceTimersByTime(1));
    expect(MockWebSocket.instances).toHaveLength(3);
  });

  it("builds the socket URL with a host_id filter, never both host_id and q", () => {
    renderHook(() => useLiveEvents({ hostId: "host-1" }));
    expect(MockWebSocket.instances[0].url).toContain("host_id=host-1");
    expect(MockWebSocket.instances[0].url).not.toContain("q=");
  });

  it("builds the socket URL with a q filter", () => {
    renderHook(() => useLiveEvents({ q: 'event_type = "PROCESS_EXEC"' }));
    expect(MockWebSocket.instances[0].url).toContain("q=");
  });
});
