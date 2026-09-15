import { useCallback, useEffect, useRef, useState } from "react";
import type { CanonicalEvent } from "./types";

const RING_BUFFER_CAPACITY = 500;
const INITIAL_BACKOFF_MS = 1000;
const MAX_BACKOFF_MS = 30000;

export type ConnectionState = "connecting" | "live" | "reconnecting" | "disconnected";

export interface LiveEventsFilter {
  hostId?: string;
  q?: string;
}

export interface UseLiveEventsResult {
  events: CanonicalEvent[];
  connectionState: ConnectionState;
  paused: boolean;
  setPaused: (paused: boolean) => void;
  clear: () => void;
}

function buildStreamUrl(filter: LiveEventsFilter): string {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const search = new URLSearchParams();
  if (filter.hostId) {
    search.set("host_id", filter.hostId);
  } else if (filter.q) {
    search.set("q", filter.q);
  }
  const queryString = search.toString();
  return `${protocol}//${window.location.host}/api/v1/stream/events${queryString ? `?${queryString}` : ""}`;
}

export function useLiveEvents(filter: LiveEventsFilter = {}): UseLiveEventsResult {
  const [events, setEvents] = useState<CanonicalEvent[]>([]);
  const [connectionState, setConnectionState] = useState<ConnectionState>("connecting");
  const [paused, setPausedState] = useState(false);
  const pausedRef = useRef(paused);
  const bufferRef = useRef<CanonicalEvent[]>([]);
  const backoffRef = useRef(INITIAL_BACKOFF_MS);

  useEffect(() => {
    pausedRef.current = paused;
  }, [paused]);

  useEffect(() => {
    let socket: WebSocket | null = null;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    let cancelled = false;

    function connect() {
      if (cancelled) {
        return;
      }
      setConnectionState((current) => (current === "live" ? current : "connecting"));
      socket = new WebSocket(buildStreamUrl(filter));

      socket.onopen = () => {
        backoffRef.current = INITIAL_BACKOFF_MS;
        setConnectionState("live");
      };

      socket.onmessage = (messageEvent) => {
        let parsed: CanonicalEvent;
        try {
          parsed = JSON.parse(messageEvent.data as string) as CanonicalEvent;
        } catch {
          console.warn("Live Events: received a non-JSON message, dropping it");
          return;
        }
        bufferRef.current = [parsed, ...bufferRef.current].slice(0, RING_BUFFER_CAPACITY);
        if (!pausedRef.current) {
          setEvents(bufferRef.current);
        }
      };

      socket.onclose = () => {
        if (cancelled) {
          return;
        }
        setConnectionState("reconnecting");
        reconnectTimer = setTimeout(connect, backoffRef.current);
        backoffRef.current = Math.min(backoffRef.current * 2, MAX_BACKOFF_MS);
      };

      socket.onerror = () => {
        socket?.close();
      };
    }

    connect();

    return () => {
      cancelled = true;
      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
      }
      socket?.close();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filter.hostId, filter.q]);

  const clear = useCallback(() => {
    bufferRef.current = [];
    setEvents([]);
  }, []);

  const setPaused = useCallback((next: boolean) => {
    setPausedState(next);
    if (!next) {
      setEvents(bufferRef.current);
    }
  }, []);

  return { events, connectionState, paused, setPaused, clear };
}
