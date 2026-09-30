import { useEffect, useRef, useState } from "react";
import { getToken } from "../services/api";
import type { WebSocketMessage } from "../types";

const WS_URL = import.meta.env.VITE_WS_URL ?? "ws://localhost:8000/ws/events";
const ADMIN_FLOW_SCORE_WS_URL =
  import.meta.env.VITE_ADMIN_FLOW_SCORE_WS_URL ??
  (() => {
    const url = new URL(WS_URL);
    url.pathname = `${url.pathname.replace(/\/ws\/events\/?$/, "")}/ws/admin/victim-flow-scores`;
    url.search = "";
    return url.toString();
  })();
const RECONNECT_DELAY_MS = 3000;
const MAX_MESSAGES = 100;

export type ConnectionStatus = "connecting" | "connected" | "disconnected";

/** Connects to the backend's live-event WebSocket, auto-reconnecting on
 * drop, and keeps a bounded rolling buffer of received messages (never
 * re-streams the whole database -- the backend only pushes new events). */
function useSocketConnection(url: string, enabled = true) {
  const [status, setStatus] = useState<ConnectionStatus>(enabled ? "connecting" : "disconnected");
  const [messages, setMessages] = useState<WebSocketMessage[]>([]);
  const socketRef = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    if (!enabled) {
      setStatus("disconnected");
      setMessages([]);
      return;
    }

    let cancelled = false;

    function connect() {
      if (cancelled) return;
      setStatus("connecting");
      const token = getToken();
      const authenticatedUrl = token ? `${url}?token=${encodeURIComponent(token)}` : url;
      const socket = new WebSocket(authenticatedUrl);
      socketRef.current = socket;

      socket.onopen = () => setStatus("connected");

      socket.onmessage = (event) => {
        try {
          const parsed = JSON.parse(event.data) as WebSocketMessage;
          if (parsed.type === "heartbeat") return;
          setMessages((prev) => [parsed, ...prev].slice(0, MAX_MESSAGES));
        } catch {
          // ignore malformed frames rather than crashing the dashboard
        }
      };

      socket.onclose = () => {
        setStatus("disconnected");
        if (!cancelled) {
          reconnectTimer.current = setTimeout(connect, RECONNECT_DELAY_MS);
        }
      };

      socket.onerror = () => {
        socket.close();
      };
    }

    connect();

    return () => {
      cancelled = true;
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
      socketRef.current?.close();
    };
  }, [enabled, url]);

  return { status, messages };
}

export function useWebSocket() {
  return useSocketConnection(WS_URL);
}

export function useAdminFlowScores(enabled: boolean) {
  return useSocketConnection(ADMIN_FLOW_SCORE_WS_URL, enabled);
}
