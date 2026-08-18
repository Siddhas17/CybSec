import { useEffect, useRef, useState } from "react";
import { getToken } from "../services/api";
import type { WebSocketMessage } from "../types";

const WS_URL = import.meta.env.VITE_WS_URL ?? "ws://localhost:8000/ws/events";
const RECONNECT_DELAY_MS = 3000;
const MAX_MESSAGES = 100;

export type ConnectionStatus = "connecting" | "connected" | "disconnected";

/** Connects to the backend's live-event WebSocket, auto-reconnecting on
 * drop, and keeps a bounded rolling buffer of received messages (never
 * re-streams the whole database -- the backend only pushes new events). */
export function useWebSocket() {
  const [status, setStatus] = useState<ConnectionStatus>("connecting");
  const [messages, setMessages] = useState<WebSocketMessage[]>([]);
  const socketRef = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    let cancelled = false;

    function connect() {
      if (cancelled) return;
      setStatus("connecting");
      const token = getToken();
      const url = token ? `${WS_URL}?token=${encodeURIComponent(token)}` : WS_URL;
      const socket = new WebSocket(url);
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
  }, []);

  return { status, messages };
}
