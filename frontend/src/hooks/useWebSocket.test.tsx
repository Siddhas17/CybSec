import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useWebSocket } from "./useWebSocket";

class MockWebSocket {
  static instances: MockWebSocket[] = [];
  onopen: (() => void) | null = null;
  onclose: (() => void) | null = null;
  onmessage: ((event: { data: string }) => void) | null = null;
  onerror: (() => void) | null = null;
  closed = false;
  url: string;

  constructor(url: string) {
    this.url = url;
    MockWebSocket.instances.push(this);
  }

  close() {
    this.closed = true;
    this.onclose?.();
  }

  send() {}

  triggerOpen() {
    this.onopen?.();
  }

  triggerMessage(data: unknown) {
    this.onmessage?.({ data: JSON.stringify(data) });
  }
}

// vi.useFakeTimers() replaces setTimeout globally, which makes
// @testing-library's waitFor (itself timer-based) deadlock -- so these
// tests assert directly after act() rather than using waitFor. State
// updates triggered synchronously inside act() are flushed before act()
// returns, so this is not a race.
describe("useWebSocket", () => {
  beforeEach(() => {
    MockWebSocket.instances = [];
    vi.stubGlobal("WebSocket", MockWebSocket as unknown as typeof WebSocket);
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("starts in connecting state, then connected once the socket opens", () => {
    const { result } = renderHook(() => useWebSocket());
    expect(result.current.status).toBe("connecting");

    act(() => MockWebSocket.instances[0].triggerOpen());
    expect(result.current.status).toBe("connected");
  });

  it("collects incoming messages, most recent first, ignoring heartbeats", () => {
    const { result } = renderHook(() => useWebSocket());
    act(() => MockWebSocket.instances[0].triggerOpen());

    act(() => MockWebSocket.instances[0].triggerMessage({ type: "heartbeat", data: {} }));
    act(() => MockWebSocket.instances[0].triggerMessage({ type: "new_threat", data: { event_id: 1 } }));

    expect(result.current.messages).toHaveLength(1);
    expect(result.current.messages[0].type).toBe("new_threat");
  });

  it("automatically reconnects after the socket closes", () => {
    const { result } = renderHook(() => useWebSocket());
    act(() => MockWebSocket.instances[0].triggerOpen());
    expect(result.current.status).toBe("connected");

    act(() => MockWebSocket.instances[0].close());
    expect(result.current.status).toBe("disconnected");
    expect(MockWebSocket.instances).toHaveLength(1); // reconnect hasn't fired yet

    act(() => {
      vi.advanceTimersByTime(3000);
    });

    expect(MockWebSocket.instances).toHaveLength(2); // a new connection attempt was made
  });
});
