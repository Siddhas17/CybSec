import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { LiveThreats } from "./LiveThreats";
import { api } from "../services/api";
import type { ThreatRow } from "../types";

vi.mock("../services/api", () => ({
  api: { listThreats: vi.fn() },
}));

vi.mock("../hooks/useWebSocket", () => ({
  useWebSocket: () => ({ status: "connected", messages: [] }),
}));

const SAMPLE_THREAT: ThreatRow = {
  event_id: 1,
  timestamp: "2017-07-07T12:59:00",
  source_ip: "172.16.0.1",
  source_port: null,
  destination_ip: "192.168.10.50",
  destination_port: null,
  protocol: null,
  canonical_attack_label: "DDoS",
  anomaly_score: 0.5,
  is_anomaly: true,
  risk_score: 9.8,
  risk_level: "Critical",
  event_source: "offline_demo",
};

describe("LiveThreats", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders the threat table with real API data", async () => {
    vi.mocked(api.listThreats).mockResolvedValue([SAMPLE_THREAT]);

    render(
      <MemoryRouter>
        <LiveThreats />
      </MemoryRouter>,
    );

    await waitFor(() => expect(screen.getByText("172.16.0.1")).toBeInTheDocument());
    expect(screen.getByText("192.168.10.50")).toBeInTheDocument();
    expect(screen.getByText("DDoS")).toBeInTheDocument();
    expect(screen.getByText("Critical")).toBeInTheDocument();
  });

  it("shows an empty state when there are no threats", async () => {
    vi.mocked(api.listThreats).mockResolvedValue([]);

    render(
      <MemoryRouter>
        <LiveThreats />
      </MemoryRouter>,
    );

    await waitFor(() => expect(screen.getByText("No events yet.")).toBeInTheDocument());
  });

  it("shows an error banner instead of crashing when the API call fails", async () => {
    vi.mocked(api.listThreats).mockRejectedValue(new Error("network error"));

    render(
      <MemoryRouter>
        <LiveThreats />
      </MemoryRouter>,
    );

    // loading indicator clears and a clear error message appears -- the
    // page stays usable rather than hanging, throwing, or showing a blank table
    await waitFor(() => expect(screen.queryByText("Loading...")).not.toBeInTheDocument());
    expect(screen.getByText(/Could not load threats/)).toBeInTheDocument();
  });
});
