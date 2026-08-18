import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ThreatDetails } from "./ThreatDetails";
import { api } from "../services/api";
import type { EventDetail } from "../types";

vi.mock("../services/api", () => ({
  api: { getEvent: vi.fn() },
}));

const SAMPLE_EVENT: EventDetail = {
  id: 1,
  event_uid: "offline-demo-abc",
  timestamp: "2017-07-04T02:09:00",
  source_ip: "172.16.0.1",
  source_port: null,
  destination_ip: "192.168.10.50",
  destination_port: null,
  protocol: null,
  canonical_attack_label: "DDoS",
  traffic_class: "ATTACK",
  source: "offline_demo",
  status: "processed",
  created_at: "2026-08-18T00:00:00",
  detection: {
    anomaly_score: 0.62,
    reconstruction_error: 0.62,
    is_anomaly: true,
    threshold_used: 0.106125,
    model_version_id: 1,
  },
  risk_assessment: {
    risk_score: 9.4,
    risk_level: "Critical",
    factors: [
      { name: "anomaly_severity", value: 0.95, contribution: 0.38 },
      { name: "edge_attack_ratio", value: 0.99, contribution: 0.25 },
      { name: "attack_activity", value: 1.0, contribution: 0.15 },
      { name: "temporal_persistence", value: 1.0, contribution: 0.1 },
      { name: "attack_context", value: 1.0, contribution: 0.1 },
    ],
    rules_applied: ["repeated_attack_heavy_communication", "very_high_anomaly"],
    reason: "High anomaly deviation combined with High attack-heavy communication; adjusted for repeated attack-heavy communication, an extreme anomaly deviation",
    risk_config_version_id: 1,
  },
  graph_context: {
    edge_attack_ratio: 0.999759,
    edge_attack_flow_count: 555630,
    edge_flow_count: 555764,
    edge_first_seen: "2017-07-04T02:09:00",
    edge_last_seen: "2017-07-07T12:38:00",
    edge_attack_label_count: 11,
  },
};

function renderAtEvent(eventId: string) {
  return render(
    <MemoryRouter initialEntries={[`/threats/${eventId}`]}>
      <Routes>
        <Route path="/threats/:eventId" element={<ThreatDetails />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("ThreatDetails risk visualization", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders the risk score, level, and every factor with its contribution", async () => {
    vi.mocked(api.getEvent).mockResolvedValue(SAMPLE_EVENT);
    renderAtEvent("1");

    await waitFor(() => expect(screen.getByText("9.40 / 10")).toBeInTheDocument());
    expect(screen.getByText("Critical")).toBeInTheDocument();
    expect(screen.getByText(/anomaly severity/)).toBeInTheDocument();
    expect(screen.getByText(/value 0.950/)).toBeInTheDocument();
  });

  it("renders applied context rules as badges (raw rule name, spaces for underscores)", async () => {
    vi.mocked(api.getEvent).mockResolvedValue(SAMPLE_EVENT);
    renderAtEvent("1");

    await waitFor(() => expect(screen.getByText("repeated attack heavy communication")).toBeInTheDocument());
    expect(screen.getByText("very high anomaly")).toBeInTheDocument();
  });

  it("shows a not-found message when the event does not exist", async () => {
    vi.mocked(api.getEvent).mockRejectedValue(new Error("404"));
    renderAtEvent("999");

    await waitFor(() => expect(screen.getByText("Event not found.")).toBeInTheDocument());
  });
});
