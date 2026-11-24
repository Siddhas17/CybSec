import { fireEvent, render, screen, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { DestinationAnalysis } from "./DestinationAnalysis";
import { api } from "../services/api";
import type { TopNode } from "../types";

vi.mock("../services/api", () => ({ api: { analytics: { topDestinations: vi.fn() } } }));

const destinations: TopNode[] = Array.from({ length: 12 }, (_, index) => ({
  ip: "10.0.0." + (index + 1),
  attack_flow_count: 120 - index * 10,
  total_flow_count: 200 - index * 10,
}));

describe("Destination IP Analysis", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(api.analytics.topDestinations).mockResolvedValue(destinations);
  });

  it("preserves the API ranking, defines attack-labelled flows, and reports missing provenance honestly", async () => {
    render(<DestinationAnalysis />);
    expect(await screen.findByText("10.0.0.1")).toBeInTheDocument();
    expect(api.analytics.topDestinations).toHaveBeenCalledWith(25);
    expect(screen.getByText(/canonical input label is not BENIGN/)).toBeInTheDocument();
    expect(screen.getByText(/represented time range are not included by this API/)).toBeInTheDocument();
    expect(screen.getByText(/single-machine environment/)).toBeInTheDocument();
  });

  it("supports sorting, IP search, pagination, and selecting supported detail fields", async () => {
    render(<DestinationAnalysis />);
    const table = await screen.findByRole("region", { name: "Destination IP analysis table" });
    expect(within(table).getAllByRole("row")).toHaveLength(11);
    fireEvent.change(screen.getByRole("combobox", { name: "Sort destinations" }), { target: { value: "ip-asc" } });
    expect(within(table).getAllByRole("row")[2]).toHaveTextContent("10.0.0.10");
    fireEvent.change(screen.getByRole("combobox", { name: "Sort destinations" }), { target: { value: "attack-desc" } });
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    expect(screen.getByText("Page 2 of 2")).toBeInTheDocument();
    fireEvent.click(within(table).getByRole("button", { name: "View details for 10.0.0.11" }));
    expect(screen.getByRole("heading", { name: "Destination details" })).toBeInTheDocument();
    expect(screen.getByText("Rank in returned top 25")).toBeInTheDocument();
    expect(screen.getByText("Time range / dataset")).toBeInTheDocument();

    fireEvent.change(screen.getByRole("searchbox", { name: "Search destination IPs" }), { target: { value: "10.0.0.2" } });
    expect(within(table).getByRole("row", { name: /10\.0\.0\.2/ })).toBeInTheDocument();
    expect(within(table).queryByRole("row", { name: /10\.0\.0\.1\s/ })).not.toBeInTheDocument();
  });

  it("shows loading errors clearly", async () => {
    vi.mocked(api.analytics.topDestinations).mockRejectedValueOnce(new Error("offline"));
    render(<DestinationAnalysis />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Could not load destination aggregates");
  });
});

