import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Agents } from "./Agents";
import { api } from "../services/api";
import type { AgentOut } from "../types";

vi.mock("../services/api", () => ({
  api: { agents: { list: vi.fn(), updateStatus: vi.fn() } },
}));

const ACTIVE_AGENT: AgentOut = {
  id: 1,
  agent_id: "victim-active",
  hostname: "VICTIM-ACTIVE",
  ip_address: "192.168.1.10",
  agent_version: "0.1.0",
  status: "active",
  last_seen: "2026-09-30T12:00:00Z",
  created_at: "2026-09-30T11:00:00Z",
  online: true,
};

const DISABLED_AGENT: AgentOut = {
  ...ACTIVE_AGENT,
  id: 2,
  agent_id: "victim-disabled",
  hostname: "VICTIM-DISABLED",
  status: "disabled",
  online: false,
};

describe("Agents", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(api.agents.list).mockResolvedValue([ACTIVE_AGENT, DISABLED_AGENT]);
  });

  it("shows lifecycle independently from connectivity and offers the matching actions", async () => {
    render(<Agents />);

    const activeRow = await screen.findByRole("row", { name: /victim-active/ });
    const disabledRow = screen.getByRole("row", { name: /victim-disabled/ });

    expect(within(activeRow).getByText("Active")).toBeInTheDocument();
    expect(within(activeRow).getByText("Online")).toBeInTheDocument();
    expect(within(activeRow).getByRole("button", { name: "Disable" })).toBeInTheDocument();
    expect(within(disabledRow).getByText("Disabled")).toBeInTheDocument();
    expect(within(disabledRow).getByText("Offline")).toBeInTheDocument();
    expect(within(disabledRow).getByRole("button", { name: "Enable" })).toBeInTheDocument();
  });

  it("disables an active agent and immediately refreshes its lifecycle display", async () => {
    const user = userEvent.setup();
    vi.mocked(api.agents.updateStatus).mockResolvedValue({ ...ACTIVE_AGENT, status: "disabled" });
    render(<Agents />);

    const activeRow = await screen.findByRole("row", { name: /victim-active/ });
    await user.click(within(activeRow).getByRole("button", { name: "Disable" }));

    expect(api.agents.updateStatus).toHaveBeenCalledWith("victim-active", "disabled");
    await waitFor(() => expect(within(activeRow).getByText("Disabled")).toBeInTheDocument());
    expect(within(activeRow).getByRole("button", { name: "Enable" })).toBeInTheDocument();
  });

  it("re-enables a disabled agent and immediately refreshes its lifecycle display", async () => {
    const user = userEvent.setup();
    vi.mocked(api.agents.updateStatus).mockResolvedValue({ ...DISABLED_AGENT, status: "active" });
    render(<Agents />);

    const disabledRow = await screen.findByRole("row", { name: /victim-disabled/ });
    await user.click(within(disabledRow).getByRole("button", { name: "Enable" }));

    expect(api.agents.updateStatus).toHaveBeenCalledWith("victim-disabled", "active");
    await waitFor(() => expect(within(disabledRow).getByText("Active")).toBeInTheDocument());
    expect(within(disabledRow).getByRole("button", { name: "Disable" })).toBeInTheDocument();
  });

  it("shows the API error when a status update fails", async () => {
    const user = userEvent.setup();
    vi.mocked(api.agents.updateStatus).mockRejectedValue({ response: { data: { detail: "Status update denied" } } });
    render(<Agents />);

    const activeRow = await screen.findByRole("row", { name: /victim-active/ });
    await user.click(within(activeRow).getByRole("button", { name: "Disable" }));

    expect(await screen.findByText("Status update denied")).toBeInTheDocument();
    expect(within(activeRow).getByText("Active")).toBeInTheDocument();
  });
});