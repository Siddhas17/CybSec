import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Prevention } from "./Prevention";
import { api } from "../services/api";
import type { PreventionAction } from "../types";

vi.mock("../services/api", () => ({
  api: {
    prevention: {
      listActions: vi.fn(),
      dryRun: vi.fn(),
      block: vi.fn(),
      unblock: vi.fn(),
    },
  },
}));

vi.mock("../hooks/useWebSocket", () => ({
  useWebSocket: () => ({ status: "connected", messages: [] }),
}));

const WOULD_BLOCK: PreventionAction = {
  id: 1,
  event_id: 42,
  detection_id: 42,
  risk_assessment_id: 42,
  user_id: null,
  source_ip: "192.168.56.10",
  risk_score: 9.4,
  risk_level: "Critical",
  requested_action: "block",
  actual_action: "would_block",
  dry_run: true,
  success: true,
  reason: "risk_score 9.40 crossed block threshold 9.0",
  adapter: "lab_dry_run",
  target_scope: "192.168.56.0/24",
  created_at: "2026-08-19T10:00:00Z",
};

const REJECTED: PreventionAction = {
  ...WOULD_BLOCK,
  id: 2,
  source_ip: "8.8.8.8",
  actual_action: "rejected",
  success: false,
  reason: "8.8.8.8 is outside the configured lab network scope (192.168.56.0/24)",
  target_scope: null,
};

describe("Prevention", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders the response action log with precise WOULD BLOCK terminology, distinct from BLOCKED", async () => {
    vi.mocked(api.prevention.listActions).mockResolvedValue([WOULD_BLOCK]);

    render(
      <MemoryRouter>
        <Prevention />
      </MemoryRouter>,
    );

    await waitFor(() => expect(screen.getByText("192.168.56.10")).toBeInTheDocument());
    expect(screen.getByText("WOULD BLOCK")).toBeInTheDocument();
    expect(screen.queryByText("BLOCKED")).not.toBeInTheDocument();
  });

  it("shows REJECTED for an out-of-scope target and never lists it as currently blocked", async () => {
    vi.mocked(api.prevention.listActions).mockResolvedValue([REJECTED]);

    render(
      <MemoryRouter>
        <Prevention />
      </MemoryRouter>,
    );

    await waitFor(() => expect(screen.getByText("REJECTED")).toBeInTheDocument());
    expect(screen.getByText(/None -- no source is currently in a real blocked state/)).toBeInTheDocument();
  });

  it("shows an empty state when no response actions exist yet", async () => {
    vi.mocked(api.prevention.listActions).mockResolvedValue([]);

    render(
      <MemoryRouter>
        <Prevention />
      </MemoryRouter>,
    );

    await waitFor(() => expect(screen.getByText("No response actions recorded yet.")).toBeInTheDocument());
  });

  it("submits a manual dry-run for the entered IP and shows the result", async () => {
    vi.mocked(api.prevention.listActions).mockResolvedValue([]);
    vi.mocked(api.prevention.dryRun).mockResolvedValue(WOULD_BLOCK);
    const user = userEvent.setup();

    render(
      <MemoryRouter>
        <Prevention />
      </MemoryRouter>,
    );

    await waitFor(() => expect(screen.getByText("No response actions recorded yet.")).toBeInTheDocument());
    await user.type(screen.getByLabelText("Source IP"), "192.168.56.10");
    await user.click(screen.getByRole("button", { name: "Dry-Run" }));

    await waitFor(() => expect(api.prevention.dryRun).toHaveBeenCalledWith("192.168.56.10", undefined));
    expect(screen.getByText(/WOULD BLOCK: risk_score 9\.40/)).toBeInTheDocument();
  });
});
