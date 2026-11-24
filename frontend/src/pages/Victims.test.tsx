import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Victims } from "./Victims";
import { api } from "../services/api";
import type { LiveDeviceIdentitiesResponse, LiveDeviceIdentity } from "../types";

vi.mock("../services/api", () => ({ api: { getLiveNetworkDevices: vi.fn() } }));

const ONLINE_ACTIVE: LiveDeviceIdentity = {
  device_id: "victim:victim-01",
  role: "victim",
  label: "Victim: MSI (victim-01)",
  ip_address: "10.0.0.12",
  ip_address_observed_at: "2026-10-10T16:00:00Z",
  ip_address_source: "transport_peer",
  ip_address_status: "verified",
  last_seen: "2026-10-10T16:01:00Z",
  registered: true,
  online: true,
  status: "active",
};

const OFFLINE_DISABLED: LiveDeviceIdentity = {
  device_id: "victim:victim-02",
  role: "victim",
  label: "Victim: PC-OFF (victim-02)",
  ip_address: "10.0.0.13",
  ip_address_observed_at: "2026-10-10T15:00:00Z",
  ip_address_source: "transport_peer",
  ip_address_status: "verified",
  last_seen: "2026-10-10T15:01:00Z",
  registered: true,
  online: false,
  status: "disabled",
};

const ADMIN_DEVICE: LiveDeviceIdentity = {
  device_id: "admin:1",
  role: "admin",
  label: "Admin",
  ip_address: "10.0.0.1",
  ip_address_observed_at: null,
  last_seen: null,
  registered: true,
  online: null,
};

describe("Victims", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(api.getLiveNetworkDevices).mockResolvedValue({
      devices: [
        ADMIN_DEVICE,
        ONLINE_ACTIVE,
        OFFLINE_DISABLED,
        { ...ONLINE_ACTIVE, device_id: "victim:unregistered", label: "Victim: Not registered (unregistered)", registered: false },
      ],
    });
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("lists registered Victim Agents and excludes Admin devices", async () => {
    render(<Victims />);

    const activeRow = await screen.findByRole("row", { name: /victim-01/ });
    const disabledRow = screen.getByRole("row", { name: /victim-02/ });
    expect(within(activeRow).getByText("MSI")).toBeInTheDocument();
    expect(within(activeRow).getByText("10.0.0.12")).toBeInTheDocument();
    expect(within(activeRow).getByText("transport_peer")).toBeInTheDocument();
    expect(within(activeRow).getAllByText(/UTC/)).toHaveLength(2);
    expect(within(activeRow).getByText("Online")).toBeInTheDocument();
    expect(within(activeRow).getByText("Active")).toBeInTheDocument();
    expect(within(disabledRow).getByText("Offline")).toBeInTheDocument();
    expect(within(disabledRow).getByText("Disabled")).toBeInTheDocument();
    expect(screen.queryByText("Admin")).not.toBeInTheDocument();
    expect(screen.queryByText("Not registered")).not.toBeInTheDocument();
    expect(api.getLiveNetworkDevices).toHaveBeenCalledTimes(1);
  });

  it("shows missing IP and nullable status values without inferring data", async () => {
    const missingIp: LiveDeviceIdentity = {
      ...ONLINE_ACTIVE,
      device_id: "victim:victim-no-ip",
      label: "Victim: PC-NO-IP (victim-no-ip)",
      ip_address: null,
      ip_address_observed_at: null,
      ip_address_source: null,
      ip_address_status: "unavailable",
      ip_address_reason: "No verified address is available.",
      last_seen: null,
      online: null,
      status: null,
    };
    vi.mocked(api.getLiveNetworkDevices).mockResolvedValue({ devices: [missingIp] });

    render(<Victims />);

    const row = await screen.findByRole("row", { name: /victim-no-ip/ });
    expect(within(row).getByText("IP unavailable")).toBeInTheDocument();
    expect(within(row).queryByText("10.0.0.12")).not.toBeInTheDocument();
    expect(within(row).getByText("Source unavailable")).toBeInTheDocument();
    expect(within(row).getAllByText("Unavailable")).toHaveLength(2);
    expect(within(row).getByText("No verified address is available.")).toBeInTheDocument();
    expect(within(row).getAllByText("Unknown")).toHaveLength(2);
    expect(within(row).getByText("Never reported")).toBeInTheDocument();
  });

  it("does not display an address unless the endpoint marks it verified", async () => {
    vi.mocked(api.getLiveNetworkDevices).mockResolvedValue({
      devices: [{
        ...ONLINE_ACTIVE,
        device_id: "victim:victim-unverified-ip",
        label: "Victim: PC-UNVERIFIED (victim-unverified-ip)",
        ip_address: "10.0.0.99",
        ip_address_status: "unavailable",
      }],
    });

    render(<Victims />);

    const row = await screen.findByRole("row", { name: /victim-unverified-ip/ });
    expect(within(row).getByText("IP unavailable")).toBeInTheDocument();
    expect(within(row).queryByText("10.0.0.99")).not.toBeInTheDocument();
  });

  it("shows loading state while the device request is pending", async () => {
    let resolveDevices: (response: LiveDeviceIdentitiesResponse) => void = () => {};
    vi.mocked(api.getLiveNetworkDevices).mockReturnValue(new Promise((resolve) => {
      resolveDevices = resolve;
    }));

    render(<Victims />);
    expect(screen.getByRole("status")).toHaveTextContent("Loading registered victim devices");

    await act(async () => {
      resolveDevices({ devices: [] });
    });
    expect(screen.getByText("No registered Victim Agents are available.")).toBeInTheDocument();
  });

  it("shows an empty state when no registered victims are returned", async () => {
    vi.mocked(api.getLiveNetworkDevices).mockResolvedValue({ devices: [ADMIN_DEVICE] });

    render(<Victims />);

    expect(await screen.findByText("No registered Victim Agents are available.")).toBeInTheDocument();
  });

  it("displays API errors", async () => {
    vi.mocked(api.getLiveNetworkDevices).mockRejectedValue(new Error("offline"));

    render(<Victims />);

    expect(await screen.findByRole("alert")).toHaveTextContent("Could not load registered victim devices");
    expect(screen.getByText("Victim device records are unavailable until the backend responds.")).toBeInTheDocument();
  });

  it("refreshes manually", async () => {
    vi.mocked(api.getLiveNetworkDevices)
      .mockResolvedValueOnce({ devices: [ONLINE_ACTIVE] })
      .mockResolvedValueOnce({ devices: [{ ...ONLINE_ACTIVE, label: "Victim: MSI-UPDATED (victim-01)" }] });
    render(<Victims />);

    expect(await screen.findByText("MSI")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Refresh" }));

    expect(await screen.findByText("MSI-UPDATED")).toBeInTheDocument();
    expect(api.getLiveNetworkDevices).toHaveBeenCalledTimes(2);
  });

  it("refreshes every five seconds and clears the interval on unmount", async () => {
    vi.useFakeTimers();
    const { unmount } = render(<Victims />);
    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(api.getLiveNetworkDevices).toHaveBeenCalledTimes(1);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(5000);
    });
    expect(api.getLiveNetworkDevices).toHaveBeenCalledTimes(2);

    unmount();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5000);
    });
    expect(api.getLiveNetworkDevices).toHaveBeenCalledTimes(2);
  });
});
