import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { EventSourceTag } from "./EventSourceTag";

describe("EventSourceTag", () => {
  it("renders 'Live' for source=live, distinct from the demo/test labels", () => {
    render(<EventSourceTag source="live" />);
    expect(screen.getByText("Live")).toBeInTheDocument();
  });

  it("never labels a live event as offline/demo/test", () => {
    render(<EventSourceTag source="live" />);
    expect(screen.queryByText("Offline Dataset Demonstration")).not.toBeInTheDocument();
    expect(screen.queryByText("Test Event")).not.toBeInTheDocument();
  });

  it("still renders the existing offline_demo and test_event labels unchanged", () => {
    const { rerender } = render(<EventSourceTag source="offline_demo" />);
    expect(screen.getByText("Offline Dataset Demonstration")).toBeInTheDocument();

    rerender(<EventSourceTag source="test_event" />);
    expect(screen.getByText("Test Event")).toBeInTheDocument();
  });
});
