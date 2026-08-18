import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { StatCard } from "./StatCard";

describe("StatCard", () => {
  it("renders the label and value", () => {
    render(<StatCard label="Total Events" value={291} />);
    expect(screen.getByText("Total Events")).toBeInTheDocument();
    expect(screen.getByText("291")).toBeInTheDocument();
  });

  it("renders an optional hint", () => {
    render(<StatCard label="High-Risk Events" value={216} hint="Risk score >= 7" />);
    expect(screen.getByText("Risk score >= 7")).toBeInTheDocument();
  });

  it("omits the hint block when not provided", () => {
    const { container } = render(<StatCard label="Benign Events" value={20} />);
    expect(container.querySelectorAll(".page-subtitle")).toHaveLength(0);
  });
});
