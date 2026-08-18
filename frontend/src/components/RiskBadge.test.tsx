import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { RiskBadge } from "./RiskBadge";

describe("RiskBadge", () => {
  it("renders each risk level with the correct label", () => {
    const { rerender } = render(<RiskBadge level="Very Low" />);
    expect(screen.getByText("Very Low")).toBeInTheDocument();

    rerender(<RiskBadge level="Critical" />);
    expect(screen.getByText("Critical")).toBeInTheDocument();
  });

  it("renders an 'Unscored' badge when level is null", () => {
    render(<RiskBadge level={null} />);
    expect(screen.getByText("Unscored")).toBeInTheDocument();
  });

  it("applies the matching CSS class per level", () => {
    render(<RiskBadge level="High" />);
    expect(screen.getByText("High")).toHaveClass("badge", "high");
  });
});
