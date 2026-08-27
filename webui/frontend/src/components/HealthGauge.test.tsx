import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { HealthGauge } from "./HealthGauge";

describe("HealthGauge", () => {
  it("renders a dim, unfilled ring with '—' and 'n/a' when no target has scored yet", () => {
    render(<HealthGauge score={null} label="Overall posture" />);
    expect(screen.getByText("—")).toBeInTheDocument();
    expect(screen.getByText("n/a")).toBeInTheDocument();
    expect(screen.getByRole("img", { name: /not yet scanned/i })).toBeInTheDocument();
  });

  it("derives grade A at the 90 threshold", () => {
    render(<HealthGauge score={90} label="Overall posture" />);
    expect(screen.getByText("A")).toBeInTheDocument();
    expect(screen.getByText("90")).toBeInTheDocument();
  });

  it("derives grade B just below the A threshold", () => {
    render(<HealthGauge score={89.4} label="Overall posture" />);
    expect(screen.getByText("B")).toBeInTheDocument();
    expect(screen.getByText("89")).toBeInTheDocument();
  });

  it("derives grade F below the 60 threshold", () => {
    render(<HealthGauge score={50} label="Overall posture" />);
    expect(screen.getByText("F")).toBeInTheDocument();
  });

  it("shows the passed label", () => {
    render(<HealthGauge score={75} label="Overall posture" />);
    expect(screen.getByText("Overall posture")).toBeInTheDocument();
  });
});
