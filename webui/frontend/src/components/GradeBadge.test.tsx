import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { GradeBadge } from "./GradeBadge";

describe("GradeBadge", () => {
  it("shows 'not scanned' when grade and score are both null", () => {
    render(<GradeBadge grade={null} score={null} />);
    expect(screen.getByText("not scanned")).toBeInTheDocument();
  });

  it("renders the grade letter and rounded score together", () => {
    render(<GradeBadge grade="B" score={82.6} />);
    expect(screen.getByText("B · 83")).toBeInTheDocument();
  });

  it("rounds the score to the nearest whole number, not truncates", () => {
    render(<GradeBadge grade="A" score={94.4} />);
    expect(screen.getByText("A · 94")).toBeInTheDocument();
  });

  it("renders an F grade for a very low score", () => {
    render(<GradeBadge grade="F" score={12} />);
    expect(screen.getByText("F · 12")).toBeInTheDocument();
  });
});
