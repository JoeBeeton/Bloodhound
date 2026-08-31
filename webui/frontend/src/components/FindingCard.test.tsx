import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { Finding } from "../lib/types";
import { FindingCard } from "./FindingCard";

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "f1",
    displayId: "bh-example.com-1",
    targetId: "t1",
    moduleType: "HTTP_HEADERS",
    ruleId: "MISSING_CSP",
    severity: "MEDIUM",
    category: "HEADERS",
    title: "Missing Content-Security-Policy header",
    description: "No CSP header was present.",
    evidence: {},
    affectedAsset: "example.com",
    firstDetectedScanRunId: "run1",
    status: "OPEN",
    resolvedAt: null,
    createdAt: "2026-01-01T00:00:00Z",
    updatedAt: "2026-01-01T00:00:00Z",
    firstSeenAt: "2026-01-01T00:00:00Z",
    lastSeenAt: "2026-01-01T00:00:00Z",
    remediationAdvice: null,
    scoreImpact: null,
    ...overrides,
  };
}

describe("FindingCard - default (non-selectable) mode", () => {
  it("renders as a single button and clicking anywhere calls onSelect", async () => {
    const user = userEvent.setup();
    const onSelect = vi.fn();
    render(<FindingCard finding={finding()} onSelect={onSelect} />);

    expect(screen.queryByRole("checkbox")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button"));
    expect(onSelect).toHaveBeenCalledTimes(1);
  });
});

describe("FindingCard - selectable mode", () => {
  // A checkbox can't nest inside the card's own <button> (invalid HTML) - selectable mode
  // restructures to a checkbox beside a separate inner button, and this is the real regression
  // risk of that restructuring: the two clicks must stay fully independent of each other.
  it("clicking the checkbox calls onToggleSelect, not onSelect", async () => {
    const user = userEvent.setup();
    const onSelect = vi.fn();
    const onToggleSelect = vi.fn();
    render(
      <FindingCard finding={finding()} onSelect={onSelect} selectable selected={false} onToggleSelect={onToggleSelect} />,
    );

    await user.click(screen.getByRole("checkbox"));

    expect(onToggleSelect).toHaveBeenCalledTimes(1);
    expect(onSelect).not.toHaveBeenCalled();
  });

  it("clicking the content calls onSelect, not onToggleSelect", async () => {
    const user = userEvent.setup();
    const onSelect = vi.fn();
    const onToggleSelect = vi.fn();
    render(
      <FindingCard finding={finding()} onSelect={onSelect} selectable selected={false} onToggleSelect={onToggleSelect} />,
    );

    await user.click(screen.getByText("Missing Content-Security-Policy header"));

    expect(onSelect).toHaveBeenCalledTimes(1);
    expect(onToggleSelect).not.toHaveBeenCalled();
  });

  it("reflects the selected prop and uses the finding's displayId for its accessible label", () => {
    render(<FindingCard finding={finding()} onSelect={vi.fn()} selectable selected={true} onToggleSelect={vi.fn()} />);

    const checkbox = screen.getByRole("checkbox", { name: "Select bh-example.com-1" });
    expect(checkbox).toBeChecked();
  });
});
