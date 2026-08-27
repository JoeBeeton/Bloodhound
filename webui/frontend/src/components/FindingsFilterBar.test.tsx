import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { FindingsFilterBar, type FindingsFilterState } from "./FindingsFilterBar";

const EMPTY: FindingsFilterState = { severities: [], categories: [] };

describe("FindingsFilterBar", () => {
  it("shows a loading placeholder for an undefined result count", () => {
    render(<FindingsFilterBar value={EMPTY} onChange={vi.fn()} resultCount={undefined} />);
    expect(screen.getByText("…")).toBeInTheDocument();
  });

  it("pluralizes the result count correctly", () => {
    const { rerender } = render(<FindingsFilterBar value={EMPTY} onChange={vi.fn()} resultCount={1} />);
    expect(screen.getByText("1 result")).toBeInTheDocument();

    rerender(<FindingsFilterBar value={EMPTY} onChange={vi.fn()} resultCount={5} />);
    expect(screen.getByText("5 results")).toBeInTheDocument();

    rerender(<FindingsFilterBar value={EMPTY} onChange={vi.fn()} resultCount={0} />);
    expect(screen.getByText("0 results")).toBeInTheDocument();
  });

  it("does not show 'Clear filters' when nothing is selected", () => {
    render(<FindingsFilterBar value={EMPTY} onChange={vi.fn()} resultCount={10} />);
    expect(screen.queryByText(/clear filters/i)).not.toBeInTheDocument();
  });

  it("shows 'Clear filters' once a severity is selected, and clicking it resets both lists", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(
      <FindingsFilterBar value={{ severities: ["HIGH"], categories: ["DNS"] }} onChange={onChange} resultCount={3} />,
    );

    const clearButton = screen.getByText(/clear filters/i);
    await user.click(clearButton);

    expect(onChange).toHaveBeenCalledWith({ severities: [], categories: [] });
  });

  it("clicking an inactive severity toggle adds it to the selection", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(<FindingsFilterBar value={EMPTY} onChange={onChange} resultCount={0} />);

    await user.click(screen.getByRole("button", { name: "CRITICAL" }));

    expect(onChange).toHaveBeenCalledWith({ severities: ["CRITICAL"], categories: [] });
  });

  it("clicking an already-active severity toggle removes it from the selection", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(
      <FindingsFilterBar value={{ severities: ["CRITICAL", "HIGH"], categories: [] }} onChange={onChange} resultCount={0} />,
    );

    await user.click(screen.getByRole("button", { name: "CRITICAL" }));

    expect(onChange).toHaveBeenCalledWith({ severities: ["HIGH"], categories: [] });
  });

  it("clicking a category toggle adds it without disturbing the severity selection", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(<FindingsFilterBar value={{ severities: ["LOW"], categories: [] }} onChange={onChange} resultCount={0} />);

    await user.click(screen.getByRole("button", { name: "Exposure" }));

    expect(onChange).toHaveBeenCalledWith({ severities: ["LOW"], categories: ["EXPOSURE"] });
  });
});
