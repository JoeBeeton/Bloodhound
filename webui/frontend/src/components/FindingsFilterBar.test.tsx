import { render, screen, waitFor } from "@testing-library/react";
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

    expect(onChange).toHaveBeenCalledWith({ severities: [], categories: [], status: undefined });
  });

  it("Clear filters preserves the Resolved status view instead of snapping back to Open", async () => {
    // Regression coverage: status is the primary Open/Resolved view mode, not an incidental
    // narrowing filter like severity/category - clearing those must not also silently discard
    // which view the user is looking at.
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(
      <FindingsFilterBar
        value={{ severities: ["HIGH"], categories: [], status: "RESOLVED" }}
        onChange={onChange}
        resultCount={3}
      />,
    );

    await user.click(screen.getByText(/clear filters/i));

    expect(onChange).toHaveBeenCalledWith({ severities: [], categories: [], status: "RESOLVED" });
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

  it("defaults to showing Open as active when status is omitted", () => {
    render(<FindingsFilterBar value={EMPTY} onChange={vi.fn()} resultCount={0} />);

    expect(screen.getByRole("button", { name: "Open" })).toHaveClass("text-neon-cyan");
    expect(screen.getByRole("button", { name: "Resolved" })).not.toHaveClass("text-neon-cyan");
  });

  it("clicking Resolved switches status without disturbing severity/category selections", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(<FindingsFilterBar value={{ severities: ["HIGH"], categories: ["DNS"] }} onChange={onChange} resultCount={0} />);

    await user.click(screen.getByRole("button", { name: "Resolved" }));

    expect(onChange).toHaveBeenCalledWith({ severities: ["HIGH"], categories: ["DNS"], status: "RESOLVED" });
  });

  it("clicking Open while already Resolved switches back to OPEN", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(<FindingsFilterBar value={{ severities: [], categories: [], status: "RESOLVED" }} onChange={onChange} resultCount={0} />);

    await user.click(screen.getByRole("button", { name: "Open" }));

    expect(onChange).toHaveBeenCalledWith({ severities: [], categories: [], status: "OPEN" });
  });

  it("debounces typed search text before calling onChange", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const user = userEvent.setup({ delay: null });
    const onChange = vi.fn();
    render(<FindingsFilterBar value={EMPTY} onChange={onChange} resultCount={0} />);

    await user.type(screen.getByLabelText(/search findings by keyword/i), "csp");
    expect(onChange).not.toHaveBeenCalled();

    vi.advanceTimersByTime(300);
    expect(onChange).toHaveBeenCalledWith({ severities: [], categories: [], search: "csp" });

    vi.useRealTimers();
  });

  it("shows 'Clear filters' once search text is present, and clearing resets search too", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(<FindingsFilterBar value={{ severities: [], categories: [], search: "csp" }} onChange={onChange} resultCount={0} />);

    expect(screen.getByText(/clear filters/i)).toBeInTheDocument();

    await user.click(screen.getByText(/clear filters/i));

    expect(onChange).toHaveBeenCalledWith({ severities: [], categories: [], status: undefined, search: undefined });
  });

  it("syncs the input's displayed text when value.search changes externally (e.g. Clear filters)", async () => {
    const { rerender } = render(
      <FindingsFilterBar value={{ severities: [], categories: [], search: "csp" }} onChange={vi.fn()} resultCount={0} />,
    );
    expect(screen.getByLabelText(/search findings by keyword/i)).toHaveValue("csp");

    rerender(<FindingsFilterBar value={EMPTY} onChange={vi.fn()} resultCount={0} />);

    await waitFor(() => expect(screen.getByLabelText(/search findings by keyword/i)).toHaveValue(""));
  });

  // Only the org-wide Findings page passes `targets` - the target-detail/subdomain-detail pages
  // that also render this bar are already scoped to one target, so no dropdown should ever
  // appear for them (see the `targets` prop's own doc comment).
  const TARGETS = [
    { id: "t1", hostname: "barclays.co.uk" },
    { id: "t2", hostname: "americanexpress.com" },
  ];

  it("does not render a target dropdown when no targets prop is passed", () => {
    render(<FindingsFilterBar value={EMPTY} onChange={vi.fn()} resultCount={0} />);
    expect(screen.queryByLabelText(/filter by target/i)).not.toBeInTheDocument();
  });

  it("does not render a target dropdown for an empty targets list", () => {
    render(<FindingsFilterBar value={EMPTY} onChange={vi.fn()} resultCount={0} targets={[]} />);
    expect(screen.queryByLabelText(/filter by target/i)).not.toBeInTheDocument();
  });

  it("renders every target as an option, plus an 'All targets' default", () => {
    render(<FindingsFilterBar value={EMPTY} onChange={vi.fn()} resultCount={0} targets={TARGETS} />);
    const select = screen.getByLabelText(/filter by target/i);
    expect(select).toHaveValue("");
    expect(screen.getByRole("option", { name: "All targets" })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "barclays.co.uk" })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "americanexpress.com" })).toBeInTheDocument();
  });

  it("selecting a target calls onChange with its id", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(<FindingsFilterBar value={EMPTY} onChange={onChange} resultCount={0} targets={TARGETS} />);

    await user.selectOptions(screen.getByLabelText(/filter by target/i), "t1");

    expect(onChange).toHaveBeenCalledWith({ severities: [], categories: [], targetId: "t1" });
  });

  it("selecting 'All targets' clears targetId back to undefined", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(
      <FindingsFilterBar value={{ severities: [], categories: [], targetId: "t1" }} onChange={onChange} resultCount={0} targets={TARGETS} />,
    );

    await user.selectOptions(screen.getByLabelText(/filter by target/i), "All targets");

    expect(onChange).toHaveBeenCalledWith({ severities: [], categories: [], targetId: undefined });
  });

  it("shows 'Clear filters' once a target is selected, and clearing resets it too", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(
      <FindingsFilterBar value={{ severities: [], categories: [], targetId: "t1" }} onChange={onChange} resultCount={0} targets={TARGETS} />,
    );

    expect(screen.getByText(/clear filters/i)).toBeInTheDocument();
    await user.click(screen.getByText(/clear filters/i));

    expect(onChange).toHaveBeenCalledWith({
      severities: [],
      categories: [],
      status: undefined,
      search: undefined,
      targetId: undefined,
    });
  });
});
