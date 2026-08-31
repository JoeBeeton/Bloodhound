import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ErrorState } from "./ErrorState";

describe("ErrorState", () => {
  it("announces itself to screen readers via role=alert", () => {
    // A screen-reader user watching a loading state otherwise gets no indication a query/mutation
    // just failed - role="alert" (implicit aria-live="assertive") is what makes this announced.
    render(<ErrorState message="Failed to load targets." />);

    expect(screen.getByRole("alert")).toHaveTextContent("Failed to load targets.");
  });

  it("does not render a retry button when onRetry is omitted", () => {
    render(<ErrorState message="Failed to load targets." />);

    expect(screen.queryByRole("button", { name: "Try again" })).not.toBeInTheDocument();
  });

  it("calls onRetry when the retry button is clicked", async () => {
    const user = userEvent.setup();
    const onRetry = vi.fn();
    render(<ErrorState message="Failed to load targets." onRetry={onRetry} />);

    await user.click(screen.getByRole("button", { name: "Try again" }));

    expect(onRetry).toHaveBeenCalledTimes(1);
  });
});
