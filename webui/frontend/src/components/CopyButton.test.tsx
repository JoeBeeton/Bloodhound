import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { CopyButton } from "./CopyButton";

describe("CopyButton", () => {
  beforeEach(() => {
    Object.defineProperty(navigator, "clipboard", {
      value: { writeText: vi.fn().mockResolvedValue(undefined) },
      configurable: true,
    });
  });

  it("shows 'Copied ✓' feedback after a successful copy", async () => {
    const user = userEvent.setup();
    render(<CopyButton value="bhk_secret123" />);

    await user.click(screen.getByText("Copy"));

    await waitFor(() => expect(screen.getByText("Copied ✓")).toBeInTheDocument());
  });

  it("reverts back to 'Copy' after the feedback window", async () => {
    const user = userEvent.setup();
    render(<CopyButton value="bhk_secret123" />);

    await user.click(screen.getByText("Copy"));
    await waitFor(() => expect(screen.getByText("Copied ✓")).toBeInTheDocument());
    await waitFor(() => expect(screen.getByText("Copy")).toBeInTheDocument(), { timeout: 3000 });
  });

  it("announces the 'Copied' confirmation to screen readers via a stable aria-live region", async () => {
    // A live region only announces content changing if the region itself already existed before
    // the mutation - present from the very first render (not just once copied) is what makes
    // this actually work, not just look right.
    const user = userEvent.setup();
    render(<CopyButton value="bhk_secret123" />);

    const liveRegion = document.querySelector('[aria-live="polite"]');
    expect(liveRegion).not.toBeNull();
    expect(liveRegion).toHaveTextContent("Copy");

    await user.click(screen.getByText("Copy"));

    await waitFor(() => expect(liveRegion).toHaveTextContent("Copied ✓"));
  });
});
