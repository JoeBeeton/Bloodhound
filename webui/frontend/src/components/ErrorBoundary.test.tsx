import { render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ErrorBoundary } from "./ErrorBoundary";

function Bomb(): never {
  throw new Error("boom");
}

describe("ErrorBoundary", () => {
  let consoleErrorSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    // React (and this boundary's own componentDidCatch) both log to console.error when a child
    // throws - expected noise for these tests, not a real failure, so it's silenced rather than
    // left to clutter the test output.
    consoleErrorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    consoleErrorSpy.mockRestore();
  });

  it("renders children normally when nothing throws", () => {
    render(
      <ErrorBoundary>
        <p>all good</p>
      </ErrorBoundary>,
    );

    expect(screen.getByText("all good")).toBeInTheDocument();
  });

  it("catches a render-time error and shows the fallback instead of crashing the whole tree", () => {
    render(
      <ErrorBoundary>
        <Bomb />
      </ErrorBoundary>,
    );

    expect(screen.getByText("Something went wrong")).toBeInTheDocument();
    expect(screen.queryByText("all good")).not.toBeInTheDocument();
  });

  it("offers both a reload and a dashboard escape hatch, as plain navigations not React state", () => {
    render(
      <ErrorBoundary>
        <Bomb />
      </ErrorBoundary>,
    );

    const reload = screen.getByRole("link", { name: /reload this page/i });
    const dashboard = screen.getByRole("link", { name: /go to dashboard/i });
    // Real <a> elements with real hrefs - not onClick handlers relying on React Router context,
    // which this boundary sits above and can't assume is still safely mounted once tripped.
    expect(reload.tagName).toBe("A");
    expect(dashboard).toHaveAttribute("href", "/dashboard");
  });

  it("logs the caught error for diagnosability rather than swallowing it silently", () => {
    render(
      <ErrorBoundary>
        <Bomb />
      </ErrorBoundary>,
    );

    expect(consoleErrorSpy).toHaveBeenCalledWith(
      "Unhandled error caught by ErrorBoundary:",
      expect.any(Error),
      expect.anything(),
    );
  });
});
