import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { apiFetch } from "../lib/apiClient";
import { ScreenshotThumbnail } from "./ScreenshotThumbnail";

vi.mock("../lib/apiClient", () => ({ apiFetch: vi.fn() }));
const mockedApiFetch = vi.mocked(apiFetch);

function pendingResponse() {
  return {
    ok: true,
    blob: () => new Promise<Blob>(() => {}), // never resolves - simulates "still loading"
  } as unknown as Response;
}

describe("ScreenshotThumbnail", () => {
  it("shows the loading skeleton (not a stale broken image) immediately after src changes", async () => {
    URL.createObjectURL = vi.fn(() => "blob:first");
    URL.revokeObjectURL = vi.fn();

    const firstBlob = new Blob(["a"]);
    mockedApiFetch.mockResolvedValueOnce({ ok: true, blob: async () => firstBlob } as unknown as Response);

    const { rerender } = render(<ScreenshotThumbnail src="/shot-a" alt="a" />);
    const img = await screen.findByAltText("a");
    expect(img.tagName).toBe("IMG");
    expect(img.getAttribute("src")).toBe("blob:first");

    // src changes to a still-loading fetch - the component must not keep rendering the old
    // (now cleanup-revoked) blob: URL while the new one is in flight.
    mockedApiFetch.mockReturnValueOnce(Promise.resolve(pendingResponse()));
    rerender(<ScreenshotThumbnail src="/shot-b" alt="b" />);

    expect(screen.queryByAltText("a")).not.toBeInTheDocument();
    expect(screen.queryByAltText("b")).not.toBeInTheDocument();
    expect(document.querySelector(".animate-pulse")).toBeInTheDocument();
  });
});
