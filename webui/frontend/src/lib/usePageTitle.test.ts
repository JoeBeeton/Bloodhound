import { renderHook } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { usePageTitle } from "./usePageTitle";

const DEFAULT_TITLE = "Bloodhound — Attack Surface Monitoring";

describe("usePageTitle", () => {
  afterEach(() => {
    document.title = DEFAULT_TITLE;
  });

  it("sets the browser tab title with the app name suffixed", () => {
    renderHook(() => usePageTitle("Targets"));

    expect(document.title).toBe("Targets — Bloodhound");
  });

  it("falls back to the default title when given null/undefined - a page still loading its resource's name", () => {
    renderHook(() => usePageTitle(null));

    expect(document.title).toBe(DEFAULT_TITLE);
  });

  it("updates live as the title value changes - e.g. once a detail page's data finishes loading", () => {
    const { rerender } = renderHook(({ title }) => usePageTitle(title), { initialProps: { title: null as string | null } });
    expect(document.title).toBe(DEFAULT_TITLE);

    rerender({ title: "example.finance" });

    expect(document.title).toBe("example.finance — Bloodhound");
  });

  it("restores the default title on unmount - a product review found every route previously left a stale title from whatever page was open before it", () => {
    const { unmount } = renderHook(() => usePageTitle("Scan: example.finance"));
    expect(document.title).toBe("Scan: example.finance — Bloodhound");

    unmount();

    expect(document.title).toBe(DEFAULT_TITLE);
  });
});
