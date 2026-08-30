import { renderHook } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useUnsavedChangesWarning } from "./useUnsavedChangesWarning";

function dispatchBeforeUnload(): BeforeUnloadEvent {
  const event = new Event("beforeunload", { cancelable: true }) as BeforeUnloadEvent;
  window.dispatchEvent(event);
  return event;
}

describe("useUnsavedChangesWarning", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("does not intercept beforeunload when there are no unsaved changes", () => {
    renderHook(() => useUnsavedChangesWarning(false));

    const event = dispatchBeforeUnload();

    expect(event.defaultPrevented).toBe(false);
  });

  it("intercepts beforeunload when there are unsaved changes", () => {
    renderHook(() => useUnsavedChangesWarning(true));

    const event = dispatchBeforeUnload();

    // defaultPrevented is the meaningful, cross-browser assertion here - it's what actually
    // triggers the browser's own confirmation prompt. returnValue isn't checked: jsdom's plain
    // Event polyfill (there's no real BeforeUnloadEvent constructor to instantiate in a test
    // environment) doesn't reliably reflect an assignment to it the way a real browser does.
    expect(event.defaultPrevented).toBe(true);
  });

  it("stops intercepting once hasUnsavedChanges flips back to false", () => {
    const { rerender } = renderHook(({ dirty }) => useUnsavedChangesWarning(dirty), {
      initialProps: { dirty: true },
    });
    expect(dispatchBeforeUnload().defaultPrevented).toBe(true);

    rerender({ dirty: false });
    expect(dispatchBeforeUnload().defaultPrevented).toBe(false);
  });

  it("removes its listener on unmount, even while dirty", () => {
    const { unmount } = renderHook(() => useUnsavedChangesWarning(true));
    unmount();

    expect(dispatchBeforeUnload().defaultPrevented).toBe(false);
  });
});
