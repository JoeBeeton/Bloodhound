import { renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useIdleLogout } from "./useIdleLogout";

// Chosen with enough margin over the hook's internal 5s check-interval granularity that ticks
// land cleanly on either side of the warn/timeout thresholds (warn at 10s, timeout at 20s,
// checks at 5s/10s/15s/20s) - real usage (30min timeout, 60s warning) has the same property.
const IDLE_TIMEOUT_MS = 20_000;
const WARNING_MS = 10_000;

describe("useIdleLogout", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("does nothing while disabled", () => {
    const onWarn = vi.fn();
    const onTimeout = vi.fn();
    renderHook(() => useIdleLogout({ enabled: false, idleTimeoutMs: IDLE_TIMEOUT_MS, warningMs: WARNING_MS, onWarn, onTimeout }));

    vi.advanceTimersByTime(IDLE_TIMEOUT_MS + 10_000);

    expect(onWarn).not.toHaveBeenCalled();
    expect(onTimeout).not.toHaveBeenCalled();
  });

  it("fires onWarn once the warning window is reached, then onTimeout once the full idle period elapses", () => {
    const onWarn = vi.fn();
    const onTimeout = vi.fn();
    renderHook(() => useIdleLogout({ enabled: true, idleTimeoutMs: IDLE_TIMEOUT_MS, warningMs: WARNING_MS, onWarn, onTimeout }));

    // Before the warn threshold (20s - 10s = 10s).
    vi.advanceTimersByTime(9_000);
    expect(onWarn).not.toHaveBeenCalled();

    // Past the warn threshold, still short of the full timeout.
    vi.advanceTimersByTime(2_000); // cumulative 11s
    expect(onWarn).toHaveBeenCalledTimes(1);
    expect(onTimeout).not.toHaveBeenCalled();

    // Past the full idle timeout.
    vi.advanceTimersByTime(10_000); // cumulative 21s
    expect(onTimeout).toHaveBeenCalledTimes(1);
  });

  it("real activity (a window event) resets the idle clock and cancels a pending warning", () => {
    const onWarn = vi.fn();
    const onTimeout = vi.fn();
    renderHook(() => useIdleLogout({ enabled: true, idleTimeoutMs: IDLE_TIMEOUT_MS, warningMs: WARNING_MS, onWarn, onTimeout }));

    vi.advanceTimersByTime(11_000); // past the 10s warn threshold
    expect(onWarn).toHaveBeenCalledTimes(1);

    window.dispatchEvent(new MouseEvent("mousemove"));

    // Without the reset, cumulative idle time would already be well past the 20s timeout.
    vi.advanceTimersByTime(9_000); // only 9s since the reset - short of another warn or timeout
    expect(onTimeout).not.toHaveBeenCalled();
    expect(onWarn).toHaveBeenCalledTimes(1);
  });

  it("removes its event listeners and stops checking once unmounted", () => {
    const onWarn = vi.fn();
    const onTimeout = vi.fn();
    const { unmount } = renderHook(() =>
      useIdleLogout({ enabled: true, idleTimeoutMs: IDLE_TIMEOUT_MS, warningMs: WARNING_MS, onWarn, onTimeout }),
    );

    unmount();
    vi.advanceTimersByTime(IDLE_TIMEOUT_MS + 10_000);

    expect(onWarn).not.toHaveBeenCalled();
    expect(onTimeout).not.toHaveBeenCalled();
  });
});
