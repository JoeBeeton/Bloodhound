import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { relativeTime } from "./relativeTime";

describe("relativeTime", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-15T12:00:00Z"));
  });
  afterEach(() => vi.useRealTimers());

  it("returns 'just now' for anything under a minute", () => {
    expect(relativeTime("2026-01-15T11:59:31Z")).toBe("just now");
  });

  it("formats minutes ago", () => {
    expect(relativeTime("2026-01-15T11:55:00Z")).toBe("5 minutes ago");
  });

  it("formats hours ago", () => {
    expect(relativeTime("2026-01-15T09:00:00Z")).toBe("3 hours ago");
  });

  it("formats days ago", () => {
    expect(relativeTime("2026-01-13T12:00:00Z")).toBe("2 days ago");
  });

  it("formats a future timestamp (clock skew) without throwing", () => {
    expect(relativeTime("2026-01-15T12:05:00Z")).toBe("in 5 minutes");
  });
});
