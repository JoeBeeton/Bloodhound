import { describe, expect, it } from "vitest";
import { summarizeActivity } from "./FindingActivityPulse";
import type { FindingActivityBucket } from "../lib/types";

function bucket(day: string, overrides: Partial<FindingActivityBucket> = {}): FindingActivityBucket {
  return { day, critical: 0, high: 0, medium: 0, low: 0, info: 0, ...overrides };
}

describe("summarizeActivity", () => {
  // Same reasoning as ScoreTrendChart's own summarizeTrend - this text summary is what a
  // screen-reader user gets in place of the unlabeled stacked-bar SVG this chart otherwise is.
  it("totals every severity across every day", () => {
    const summary = summarizeActivity([
      bucket("2026-01-01", { critical: 1, high: 2 }),
      bucket("2026-01-02", { medium: 3, low: 1, info: 1 }),
    ]);
    expect(summary).toContain("8 total");
    expect(summary).toContain("2 days");
  });

  it("identifies the busiest day by total count across severities, not any single one", () => {
    const summary = summarizeActivity([
      bucket("2026-01-01", { critical: 5 }),
      bucket("2026-01-02", { low: 1, info: 1, medium: 1 }),
    ]);
    expect(summary).toContain("with 5");
  });

  it("a day with mixed low-severity counts can still be busiest overall", () => {
    const summary = summarizeActivity([
      bucket("2026-01-01", { critical: 2 }),
      bucket("2026-01-02", { low: 3, info: 3 }),
    ]);
    expect(summary).toContain("with 6");
  });
});
