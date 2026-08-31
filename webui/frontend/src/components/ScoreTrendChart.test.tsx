import { describe, expect, it } from "vitest";
import { summarizeTrend } from "./ScoreTrendChart";
import type { ScoreSnapshot } from "../lib/types";

function snapshot(overallScore: number, grade: ScoreSnapshot["grade"], computedAt = "2026-01-01T00:00:00Z"): ScoreSnapshot {
  return {
    id: `${computedAt}-${overallScore}`,
    scanRunId: "run-1",
    computedAt,
    overallScore,
    grade,
    categoryScores: {} as ScoreSnapshot["categoryScores"],
    findingCounts: {} as ScoreSnapshot["findingCounts"],
    tier1OverallScore: null,
    tier1Grade: null,
    tier1CategoryScores: null,
  };
}

describe("summarizeTrend", () => {
  // A screen-reader user gets nothing useful from an unlabeled Recharts SVG - this is the text
  // summary that stands in for "look at the shape of the line" a sighted user gets at a glance.
  it("describes a single scan distinctly from a real trend", () => {
    const summary = summarizeTrend([snapshot(72, "C")]);
    expect(summary).toContain("one scan so far");
    expect(summary).toContain("72");
    expect(summary).toContain("C");
  });

  it("describes a multi-scan trend with its latest score and the full range", () => {
    const summary = summarizeTrend([snapshot(60, "D"), snapshot(75, "C"), snapshot(90, "A")]);
    expect(summary).toContain("3 scans");
    expect(summary).toContain("latest score 90");
    expect(summary).toContain("grade A");
    expect(summary).toContain("ranging from 60 to 90");
  });

  it("range reflects the true min/max, not just first-vs-last", () => {
    // A trend that dips in the middle (60 -> 90 -> 55 -> 80) has a wider true range than what
    // comparing only the first and last points would suggest.
    const summary = summarizeTrend([snapshot(60, "D"), snapshot(90, "A"), snapshot(55, "F"), snapshot(80, "B")]);
    expect(summary).toContain("ranging from 55 to 90");
    expect(summary).toContain("latest score 80");
  });
});
