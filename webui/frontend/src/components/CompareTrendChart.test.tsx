import { describe, expect, it } from "vitest";
import { summarizeComparison } from "./CompareTrendChart";
import type { CompareSeries, ScoreSnapshot, TargetType } from "../lib/types";

function snapshot(overallScore: number, tier1OverallScore: number | null): ScoreSnapshot {
  return {
    id: "s1",
    scanRunId: "run-1",
    computedAt: "2026-01-01T00:00:00Z",
    overallScore,
    grade: "C",
    categoryScores: {} as ScoreSnapshot["categoryScores"],
    findingCounts: {} as ScoreSnapshot["findingCounts"],
    tier1OverallScore,
    tier1Grade: tier1OverallScore !== null ? "C" : null,
    tier1CategoryScores: null,
  };
}

function series(hostname: string, targetType: TargetType, history: ScoreSnapshot[]): CompareSeries {
  return { targetId: hostname, hostname, targetType, history };
}

describe("summarizeComparison", () => {
  // Same reasoning as ScoreTrendChart's own summarizeTrend - this text summary is what a
  // screen-reader user gets in place of the unlabeled multi-line SVG this chart otherwise is.
  it("describes no history distinctly from a real comparison", () => {
    const summary = summarizeComparison([series("a.example.com", "OWN", [])], "tier1");
    expect(summary).toContain("no scan history yet");
  });

  it("lists each target with history and its latest score, skipping targets with none", () => {
    const summary = summarizeComparison(
      [
        series("own.example.com", "OWN", [snapshot(85, 80)]),
        series("rival.example.com", "COMPETITOR", [snapshot(70, null)]),
        series("watchlist.example.com", "WATCHLIST", []),
      ],
      "full",
    );
    expect(summary).toContain("own.example.com at 85");
    expect(summary).toContain("rival.example.com at 70");
    expect(summary).not.toContain("watchlist.example.com");
  });

  it("tier1 mode uses tier1OverallScore, falling back to the full score when absent", () => {
    const summary = summarizeComparison(
      [
        series("own.example.com", "OWN", [snapshot(85, 60)]),
        series("legacy.example.com", "COMPETITOR", [snapshot(70, null)]),
      ],
      "tier1",
    );
    expect(summary).toContain("own.example.com at 60");
    // No tier1OverallScore recorded yet (pre-fix snapshot) - falls back to the full score.
    expect(summary).toContain("legacy.example.com at 70");
    expect(summary).toContain("fair comparison");
  });

  it("full mode always uses the full overallScore, ignoring tier1OverallScore", () => {
    const summary = summarizeComparison([series("own.example.com", "OWN", [snapshot(85, 60)])], "full");
    expect(summary).toContain("own.example.com at 85");
    expect(summary).toContain("full picture");
  });

  it("uses only the most recent snapshot per target, not an average", () => {
    const summary = summarizeComparison([series("own.example.com", "OWN", [snapshot(50, 50), snapshot(90, 90)])], "full");
    expect(summary).toContain("own.example.com at 90");
    expect(summary).not.toContain("at 50");
  });
});
