import { describe, expect, it } from "vitest";
import { colorsForSeries, summarizeComparison } from "./CompareTrendChart";
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

describe("colorsForSeries", () => {
  // A product review found colors were assigned by array position, so deselecting one target
  // shifted every other selected target's color, and re-adding it later gave it a different one -
  // confusing when comparing the same targets repeatedly.
  it("gives an id the same color across calls with the same set", () => {
    const a = "56c93bd5-c331-47ca-af29-22d37a22da5c";
    const b = "57edf8ea-0865-4261-8092-0a3031abc868";
    expect(colorsForSeries([a, b]).get(a)).toEqual(colorsForSeries([a, b]).get(a));
  });

  it("is unaffected by selection order - a's color is the same whether it's plotted first or second", () => {
    const a = "56c93bd5-c331-47ca-af29-22d37a22da5c";
    const b = "57edf8ea-0865-4261-8092-0a3031abc868";
    expect(colorsForSeries([a, b]).get(a)).toEqual(colorsForSeries([b, a]).get(a));
  });

  it("removing an unrelated target doesn't change a non-colliding target's color", () => {
    // The exact "shuffled on deselect" bug: with only 6 fixed colors and hash-mod-6, which two
    // targets happened to share a slot changed on every add/remove even though each one's own
    // color was technically stable. These three ids don't collide (see the "never the same"
    // test below for a large set), so removing "c" must leave "a" untouched.
    const a = "56c93bd5-c331-47ca-af29-22d37a22da5c";
    const b = "57edf8ea-0865-4261-8092-0a3031abc868";
    const c = "11111111-1111-1111-1111-111111111111";
    const withAll = colorsForSeries([a, b, c]);
    const withoutC = colorsForSeries([a, b]);
    expect(withoutC.get(a)).toEqual(withAll.get(a));
    expect(withoutC.get(b)).toEqual(withAll.get(b));
  });

  it("never assigns the same color to two different ids, even well beyond typical comparison sizes", () => {
    const ids = Array.from({ length: 25 }, (_, i) => `target-${i}`);
    const colors = colorsForSeries(ids);
    const distinctColors = new Set(colors.values());
    expect(distinctColors.size).toBe(ids.length);
  });

  it("returns a valid hsl() color", () => {
    const color = colorsForSeries(["some-id"]).get("some-id");
    expect(color).toMatch(/^hsl\(\d+(\.\d+)?, \d+%, \d+%\)$/);
  });
});
