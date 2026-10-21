import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { colorsForSeries } from "./CompareTrendChart";
import type { CompareScoreMode } from "./CompareTrendChart";
import { ChartContainer } from "./ChartContainer";
import {
  SCORE_CATEGORIES,
  type CompareSeries,
  type ScoreCategory,
} from "../lib/types";

const CATEGORY_LABELS: Record<ScoreCategory, string> = {
  EXPOSURE: "Exposure",
  TLS: "TLS",
  DNS: "DNS",
  NETWORK: "Network",
  HEADERS: "Headers",
  SUBDOMAIN_HYGIENE: "Subdomain hygiene",
  WEB_APP: "Web app",
};

/** A target with no history yet contributes no bar at all for any category - same "silently
 * skipped" convention CompareTrendChart's own Line rendering already uses, rather than drawing a
 * misleading zero. */
function latestCategoryScores(
  s: CompareSeries,
  mode: CompareScoreMode,
): Record<ScoreCategory, number> | null {
  if (s.history.length === 0) return null;
  const latest = s.history[s.history.length - 1];
  if (mode === "tier1")
    return latest.tier1CategoryScores ?? latest.categoryScores;
  return latest.categoryScores;
}

/** One row per category, one key per target - Recharts' grouped-bar convention: unlike
 * CompareTrendChart's per-series data arrays (needed there because each target scans on its own
 * schedule), every target's CURRENT score exists at the same instant ("right now"), so there's no
 * equivalent misalignment problem here - a single shared dataset is both simpler and correct. */
function buildRows(series: CompareSeries[], mode: CompareScoreMode) {
  return SCORE_CATEGORIES.map((category) => {
    const row: Record<string, number | string> = {
      category: CATEGORY_LABELS[category],
    };
    for (const s of series) {
      const scores = latestCategoryScores(s, mode);
      if (scores) row[s.targetId] = scores[category];
    }
    return row;
  });
}

/**
 * "Who's weak where" - each selected target's CURRENT category scores side
 * by side, one group of bars per category. Complements CompareTrendChart's
 * single rolled-up score-over-time line: this view trades the time
 * dimension for a category breakdown of right-now, the same differentiator
 * CategoryBreakdown already gives for a single target, extended across
 * every target on the comparison.
 */
export function CompareCategoryChart({
  series,
  mode,
}: {
  series: CompareSeries[];
  mode: CompareScoreMode;
}) {
  if (series.length === 0) {
    return (
      <p className="font-mono text-sm text-slate-400">
        Select at least one target to compare.
      </p>
    );
  }
  const withHistory = series.filter((s) => s.history.length > 0);
  if (withHistory.length === 0) {
    return (
      <p className="font-mono text-sm text-slate-400">
        No scan history yet for the selected targets — run a scan to start the
        trend.
      </p>
    );
  }

  const colors = colorsForSeries(series.map((s) => s.targetId));
  const rows = buildRows(withHistory, mode);
  const summary = withHistory
    .map((s) => {
      const scores = latestCategoryScores(s, mode);
      if (!scores) return null;
      const weakest = SCORE_CATEGORIES.reduce((a, b) =>
        scores[a] <= scores[b] ? a : b,
      );
      return `${s.hostname} weakest in ${CATEGORY_LABELS[weakest]} at ${scores[weakest].toFixed(0)}`;
    })
    .filter((c): c is string => c !== null)
    .join("; ");

  return (
    <ChartContainer ariaLabel={`Category score breakdown: ${summary}.`}>
      <BarChart data={rows} margin={{ top: 8, right: 28, bottom: 0, left: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="rgba(0,240,255,0.1)" />
        <XAxis
          dataKey="category"
          stroke="#7a8aa0"
          fontSize={11}
          fontFamily="JetBrains Mono, monospace"
          interval={0}
          angle={-20}
          textAnchor="end"
          height={48}
        />
        <YAxis
          domain={[0, 100]}
          stroke="#7a8aa0"
          fontSize={11}
          fontFamily="JetBrains Mono, monospace"
          width={40}
        />
        <Tooltip
          contentStyle={{
            background: "#12071f",
            border: "1px solid rgba(0,240,255,0.3)",
            borderRadius: 6,
            fontFamily: "JetBrains Mono, monospace",
            fontSize: 12,
          }}
          labelStyle={{ color: "#7a8aa0", marginBottom: 4 }}
          formatter={(value: number) => value.toFixed(0)}
        />
        <Legend
          formatter={(value) => (
            <span
              style={{ fontFamily: "JetBrains Mono, monospace", fontSize: 12 }}
            >
              {value}
            </span>
          )}
        />
        {withHistory.map((s) => (
          <Bar
            key={s.targetId}
            name={`${s.hostname} (${s.targetType})`}
            dataKey={s.targetId}
            fill={colors.get(s.targetId)}
            radius={[2, 2, 0, 0]}
            isAnimationActive={false}
          />
        ))}
      </BarChart>
    </ChartContainer>
  );
}
