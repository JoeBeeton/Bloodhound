import { GradeBadge } from "./GradeBadge";
import { TargetTypeBadge } from "./TargetTypeBadge";
import type { CompareScoreMode } from "./CompareTrendChart";
import type { CompareSeries } from "../lib/types";

interface Row {
  series: CompareSeries;
  score: number;
  grade: CompareSeries["history"][number]["grade"];
  deltaSinceFirst: number | null;
}

function scoreAndGrade(
  s: CompareSeries,
  mode: CompareScoreMode,
  snapshot: CompareSeries["history"][number],
) {
  if (mode === "tier1") {
    return {
      score: snapshot.tier1OverallScore ?? snapshot.overallScore,
      grade: snapshot.tier1Grade ?? snapshot.grade,
    };
  }
  return { score: snapshot.overallScore, grade: snapshot.grade };
}

function buildRows(series: CompareSeries[], mode: CompareScoreMode): Row[] {
  return series
    .filter((s) => s.history.length > 0)
    .map((s) => {
      const first = s.history[0];
      const latest = s.history[s.history.length - 1];
      const { score, grade } = scoreAndGrade(s, mode, latest);
      const firstScore = scoreAndGrade(s, mode, first).score;
      return {
        series: s,
        score,
        grade,
        deltaSinceFirst: s.history.length > 1 ? score - firstScore : null,
      };
    })
    .sort((a, b) => b.score - a.score);
}

function DeltaBadge({ delta }: { delta: number | null }) {
  if (delta === null) {
    return <span className="font-mono text-xs text-slate-500">—</span>;
  }
  if (Math.abs(delta) < 0.5) {
    return <span className="font-mono text-xs text-slate-400">flat</span>;
  }
  const up = delta > 0;
  return (
    <span
      className={`font-mono text-xs ${up ? "text-neon-cyan" : "text-severity-critical"}`}
    >
      {up ? "▲" : "▼"} {Math.abs(delta).toFixed(0)}
    </span>
  );
}

/**
 * A straight ranked table - the plain alternative every chart on this page
 * needs (a bar/line chart is read by sighted users eyeballing geometry; a
 * table is the one view a screen reader and a quick skim both use
 * natively). Doubles as the most legible view once enough targets are
 * selected that the trend chart's legend and lines start overlapping -
 * ranking by score needs no decoding at all, unlike reading it off a dense
 * line chart.
 */
export function CompareLeaderboard({
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
  const rows = buildRows(series, mode);
  if (rows.length === 0) {
    return (
      <p className="font-mono text-sm text-slate-400">
        No scan history yet for the selected targets — run a scan to start the
        trend.
      </p>
    );
  }

  return (
    <div className="w-full overflow-hidden rounded-lg border border-neon-cyan/20 bg-panel/60">
      <table className="w-full text-left font-mono text-sm">
        <thead>
          <tr className="border-b border-neon-cyan/20 text-xs uppercase tracking-widest text-slate-400">
            <th className="px-4 py-3 font-normal">Rank</th>
            <th className="px-4 py-3 font-normal">Target</th>
            <th className="px-4 py-3 font-normal">Grade</th>
            <th className="px-4 py-3 font-normal">Change</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr
              key={row.series.targetId}
              className="border-b border-neon-cyan/10 last:border-0"
            >
              <td className="px-4 py-3 text-slate-500">{i + 1}</td>
              <td className="px-4 py-3">
                <span className="text-slate-200">{row.series.hostname}</span>{" "}
                {row.series.targetType === "PORTFOLIO" ? (
                  <span className="rounded border border-neon-magenta/50 px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-widest text-neon-magenta">
                    PORTFOLIO
                  </span>
                ) : (
                  <TargetTypeBadge targetType={row.series.targetType} />
                )}
              </td>
              <td className="px-4 py-3">
                <GradeBadge grade={row.grade} score={row.score} />
              </td>
              <td className="px-4 py-3">
                <DeltaBadge delta={row.deltaSinceFirst} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
