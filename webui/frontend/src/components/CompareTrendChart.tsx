import { CartesianGrid, Legend, Line, LineChart, ReferenceArea, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { CompareSeries } from "../lib/types";

/** Cycled per selected target — cyan/magenta/amber first (the core retro-Tokyo palette), then a few extra hues for larger comparisons. */
const LINE_COLORS = ["#00f0ff", "#ff2e97", "#ffb800", "#7c3aed", "#34d399", "#f472b6"];

/** Faint A-F grade bands behind the lines - same 90/80/70/60 thresholds and color language as
 * GradeBadge/HealthGauge (cyan=healthy, amber=warning, magenta=critical), so "where does this
 * competitor's line sit" reads as a grade at a glance instead of requiring a mental lookup
 * against the Y axis. Opacity kept low (0.02-0.05) so the bands read as a watermark, not
 * something competing with the actual score lines drawn on top. */
const GRADE_BANDS: { y1: number; y2: number; color: string; opacity: number; label: string }[] = [
  { y1: 90, y2: 100, color: "#00f0ff", opacity: 0.05, label: "A" },
  { y1: 80, y2: 90, color: "#00f0ff", opacity: 0.025, label: "B" },
  { y1: 70, y2: 80, color: "#ffb800", opacity: 0.04, label: "C" },
  { y1: 60, y2: 70, color: "#ffb800", opacity: 0.02, label: "D" },
  { y1: 0, y2: 60, color: "#ff2e97", opacity: 0.04, label: "F" },
];

export type CompareScoreMode = "tier1" | "full";

/**
 * The headline "our score vs. competitors over time" chart. Each target
 * scans on its own schedule, so timestamps rarely align across series —
 * rather than force a shared categorical X axis (which would leave most
 * cells empty), each Line gets its own {computedAtMs, score} data array and
 * they all share one numeric time XAxis, which is Recharts' supported
 * pattern for independently-timed series on one chart.
 *
 * `mode` selects which of a snapshot's two scores gets plotted: "tier1" (the
 * default, fair-comparison score excluding Tier 2-exclusive findings that
 * only ever accumulate on authorized/owned targets) or "full" (everything,
 * including deep-scan findings). A competitor with no Tier 2 history plots
 * identically in both modes - that's correct, not a bug, since it never had
 * Tier 2-exclusive findings to differ by.
 */
export function CompareTrendChart({ series, mode }: { series: CompareSeries[]; mode: CompareScoreMode }) {
  if (series.length === 0) {
    return <p className="font-mono text-sm text-slate-400">Select at least one target to compare.</p>;
  }
  if (!series.some((s) => s.history.length > 0)) {
    return (
      <p className="font-mono text-sm text-slate-400">
        No scan history yet for the selected targets — run a scan to start the trend.
      </p>
    );
  }

  return (
    <div className="h-80 w-full rounded-lg border border-neon-cyan/20 bg-panel/60 p-4">
      <ResponsiveContainer width="100%" height="100%">
        {/* left:0 (not a negative margin) + a wider YAxis: a negative left margin combined
            with a narrow axis width clips the leading digit(s) of 2-3 digit tick labels
            ("100" rendered as "0", "75" as "5") - found via Milestone 9's real screenshot
            review. right:28 leaves room so the final X-axis date label isn't clipped either. */}
        <LineChart margin={{ top: 8, right: 28, bottom: 0, left: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(0,240,255,0.1)" />
          {GRADE_BANDS.map((band) => (
            <ReferenceArea
              key={band.label}
              y1={band.y1}
              y2={band.y2}
              fill={band.color}
              fillOpacity={band.opacity}
              stroke="none"
              ifOverflow="extendDomain"
              label={{
                value: band.label,
                position: "insideLeft",
                fill: band.color,
                fillOpacity: 0.5,
                fontSize: 10,
                fontFamily: "JetBrains Mono, monospace",
              }}
            />
          ))}
          <XAxis
            dataKey="computedAtMs"
            type="number"
            domain={["dataMin", "dataMax"]}
            tickFormatter={(ms: number) => new Date(ms).toLocaleDateString()}
            stroke="#7a8aa0"
            fontSize={11}
            fontFamily="JetBrains Mono, monospace"
          />
          <YAxis domain={[0, 100]} stroke="#7a8aa0" fontSize={11} fontFamily="JetBrains Mono, monospace" width={40} />
          <Tooltip
            labelFormatter={(ms) => new Date(ms as number).toLocaleString()}
            contentStyle={{
              background: "#12071f",
              border: "1px solid rgba(0,240,255,0.3)",
              borderRadius: 6,
              fontFamily: "JetBrains Mono, monospace",
              fontSize: 12,
            }}
            labelStyle={{ color: "#7a8aa0" }}
          />
          <Legend formatter={(value) => <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: 12 }}>{value}</span>} />
          {series.map((s, i) => {
            const color = LINE_COLORS[i % LINE_COLORS.length];
            // Pre-fix snapshots have no tier1OverallScore - fall back to the full score rather
            // than dropping the point, so old history doesn't just vanish from the "tier1" view.
            const data = s.history.map((h) => ({
              computedAtMs: new Date(h.computedAt).getTime(),
              score: mode === "tier1" ? h.tier1OverallScore ?? h.overallScore : h.overallScore,
            }));
            return (
              <Line
                key={s.targetId}
                name={`${s.hostname} (${s.targetType})`}
                data={data}
                type="monotone"
                dataKey="score"
                stroke={color}
                strokeWidth={2}
                dot={{ r: 3, fill: color, strokeWidth: 0 }}
                activeDot={{ r: 6 }}
                isAnimationActive={false}
                connectNulls
              />
            );
          })}
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
