import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { ChartContainer } from "./ChartContainer";
import { SEVERITY_HEX } from "../lib/severityStyles";
import { SEVERITIES, type CompareSeries } from "../lib/types";

/** findingCounts carries no tier1/full split (unlike overallScore/categoryScores) - it's always
 * the current open-finding count regardless of score mode, so this view has no mode prop at all. */
function buildRows(series: CompareSeries[]) {
  return series
    .filter((s) => s.history.length > 0)
    .map((s) => {
      const latest = s.history[s.history.length - 1];
      const row: Record<string, number | string> = {
        target: `${s.hostname} (${s.targetType})`,
      };
      for (const severity of SEVERITIES) {
        row[severity] = latest.findingCounts[severity] ?? 0;
      }
      return row;
    });
}

/** Status colors (severity) are reserved for severity alone and never reused for target identity
 * here - unlike the category-breakdown and trend views, where color follows the TARGET, this
 * chart's bars are segmented by SEVERITY, so the established severity palette applies directly
 * instead of the per-target hash hues. */
export function CompareFindingsChart({ series }: { series: CompareSeries[] }) {
  if (series.length === 0) {
    return (
      <p className="font-mono text-sm text-slate-400">
        Select at least one target to compare.
      </p>
    );
  }
  const rows = buildRows(series);
  if (rows.length === 0) {
    return (
      <p className="font-mono text-sm text-slate-400">
        No scan history yet for the selected targets — run a scan to start the
        trend.
      </p>
    );
  }

  const summary = rows
    .map(
      (r) =>
        `${r.target}: ${SEVERITIES.map((sev) => `${r[sev]} ${sev.toLowerCase()}`).join(", ")}`,
    )
    .join("; ");

  return (
    <ChartContainer ariaLabel={`Open findings by severity: ${summary}.`}>
      <BarChart
        data={rows}
        layout="vertical"
        margin={{ top: 8, right: 28, bottom: 0, left: 0 }}
      >
        <CartesianGrid strokeDasharray="3 3" stroke="rgba(0,240,255,0.1)" />
        <XAxis
          type="number"
          stroke="#7a8aa0"
          fontSize={11}
          fontFamily="JetBrains Mono, monospace"
          allowDecimals={false}
        />
        <YAxis
          dataKey="target"
          type="category"
          stroke="#7a8aa0"
          fontSize={11}
          fontFamily="JetBrains Mono, monospace"
          width={160}
        />
        <Tooltip
          contentStyle={{
            background: "#12071f",
            border: "1px solid rgba(0,240,255,0.3)",
            borderRadius: 6,
            fontFamily: "JetBrains Mono, monospace",
            fontSize: 12,
          }}
          labelStyle={{ color: "#e2e8f0", marginBottom: 4 }}
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
        {SEVERITIES.map((severity) => (
          <Bar
            key={severity}
            name={severity}
            dataKey={severity}
            stackId="findings"
            fill={SEVERITY_HEX[severity]}
            isAnimationActive={false}
          />
        ))}
      </BarChart>
    </ChartContainer>
  );
}
