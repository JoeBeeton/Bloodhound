import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { SEVERITY_HEX } from "../lib/severityStyles";
import type { FindingActivityBucket, Severity } from "../lib/types";

const SEVERITY_KEYS: { key: keyof Omit<FindingActivityBucket, "day">; severity: Severity }[] = [
  { key: "info", severity: "INFO" },
  { key: "low", severity: "LOW" },
  { key: "medium", severity: "MEDIUM" },
  { key: "high", severity: "HIGH" },
  { key: "critical", severity: "CRITICAL" },
];

function total(b: FindingActivityBucket): number {
  return b.critical + b.high + b.medium + b.low + b.info;
}

/** Mirrors ScoreTrendChart's own role="img" + summarizing aria-label pattern - a screen-reader
 * user gets the same "what does this show" a sighted user gets at a glance, not a silent chart
 * or a confusing read-out of individual bar elements. */
export function summarizeActivity(buckets: FindingActivityBucket[]): string {
  const grandTotal = buckets.reduce((sum, b) => sum + total(b), 0);
  const busiest = buckets.reduce((max, b) => (total(b) > total(max) ? b : max), buckets[0]);
  const busiestLabel = new Date(busiest.day).toLocaleDateString();
  return `Findings activity over the last ${buckets.length} days: ${grandTotal} total, busiest day ${busiestLabel} with ${total(busiest)}.`;
}

/**
 * A 14-day (by default) stacked bar of finding-creation counts per severity, sitting above the
 * Findings Feed's timeline - "when did things spike", a question the feed's own scroll-order
 * can't answer at a glance once there's more than a page of history. Clicking a day's column
 * narrows the feed below to just that day; clicking the already-selected day clears it.
 */
export function FindingActivityPulse({
  buckets,
  selectedDay,
  onSelectDay,
}: {
  buckets: FindingActivityBucket[] | undefined;
  selectedDay: string | undefined;
  onSelectDay: (day: string | undefined) => void;
}) {
  if (!buckets || buckets.length === 0) {
    return null;
  }

  const data = buckets.map((b) => ({
    ...b,
    label: new Date(b.day).toLocaleDateString(undefined, { month: "short", day: "numeric" }),
  }));
  const summary = summarizeActivity(buckets);
  const tickInterval = Math.max(0, Math.floor(data.length / 7) - 1);

  return (
    <div
      className="mb-4 h-32 w-full rounded-lg border border-neon-cyan/20 bg-panel/60 p-3"
      role="img"
      aria-label={summary}
    >
      <ResponsiveContainer width="100%" height="100%">
        <BarChart
          data={data}
          margin={{ top: 4, right: 8, bottom: 0, left: 0 }}
          onClick={(e) => {
            const day = (e?.activePayload?.[0]?.payload as FindingActivityBucket | undefined)?.day;
            if (day) onSelectDay(day === selectedDay ? undefined : day);
          }}
        >
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(0,240,255,0.08)" vertical={false} />
          <XAxis
            dataKey="label"
            stroke="#7a8aa0"
            fontSize={10}
            fontFamily="JetBrains Mono, monospace"
            interval={tickInterval}
            tickLine={false}
          />
          <YAxis hide />
          <Tooltip
            cursor={{ fill: "rgba(0,240,255,0.06)" }}
            contentStyle={{
              background: "#12071f",
              border: "1px solid rgba(0,240,255,0.3)",
              borderRadius: 8,
              fontFamily: "JetBrains Mono, monospace",
              fontSize: 11,
            }}
            labelStyle={{ color: "#00f0ff" }}
            formatter={(value: number, name: string) => [value, name.toUpperCase()]}
          />
          {SEVERITY_KEYS.map(({ key, severity }) => (
            <Bar key={key} dataKey={key} stackId="day" fill={SEVERITY_HEX[severity]} cursor="pointer" />
          ))}
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
