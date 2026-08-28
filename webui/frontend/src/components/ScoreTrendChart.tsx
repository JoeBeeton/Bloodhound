import { CartesianGrid, Line, LineChart, ReferenceArea, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { GRADE_BANDS } from "../lib/gradeBands";
import type { ScoreSnapshot } from "../lib/types";

/** `compact`: no axes/grid/border, smaller height - for the dashboard hero sparkline, which just needs "shape of the trend", not a fully readable chart (the full one is one click away on the target detail page). */
export function ScoreTrendChart({
  history,
  compact = false,
}: {
  history: ScoreSnapshot[] | undefined;
  compact?: boolean;
}) {
  if (!history || history.length === 0) {
    return (
      <p className="font-mono text-sm text-slate-400">
        {compact ? "No scan history yet." : "No scan history yet — run a scan to start the trend."}
      </p>
    );
  }

  const data = history.map((snapshot) => ({
    computedAt: snapshot.computedAt,
    label: new Date(snapshot.computedAt).toLocaleDateString(),
    overallScore: snapshot.overallScore,
  }));

  if (compact) {
    return (
      <div className="h-16 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={data} margin={{ top: 4, right: 4, bottom: 0, left: 4 }}>
            <YAxis domain={[0, 100]} hide />
            <Line
              type="monotone"
              dataKey="overallScore"
              stroke="#00f0ff"
              strokeWidth={2}
              dot={false}
              isAnimationActive={false}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    );
  }

  return (
    <div className="h-56 w-full rounded-lg border border-neon-cyan/20 bg-panel/60 p-4">
      <ResponsiveContainer width="100%" height="100%">
        {/* left:0 + wider YAxis: a negative left margin + narrow axis width clips the
            leading digit(s) of 2-3 digit tick labels ("100" -> "0") - same fix as
            CompareTrendChart, found via Milestone 9's real screenshot review. */}
        <LineChart data={data} margin={{ top: 8, right: 20, bottom: 0, left: 0 }}>
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
          <XAxis dataKey="label" stroke="#7a8aa0" fontSize={11} fontFamily="JetBrains Mono, monospace" />
          <YAxis domain={[0, 100]} stroke="#7a8aa0" fontSize={11} fontFamily="JetBrains Mono, monospace" width={40} />
          <Tooltip
            contentStyle={{
              background: "#12071f",
              border: "1px solid rgba(0,240,255,0.3)",
              borderRadius: 6,
              fontFamily: "JetBrains Mono, monospace",
              fontSize: 12,
            }}
            labelStyle={{ color: "#7a8aa0" }}
            itemStyle={{ color: "#00f0ff" }}
          />
          {/* A single data point renders as just the dot marker (no visible line segment), which is the correct,
              non-broken rendering for a target scanned only once so far. */}
          <Line
            type="monotone"
            dataKey="overallScore"
            stroke="#00f0ff"
            strokeWidth={2}
            dot={{ r: 4, fill: "#00f0ff", strokeWidth: 0 }}
            activeDot={{ r: 6 }}
            isAnimationActive={false}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
